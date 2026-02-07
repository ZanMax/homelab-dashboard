package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	StatusOnline   = "Online"
	StatusOffline  = "Offline"
	StatusScanning = "Scanning"
	StatusError    = "Error"
	StatusUnknown  = "Unknown"
)

type NetMonitorConfig struct {
	Enable              bool   `yaml:"enable"`
	DefaultSubnet       string `yaml:"default_subnet"`
	DefaultInterval     int    `yaml:"default_interval"`
	NmapScanEnabled     bool   `yaml:"nmap_scan_enabled"`
	NmapDefaultInterval int    `yaml:"nmap_default_interval"`
	NmapCommandArgs     string `yaml:"nmap_command_args"`
	NmapHostTimeout     int    `yaml:"nmap_host_timeout"`
	PingTimeoutMs       int    `yaml:"ping_timeout_ms"`
	PortScanEnabled     bool   `yaml:"port_scan_enabled"`
	PortScanInterval    int    `yaml:"port_scan_interval"`
	PortScanTimeoutMs   int    `yaml:"port_scan_timeout_ms"`
	OfflineThreshold    int    `yaml:"offline_threshold"`
}

type MonitoredHost struct {
	IP           string    `json:"ip"`
	Status       string    `json:"status"`
	LastSeen     time.Time `json:"last_seen"`
	OpenPorts    []string  `json:"open_ports,omitempty"`
	LastPortScan time.Time `json:"last_port_scan,omitempty"`
	missCount    int
	mu           sync.RWMutex
}

type NetworkMonitor struct {
	config         NetMonitorConfig
	hosts          map[string]*MonitoredHost
	mu             sync.RWMutex
	stopChan       chan struct{}
	wg             sync.WaitGroup
	nmapPath       string
	isNmapScanning bool
	nmapMu         sync.Mutex
	isPortScanning bool
	portScanMu     sync.Mutex
}

type icmpScanResult struct {
	Alive bool
	RTT   time.Duration
}

var globalNetworkMonitor *NetworkMonitor

func NewNetworkMonitor(cfg NetMonitorConfig) (*NetworkMonitor, error) {
	nm := &NetworkMonitor{
		config:   cfg,
		hosts:    make(map[string]*MonitoredHost),
		stopChan: make(chan struct{}),
	}

	if cfg.NmapScanEnabled {
		path, err := exec.LookPath("nmap")
		if err != nil {
			log.Printf("Warning: nmap executable not found, nmap scans will be disabled. Error: %v", err)
			nm.config.NmapScanEnabled = false
		} else {
			nm.nmapPath = path
			log.Printf("Found nmap at: %s", nm.nmapPath)
		}
	}
	if nm.config.PingTimeoutMs <= 0 {
		nm.config.PingTimeoutMs = 500
	}
	if nm.config.DefaultInterval <= 0 {
		nm.config.DefaultInterval = 5
	}
	if nm.config.NmapDefaultInterval <= 0 {
		nm.config.NmapDefaultInterval = 300
	}
	if nm.config.NmapHostTimeout <= 0 {
		nm.config.NmapHostTimeout = 300
	}
	if nm.config.PortScanInterval <= 0 {
		nm.config.PortScanInterval = 300
	}
	if nm.config.PortScanTimeoutMs <= 0 {
		nm.config.PortScanTimeoutMs = 2000
	}
	if nm.config.OfflineThreshold <= 0 {
		nm.config.OfflineThreshold = 3
	}

	globalNetworkMonitor = nm
	return nm, nil
}

func (nm *NetworkMonitor) Start() {
	if !nm.config.Enable {
		log.Println("Network monitor is disabled by configuration.")
		return
	}
	log.Println("Starting network monitor...")
	nm.wg.Add(1)
	go nm.runPingScheduler()

	if nm.config.NmapScanEnabled && nm.nmapPath != "" {
		nm.wg.Add(1)
		go nm.runNmapScheduler()
	}
}

func (nm *NetworkMonitor) Stop() {
	if !nm.config.Enable {
		return
	}
	log.Println("Stopping network monitor...")
	close(nm.stopChan)
	nm.wg.Wait()
	log.Println("Network monitor stopped.")
}

func (nm *NetworkMonitor) runPingScheduler() {
	defer nm.wg.Done()
	ticker := time.NewTicker(time.Duration(nm.config.DefaultInterval) * time.Second)
	defer ticker.Stop()

	nm.performPingScan()

	for {
		select {
		case <-ticker.C:
			nm.performPingScan()
		case <-nm.stopChan:
			return
		}
	}
}

func (nm *NetworkMonitor) runNmapScheduler() {
	defer nm.wg.Done()
	if !nm.config.NmapScanEnabled || nm.nmapPath == "" {
		return
	}
	ticker := time.NewTicker(time.Duration(nm.config.NmapDefaultInterval) * time.Second)
	defer ticker.Stop()

	nm.performNmapScanForAllOnlineHosts()

	for {
		select {
		case <-ticker.C:
			nm.performNmapScanForAllOnlineHosts()
		case <-nm.stopChan:
			return
		}
	}
}

func (nm *NetworkMonitor) GetHostStatus() []MonitoredHost {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	var statuses []MonitoredHost
	for _, host := range nm.hosts {
		host.mu.RLock()
		statuses = append(statuses, MonitoredHost{
			IP:           host.IP,
			Status:       host.Status,
			LastSeen:     host.LastSeen,
			OpenPorts:    append([]string{}, host.OpenPorts...),
			LastPortScan: host.LastPortScan,
		})
		host.mu.RUnlock()
	}
	return statuses
}

func getIPsFromSubnet(subnetCIDR string) ([]net.IP, error) {
	ipAddr, ipNet, err := net.ParseCIDR(subnetCIDR)
	if err != nil {
		return nil, err
	}

	var ips []net.IP
	for ip := ipAddr.Mask(ipNet.Mask); ipNet.Contains(ip); incIP(ip) {
		ipCopy := make(net.IP, len(ip))
		copy(ipCopy, ip)
		ips = append(ips, ipCopy)
	}

	if len(ips) > 2 {
		ones, bits := ipNet.Mask.Size()
		if bits == 32 && (ones < 31 || ones == 32 && len(ips) == 1) {
			if len(ips) > 1 {
				ips = ips[1:]
			}
			if len(ips) > 1 {
				ips = ips[:len(ips)-1]
			}
		} else if bits == 128 && ones < 127 {
			if len(ips) > 1 {
				ips = ips[1:]
			}
		}
	}

	return ips, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

const maxConcurrentPings = 50
const maxConcurrentPortScanHosts = 10
const maxConcurrentDialsPerHost = 30

var defaultScanPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
	143, 443, 445, 465, 514, 587, 631, 636, 993,
	995, 1080, 1433, 1521, 1723, 1883, 2049, 2181,
	2375, 2376, 3000, 3306, 3389, 4443, 5000, 5060,
	5432, 5672, 5900, 5984, 6379, 6443, 7070, 7443,
	8000, 8080, 8081, 8083, 8086, 8088, 8123, 8200,
	8443, 8444, 8500, 8834, 8888, 8883, 9000, 9090,
	9091, 9092, 9100, 9200, 9300, 9443, 10000, 10250,
	11211, 15672, 19132, 25565, 27017, 28017, 32400,
	51820, 54321,
}

func (nm *NetworkMonitor) performPingScan() {
	log.Println("Performing host discovery for subnet:", nm.config.DefaultSubnet)
	ips, err := getIPsFromSubnet(nm.config.DefaultSubnet)
	if err != nil {
		log.Printf("Error getting IPs from subnet %s: %v", nm.config.DefaultSubnet, err)
		return
	}

	ipStrs := make([]string, len(ips))
	for i, ip := range ips {
		ipStrs[i] = ip.String()
	}

	results, err := nm.icmpBatchScan(ipStrs)
	if err != nil {
		log.Printf("ICMP scan failed (%v), skipping to TCP probes", err)
		results = make(map[string]icmpScanResult, len(ipStrs))
	}

	icmpAlive := 0
	for _, r := range results {
		if r.Alive {
			icmpAlive++
		}
	}

	var missedIPs []string
	for _, ip := range ipStrs {
		if !results[ip].Alive {
			missedIPs = append(missedIPs, ip)
		}
	}

	if len(missedIPs) > 0 {
		tcpResults := nm.tcpProbeHosts(missedIPs)
		tcpAlive := 0
		for ip, res := range tcpResults {
			if res.Alive {
				results[ip] = res
				tcpAlive++
			}
		}
		log.Printf("Host discovery: ICMP found %d, TCP probe found %d more", icmpAlive, tcpAlive)
	} else {
		log.Printf("Host discovery: ICMP found %d", icmpAlive)
	}

	now := time.Now()
	for _, ipStr := range ipStrs {
		nm.mu.RLock()
		host, exists := nm.hosts[ipStr]
		nm.mu.RUnlock()

		if !exists {
			nm.mu.Lock()
			host, exists = nm.hosts[ipStr]
			if !exists {
				host = &MonitoredHost{IP: ipStr, Status: StatusUnknown}
				nm.hosts[ipStr] = host
			}
			nm.mu.Unlock()
		}

		res := results[ipStr]
		host.mu.Lock()
		if host.Status == StatusScanning {
			host.mu.Unlock()
			continue
		}
		if res.Alive {
			host.Status = StatusOnline
			host.LastSeen = now
			host.missCount = 0
			host.mu.Unlock()
		} else {
			host.missCount++
			if host.missCount >= nm.config.OfflineThreshold || host.Status == StatusUnknown {
				host.Status = StatusOffline
			}
			host.mu.Unlock()
		}
	}
	log.Println("Host discovery finished.")

	if nm.config.PortScanEnabled {
		go nm.performTCPPortScan()
	}
}

func (nm *NetworkMonitor) icmpBatchScan(ips []string) (map[string]icmpScanResult, error) {
	conn, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		conn, err = icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		if err != nil {
			return nil, fmt.Errorf("cannot open ICMP socket: %w", err)
		}
	}
	defer conn.Close()

	icmpID := os.Getpid() & 0xFFFF
	timeout := time.Duration(nm.config.PingTimeoutMs) * time.Millisecond
	if timeout < 2*time.Second {
		timeout = 2 * time.Second
	}

	seqToIP := make(map[int]string, len(ips))
	results := make(map[string]icmpScanResult, len(ips))

	sendStart := time.Now()
	for i, ipStr := range ips {
		seq := i + 1
		seqToIP[seq] = ipStr

		msg := &icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &icmp.Echo{
				ID:   icmpID,
				Seq:  seq,
				Data: []byte("SCAN"),
			},
		}
		msgBytes, err := msg.Marshal(nil)
		if err != nil {
			continue
		}

		dst := &net.UDPAddr{IP: net.ParseIP(ipStr)}
		conn.WriteTo(msgBytes, dst)

		if (i+1)%50 == 0 {
			time.Sleep(10 * time.Millisecond)
		}
	}
	log.Printf("Sent %d ICMP Echo Requests in %v", len(ips), time.Since(sendStart))

	replied := 0
	deadline := time.Now().Add(timeout)
	conn.SetReadDeadline(deadline)
	buf := make([]byte, 1500)

	for replied < len(ips) && time.Now().Before(deadline) {
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			break
		}

		var proto int
		if _, ok := peer.(*net.UDPAddr); ok {
			proto = 1
		} else {
			proto = 1
		}

		msg, err := icmp.ParseMessage(proto, buf[:n])
		if err != nil {
			continue
		}

		if msg.Type != ipv4.ICMPTypeEchoReply {
			continue
		}

		echo, ok := msg.Body.(*icmp.Echo)
		if !ok || echo.ID != icmpID {
			continue
		}

		ipStr, found := seqToIP[echo.Seq]
		if !found {
			continue
		}

		var peerIP string
		switch addr := peer.(type) {
		case *net.UDPAddr:
			peerIP = addr.IP.String()
		case *net.IPAddr:
			peerIP = addr.IP.String()
		}
		if peerIP != ipStr {
			continue
		}

		if !results[ipStr].Alive {
			replied++
			results[ipStr] = icmpScanResult{
				Alive: true,
				RTT:   time.Since(sendStart),
			}
		}
	}

	log.Printf("Received %d ICMP Echo Replies", replied)
	return results, nil
}

func (nm *NetworkMonitor) tcpProbeHosts(ips []string) map[string]icmpScanResult {
	results := make(map[string]icmpScanResult, len(ips))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrentPings)
	timeout := time.Duration(nm.config.PingTimeoutMs) * time.Millisecond
	if timeout < 1*time.Second {
		timeout = 1 * time.Second
	}
	probePorts := []string{"22", "80", "443", "53", "445", "8080", "3389", "8443", "5000", "8123"}

	for _, ipStr := range ips {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			for _, port := range probePorts {
				conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), timeout)
				if err == nil {
					conn.Close()
					mu.Lock()
					results[ip] = icmpScanResult{Alive: true}
					mu.Unlock()
					return
				}
			}
		}(ipStr)
	}
	wg.Wait()
	return results
}

func (r icmpScanResult) RTTString() string {
	if !r.Alive {
		return "N/A"
	}
	return r.RTT.Round(time.Microsecond).String()
}

func (nm *NetworkMonitor) performNmapScanForAllOnlineHosts() {
	if !nm.config.NmapScanEnabled || nm.nmapPath == "" {
		return
	}

	nm.nmapMu.Lock()
	if nm.isNmapScanning {
		nm.nmapMu.Unlock()
		log.Println("Nmap scan cycle already in progress. Skipping.")
		return
	}
	nm.isNmapScanning = true
	nm.nmapMu.Unlock()

	defer func() {
		nm.nmapMu.Lock()
		nm.isNmapScanning = false
		nm.nmapMu.Unlock()
	}()

	log.Println("Starting nmap scan cycle for online hosts...")
	var onlineHostsToScan []*MonitoredHost

	nm.mu.RLock()
	for _, host := range nm.hosts {
		host.mu.RLock()
		if host.Status == StatusOnline || host.Status == StatusScanning {
			onlineHostsToScan = append(onlineHostsToScan, host)
		}
		host.mu.RUnlock()
	}
	nm.mu.RUnlock()

	var nmapWg sync.WaitGroup
	for _, host := range onlineHostsToScan {
		nmapWg.Add(1)
		go func(h *MonitoredHost) {
			defer nmapWg.Done()
			nm.scanHostWithNmap(h)
		}(host)
	}
	nmapWg.Wait()
	log.Println("Nmap scan cycle finished.")
}

func (nm *NetworkMonitor) scanHostWithNmap(host *MonitoredHost) {
	host.mu.Lock()
	if host.Status == StatusOffline {
		host.mu.Unlock()
		return
	}

	host.Status = StatusScanning
	host.mu.Unlock()

	log.Printf("Nmap scanning: %s with args: %s", host.IP, nm.config.NmapCommandArgs)

	args := strings.Fields(nm.config.NmapCommandArgs)
	args = append(args, host.IP)

	nmapTimeout := time.Duration(nm.config.NmapHostTimeout) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), nmapTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, nm.nmapPath, args...)
	var outbuf, errbuf bytes.Buffer
	cmd.Stdout = &outbuf
	cmd.Stderr = &errbuf

	err := cmd.Run()

	host.mu.Lock()
	defer host.mu.Unlock()

	host.LastPortScan = time.Now()

	if ctx.Err() == context.DeadlineExceeded {
		log.Printf("Nmap scan timed out for %s", host.IP)
		host.Status = StatusError
		host.OpenPorts = []string{"Nmap Timeout"}
		return
	} else if err != nil {
		log.Printf("Nmap scan error for %s: %v. Stderr: %s", host.IP, err, errbuf.String())
		host.Status = StatusError
		host.OpenPorts = []string{fmt.Sprintf("Nmap Error: %v", err)}
		return
	}

	host.Status = StatusOnline
	host.LastSeen = time.Now()

	output := outbuf.String()
	var ports []string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "/tcp") && strings.Contains(line, "open") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				portSpec := strings.Split(fields[0], "/")[0]
				ports = append(ports, portSpec)
			}
		}
	}
	host.OpenPorts = ports
	log.Printf("Nmap scan for %s complete. Ports: %v", host.IP, ports)
}

func (nm *NetworkMonitor) performTCPPortScan() {
	nm.portScanMu.Lock()
	if nm.isPortScanning {
		nm.portScanMu.Unlock()
		log.Println("TCP port scan already in progress. Skipping.")
		return
	}
	nm.isPortScanning = true
	nm.portScanMu.Unlock()

	defer func() {
		nm.portScanMu.Lock()
		nm.isPortScanning = false
		nm.portScanMu.Unlock()
	}()

	cooldown := time.Duration(nm.config.PortScanInterval) * time.Second
	now := time.Now()

	var hostsToScan []*MonitoredHost
	nm.mu.RLock()
	for _, host := range nm.hosts {
		host.mu.RLock()
		if host.Status == StatusOnline && (host.LastPortScan.IsZero() || now.Sub(host.LastPortScan) >= cooldown) {
			hostsToScan = append(hostsToScan, host)
		}
		host.mu.RUnlock()
	}
	nm.mu.RUnlock()

	if len(hostsToScan) == 0 {
		return
	}

	log.Printf("Starting TCP port scan for %d host(s)...", len(hostsToScan))
	sem := make(chan struct{}, maxConcurrentPortScanHosts)
	var wg sync.WaitGroup

	for _, host := range hostsToScan {
		select {
		case <-nm.stopChan:
			log.Println("TCP port scan interrupted by shutdown.")
			wg.Wait()
			return
		default:
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(h *MonitoredHost) {
			defer wg.Done()
			defer func() { <-sem }()
			nm.scanHostTCPPorts(h)
		}(host)
	}
	wg.Wait()
	log.Println("TCP port scan cycle finished.")
}

func (nm *NetworkMonitor) scanHostTCPPorts(host *MonitoredHost) {
	host.mu.Lock()
	if host.Status != StatusOnline {
		host.mu.Unlock()
		return
	}
	host.Status = StatusScanning
	host.mu.Unlock()

	timeout := time.Duration(nm.config.PortScanTimeoutMs) * time.Millisecond
	var openPorts []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrentDialsPerHost)

	for _, port := range defaultScanPorts {
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()
			addr := net.JoinHostPort(host.IP, fmt.Sprintf("%d", p))
			conn, err := net.DialTimeout("tcp", addr, timeout)
			if err == nil {
				conn.Close()
				mu.Lock()
				openPorts = append(openPorts, fmt.Sprintf("%d", p))
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()

	host.mu.Lock()
	host.OpenPorts = openPorts
	host.LastPortScan = time.Now()
	host.Status = StatusOnline
	host.mu.Unlock()

	log.Printf("TCP port scan for %s complete. Open ports: %v", host.IP, openPorts)
}
