package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
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
	DefaultInterval     int    `yaml:"default_interval"`      // Basic ping scan interval in seconds
	NmapScanEnabled     bool   `yaml:"nmap_scan_enabled"`     // Enable nmap for detailed scans
	NmapDefaultInterval int    `yaml:"nmap_default_interval"` // Nmap scan interval in seconds
	NmapCommandArgs     string `yaml:"nmap_command_args"`     // e.g., "-T4 -F"
	NmapHostTimeout     int    `yaml:"nmap_host_timeout"`     // Timeout for nmap scan per host
	PingTimeoutMs       int    `yaml:"ping_timeout_ms"`       // Ping timeout in milliseconds
}

type MonitoredHost struct {
	IP           string    `json:"ip"`
	Hostname     string    `json:"hostname"`
	Status       string    `json:"status"`
	LastSeen     time.Time `json:"last_seen"`
	OpenPorts    []string  `json:"open_ports,omitempty"`
	LastNmapScan time.Time `json:"last_nmap_scan,omitempty"`
	mu           sync.RWMutex
}

type NetworkMonitor struct {
	config         NetMonitorConfig
	hosts          map[string]*MonitoredHost // IP -> Host
	mu             sync.RWMutex
	stopChan       chan struct{}
	wg             sync.WaitGroup
	nmapPath       string
	isNmapScanning bool
	nmapMu         sync.Mutex
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
			nm.config.NmapScanEnabled = false // Disable if not found
		} else {
			nm.nmapPath = path
			log.Printf("Found nmap at: %s", nm.nmapPath)
		}
	}
	if nm.config.PingTimeoutMs <= 0 {
		nm.config.PingTimeoutMs = 500 // Default ping timeout
	}
	if nm.config.DefaultInterval <= 0 {
		nm.config.DefaultInterval = 5 // Default ping interval
	}
	if nm.config.NmapDefaultInterval <= 0 {
		nm.config.NmapDefaultInterval = 300 // Default nmap interval
	}
	if nm.config.NmapHostTimeout <= 0 {
		nm.config.NmapHostTimeout = 300 // Default nmap host timeout
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

	nm.performPingScan() // Initial scan

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

	nm.performNmapScanForAllOnlineHosts() // Initial scan

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
			Hostname:     host.Hostname,
			Status:       host.Status,
			LastSeen:     host.LastSeen,
			OpenPorts:    append([]string{}, host.OpenPorts...), // Create a copy
			LastNmapScan: host.LastNmapScan,
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
		// Create a copy of the IP to add to the slice
		ipCopy := make(net.IP, len(ip))
		copy(ipCopy, ip)
		ips = append(ips, ipCopy)
	}

	// Remove network and broadcast addresses for typical scanning use cases
	if len(ips) > 2 { // Only if there are enough IPs to remove them
		// Check if the subnet is not a /32 or /31 for IPv4
		ones, bits := ipNet.Mask.Size()
		if bits == 32 && (ones < 31 || ones == 32 && len(ips) == 1) { // For IPv4
			if len(ips) > 1 { // Avoid panic on very small subnets like /32
				ips = ips[1:] // Remove network address
			}
			if len(ips) > 1 {
				ips = ips[:len(ips)-1] // Remove broadcast address
			}
		} else if bits == 128 && ones < 127 { // For IPv6, typically no broadcast, network often not scanned.
			if len(ips) > 1 {
				ips = ips[1:]
			}
		}
	} else if len(ips) == 1 { // For /32 on IPv4 or /128 on IPv6
		// Keep the single IP
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

func (nm *NetworkMonitor) performPingScan() {
	log.Println("Performing ping scan for subnet:", nm.config.DefaultSubnet)
	ips, err := getIPsFromSubnet(nm.config.DefaultSubnet)
	if err != nil {
		log.Printf("Error getting IPs from subnet %s: %v", nm.config.DefaultSubnet, err)
		return
	}

	var scanWg sync.WaitGroup
	for _, ip := range ips {
		scanWg.Add(1)
		go func(ipAddr net.IP) {
			defer scanWg.Done()
			nm.pingHost(ipAddr.String())
		}(ip)
	}
	scanWg.Wait()
	log.Println("Ping scan finished.")
}

func (nm *NetworkMonitor) pingHost(ipStr string) {
	nm.mu.RLock()
	host, exists := nm.hosts[ipStr]
	nm.mu.RUnlock()

	if !exists {
		nm.mu.Lock()
		host = &MonitoredHost{IP: ipStr, Status: StatusUnknown}
		nm.hosts[ipStr] = host
		nm.mu.Unlock()
	}

	host.mu.Lock()
	originalStatus := host.Status
	if host.Status != StatusScanning { // Don't interrupt nmap scan status
		host.Status = StatusScanning // Tentative status while pinging
	}
	host.mu.Unlock()

	var cmd *exec.Cmd
	timeout := time.Duration(nm.config.PingTimeoutMs) * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), timeout+200*time.Millisecond) // Add buffer for command overhead
	defer cancel()

	switch runtime.GOOS {
	case "windows":
		// -n 1: send 1 echo request
		// -w timeout_ms: timeout in milliseconds to wait for each reply
		cmd = exec.CommandContext(ctx, "ping", "-n", "1", "-w", fmt.Sprintf("%d", nm.config.PingTimeoutMs), ipStr)
	default: // Linux, macOS
		// -c 1: send 1 echo request
		// -W timeout_seconds (for Linux ping) / -t timeout_seconds (for macOS ping)
		// Using a short deadline with -c 1 is often more reliable across Unix-likes
		deadline := time.Now().Add(timeout).Unix()
		if runtime.GOOS == "darwin" {
			cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-t", fmt.Sprintf("%d", int(timeout.Seconds())+1), ipStr)
		} else { // Assuming Linux
			cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", fmt.Sprintf("%d", int(timeout.Seconds())+1), "-i", "0.2", "-w", fmt.Sprintf("%d", deadline), ipStr)
		}
	}

	err := cmd.Run()

	host.mu.Lock()
	defer host.mu.Unlock()

	if ctx.Err() == context.DeadlineExceeded {
		if host.Status != StatusScanning || originalStatus != StatusScanning { // Only change if not in nmap scan
			host.Status = StatusOffline
		}
		log.Printf("Ping timeout for %s", ipStr)
	} else if err != nil {
		if host.Status != StatusScanning || originalStatus != StatusScanning {
			host.Status = StatusOffline
		}
		// log.Printf("Ping failed for %s: %v", ipStr, err) // Can be noisy
	} else {
		host.Status = StatusOnline
		host.LastSeen = time.Now()
		// Attempt to resolve hostname if it's not set or was N/A
		if host.Hostname == "" || host.Hostname == "N/A" {
			go nm.resolveHostname(host) // Run in goroutine to not block ping
		}
	}
}

func (nm *NetworkMonitor) resolveHostname(host *MonitoredHost) {
	names, err := net.LookupAddr(host.IP)
	host.mu.Lock()
	defer host.mu.Unlock()
	if err == nil && len(names) > 0 {
		host.Hostname = strings.TrimSuffix(names[0], ".")
	} else {
		host.Hostname = "N/A"
		// log.Printf("Could not resolve hostname for %s: %v", host.IP, err)
	}
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
		if host.Status == StatusOnline || host.Status == StatusScanning { // Also include hosts currently marked scanning by ping
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
	if host.Status == StatusOffline { // Check again before scan
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

	host.LastNmapScan = time.Now()

	if ctx.Err() == context.DeadlineExceeded {
		log.Printf("Nmap scan timed out for %s", host.IP)
		host.Status = StatusError // Keep host as error if nmap timed out
		host.OpenPorts = []string{"Nmap Timeout"}
		return
	} else if err != nil {
		log.Printf("Nmap scan error for %s: %v. Stderr: %s", host.IP, err, errbuf.String())
		host.Status = StatusError
		host.OpenPorts = []string{fmt.Sprintf("Nmap Error: %v", err)}
		return
	}

	// If nmap ran successfully, host is at least online from nmap's perspective
	host.Status = StatusOnline
	host.LastSeen = time.Now() // Update last seen from nmap successful scan

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
	if host.Hostname == "" || host.Hostname == "N/A" {
		// Nmap might have resolved the hostname, or we can try again.
		// For simplicity, we rely on the ping-triggered resolve or nmap's own output if parsed.
		// Nmap output parsing for hostname can be added here if needed.
		go nm.resolveHostname(host) // Re-try resolve if still N/A
	}
	log.Printf("Nmap scan for %s complete. Ports: %v", host.IP, ports)
}
