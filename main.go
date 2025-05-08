package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

type Service struct {
	Name        string `yaml:"name"`
	URL         string `yaml:"url"`
	Description string `yaml:"description,omitempty"`
	VaultURL    string `yaml:"vault_url,omitempty"`
}

type Group struct {
	Name     string    `yaml:"name"`
	Services []Service `yaml:"services"`
}

type ServerConfig struct {
	Port           string `yaml:"port"`
	HashedPassword string `yaml:"hashedPassword"`
	Username       string `yaml:"username,omitempty"`
}

type AppConfig struct {
	Server     ServerConfig     `yaml:"server"`
	Groups     []Group          `yaml:"groups"`
	NetMonitor NetMonitorConfig `yaml:"net_monitor"` // Added
}

var appConfig AppConfig
var dashboardTemplate *template.Template

func loadConfig(filePath string) (AppConfig, error) {
	cfg := AppConfig{}
	// Set defaults for NetMonitorConfig before loading
	cfg.NetMonitor = NetMonitorConfig{
		Enable:              true,
		DefaultSubnet:       "192.168.1.0/24",
		DefaultInterval:     5, // seconds for ping
		NmapScanEnabled:     false,
		NmapDefaultInterval: 300,      // seconds for nmap
		NmapCommandArgs:     "-T4 -F", // nmap arguments
		NmapHostTimeout:     300,      // seconds for nmap host timeout
		PingTimeoutMs:       500,      // ms for ping
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return cfg, fmt.Errorf("could not read config file %s: %w", filePath, err)
	}

	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		return cfg, fmt.Errorf("could not unmarshal config YAML: %w", err)
	}

	if cfg.Server.Username == "" {
		cfg.Server.Username = "admin"
	}
	if cfg.Server.Port == "" {
		cfg.Server.Port = "8080"
	}
	// Ensure net_monitor substruct has some defaults if not fully defined in yaml
	if cfg.NetMonitor.DefaultInterval == 0 && cfg.NetMonitor.Enable {
		cfg.NetMonitor.DefaultInterval = 5 // Sensible default if enabled but interval not set
	}
	if cfg.NetMonitor.PingTimeoutMs == 0 && cfg.NetMonitor.Enable {
		cfg.NetMonitor.PingTimeoutMs = 500
	}

	return cfg, nil
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func basicAuthMiddleware(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != appConfig.Server.Username || !checkPasswordHash(pass, appConfig.Server.HashedPassword) {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized.", http.StatusUnauthorized)
			return
		}
		handler(w, r)
	}
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	err := dashboardTemplate.Execute(w, appConfig) // Pass the whole appConfig
	if err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func netMonitorApiHandler(w http.ResponseWriter, r *http.Request) {
	if globalNetworkMonitor == nil {
		http.Error(w, "Network monitor not initialized", http.StatusInternalServerError)
		return
	}
	statuses := globalNetworkMonitor.GetHostStatus()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(statuses)
}

func main() {
	var err error
	appConfig, err = loadConfig("config.yaml")
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	if appConfig.Server.HashedPassword == "" || appConfig.Server.HashedPassword == "$2a$14$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" {
		log.Println("--------------------------------------------------------------------")
		log.Println("WARNING: Server password is not set or is the default placeholder.")
		log.Println("Please generate a bcrypt hash for your desired password and")
		log.Println("update the 'hashedPassword' field in 'config.yaml'.")
		log.Println("--------------------------------------------------------------------")
		log.Fatal("Exiting due to insecure password configuration.")
		return
	}

	// Initialize and start the network monitor
	if appConfig.NetMonitor.Enable {
		monitor, err := NewNetworkMonitor(appConfig.NetMonitor)
		if err != nil {
			log.Fatalf("Failed to initialize network monitor: %v", err)
		}
		globalNetworkMonitor = monitor // Assign to global
		monitor.Start()
		defer monitor.Stop() // Ensure it stops cleanly on exit
		log.Println("Network monitor initialized and started.")
	} else {
		log.Println("Network monitor is disabled in config.")
	}

	funcMap := template.FuncMap{
		"ToLower": strings.ToLower,
		"FormatTime": func(t time.Time) string {
			if t.IsZero() {
				return "N/A"
			}
			return t.Format("2006-01-02 15:04:05")
		},
		"JoinStrings": func(s []string, sep string) string {
			if s == nil || len(s) == 0 {
				return "-"
			}
			return strings.Join(s, sep)
		},
	}

	templatePath := filepath.Join("templates", "index.html")
	dashboardTemplate, err = template.New(filepath.Base(templatePath)).Funcs(funcMap).ParseFiles(templatePath)
	if err != nil {
		log.Fatalf("Failed to parse HTML template from %s: %v", templatePath, err)
	}

	http.HandleFunc("/", basicAuthMiddleware(dashboardHandler))
	http.HandleFunc("/api/netmonitor/status", basicAuthMiddleware(netMonitorApiHandler)) // API endpoint

	log.Printf("Starting Simple Homelab Dashboard on port %s", appConfig.Server.Port)
	log.Printf("Access at http://localhost:%s", appConfig.Server.Port)
	if err := http.ListenAndServe(":"+appConfig.Server.Port, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
