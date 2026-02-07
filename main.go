package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
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
	NetMonitor NetMonitorConfig `yaml:"net_monitor"`
}

var appConfig AppConfig
var dashboardTemplate *template.Template

func loadConfig(filePath string) (AppConfig, error) {
	cfg := AppConfig{}
	cfg.NetMonitor = NetMonitorConfig{
		Enable:              true,
		DefaultSubnet:       "192.168.1.0/24",
		DefaultInterval:     5,
		NmapScanEnabled:     false,
		NmapDefaultInterval: 300,
		NmapCommandArgs:     "-T4 -F",
		NmapHostTimeout:     300,
		PingTimeoutMs:       500,
		PortScanEnabled:     true,
		PortScanInterval:    300,
		PortScanTimeoutMs:   2000,
		OfflineThreshold:    3,
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
	if cfg.NetMonitor.DefaultInterval == 0 && cfg.NetMonitor.Enable {
		cfg.NetMonitor.DefaultInterval = 5
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

func securityHeadersMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'")
		next(w, r)
	}
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	err := dashboardTemplate.Execute(w, appConfig)
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
	}

	if appConfig.NetMonitor.Enable {
		monitor, err := NewNetworkMonitor(appConfig.NetMonitor)
		if err != nil {
			log.Fatalf("Failed to initialize network monitor: %v", err)
		}
		globalNetworkMonitor = monitor
		monitor.Start()
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

	http.HandleFunc("/", securityHeadersMiddleware(basicAuthMiddleware(dashboardHandler)))
	http.HandleFunc("/api/netmonitor/status", securityHeadersMiddleware(basicAuthMiddleware(netMonitorApiHandler)))

	server := &http.Server{
		Addr:         ":" + appConfig.Server.Port,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("Starting Simple Homelab Dashboard on port %s", appConfig.Server.Port)
		log.Printf("Access at http://localhost:%s", appConfig.Server.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	if globalNetworkMonitor != nil {
		globalNetworkMonitor.Stop()
	}

	log.Println("Server exited gracefully.")
}
