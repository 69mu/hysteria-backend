package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
)

func ensureHysteriaInstalled(debug bool) {
	path, err := exec.LookPath("hysteria")
	if err == nil {
		if debug {
			log.Printf("[DEBUG] hysteria found at %s", path)
		}
		log.Printf("[INFO] hysteria is installed")
		return
	}

	log.Printf("[INFO] hysteria not found, installing...")
	cmd := exec.Command("bash", "-c", "curl -fsSL https://get.hy2.sh/ | bash")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("[FATAL] failed to install hysteria: %v", err)
	}
	log.Printf("[INFO] hysteria installed successfully")
}

func (a *App) writeHysteriaConfig() error {
	a.configMu.RLock()
	cfg := a.config
	a.configMu.RUnlock()

	_, listenPort, _ := net.SplitHostPort(a.listenAddr)
	_, trafficPort, _ := net.SplitHostPort(a.trafficStatsAddr)

	yaml := fmt.Sprintf(`acme:
  domains:
    - %s
  email: %s

auth:
  type: http
  http:
    url: http://127.0.0.1:%s/

trafficStats:
  listen: :%s
  secret: %s
`, cfg.AcmeDomain, cfg.AcmeEmail, listenPort, trafficPort, a.secret)

	// Ensure directory exists.
	if err := os.MkdirAll("/etc/hysteria", 0755); err != nil {
		return fmt.Errorf("create /etc/hysteria: %w", err)
	}

	if err := os.WriteFile("/etc/hysteria/config.yaml", []byte(yaml), 0644); err != nil {
		return fmt.Errorf("write config.yaml: %w", err)
	}

	log.Printf("[INFO] wrote /etc/hysteria/config.yaml (domain=%s, auth_port=%s, stats_port=%s)", cfg.AcmeDomain, listenPort, trafficPort)
	return nil
}

func restartHysteria() error {
	cmd := exec.Command("systemctl", "restart", "hysteria-server.service")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl restart: %v: %s", err, string(out))
	}
	log.Printf("[INFO] restarted hysteria-server.service")
	return nil
}

func getHysteriaPath() string {
	// Try to get the binary path from the systemd service.
	out, err := exec.Command("systemctl", "show", "-p", "ExecStart", "hysteria-server.service").CombinedOutput()
	if err == nil {
		// Output format: ExecStart={ path=/usr/local/bin/hysteria ; ... }
		s := string(out)
		if idx := strings.Index(s, "path="); idx >= 0 {
			s = s[idx+5:]
			if end := strings.IndexAny(s, " ;}\n"); end >= 0 {
				p := strings.TrimSpace(s[:end])
				if p != "" {
					return p
				}
			}
		}
	}
	// Fallback to PATH lookup.
	if p, err := exec.LookPath("hysteria"); err == nil {
		return p
	}
	return "hysteria"
}

func getHysteriaVersion() string {
	bin := getHysteriaPath()
	out, err := exec.Command(bin, "version").CombinedOutput()
	if err != nil {
		return "unknown"
	}
	// Parse the "Version:" line from the output.
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Version:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		}
	}
	return "unknown"
}
