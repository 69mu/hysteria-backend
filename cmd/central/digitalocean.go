package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// resolveSSHKey reads the SSH public key file and registers it with DO.
func (s *Server) resolveSSHKey() error {
	pubKey, err := os.ReadFile(s.doSSHKeyFile)
	if err != nil {
		return fmt.Errorf("read SSH public key %s: %w", s.doSSHKeyFile, err)
	}

	// Try to create the key in DO.
	payload, _ := json.Marshal(map[string]string{
		"name":       "central",
		"public_key": strings.TrimSpace(string(pubKey)),
	})
	req, _ := http.NewRequest("POST", "https://api.digitalocean.com/v2/account/keys", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+s.doToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("DO create key request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == 201 {
		var result struct {
			SSHKey struct {
				ID int `json:"id"`
			} `json:"ssh_key"`
		}
		json.Unmarshal(body, &result)
		s.doSSHKeyID = result.SSHKey.ID
		return nil
	}

	// Key likely already exists — list all keys and match by fingerprint.
	req, _ = http.NewRequest("GET", "https://api.digitalocean.com/v2/account/keys?per_page=200", nil)
	req.Header.Set("Authorization", "Bearer "+s.doToken)

	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("DO list keys request: %w", err)
	}
	defer resp2.Body.Close()
	body2, _ := io.ReadAll(resp2.Body)

	var listResult struct {
		SSHKeys []struct {
			ID        int    `json:"id"`
			PublicKey string `json:"public_key"`
		} `json:"ssh_keys"`
	}
	json.Unmarshal(body2, &listResult)

	keyStr := strings.TrimSpace(string(pubKey))
	for _, k := range listResult.SSHKeys {
		if strings.TrimSpace(k.PublicKey) == keyStr {
			s.doSSHKeyID = k.ID
			return nil
		}
	}

	return fmt.Errorf("SSH key not found in DO account after registration attempt (status %d: %s)", resp.StatusCode, string(body))
}

// createDroplet creates a DO droplet and returns the droplet ID.
func (s *Server) createDroplet(name, region, size string) (string, error) {
	payload, _ := json.Marshal(map[string]interface{}{
		"name":     name,
		"size":     size,
		"region":   region,
		"image":    s.doImage,
		"ssh_keys": []int{s.doSSHKeyID},
	})
	req, _ := http.NewRequest("POST", "https://api.digitalocean.com/v2/droplets", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+s.doToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("DO create droplet: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 202 {
		return "", fmt.Errorf("DO create droplet: status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Droplet struct {
			ID int `json:"id"`
		} `json:"droplet"`
	}
	json.Unmarshal(body, &result)
	return fmt.Sprintf("%d", result.Droplet.ID), nil
}

// waitForDropletIP polls DO until the droplet is active and returns its public IPv4.
func (s *Server) waitForDropletIP(dropletID string) (string, error) {
	url := "https://api.digitalocean.com/v2/droplets/" + dropletID
	for i := 0; i < 60; i++ {
		time.Sleep(5 * time.Second)

		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("Authorization", "Bearer "+s.doToken)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var result struct {
			Droplet struct {
				Status   string `json:"status"`
				Networks struct {
					V4 []struct {
						IPAddress string `json:"ip_address"`
						Type      string `json:"type"`
					} `json:"v4"`
				} `json:"networks"`
			} `json:"droplet"`
		}
		json.Unmarshal(body, &result)

		if result.Droplet.Status == "active" {
			for _, net := range result.Droplet.Networks.V4 {
				if net.Type == "public" && net.IPAddress != "" {
					return net.IPAddress, nil
				}
			}
		}
	}
	return "", fmt.Errorf("timed out waiting for droplet %s to become active", dropletID)
}

// deleteDroplet deletes a DO droplet by ID.
func (s *Server) deleteDroplet(dropletID string) error {
	req, _ := http.NewRequest("DELETE", "https://api.digitalocean.com/v2/droplets/"+dropletID, nil)
	req.Header.Set("Authorization", "Bearer "+s.doToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("DO delete droplet: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 204 {
		return fmt.Errorf("DO delete droplet: status %d", resp.StatusCode)
	}
	log.Printf("[INFO] DO: deleted droplet %s", dropletID)
	return nil
}

// updateProvisionStatus updates the provision_status in server_status.
func (s *Server) updateProvisionStatus(serverID, status string) {
	s.db.Exec(`
		INSERT INTO server_status (server_id, provision_status) VALUES (?, ?)
		ON CONFLICT(server_id) DO UPDATE SET provision_status = excluded.provision_status
	`, serverID, status)
}

// updateDropletInfo stores droplet_id and ip in server_status.
func (s *Server) updateDropletInfo(serverID, dropletID, ip string) {
	s.db.Exec(`
		INSERT INTO server_status (server_id, droplet_id, ip) VALUES (?, ?, ?)
		ON CONFLICT(server_id) DO UPDATE SET droplet_id = excluded.droplet_id, ip = excluded.ip
	`, serverID, dropletID, ip)
}

// provisionServer runs the full provisioning flow in the background.
func (s *Server) provisionServer(serverID string) {
	log.Printf("[INFO] provisioning server %s: starting", serverID)

	// Read server config from DB.
	var acmeDomain, region, size, serverToken string
	err := s.db.QueryRow(`SELECT acme_domain, region, size, token FROM servers WHERE id = ?`, serverID).Scan(&acmeDomain, &region, &size, &serverToken)
	if err != nil {
		log.Printf("[INFO] provision %s: failed to read config: %v", serverID, err)
		s.updateProvisionStatus(serverID, "error: "+err.Error())
		return
	}

	// 1. Create droplet.
	s.updateProvisionStatus(serverID, "creating")
	dropletID, err := s.createDroplet(serverID, region, size)
	if err != nil {
		log.Printf("[INFO] provision %s: create droplet failed: %v", serverID, err)
		s.updateProvisionStatus(serverID, "error: "+err.Error())
		return
	}
	log.Printf("[INFO] provision %s: created droplet %s", serverID, dropletID)
	s.updateDropletInfo(serverID, dropletID, "")

	// 2. Wait for active + get IP.
	ip, err := s.waitForDropletIP(dropletID)
	if err != nil {
		log.Printf("[INFO] provision %s: wait for IP failed: %v", serverID, err)
		s.updateProvisionStatus(serverID, "error: "+err.Error())
		return
	}
	if !isValidIP(ip) {
		log.Printf("[INFO] provision %s: invalid IP from DO: %q", serverID, ip)
		s.updateProvisionStatus(serverID, "error: invalid IP")
		return
	}
	log.Printf("[INFO] provision %s: droplet active, ip=%s", serverID, ip)
	s.updateDropletInfo(serverID, dropletID, ip)

	// 3. DNS record.
	s.updateProvisionStatus(serverID, "dns")
	if s.cfAPIToken != "" && s.cfZoneID != "" && acmeDomain != "" {
		if err := s.ensureDNSRecord(acmeDomain, ip); err != nil {
			log.Printf("[INFO] provision %s: DNS failed: %v", serverID, err)
			s.updateProvisionStatus(serverID, "error: dns: "+err.Error())
			return
		}
	}

	// 4. Deploy via SSH.
	s.updateProvisionStatus(serverID, "deploying")
	sshKey := strings.TrimSuffix(s.doSSHKeyFile, ".pub")
	sshOpts := []string{"-i", sshKey, "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=5", "-o", "BatchMode=yes"}
	target := "root@" + ip

	// Wait for SSH readiness.
	sshReady := false
	for i := 0; i < 24; i++ {
		time.Sleep(5 * time.Second)
		args := append(sshOpts, target, "echo ok")
		if out, err := exec.Command("ssh", args...).CombinedOutput(); err == nil && strings.Contains(string(out), "ok") {
			sshReady = true
			break
		}
	}
	if !sshReady {
		log.Printf("[INFO] provision %s: SSH not ready after 2 minutes", serverID)
		s.updateProvisionStatus(serverID, "error: ssh timeout")
		return
	}

	// Rsync backend binary.
	rsyncArgs := []string{"-e", "ssh " + strings.Join(sshOpts, " "), s.backendBinary, target + ":/root/backend"}
	if out, err := exec.Command("rsync", rsyncArgs...).CombinedOutput(); err != nil {
		log.Printf("[INFO] provision %s: rsync failed: %v: %s", serverID, err, string(out))
		s.updateProvisionStatus(serverID, "error: rsync: "+err.Error())
		return
	}
	log.Printf("[INFO] provision %s: backend binary deployed", serverID)

	// Validate values before embedding in the systemd service file.
	if !isSafeShellArg(s.baseURL) || !isSafeShellArg(serverToken) {
		log.Printf("[INFO] provision %s: unsafe baseURL or serverToken, aborting", serverID)
		s.updateProvisionStatus(serverID, "error: unsafe config values")
		return
	}

	// Make binary executable + create systemd service + start it.
	serviceFile := fmt.Sprintf(`[Unit]
Description=Hysteria Backend
After=network.target

[Service]
ExecStart=/root/backend -central-server %s -server-id %s
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target`, s.baseURL, serverToken)

	setupCmd := fmt.Sprintf(
		`chmod +x /root/backend && cat > /etc/systemd/system/hysteria-backend.service << 'SERVICEEOF'
%s
SERVICEEOF
systemctl daemon-reload && systemctl enable --now hysteria-backend`, serviceFile)

	args := append(sshOpts, target, setupCmd)
	if out, err := exec.Command("ssh", args...).CombinedOutput(); err != nil {
		log.Printf("[INFO] provision %s: service setup failed: %v: %s", serverID, err, string(out))
		s.updateProvisionStatus(serverID, "error: service: "+err.Error())
		return
	}

	s.updateProvisionStatus(serverID, "running")
	log.Printf("[INFO] provision %s: complete — backend running on %s (%s)", serverID, ip, acmeDomain)
}
