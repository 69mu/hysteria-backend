package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"strings"
)

// /admin/users — list or add users
func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rows, err := s.db.Query("SELECT id FROM users ORDER BY id")
		if err != nil {
			log.Printf("[INFO] admin list users error: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		users := []string{}
		for rows.Next() {
			var id string
			rows.Scan(&id)
			users = append(users, id)
		}

		log.Printf("[INFO] GET /admin/users: %d users", len(users))
		if s.debug {
			log.Printf("[DEBUG] GET /admin/users: %v", users)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(users)

	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
		var body struct {
			ID    string `json:"id"`
			Quota int64  `json:"quota"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == "" {
			http.Error(w, "bad request: need {\"id\":\"...\"}", http.StatusBadRequest)
			return
		}
		if _, err := s.db.Exec("INSERT OR IGNORE INTO users (id, token, quota) VALUES (?, ?, ?)", body.ID, generateToken(s.db), body.Quota); err != nil {
			log.Printf("[INFO] admin add user error: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		log.Printf("[INFO] POST /admin/users: added user %q (quota=%d)", body.ID, body.Quota)
		w.WriteHeader(http.StatusCreated)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// /admin/users/{user_id}[/groups[/{group_name}]]
func (s *Server) handleAdminUser(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/admin/users/")
	if path == "" {
		http.Error(w, "missing user_id", http.StatusBadRequest)
		return
	}

	parts := strings.SplitN(path, "/", 3) // user_id [, "groups" [, group_name]]
	userID := parts[0]

	// /admin/users/{id}/groups[/{group_name}]
	if len(parts) >= 2 && parts[1] == "groups" {
		s.handleAdminUserGroups(w, r, userID, parts)
		return
	}

	// /admin/users/{id} — DELETE
	switch r.Method {
	case http.MethodDelete:
		if _, err := s.db.Exec("DELETE FROM users WHERE id = ?", userID); err != nil {
			log.Printf("[INFO] admin delete user error: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		// Also clean up group assignments.
		s.db.Exec("DELETE FROM group_users WHERE user_id = ?", userID)
		log.Printf("[INFO] DELETE /admin/users/%s: deleted", userID)
		w.WriteHeader(http.StatusOK)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// /admin/users/{id}/groups[/{group_name}] — user group management
func (s *Server) handleAdminUserGroups(w http.ResponseWriter, r *http.Request, userID string, parts []string) {
	// /admin/users/{id}/groups/{group_name} — DELETE
	if len(parts) == 3 && parts[2] != "" {
		groupName := parts[2]
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if _, err := s.db.Exec("DELETE FROM group_users WHERE group_name = ? AND user_id = ?", groupName, userID); err != nil {
			log.Printf("[INFO] admin remove user group error: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		log.Printf("[INFO] DELETE /admin/users/%s/groups/%s: removed", userID, groupName)
		w.WriteHeader(http.StatusOK)
		return
	}

	// /admin/users/{id}/groups — GET or POST
	switch r.Method {
	case http.MethodGet:
		rows, err := s.db.Query("SELECT group_name FROM group_users WHERE user_id = ? ORDER BY group_name", userID)
		if err != nil {
			log.Printf("[INFO] admin list user groups error: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		groups := []string{}
		for rows.Next() {
			var g string
			rows.Scan(&g)
			groups = append(groups, g)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(groups)

	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
		var body struct {
			Group string `json:"group"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Group == "" {
			http.Error(w, "bad request: need {\"group\":\"...\"}", http.StatusBadRequest)
			return
		}
		if _, err := s.db.Exec(
			"INSERT OR IGNORE INTO group_users (group_name, user_id) VALUES (?, ?)",
			body.Group, userID,
		); err != nil {
			log.Printf("[INFO] admin add user group error: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		log.Printf("[INFO] POST /admin/users/%s/groups: added group %q", userID, body.Group)
		w.WriteHeader(http.StatusCreated)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// /admin/servers/ — dispatcher
func (s *Server) handleAdminServers(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/admin/servers/")

	// /admin/servers/ — list or create servers
	if path == "" {
		s.handleAdminServerList(w, r)
		return
	}

	parts := strings.SplitN(path, "/", 3) // id [, "users"/"groups" [, sub-id]]

	// /admin/servers/{id}/users[/{uid}]
	if len(parts) >= 2 && parts[1] == "users" {
		s.handleAdminServerUsers(w, r, parts)
		return
	}

	// /admin/servers/{id}/groups[/{group_name}]
	if len(parts) >= 2 && parts[1] == "groups" {
		s.handleAdminServerGroups(w, r, parts)
		return
	}

	// POST /admin/servers/{id}/restart
	if len(parts) == 2 && parts[1] == "restart" {
		s.handleAdminServerRestart(w, r, parts[0])
		return
	}

	// /admin/servers/{id} — single server CRUD
	if len(parts) == 1 {
		s.handleAdminServerCRUD(w, r, parts[0])
		return
	}

	http.Error(w, "not found", http.StatusNotFound)
}

// GET /admin/servers/ — list all servers; POST — create server
func (s *Server) handleAdminServerList(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rows, err := s.db.Query(`SELECT id, token, acme_domain, acme_email,
			auth_url, traffic_url, region, size,
			interval_auth, interval_kick, interval_traffic_from_proxy, interval_traffic_to_central
			FROM servers ORDER BY id`)
		if err != nil {
			log.Printf("[INFO] admin list servers error: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		servers := []ServerConfig{}
		for rows.Next() {
			var c ServerConfig
			rows.Scan(&c.ID, &c.Token, &c.AcmeDomain, &c.AcmeEmail,
				&c.AuthURL, &c.TrafficURL, &c.Region, &c.Size,
				&c.IntervalAuth, &c.IntervalKick, &c.IntervalTrafficFromProxy, &c.IntervalTrafficToCentral)
			servers = append(servers, c)
		}

		log.Printf("[INFO] GET /admin/servers/: %d servers", len(servers))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(servers)

	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
		var cfg ServerConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if cfg.ID == "" {
			cfg.ID = generateServerID(s.db)
		}
		// Apply defaults for empty fields.
		if cfg.IntervalAuth == "" {
			cfg.IntervalAuth = "10s"
		}
		if cfg.IntervalKick == "" {
			cfg.IntervalKick = "10s"
		}
		if cfg.IntervalTrafficFromProxy == "" {
			cfg.IntervalTrafficFromProxy = "10s"
		}
		if cfg.IntervalTrafficToCentral == "" {
			cfg.IntervalTrafficToCentral = "10s"
		}

		// Apply defaults for region/size from server config.
		if cfg.Region == "" {
			cfg.Region = s.doRegion
		}
		if cfg.Size == "" {
			cfg.Size = s.doSize
		}

		cfg.Token = generateToken(s.db)
		_, err := s.db.Exec(`
			INSERT INTO servers (id, token, acme_domain, acme_email,
				auth_url, traffic_url, region, size,
				interval_auth, interval_kick, interval_traffic_from_proxy, interval_traffic_to_central)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, cfg.ID, cfg.Token, cfg.AcmeDomain, cfg.AcmeEmail,
			cfg.AuthURL, cfg.TrafficURL, cfg.Region, cfg.Size,
			cfg.IntervalAuth, cfg.IntervalKick, cfg.IntervalTrafficFromProxy, cfg.IntervalTrafficToCentral)
		if err != nil {
			log.Printf("[INFO] admin create server error: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Trigger background provisioning if DO token is configured.
		if s.doToken != "" {
			s.updateProvisionStatus(cfg.ID, "creating")
			go s.provisionServer(cfg.ID)
		}

		log.Printf("[INFO] POST /admin/servers/: created server %q", cfg.ID)
		w.WriteHeader(http.StatusCreated)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// GET/PUT/DELETE /admin/servers/{id}
func (s *Server) handleAdminServerCRUD(w http.ResponseWriter, r *http.Request, serverID string) {
	switch r.Method {
	case http.MethodGet:
		var cfg ServerConfig
		err := s.db.QueryRow(`
			SELECT id, token, acme_domain, acme_email,
			       auth_url, traffic_url, region, size,
			       interval_auth, interval_kick, interval_traffic_from_proxy, interval_traffic_to_central
			FROM servers WHERE id = ?
		`, serverID).Scan(
			&cfg.ID, &cfg.Token, &cfg.AcmeDomain, &cfg.AcmeEmail,
			&cfg.AuthURL, &cfg.TrafficURL, &cfg.Region, &cfg.Size,
			&cfg.IntervalAuth, &cfg.IntervalKick, &cfg.IntervalTrafficFromProxy, &cfg.IntervalTrafficToCentral,
		)
		if err == sql.ErrNoRows {
			http.Error(w, "server not found", http.StatusNotFound)
			return
		}
		if err != nil {
			log.Printf("[INFO] admin get server error: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		log.Printf("[INFO] GET /admin/servers/%s: ok", serverID)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cfg)

	case http.MethodPut:
		r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
		var cfg ServerConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		result, err := s.db.Exec(`
			UPDATE servers SET acme_domain=?, acme_email=?,
				auth_url=?, traffic_url=?, region=?, size=?,
				interval_auth=?, interval_kick=?, interval_traffic_from_proxy=?, interval_traffic_to_central=?
			WHERE id = ?
		`, cfg.AcmeDomain, cfg.AcmeEmail,
			cfg.AuthURL, cfg.TrafficURL, cfg.Region, cfg.Size,
			cfg.IntervalAuth, cfg.IntervalKick, cfg.IntervalTrafficFromProxy, cfg.IntervalTrafficToCentral,
			serverID)
		if err != nil {
			log.Printf("[INFO] admin update server error: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		affected, _ := result.RowsAffected()
		if affected == 0 {
			http.Error(w, "server not found", http.StatusNotFound)
			return
		}

		log.Printf("[INFO] PUT /admin/servers/%s: updated", serverID)
		w.WriteHeader(http.StatusOK)

	case http.MethodDelete:
		// Destroy DO droplet and CF DNS record before DB cleanup.
		if s.doToken != "" {
			var dropletID string
			s.db.QueryRow("SELECT COALESCE(droplet_id, '') FROM server_status WHERE server_id = ?", serverID).Scan(&dropletID)
			if dropletID != "" {
				if err := s.deleteDroplet(dropletID); err != nil {
					log.Printf("[WARN] failed to delete droplet %s for server %s: %v", dropletID, serverID, err)
				} else {
					log.Printf("[INFO] deleted DO droplet %s for server %s", dropletID, serverID)
				}
			}
		}
		if s.cfAPIToken != "" && s.cfZoneID != "" {
			var domain string
			s.db.QueryRow("SELECT acme_domain FROM servers WHERE id = ?", serverID).Scan(&domain)
			if domain != "" {
				if err := s.deleteDNSRecord(domain); err != nil {
					log.Printf("[WARN] failed to delete DNS record for %s: %v", domain, err)
				} else {
					log.Printf("[INFO] deleted CF DNS record for %s", domain)
				}
			}
		}

		if _, err := s.db.Exec("DELETE FROM servers WHERE id = ?", serverID); err != nil {
			log.Printf("[INFO] admin delete server error: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		// Also clean up status and group assignments.
		s.db.Exec("DELETE FROM server_status WHERE server_id = ?", serverID)
		s.db.Exec("DELETE FROM server_groups WHERE server_id = ?", serverID)

		log.Printf("[INFO] DELETE /admin/servers/%s: deleted", serverID)
		w.WriteHeader(http.StatusOK)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// POST /admin/servers/{id}/restart — SSH into the server and restart the backend service
func (s *Server) handleAdminServerRestart(w http.ResponseWriter, r *http.Request, serverID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var ip, serverToken string
	err := s.db.QueryRow("SELECT COALESCE(ss.ip, ''), s.token FROM server_status ss JOIN servers s ON s.id = ss.server_id WHERE ss.server_id = ?", serverID).Scan(&ip, &serverToken)
	if err != nil || ip == "" {
		http.Error(w, "server IP not found", http.StatusBadRequest)
		return
	}
	if !isValidIP(ip) {
		log.Printf("[WARN] restart %s: invalid IP in database: %q", serverID, ip)
		http.Error(w, "server has invalid IP", http.StatusInternalServerError)
		return
	}

	sshKey := strings.TrimSuffix(s.doSSHKeyFile, ".pub")
	sshOpts := []string{"-i", sshKey, "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=10", "-o", "BatchMode=yes"}
	target := "root@" + ip

	// Rsync latest backend binary.
	rsyncSSH := "ssh " + strings.Join(sshOpts, " ")
	rsyncArgs := []string{"-e", rsyncSSH, s.backendBinary, target + ":/root/backend"}
	if out, err := exec.Command("rsync", rsyncArgs...).CombinedOutput(); err != nil {
		log.Printf("[WARN] rsync backend to %s (%s) failed: %v: %s", serverID, ip, err, string(out))
		http.Error(w, "rsync failed", http.StatusInternalServerError)
		return
	}

	// Validate values before embedding in the systemd service file.
	if !isSafeShellArg(s.baseURL) || !isSafeShellArg(serverToken) {
		log.Printf("[WARN] restart %s: unsafe baseURL or serverToken, aborting", serverID)
		http.Error(w, "server configuration contains unsafe characters", http.StatusInternalServerError)
		return
	}

	// Update systemd service file with current server token, then restart.
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
		`cat > /etc/systemd/system/hysteria-backend.service << 'SERVICEEOF'
%s
SERVICEEOF
systemctl daemon-reload && systemctl restart hysteria-backend.service`, serviceFile)

	args := append(sshOpts, target, setupCmd)
	if out, err := exec.Command("ssh", args...).CombinedOutput(); err != nil {
		log.Printf("[WARN] restart backend on %s (%s) failed: %v: %s", serverID, ip, err, string(out))
		http.Error(w, "restart failed", http.StatusInternalServerError)
		return
	}

	log.Printf("[INFO] synced, updated service, and restarted backend on %s (%s)", serverID, ip)
	w.WriteHeader(http.StatusOK)
}

// /admin/servers/{id}/users[/{uid}] — user assignment management
func (s *Server) handleAdminServerUsers(w http.ResponseWriter, r *http.Request, parts []string) {
	serverID := parts[0]
	if serverID == "" {
		http.Error(w, "missing server_id", http.StatusBadRequest)
		return
	}

	// /admin/servers/{id}/users/{uid} — DELETE
	if len(parts) == 3 && parts[2] != "" {
		userID := parts[2]
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if _, err := s.db.Exec("DELETE FROM server_users WHERE server_id = ? AND user_id = ?", serverID, userID); err != nil {
			log.Printf("[INFO] admin unassign user error: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		log.Printf("[INFO] DELETE /admin/servers/%s/users/%s: unassigned", serverID, userID)
		w.WriteHeader(http.StatusOK)
		return
	}

	// /admin/servers/{id}/users — GET or POST
	switch r.Method {
	case http.MethodGet:
		rows, err := s.db.Query("SELECT user_id FROM server_users WHERE server_id = ? ORDER BY user_id", serverID)
		if err != nil {
			log.Printf("[INFO] admin list server users error: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		users := []string{}
		for rows.Next() {
			var uid string
			rows.Scan(&uid)
			users = append(users, uid)
		}

		log.Printf("[INFO] GET /admin/servers/%s/users: %d users", serverID, len(users))
		if s.debug {
			log.Printf("[DEBUG] GET /admin/servers/%s/users: %v", serverID, users)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(users)

	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
		var body struct {
			ID string `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == "" {
			http.Error(w, "bad request: need {\"id\":\"...\"}", http.StatusBadRequest)
			return
		}
		if _, err := s.db.Exec(
			"INSERT OR IGNORE INTO server_users (server_id, user_id) VALUES (?, ?)",
			serverID, body.ID,
		); err != nil {
			log.Printf("[INFO] admin assign user error: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		log.Printf("[INFO] POST /admin/servers/%s/users: assigned user %q", serverID, body.ID)
		w.WriteHeader(http.StatusCreated)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// /admin/servers/{id}/groups[/{group_name}] — server group management
func (s *Server) handleAdminServerGroups(w http.ResponseWriter, r *http.Request, parts []string) {
	serverID := parts[0]
	if serverID == "" {
		http.Error(w, "missing server_id", http.StatusBadRequest)
		return
	}

	// /admin/servers/{id}/groups/{group_name} — DELETE
	if len(parts) == 3 && parts[2] != "" {
		groupName := parts[2]
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if _, err := s.db.Exec("DELETE FROM server_groups WHERE server_id = ? AND group_name = ?", serverID, groupName); err != nil {
			log.Printf("[INFO] admin remove server group error: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		log.Printf("[INFO] DELETE /admin/servers/%s/groups/%s: removed", serverID, groupName)
		w.WriteHeader(http.StatusOK)
		return
	}

	// /admin/servers/{id}/groups — GET or POST
	switch r.Method {
	case http.MethodGet:
		rows, err := s.db.Query("SELECT group_name FROM server_groups WHERE server_id = ? ORDER BY group_name", serverID)
		if err != nil {
			log.Printf("[INFO] admin list server groups error: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		groups := []string{}
		for rows.Next() {
			var g string
			rows.Scan(&g)
			groups = append(groups, g)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(groups)

	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
		var body struct {
			Group string `json:"group"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Group == "" {
			http.Error(w, "bad request: need {\"group\":\"...\"}", http.StatusBadRequest)
			return
		}
		if _, err := s.db.Exec(
			"INSERT OR IGNORE INTO server_groups (server_id, group_name) VALUES (?, ?)",
			serverID, body.Group,
		); err != nil {
			log.Printf("[INFO] admin add server group error: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		log.Printf("[INFO] POST /admin/servers/%s/groups: added group %q", serverID, body.Group)
		w.WriteHeader(http.StatusCreated)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// /admin/quota/{user_id} — get, set, or adjust a user's quota
func (s *Server) handleAdminQuota(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimPrefix(r.URL.Path, "/admin/quota/")
	if userID == "" {
		http.Error(w, "missing user_id", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		var quota int64
		err := s.db.QueryRow("SELECT quota FROM users WHERE id = ?", userID).Scan(&quota)
		if err == sql.ErrNoRows {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		if err != nil {
			log.Printf("[INFO] admin get quota error: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		var used int64
		err = s.db.QueryRow("SELECT COALESCE(tx + rx, 0) FROM traffic WHERE user_id = ?", userID).Scan(&used)
		if err != nil && err != sql.ErrNoRows {
			log.Printf("[INFO] admin get quota usage error: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		log.Printf("[INFO] GET /admin/quota/%s: quota=%d used=%d", userID, quota, used)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]int64{
			"quota": quota,
			"used":  used,
		})

	case http.MethodPut:
		r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
		var body struct {
			Quota int64 `json:"quota"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad request: need {\"quota\": N}", http.StatusBadRequest)
			return
		}
		if body.Quota < 0 {
			http.Error(w, "quota must be >= 0", http.StatusBadRequest)
			return
		}

		result, err := s.db.Exec("UPDATE users SET quota = ? WHERE id = ?", body.Quota, userID)
		if err != nil {
			log.Printf("[INFO] admin set quota error: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		affected, _ := result.RowsAffected()
		if affected == 0 {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}

		log.Printf("[INFO] PUT /admin/quota/%s: set quota to %d", userID, body.Quota)
		w.WriteHeader(http.StatusOK)

	case http.MethodPatch:
		r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
		var body struct {
			Delta int64 `json:"delta"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad request: need {\"delta\": N}", http.StatusBadRequest)
			return
		}
		if body.Delta == 0 {
			http.Error(w, "delta must be non-zero", http.StatusBadRequest)
			return
		}

		result, err := s.db.Exec(
			"UPDATE users SET quota = MAX(quota + ?, 0) WHERE id = ?",
			body.Delta, userID,
		)
		if err != nil {
			log.Printf("[INFO] admin adjust quota error: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		affected, _ := result.RowsAffected()
		if affected == 0 {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}

		log.Printf("[INFO] PATCH /admin/quota/%s: adjusted quota by %d", userID, body.Delta)
		w.WriteHeader(http.StatusOK)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// /admin/traffic — view all traffic
func (s *Server) handleAdminTrafficAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rows, err := s.db.Query(`
		SELECT t.user_id, t.tx, t.rx, COALESCE(u.quota, 0)
		FROM traffic t
		LEFT JOIN users u ON u.id = t.user_id
		ORDER BY t.user_id
	`)
	if err != nil {
		log.Printf("[INFO] admin traffic query error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	result := make(map[string]*TrafficStatsWithQuota)
	for rows.Next() {
		var uid string
		var t TrafficStatsWithQuota
		rows.Scan(&uid, &t.TX, &t.RX, &t.Quota)
		result[uid] = &t
	}

	log.Printf("[INFO] GET /admin/traffic: %d users", len(result))
	if s.debug {
		for uid, t := range result {
			log.Printf("[DEBUG]   %s: tx=%d rx=%d quota=%d", uid, t.TX, t.RX, t.Quota)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// /admin/traffic/{user_id} — view traffic for one user
func (s *Server) handleAdminTrafficUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := strings.TrimPrefix(r.URL.Path, "/admin/traffic/")
	if userID == "" {
		http.Error(w, "missing user_id", http.StatusBadRequest)
		return
	}

	var t TrafficStatsWithQuota
	err := s.db.QueryRow(`
		SELECT t.tx, t.rx, COALESCE(u.quota, 0)
		FROM traffic t
		LEFT JOIN users u ON u.id = t.user_id
		WHERE t.user_id = ?
	`, userID).Scan(&t.TX, &t.RX, &t.Quota)
	if err == sql.ErrNoRows {
		// User may exist but have no traffic yet — fetch their quota
		var quota int64
		qerr := s.db.QueryRow("SELECT quota FROM users WHERE id = ?", userID).Scan(&quota)
		if qerr == sql.ErrNoRows {
			log.Printf("[INFO] GET /admin/traffic/%s: no data", userID)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(&TrafficStatsWithQuota{})
			return
		}
		if qerr != nil {
			log.Printf("[INFO] admin traffic user query error: %v", qerr)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		log.Printf("[INFO] GET /admin/traffic/%s: no traffic, quota=%d", userID, quota)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(&TrafficStatsWithQuota{Quota: quota})
		return
	}
	if err != nil {
		log.Printf("[INFO] admin traffic user query error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	log.Printf("[INFO] GET /admin/traffic/%s: tx=%d rx=%d quota=%d", userID, t.TX, t.RX, t.Quota)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(&t)
}

// /admin/overview — combined view of all users for the dashboard
func (s *Server) handleAdminOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Fetch all users with their traffic, quota and last_seen.
	rows, err := s.db.Query(`
		SELECT u.id, u.token, COALESCE(t.tx, 0), COALESCE(t.rx, 0), u.quota, u.last_seen
		FROM users u
		LEFT JOIN traffic t ON t.user_id = u.id
		ORDER BY u.id
	`)
	if err != nil {
		log.Printf("[INFO] admin overview query error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	users := []*UserOverview{}
	userMap := map[string]*UserOverview{}
	for rows.Next() {
		var u UserOverview
		rows.Scan(&u.ID, &u.Token, &u.TX, &u.RX, &u.Quota, &u.LastSeen)
		u.Servers = []string{}
		u.Groups = []string{}
		users = append(users, &u)
		userMap[u.ID] = &u
	}

	// Fetch server assignments for all users.
	srows, err := s.db.Query(`SELECT user_id, server_id FROM server_users ORDER BY user_id, server_id`)
	if err != nil {
		log.Printf("[INFO] admin overview server query error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer srows.Close()

	for srows.Next() {
		var userID, serverID string
		srows.Scan(&userID, &serverID)
		if u, ok := userMap[userID]; ok {
			u.Servers = append(u.Servers, serverID)
		}
	}

	// Fetch group assignments for all users.
	grows, err := s.db.Query(`SELECT user_id, group_name FROM group_users ORDER BY user_id, group_name`)
	if err != nil {
		log.Printf("[INFO] admin overview group query error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer grows.Close()

	for grows.Next() {
		var userID, groupName string
		grows.Scan(&userID, &groupName)
		if u, ok := userMap[userID]; ok {
			u.Groups = append(u.Groups, groupName)
		}
	}

	log.Printf("[INFO] GET /admin/overview: %d users", len(users))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

// GET /admin/server-overview — list all servers with config + status + user count
func (s *Server) handleAdminServerOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rows, err := s.db.Query(`
		SELECT s.id, s.token, s.acme_domain, s.acme_email,
		       s.auth_url, s.traffic_url, s.region, s.size,
		       s.interval_auth, s.interval_kick, s.interval_traffic_from_proxy, s.interval_traffic_to_central,
		       COALESCE(ss.status, ''), COALESCE(ss.ip, ''),
		       COALESCE(ss.droplet_id, ''), COALESCE(ss.provision_status, ''),
		       COALESCE(ss.hysteria_version, ''), COALESCE(ss.backend_version, ''),
		       COALESCE(ss.last_config_update, ''), COALESCE(ss.uptime_seconds, 0), COALESCE(ss.updated_at, ''),
		       (SELECT COUNT(DISTINCT uid) FROM (
		         SELECT su.user_id AS uid FROM server_users su WHERE su.server_id = s.id
		         UNION
		         SELECT gu.user_id AS uid FROM server_groups sg
		           JOIN group_users gu ON gu.group_name = sg.group_name WHERE sg.server_id = s.id
		         UNION
		         SELECT gu.user_id AS uid FROM group_users gu WHERE gu.group_name = 'all'
		       ))
		FROM servers s
		LEFT JOIN server_status ss ON ss.server_id = s.id
		ORDER BY s.id
	`)
	if err != nil {
		log.Printf("[INFO] admin server overview query error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var result []*ServerOverview
	srvMap := map[string]*ServerOverview{}
	for rows.Next() {
		var o ServerOverview
		rows.Scan(
			&o.ID, &o.Token, &o.AcmeDomain, &o.AcmeEmail,
			&o.AuthURL, &o.TrafficURL, &o.Region, &o.Size,
			&o.IntervalAuth, &o.IntervalKick, &o.IntervalTrafficFromProxy, &o.IntervalTrafficToCentral,
			&o.Status, &o.IP,
			&o.DropletID, &o.ProvisionStatus,
			&o.HysteriaVersion, &o.BackendVersion,
			&o.LastConfigUpdate, &o.UptimeSeconds, &o.LastSeen,
			&o.UserCount,
		)
		o.Groups = []string{}
		result = append(result, &o)
		srvMap[o.ID] = result[len(result)-1]
	}

	// Fetch group assignments for all servers.
	grows, err := s.db.Query(`SELECT server_id, group_name FROM server_groups ORDER BY server_id, group_name`)
	if err == nil {
		defer grows.Close()
		for grows.Next() {
			var sid, gname string
			grows.Scan(&sid, &gname)
			if srv, ok := srvMap[sid]; ok {
				srv.Groups = append(srv.Groups, gname)
			}
		}
	}

	// Fetch per-server traffic from server_traffic table.
	trows, err := s.db.Query(`
		SELECT server_id, COALESCE(SUM(tx), 0), COALESCE(SUM(rx), 0)
		FROM server_traffic
		GROUP BY server_id
	`)
	if err != nil {
		log.Printf("[INFO] server traffic query error: %v", err)
	} else {
		defer trows.Close()
		for trows.Next() {
			var sid string
			var tx, rx int64
			trows.Scan(&sid, &tx, &rx)
			if srv, ok := srvMap[sid]; ok {
				srv.TX = tx
				srv.RX = rx
			}
		}
	}

	log.Printf("[INFO] GET /admin/server-overview: %d servers", len(result))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
