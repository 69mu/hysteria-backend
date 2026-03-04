package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

// GET /backend/auth — return user list for a server (quota-filtered)
func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/backend/auth" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := readBearerToken(r)
	if token == "" {
		http.Error(w, "missing server token", http.StatusUnauthorized)
		return
	}
	serverID := s.resolveServerToken(token)
	if serverID == "" {
		http.Error(w, "invalid server token", http.StatusUnauthorized)
		return
	}

	rows, err := s.db.Query(`
		SELECT DISTINCT u.token
		FROM users u
		LEFT JOIN traffic t ON t.user_id = u.id
		WHERE u.quota > 0
		  AND COALESCE(t.tx + t.rx, 0) < u.quota
		  AND (
		    EXISTS (SELECT 1 FROM server_users su WHERE su.server_id = ? AND su.user_id = u.id)
		    OR EXISTS (
		      SELECT 1 FROM server_groups sg
		      JOIN group_users gu ON gu.group_name = sg.group_name
		      WHERE sg.server_id = ? AND gu.user_id = u.id
		    )
		    OR EXISTS (SELECT 1 FROM group_users gu WHERE gu.group_name = 'all' AND gu.user_id = u.id)
		  )
	`, serverID, serverID)
	if err != nil {
		log.Printf("[INFO] auth query error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	users := []string{}
	for rows.Next() {
		var uid string
		if err := rows.Scan(&uid); err != nil {
			log.Printf("[INFO] auth scan error: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		users = append(users, uid)
	}

	log.Printf("[INFO] GET /auth/%s: %d authorized users", serverID, len(users))
	if s.debug {
		log.Printf("[DEBUG] GET /auth/%s: authorized users=%d", serverID, len(users))

		// Log users excluded by quota
		excludedRows, err := s.db.Query(`
			SELECT DISTINCT u.id, u.quota, COALESCE(t.tx + t.rx, 0) as used
			FROM users u
			LEFT JOIN traffic t ON t.user_id = u.id
			WHERE (u.quota = 0 OR COALESCE(t.tx + t.rx, 0) >= u.quota)
			  AND (
			    EXISTS (SELECT 1 FROM server_users su WHERE su.server_id = ? AND su.user_id = u.id)
			    OR EXISTS (
			      SELECT 1 FROM server_groups sg
			      JOIN group_users gu ON gu.group_name = sg.group_name
			      WHERE sg.server_id = ? AND gu.user_id = u.id
			    )
			    OR EXISTS (SELECT 1 FROM group_users gu WHERE gu.group_name = 'all' AND gu.user_id = u.id)
			  )
		`, serverID, serverID)
		if err == nil {
			defer excludedRows.Close()
			for excludedRows.Next() {
				var uid string
				var quota, used int64
				excludedRows.Scan(&uid, &quota, &used)
				log.Printf("[DEBUG] GET /auth/%s: user %s excluded (used=%d, quota=%d)", serverID, uid, used, quota)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

// POST /backend/traffic — receive and accumulate traffic
func (s *Server) handleTraffic(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/backend/traffic" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := readBearerToken(r)
	serverID := s.resolveServerToken(token)
	if serverID == "" {
		http.Error(w, "invalid server token", http.StatusUnauthorized)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
	var stats map[string]*TrafficStats
	if err := json.NewDecoder(r.Body).Decode(&stats); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	tx, err := s.db.Begin()
	if err != nil {
		log.Printf("[INFO] traffic tx begin error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO traffic (user_id, tx, rx) VALUES (?, ?, ?)
		ON CONFLICT(user_id) DO UPDATE SET tx = tx + excluded.tx, rx = rx + excluded.rx
	`)
	if err != nil {
		log.Printf("[INFO] traffic prepare error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	srvStmt, err := tx.Prepare(`
		INSERT INTO server_traffic (server_id, user_id, tx, rx) VALUES (?, ?, ?, ?)
		ON CONFLICT(server_id, user_id) DO UPDATE SET tx = tx + excluded.tx, rx = rx + excluded.rx
	`)
	if err != nil {
		log.Printf("[INFO] server_traffic prepare error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer srvStmt.Close()

	now := time.Now().UTC().Format(time.RFC3339)
	for userKey, t := range stats {
		if t == nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if t.TX < 0 || t.RX < 0 {
			http.Error(w, "negative traffic is not allowed", http.StatusBadRequest)
			return
		}
		// userKey is the user token (from auth endpoint). Resolve to user ID.
		var userID string
		if err := s.db.QueryRow("SELECT id FROM users WHERE token = ?", userKey).Scan(&userID); err != nil {
			log.Printf("[INFO] traffic: unknown user token (len=%d), skipping", len(userKey))
			continue
		}
		allowed, err := s.isUserAssignedToServer(serverID, userID)
		if err != nil {
			log.Printf("[INFO] traffic: assignment check failed for %s/%s: %v", serverID, userID, err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !allowed {
			log.Printf("[WARN] traffic: rejected unassigned user %s for server %s", userID, serverID)
			continue
		}
		if _, err := stmt.Exec(userID, t.TX, t.RX); err != nil {
			log.Printf("[INFO] traffic upsert error for %s: %v", userID, err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if _, err := srvStmt.Exec(serverID, userID, t.TX, t.RX); err != nil {
			log.Printf("[INFO] server_traffic upsert error for %s/%s: %v", serverID, userID, err)
		}
		if t.TX > 0 || t.RX > 0 {
			tx.Exec(`UPDATE users SET last_seen = ? WHERE id = ?`, now, userID)
		}
	}

	if err := tx.Commit(); err != nil {
		log.Printf("[INFO] traffic tx commit error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	log.Printf("[INFO] POST /traffic/%s: received traffic for %d users", serverID, len(stats))
	if s.debug {
		for _, t := range stats {
			if t == nil {
				continue
			}
			log.Printf("[DEBUG] traffic sample: tx=%d rx=%d", t.TX, t.RX)
		}
	}

	w.WriteHeader(http.StatusOK)
}

// GET /backend/config — return server config for backend node
func (s *Server) handleServerConfig(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/backend/config" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := readBearerToken(r)
	if token == "" {
		http.Error(w, "missing server token", http.StatusUnauthorized)
		return
	}
	serverID := s.resolveServerToken(token)
	if serverID == "" {
		http.Error(w, "invalid server token", http.StatusUnauthorized)
		return
	}

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
		log.Printf("[INFO] server config query error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Auto-fill auth_url and traffic_url from base URL if empty.
	if cfg.AuthURL == "" && s.baseURL != "" {
		cfg.AuthURL = s.baseURL + "/backend/auth"
	}
	if cfg.TrafficURL == "" && s.baseURL != "" {
		cfg.TrafficURL = s.baseURL + "/backend/traffic"
	}

	log.Printf("[INFO] GET /server/config/%s: ok", serverID)
	if s.debug {
		log.Printf("[DEBUG] GET /server/config/%s: domain=%q region=%q size=%q", serverID, cfg.AcmeDomain, cfg.Region, cfg.Size)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cfg)
}

// POST /backend/status — receive status from backend node
func (s *Server) handleServerStatus(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/backend/status" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := readBearerToken(r)
	if token == "" {
		http.Error(w, "missing server token", http.StatusUnauthorized)
		return
	}
	serverID := s.resolveServerToken(token)
	if serverID == "" {
		http.Error(w, "invalid server token", http.StatusUnauthorized)
		return
	}

	var body struct {
		Status           string `json:"status"`
		HysteriaVersion  string `json:"hysteria_version"`
		BackendVersion   string `json:"backend_version"`
		LastConfigUpdate string `json:"last_config_update"`
		UptimeSeconds    int64  `json:"uptime_seconds"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(`
		INSERT INTO server_status (server_id, status, hysteria_version, backend_version, last_config_update, uptime_seconds, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(server_id) DO UPDATE SET
			status = excluded.status,
			hysteria_version = excluded.hysteria_version,
			backend_version = excluded.backend_version,
			last_config_update = excluded.last_config_update,
			uptime_seconds = excluded.uptime_seconds,
			updated_at = excluded.updated_at
	`, serverID, body.Status, body.HysteriaVersion, body.BackendVersion, body.LastConfigUpdate, body.UptimeSeconds, now)
	if err != nil {
		log.Printf("[INFO] server status upsert error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	log.Printf("[INFO] POST /server/status/%s: %s (hysteria=%s, uptime=%ds)", serverID, body.Status, body.HysteriaVersion, body.UptimeSeconds)
	w.WriteHeader(http.StatusOK)
}
