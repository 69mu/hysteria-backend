package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"

	_ "modernc.org/sqlite"
)

const banner = `
                 _             _
  ___ ___ _ __ | |_ _ __ __ _| |
 / __/ _ \ '_ \| __| '__/ _' | |
| (_|  __/ | | | |_| | | (_| | |
 \___\___|_| |_|\__|_|  \__,_|_|

  Hysteria central management server
`

type Server struct {
	db *sql.DB
}

func main() {
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), banner)
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", flag.CommandLine.Name())
		flag.PrintDefaults()
	}

	listenAddr := flag.String("listen", ":9090", "Listen address")
	dbPath := flag.String("db", "central.db", "SQLite database file path")

	flag.Parse()

	db, err := sql.Open("sqlite", *dbPath)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	// Enable WAL mode for better concurrent read/write performance.
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		log.Fatalf("failed to set WAL mode: %v", err)
	}

	if err := initDB(db); err != nil {
		log.Fatalf("failed to initialize database: %v", err)
	}

	srv := &Server{db: db}

	mux := http.NewServeMux()

	// Backend APIs (called by hysteria-backend nodes)
	mux.HandleFunc("/auth/", srv.handleAuth)
	mux.HandleFunc("/traffic/", srv.handleTraffic)

	// Admin APIs
	mux.HandleFunc("/admin/users", srv.handleAdminUsers)
	mux.HandleFunc("/admin/users/", srv.handleAdminUser)
	mux.HandleFunc("/admin/servers/", srv.handleAdminServers)
	mux.HandleFunc("/admin/traffic", srv.handleAdminTrafficAll)
	mux.HandleFunc("/admin/traffic/", srv.handleAdminTrafficUser)

	log.Printf("central server listening on %s", *listenAddr)
	log.Fatal(http.ListenAndServe(*listenAddr, mux))
}

func initDB(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY
		);
		CREATE TABLE IF NOT EXISTS server_users (
			server_id TEXT NOT NULL,
			user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			PRIMARY KEY (server_id, user_id)
		);
		CREATE TABLE IF NOT EXISTS traffic (
			user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
			tx      INTEGER NOT NULL DEFAULT 0,
			rx      INTEGER NOT NULL DEFAULT 0
		);
	`)
	return err
}

// ---------------------------------------------------------------------------
// GET /auth/{server_id} — return user list for a server
// ---------------------------------------------------------------------------

func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	serverID := strings.TrimPrefix(r.URL.Path, "/auth/")
	if serverID == "" {
		http.Error(w, "missing server_id", http.StatusBadRequest)
		return
	}

	rows, err := s.db.Query("SELECT user_id FROM server_users WHERE server_id = ?", serverID)
	if err != nil {
		log.Printf("auth query error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	users := []string{}
	for rows.Next() {
		var uid string
		if err := rows.Scan(&uid); err != nil {
			log.Printf("auth scan error: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		users = append(users, uid)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

// ---------------------------------------------------------------------------
// POST /traffic/{server_id} — receive and accumulate traffic
// ---------------------------------------------------------------------------

type TrafficStats struct {
	TX int64 `json:"tx"`
	RX int64 `json:"rx"`
}

func (s *Server) handleTraffic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// server_id is in the path but we don't need it for traffic —
	// we accumulate globally per user.

	var stats map[string]*TrafficStats
	if err := json.NewDecoder(r.Body).Decode(&stats); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	tx, err := s.db.Begin()
	if err != nil {
		log.Printf("traffic tx begin error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO traffic (user_id, tx, rx) VALUES (?, ?, ?)
		ON CONFLICT(user_id) DO UPDATE SET tx = tx + excluded.tx, rx = rx + excluded.rx
	`)
	if err != nil {
		log.Printf("traffic prepare error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	for userID, t := range stats {
		if _, err := stmt.Exec(userID, t.TX, t.RX); err != nil {
			log.Printf("traffic upsert error for %s: %v", userID, err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}

	if err := tx.Commit(); err != nil {
		log.Printf("traffic tx commit error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// ---------------------------------------------------------------------------
// Admin: /admin/users — list or add users
// ---------------------------------------------------------------------------

func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rows, err := s.db.Query("SELECT id FROM users ORDER BY id")
		if err != nil {
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
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(users)

	case http.MethodPost:
		var body struct {
			ID string `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == "" {
			http.Error(w, "bad request: need {\"id\":\"...\"}", http.StatusBadRequest)
			return
		}
		if _, err := s.db.Exec("INSERT OR IGNORE INTO users (id) VALUES (?)", body.ID); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ---------------------------------------------------------------------------
// Admin: /admin/users/{user_id} — delete a user
// ---------------------------------------------------------------------------

func (s *Server) handleAdminUser(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimPrefix(r.URL.Path, "/admin/users/")
	if userID == "" {
		http.Error(w, "missing user_id", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodDelete:
		if _, err := s.db.Exec("DELETE FROM users WHERE id = ?", userID); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ---------------------------------------------------------------------------
// Admin: /admin/servers/{server_id}/users[/{user_id}]
// ---------------------------------------------------------------------------

func (s *Server) handleAdminServers(w http.ResponseWriter, r *http.Request) {
	// Parse: /admin/servers/{server_id}/users[/{user_id}]
	path := strings.TrimPrefix(r.URL.Path, "/admin/servers/")
	parts := strings.SplitN(path, "/", 3) // server_id, "users", [user_id]

	if len(parts) < 2 || parts[1] != "users" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	serverID := parts[0]
	if serverID == "" {
		http.Error(w, "missing server_id", http.StatusBadRequest)
		return
	}

	// /admin/servers/{server_id}/users/{user_id} — DELETE
	if len(parts) == 3 && parts[2] != "" {
		userID := parts[2]
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if _, err := s.db.Exec("DELETE FROM server_users WHERE server_id = ? AND user_id = ?", serverID, userID); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}

	// /admin/servers/{server_id}/users — GET or POST
	switch r.Method {
	case http.MethodGet:
		rows, err := s.db.Query("SELECT user_id FROM server_users WHERE server_id = ? ORDER BY user_id", serverID)
		if err != nil {
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
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(users)

	case http.MethodPost:
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
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ---------------------------------------------------------------------------
// Admin: /admin/traffic — view all traffic
// ---------------------------------------------------------------------------

func (s *Server) handleAdminTrafficAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rows, err := s.db.Query("SELECT user_id, tx, rx FROM traffic ORDER BY user_id")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	result := make(map[string]*TrafficStats)
	for rows.Next() {
		var uid string
		var t TrafficStats
		rows.Scan(&uid, &t.TX, &t.RX)
		result[uid] = &t
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// ---------------------------------------------------------------------------
// Admin: /admin/traffic/{user_id} — view traffic for one user
// ---------------------------------------------------------------------------

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

	var t TrafficStats
	err := s.db.QueryRow("SELECT tx, rx FROM traffic WHERE user_id = ?", userID).Scan(&t.TX, &t.RX)
	if err == sql.ErrNoRows {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(&TrafficStats{})
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(&t)
}
