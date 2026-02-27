package main

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

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
	db            *sql.DB
	debug         bool
	baseURL       string
	adminToken    string
	cfAPIToken    string
	cfZoneID      string
	doToken       string
	doSSHKeyFile  string
	doRegion      string
	doSize        string
	doImage       string
	backendBinary string
	doSSHKeyID    int
}

type ServerConfig struct {
	ID                       string `json:"id"`
	Token                    string `json:"token"`
	AcmeDomain               string `json:"acme_domain"`
	AcmeEmail                string `json:"acme_email"`
	AuthURL                  string `json:"auth_url"`
	TrafficURL               string `json:"traffic_url"`
	Region                   string `json:"region"`
	Size                     string `json:"size"`
	IntervalAuth             string `json:"interval_auth"`
	IntervalKick             string `json:"interval_kick"`
	IntervalTrafficFromProxy string `json:"interval_traffic_from_proxy"`
	IntervalTrafficToCentral string `json:"interval_traffic_to_central"`
}

type ServerOverview struct {
	ServerConfig
	Status           string   `json:"status"`
	IP               string   `json:"ip"`
	DropletID        string   `json:"droplet_id"`
	ProvisionStatus  string   `json:"provision_status"`
	HysteriaVersion  string   `json:"hysteria_version"`
	BackendVersion   string   `json:"backend_version"`
	LastConfigUpdate string   `json:"last_config_update"`
	UptimeSeconds    int64    `json:"uptime_seconds"`
	LastSeen         string   `json:"last_seen"`
	UserCount        int      `json:"user_count"`
	Groups           []string `json:"groups"`
	TX               int64    `json:"tx"`
	RX               int64    `json:"rx"`
}

func main() {
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), banner)
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", flag.CommandLine.Name())
		flag.PrintDefaults()
	}

	listenAddr := flag.String("listen", ":9090", "Listen address")
	dbPath := flag.String("db", "central.db", "SQLite database file path")
	debug := flag.Bool("debug", false, "Enable debug logging (show request/response details)")
	baseURL := flag.String("base-url", "https://central.yundong.dev", "Base URL of this central server, used to auto-fill auth_url/traffic_url and passed to backends as -central-server")
	cfAPIToken := flag.String("cf-api-token", "", "Cloudflare API token for DNS management")
	cfZoneID := flag.String("cf-zone-id", "", "Cloudflare Zone ID for DNS records")
	adminToken := flag.String("admin-token", "", "Admin dashboard token (auto-generated if empty)")
	doToken := flag.String("do-token", "", "DigitalOcean API token for droplet management")
	doSSHKeyFile := flag.String("do-ssh-key", "/root/.ssh/central.pub", "Path to SSH public key for droplets")
	backendBinary := flag.String("backend-binary", "./backend", "Path to backend binary for deployment (must be linux/amd64)")

	flag.Parse()

	if *adminToken == "" {
		*adminToken = generateToken()
		log.Printf("[INFO] generated admin token: %s", *adminToken)
	}

	log.SetFlags(log.Ldate | log.Ltime)

	db, err := sql.Open("sqlite", *dbPath)
	if err != nil {
		log.Fatalf("[FATAL] failed to open database: %v", err)
	}
	defer db.Close()

	// Enable WAL mode for better concurrent read/write performance.
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		log.Fatalf("[FATAL] failed to set WAL mode: %v", err)
	}

	if err := initDB(db); err != nil {
		log.Fatalf("[FATAL] failed to initialize database: %v", err)
	}

	srv := &Server{
		db:            db,
		debug:         *debug,
		baseURL:       strings.TrimRight(*baseURL, "/"),
		adminToken:    *adminToken,
		cfAPIToken:    *cfAPIToken,
		cfZoneID:      *cfZoneID,
		doToken:       *doToken,
		doSSHKeyFile:  *doSSHKeyFile,
		doRegion:      "sfo3",
		doSize:        "s-1vcpu-1gb",
		doImage:       "ubuntu-24-04-x64",
		backendBinary: *backendBinary,
	}

	// Resolve DO SSH key ID at startup if DO token is configured.
	if srv.doToken != "" {
		if err := srv.resolveSSHKey(); err != nil {
			log.Fatalf("[FATAL] failed to resolve DO SSH key: %v", err)
		}
		log.Printf("[INFO] resolved DO SSH key ID: %d", srv.doSSHKeyID)
	}

	mux := http.NewServeMux()

	// Backend APIs (called by hysteria-backend nodes)
	mux.HandleFunc("/backend/auth/", srv.handleAuth)
	mux.HandleFunc("/backend/traffic/", srv.handleTraffic)
	mux.HandleFunc("/backend/config/", srv.handleServerConfig)
	mux.HandleFunc("/backend/status/", srv.handleServerStatus)

	// User-facing
	mux.HandleFunc("/user/", srv.handleUser)

	// Admin (token-gated)
	mux.HandleFunc("/admin/", srv.handleAdmin)

	log.Printf("[INFO] admin dashboard: http://localhost%s/admin/%s/", *listenAddr, srv.adminToken)
	log.Printf("[INFO] central server listening on %s (db: %s)", *listenAddr, *dbPath)
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
		CREATE TABLE IF NOT EXISTS servers (
			id TEXT PRIMARY KEY,
			acme_domain TEXT NOT NULL DEFAULT '',
			acme_email TEXT NOT NULL DEFAULT '',
			auth_url TEXT NOT NULL DEFAULT '',
			traffic_url TEXT NOT NULL DEFAULT '',
			interval_auth TEXT NOT NULL DEFAULT '10s',
			interval_kick TEXT NOT NULL DEFAULT '10s',
			interval_traffic_from_proxy TEXT NOT NULL DEFAULT '10s',
			interval_traffic_to_central TEXT NOT NULL DEFAULT '10s'
		);
		CREATE TABLE IF NOT EXISTS server_status (
			server_id TEXT PRIMARY KEY,
			status TEXT NOT NULL DEFAULT '',
			hysteria_version TEXT NOT NULL DEFAULT '',
			backend_version TEXT NOT NULL DEFAULT '',
			last_config_update TEXT NOT NULL DEFAULT '',
			uptime_seconds INTEGER NOT NULL DEFAULT 0,
			updated_at TEXT NOT NULL DEFAULT ''
		);
		CREATE TABLE IF NOT EXISTS server_groups (
			server_id TEXT NOT NULL,
			group_name TEXT NOT NULL,
			PRIMARY KEY (server_id, group_name)
		);
		CREATE TABLE IF NOT EXISTS group_users (
			group_name TEXT NOT NULL,
			user_id TEXT NOT NULL,
			PRIMARY KEY (group_name, user_id)
		);
	`)
	if err != nil {
		return err
	}

	// Migrate: add quota column if it doesn't exist.
	// Default 0 = no access; admin must set a positive quota for each user.
	_, err = db.Exec(`ALTER TABLE users ADD COLUMN quota INTEGER NOT NULL DEFAULT 0`)
	if err != nil {
		// "duplicate column name" means migration already applied; ignore it.
		if !strings.Contains(err.Error(), "duplicate column") {
			return fmt.Errorf("migrate quota column: %w", err)
		}
	}

	// Migrate: add last_seen column for user auth tracking.
	_, err = db.Exec(`ALTER TABLE users ADD COLUMN last_seen TEXT NOT NULL DEFAULT ''`)
	if err != nil {
		if !strings.Contains(err.Error(), "duplicate column") {
			return fmt.Errorf("migrate last_seen column: %w", err)
		}
	}

	// Migrate: add ip column to server_status.
	_, err = db.Exec(`ALTER TABLE server_status ADD COLUMN ip TEXT NOT NULL DEFAULT ''`)
	if err != nil {
		if !strings.Contains(err.Error(), "duplicate column") {
			return fmt.Errorf("migrate ip column: %w", err)
		}
	}

	// Migrate: add region and size columns to servers.
	for _, col := range []string{
		"ALTER TABLE servers ADD COLUMN region TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE servers ADD COLUMN size TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE server_status ADD COLUMN droplet_id TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE server_status ADD COLUMN provision_status TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE users ADD COLUMN token TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE servers ADD COLUMN token TEXT NOT NULL DEFAULT ''",
	} {
		_, err = db.Exec(col)
		if err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return fmt.Errorf("migrate: %w", err)
		}
	}

	// Backfill empty tokens.
	backfillToken := func(table string) error {
		rows, err := db.Query(fmt.Sprintf("SELECT id FROM %s WHERE token = ''", table))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			rows.Scan(&id)
			db.Exec(fmt.Sprintf("UPDATE %s SET token = ? WHERE id = ?", table), generateToken(), id)
		}
		return nil
	}
	if err := backfillToken("users"); err != nil {
		return fmt.Errorf("backfill user tokens: %w", err)
	}
	if err := backfillToken("servers"); err != nil {
		return fmt.Errorf("backfill server tokens: %w", err)
	}

	// Migrate: create server_traffic table for per-server traffic tracking.
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS server_traffic (
			server_id TEXT NOT NULL,
			user_id   TEXT NOT NULL,
			tx        INTEGER NOT NULL DEFAULT 0,
			rx        INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (server_id, user_id)
		)
	`)
	if err != nil {
		return fmt.Errorf("create server_traffic: %w", err)
	}

	return nil
}

// ---------------------------------------------------------------------------
// Random server ID generation (adjective-noun style)
// ---------------------------------------------------------------------------

var idAdjectives = []string{
	"alpine", "amber", "ancient", "arctic", "autumn", "blazing", "bold", "brave", "bright", "calm",
	"cedar", "clever", "cobalt", "coral", "cosmic", "crimson", "crystal", "dancing", "dark", "dawn",
	"deep", "dusty", "eager", "echo", "electric", "emerald", "fading", "fern", "fierce", "floral",
	"foggy", "frozen", "gentle", "gilded", "glacial", "golden", "granite", "hollow", "humble", "icy",
	"iron", "ivory", "jade", "jasper", "keen", "lemon", "light", "lime", "lofty", "lunar",
	"marble", "meadow", "misty", "mossy", "noble", "oak", "obsidian", "olive", "opal", "pale",
	"pearl", "pine", "polar", "proud", "quiet", "rapid", "raven", "rocky", "rosy", "royal",
	"ruby", "rustic", "sage", "sandy", "scarlet", "shadow", "sharp", "silent", "silver", "slate",
	"snowy", "solar", "spicy", "steady", "stone", "stormy", "sunny", "swift", "teal", "thorn",
	"timber", "topaz", "twin", "velvet", "violet", "vivid", "warm", "wild", "windy", "winter",
}

var idNouns = []string{
	"badger", "bear", "bison", "brook", "canyon", "cedar", "cliff", "cloud", "condor", "coral",
	"crane", "creek", "crow", "dawn", "deer", "delta", "dove", "dusk", "eagle", "elk",
	"falcon", "fern", "finch", "flame", "flora", "forge", "fox", "frost", "grove", "hawk",
	"haze", "heron", "hill", "horse", "island", "jade", "jay", "lake", "lark", "leaf",
	"lion", "lotus", "lynx", "maple", "marsh", "mesa", "mist", "moon", "moose", "nest",
	"oak", "ocean", "orchid", "osprey", "otter", "owl", "palm", "panther", "peak", "pebble",
	"pine", "pond", "quail", "rain", "raven", "reef", "ridge", "river", "robin", "sage",
	"seal", "shore", "sky", "snow", "sparrow", "spring", "spruce", "star", "stone", "storm",
	"stream", "summit", "swan", "thorn", "tide", "trail", "trout", "tulip", "vale", "wave",
	"whale", "willow", "wolf", "wren",
}

func generateServerID() string {
	ai, _ := rand.Int(rand.Reader, big.NewInt(int64(len(idAdjectives))))
	ni, _ := rand.Int(rand.Reader, big.NewInt(int64(len(idNouns))))
	a := idAdjectives[ai.Int64()]
	n := idNouns[ni.Int64()]
	return a + "-" + n
}

func generateToken() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// ---------------------------------------------------------------------------
// /user/{user_id} — user overview page
// /user/{user_id}/sub/shadowrocket/ — subscription file (hysteria2 URIs)
// ---------------------------------------------------------------------------

func (s *Server) handleUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/user/")
	parts := strings.SplitN(path, "/", 3) // token [, "sub" [, "shadowrocket/"]]
	if len(parts) == 0 || parts[0] == "" {
		s.handleUserLogin(w, r, false)
		return
	}
	token := parts[0]

	// Look up user by token.
	var userID string
	if err := s.db.QueryRow("SELECT id FROM users WHERE token = ?", token).Scan(&userID); err != nil {
		s.handleUserLogin(w, r, true)
		return
	}

	// /user/{token}/sub/shadowrocket/
	if len(parts) >= 3 && parts[1] == "sub" && strings.TrimSuffix(parts[2], "/") == "shadowrocket" {
		s.handleSubShadowrocket(w, r, userID, token)
		return
	}

	// /user/{token}/sub/clash/
	if len(parts) >= 3 && parts[1] == "sub" && strings.TrimSuffix(parts[2], "/") == "clash" {
		s.handleSubClash(w, r, userID, token)
		return
	}

	// /user/{token} — overview page
	if len(parts) == 1 || (len(parts) == 2 && parts[1] == "") {
		s.handleUserPage(w, r, userID, token)
		return
	}

	http.NotFound(w, r)
}

// userServerInfo holds server data for the user page and subscription.
type userServerInfo struct {
	ID     string `json:"id"`
	Domain string `json:"domain"`
	IP     string `json:"ip"`
}

func (s *Server) queryUserServers(userID string) ([]userServerInfo, error) {
	rows, err := s.db.Query(`
		SELECT DISTINCT srv.id, srv.acme_domain, COALESCE(ss.ip, '')
		FROM servers srv
		LEFT JOIN server_status ss ON ss.server_id = srv.id
		WHERE (
		    EXISTS (SELECT 1 FROM server_users su WHERE su.server_id = srv.id AND su.user_id = ?)
		    OR EXISTS (
		      SELECT 1 FROM server_groups sg
		      JOIN group_users gu ON gu.group_name = sg.group_name
		      WHERE sg.server_id = srv.id AND gu.user_id = ?
		    )
		    OR EXISTS (SELECT 1 FROM group_users gu WHERE gu.group_name = 'all' AND gu.user_id = ?)
		)
		ORDER BY srv.id
	`, userID, userID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var servers []userServerInfo
	for rows.Next() {
		var si userServerInfo
		rows.Scan(&si.ID, &si.Domain, &si.IP)
		servers = append(servers, si)
	}
	return servers, nil
}

// GET /user/{id}/sub/shadowrocket/ — plain text subscription
func (s *Server) handleSubShadowrocket(w http.ResponseWriter, r *http.Request, userID string, userToken string) {
	var exists int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM users WHERE id = ?", userID).Scan(&exists); err != nil || exists == 0 {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	servers, err := s.queryUserServers(userID)
	if err != nil {
		log.Printf("[INFO] sub query error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	var lines []string
	for _, si := range servers {
		if si.IP == "" || si.Domain == "" {
			continue
		}
		lines = append(lines, fmt.Sprintf("hysteria2://%s@%s:443?peer=%s&obfs=none#%s", userToken, si.IP, si.Domain, si.ID))
	}

	log.Printf("[INFO] GET /user/%s/sub/shadowrocket/: %d servers", userID, len(lines))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, strings.Join(lines, "\n"))
}

// GET /user/{token}/sub/clash/ — Clash YAML subscription
func (s *Server) handleSubClash(w http.ResponseWriter, r *http.Request, userID string, userToken string) {
	var exists int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM users WHERE id = ?", userID).Scan(&exists); err != nil || exists == 0 {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	servers, err := s.queryUserServers(userID)
	if err != nil {
		log.Printf("[INFO] clash sub query error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	var proxies, names strings.Builder
	for i, si := range servers {
		if si.IP == "" || si.Domain == "" {
			continue
		}
		name := si.ID + "-hysteria2"
		if i > 0 {
			names.WriteString("\n")
		}
		names.WriteString("  - " + name)
		proxies.WriteString(fmt.Sprintf(`- name: %s
  type: hysteria2
  server: %s
  port: 443
  password: %s
`, name, si.Domain, userToken))
	}

	nameList := names.String()

	log.Printf("[INFO] GET /user/%s/sub/clash/: %d servers", userID, len(servers))
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename="+userID+".yaml")
	fmt.Fprintf(w, `port: 7890
allow-lan: true
mode: rule
log-level: info
unified-delay: true
global-client-fingerprint: chrome
dns:
  enable: true
  listen: :53
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  default-nameserver:
  - 1.1.1.1
  - 223.5.5.5
  - 114.114.114.114
  - 8.8.8.8
  nameserver:
  - https://dns.alidns.com/dns-query
  - https://doh.pub/dns-query
  fallback:
  - https://1.0.0.1/dns-query
  - tls://dns.google
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
    - 240.0.0.0/4

proxies:
%sproxy-groups:
- name: 负载均衡
  type: load-balance
  url: http://www.gstatic.com/generate_204
  interval: 300
  proxies:
%s
- name: 自动选择
  type: url-test
  url: http://www.gstatic.com/generate_204
  interval: 300
  tolerance: 50
  proxies:
%s
- name: 🌍选择代理
  type: select
  proxies:
  - 负载均衡
  - 自动选择
  - DIRECT
%s
rules:
- GEOIP,LAN,DIRECT
- GEOIP,CN,DIRECT
- MATCH,🌍选择代理
`, proxies.String(), nameList, nameList, nameList)
}

// GET /user/ — token login page
func (s *Server) handleUserLogin(w http.ResponseWriter, r *http.Request, invalid bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	errMsg := ""
	inputClass := ""
	if invalid {
		errMsg = "Invalid token. Please try again."
		inputClass = "err"
	}
	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hysteria</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f5f5f5; color: #333; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
  .card { background: #fff; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,0.08); padding: 40px 36px; max-width: 400px; width: 100%%; text-align: center; }
  h1 { font-size: 22px; color: #1a237e; margin-bottom: 6px; }
  .sub { color: #888; font-size: 13px; margin-bottom: 28px; }
  .input-wrap { position: relative; margin-bottom: 16px; }
  input[type="text"] { width: 100%%; padding: 14px 16px; border: 2px solid #e0e0e0; border-radius: 8px; font-size: 15px; font-family: monospace; letter-spacing: 1px; text-align: center; outline: none; transition: border-color 0.2s; }
  input[type="text"]:focus { border-color: #3949ab; }
  input[type="text"].err { border-color: #f44336; }
  .err-msg { color: #f44336; font-size: 13px; margin-bottom: 12px; min-height: 18px; }
  button { width: 100%%; padding: 13px; background: #3949ab; color: #fff; border: none; border-radius: 8px; font-size: 15px; font-weight: 500; cursor: pointer; transition: background 0.2s; }
  button:hover { background: #303f9f; }
</style>
</head>
<body>
<div class="card">
  <h1>Hysteria</h1>
  <p class="sub">Enter your access token to continue</p>
  <div class="err-msg" id="err">%s</div>
  <form onsubmit="go(event)">
    <div class="input-wrap">
      <input type="text" id="tok" placeholder="Your token" autocomplete="off" autofocus spellcheck="false" class="%s">
    </div>
    <button type="submit">Continue</button>
  </form>
</div>
<script>
function go(e) {
  e.preventDefault();
  var t = document.getElementById("tok").value.trim();
  if (t) window.location.href = "/user/" + encodeURIComponent(t);
}
</script>
</body>
</html>`, errMsg, inputClass)
}

// GET /user/{token} — user overview HTML page
func (s *Server) handleUserPage(w http.ResponseWriter, r *http.Request, userID string, userToken string) {
	var quota int64
	var lastSeen string
	err := s.db.QueryRow("SELECT quota, COALESCE(last_seen, '') FROM users WHERE id = ?", userID).Scan(&quota, &lastSeen)
	if err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	var tx, rx int64
	s.db.QueryRow("SELECT COALESCE(tx, 0), COALESCE(rx, 0) FROM traffic WHERE user_id = ?", userID).Scan(&tx, &rx)

	servers, err := s.queryUserServers(userID)
	if err != nil {
		log.Printf("[INFO] user page query error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Build servers JSON for embedding.
	serversJSON, _ := json.Marshal(servers)

	subURL := s.baseURL + "/user/" + userToken + "/sub/shadowrocket/"
	clashURL := s.baseURL + "/user/" + userToken + "/sub/clash/"

	total := tx + rx
	var pct float64
	if quota > 0 {
		pct = float64(total) / float64(quota) * 100
		if pct > 100 {
			pct = 100
		}
	}

	log.Printf("[INFO] GET /user/%s/sub/: serving user page", userID)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s — Hysteria</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f5f5f5; color: #333; padding: 24px; }
  .card { background: #fff; border-radius: 10px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); padding: 24px; max-width: 540px; margin: 0 auto; }
  h1 { font-size: 20px; margin-bottom: 20px; color: #1a237e; }
  .row { display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid #f0f0f0; font-size: 14px; }
  .row:last-child { border-bottom: none; }
  .label { color: #888; }
  .value { font-weight: 500; text-align: right; }
  .section { margin-top: 20px; }
  .section h2 { font-size: 15px; color: #555; margin-bottom: 10px; }
  .server { display: flex; justify-content: space-between; padding: 8px 12px; background: #f8f9fa; border-radius: 6px; margin-bottom: 6px; font-size: 13px; }
  .server .name { font-weight: 500; }
  .server .domain { color: #888; }
  .token-box { background: #f8f9fa; border: 1px dashed #ccc; border-radius: 8px; padding: 14px 16px; margin-bottom: 20px; text-align: center; cursor: pointer; transition: border-color 0.2s, background 0.2s; position: relative; }
  .token-box:hover { border-color: #3949ab; background: #f0f1fa; }
  .token-box.copied { border-color: #2e7d32; background: #e6f4ea; }
  .token-code { font-family: monospace; font-size: 18px; letter-spacing: 2px; color: #1a237e; font-weight: 600; }
  .token-hint { font-size: 11px; color: #999; margin-top: 6px; }
  .token-hint.copied { color: #2e7d32; }
  .sub-btn { display: block; width: 100%%; margin-top: 20px; padding: 12px; background: #3949ab; color: #fff; border: none; border-radius: 8px; font-size: 14px; font-weight: 500; cursor: pointer; text-align: center; }
  .sub-btn:hover { background: #303f9f; }
  .sub-btn.copied { background: #2e7d32; }
  .pct-bar { height: 6px; border-radius: 3px; background: #e0e0e0; margin-top: 4px; }
  .pct-fill { height: 100%%; border-radius: 3px; }
  .pct-green { background: #4caf50; }
  .pct-yellow { background: #ff9800; }
  .pct-red { background: #f44336; }
</style>
</head>
<body>
<div class="card">
  <h1>%s</h1>
  <div class="token-box" onclick="copyToken(this)">
    <div class="token-code">%s</div>
    <div class="token-hint" id="token-hint">This is your access token — click to copy. Bookmark this page or save the token.</div>
  </div>
  <div class="row"><span class="label">TX</span><span class="value" id="tx"></span></div>
  <div class="row"><span class="label">RX</span><span class="value" id="rx"></span></div>
  <div class="row"><span class="label">Total</span><span class="value" id="total"></span></div>
  <div class="row"><span class="label">Quota</span><span class="value" id="quota"></span></div>
  <div class="row" style="display:block">
    <div style="display:flex;justify-content:space-between"><span class="label">Used</span><span class="value" id="pct"></span></div>
    <div class="pct-bar"><div class="pct-fill" id="pct-fill"></div></div>
  </div>
  <div class="row"><span class="label">Last Seen</span><span class="value" id="last-seen"></span></div>

  <div class="section">
    <h2>Servers</h2>
    <div id="servers"></div>
  </div>

  <div style="display:flex;gap:10px;margin-top:20px">
    <button class="sub-btn" style="margin:0" onclick="copySub(this, subURL)">Copy Shadowrocket Subscription</button>
    <button class="sub-btn" style="margin:0;background:#5c6bc0" onclick="copySub(this, clashURL)">Copy Clash Subscription</button>
  </div>
</div>
<script>
var GiB = 1073741824;
var tx = %d, rx = %d, quota = %d;
var pct = %f;
var lastSeen = "%s";
var servers = %s;
var subURL = "%s";
var clashURL = "%s";
var userToken = "%s";

function copyToken(box) {
  navigator.clipboard.writeText(userToken).then(function() {
    box.classList.add("copied");
    var hint = document.getElementById("token-hint");
    hint.textContent = "Copied!";
    hint.classList.add("copied");
    setTimeout(function() { box.classList.remove("copied"); hint.textContent = "This is your access token \u2014 click to copy. Bookmark this page or save the token."; hint.classList.remove("copied"); }, 2000);
  });
}

function fmtBytes(b) {
  if (b >= GiB) return (b / GiB).toFixed(2) + " GiB";
  if (b >= 1048576) return (b / 1048576).toFixed(1) + " MiB";
  if (b >= 1024) return (b / 1024).toFixed(0) + " KiB";
  return b + " B";
}
function fmtAgo(ts) {
  var d = (Date.now() - new Date(ts).getTime()) / 1000;
  if (d < 60) return Math.floor(d) + "s ago";
  if (d < 3600) return Math.floor(d/60) + "m ago";
  if (d < 86400) return Math.floor(d/3600) + "h ago";
  return Math.floor(d/86400) + "d ago";
}

document.getElementById("tx").textContent = fmtBytes(tx);
document.getElementById("rx").textContent = fmtBytes(rx);
document.getElementById("total").textContent = fmtBytes(tx + rx);
document.getElementById("quota").textContent = quota > 0 ? fmtBytes(quota) : "blocked";
document.getElementById("pct").textContent = quota > 0 ? pct.toFixed(1) + "%%" : "N/A";
var fill = document.getElementById("pct-fill");
fill.style.width = (quota > 0 ? pct : 0) + "%%";
fill.className = "pct-fill " + (pct < 70 ? "pct-green" : pct < 90 ? "pct-yellow" : "pct-red");
document.getElementById("last-seen").textContent = lastSeen ? new Date(lastSeen).toLocaleString() + " (" + fmtAgo(lastSeen) + ")" : "-";

var sh = document.getElementById("servers");
if (!servers || servers.length === 0) {
  sh.innerHTML = '<div class="server" style="color:#aaa">No servers assigned</div>';
} else {
  var h = "";
  for (var i = 0; i < servers.length; i++) {
    h += '<div class="server"><span class="name">' + servers[i].id + '</span><span class="domain">' + (servers[i].domain || "-") + '</span></div>';
  }
  sh.innerHTML = h;
}

function copySub(btn, url) {
  var orig = btn.textContent;
  navigator.clipboard.writeText(url).then(function() {
    btn.textContent = "Copied!";
    btn.classList.add("copied");
    setTimeout(function() { btn.textContent = orig; btn.classList.remove("copied"); }, 2000);
  });
}
</script>
</body>
</html>`, userID, userID, userToken, tx, rx, quota, pct, lastSeen, string(serversJSON), subURL, clashURL, userToken)
}

// ---------------------------------------------------------------------------
// GET /auth/{server_id} — return user list for a server (quota-filtered)
// ---------------------------------------------------------------------------

func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := strings.TrimPrefix(r.URL.Path, "/backend/auth/")
	if token == "" {
		http.Error(w, "missing server token", http.StatusBadRequest)
		return
	}
	serverID := s.resolveServerToken(token)
	if serverID == "" {
		http.Error(w, "server not found", http.StatusNotFound)
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
		log.Printf("[DEBUG] GET /auth/%s: %v", serverID, users)

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

// ---------------------------------------------------------------------------
// POST /traffic/{server_id} — receive and accumulate traffic
// ---------------------------------------------------------------------------

type TrafficStats struct {
	TX int64 `json:"tx"`
	RX int64 `json:"rx"`
}

// TrafficStatsWithQuota extends TrafficStats with quota info for admin responses.
type TrafficStatsWithQuota struct {
	TX    int64 `json:"tx"`
	RX    int64 `json:"rx"`
	Quota int64 `json:"quota"`
}

func (s *Server) handleTraffic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := strings.TrimPrefix(r.URL.Path, "/backend/traffic/")
	serverID := s.resolveServerToken(token)
	if serverID == "" {
		http.Error(w, "server not found", http.StatusNotFound)
		return
	}

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
		// userKey is the user token (from auth endpoint). Resolve to user ID.
		var userID string
		if err := s.db.QueryRow("SELECT id FROM users WHERE token = ?", userKey).Scan(&userID); err != nil {
			log.Printf("[INFO] traffic: unknown user token %s, skipping", userKey)
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
		for userID, t := range stats {
			log.Printf("[DEBUG]   %s: tx=%d rx=%d", userID, t.TX, t.RX)
		}
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
		var body struct {
			ID    string `json:"id"`
			Quota int64  `json:"quota"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == "" {
			http.Error(w, "bad request: need {\"id\":\"...\"}", http.StatusBadRequest)
			return
		}
		if _, err := s.db.Exec("INSERT OR IGNORE INTO users (id, token, quota) VALUES (?, ?, ?)", body.ID, generateToken(), body.Quota); err != nil {
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

// ---------------------------------------------------------------------------
// Admin: /admin/users/{user_id}[/groups[/{group_name}]]
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Admin: /admin/servers/ — dispatcher
//   ""                          → handleAdminServerList (GET list, POST create)
//   "{id}"                      → handleAdminServerCRUD (GET/PUT/DELETE)
//   "{id}/users[/{uid}]"        → handleAdminServerUsers (existing user assignment)
//   "{id}/groups[/{group_name}]" → handleAdminServerGroups (group management)
// ---------------------------------------------------------------------------

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
		var cfg ServerConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if cfg.ID == "" {
			cfg.ID = generateServerID()
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

		cfg.Token = generateToken()
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

	sshKey := strings.TrimSuffix(s.doSSHKeyFile, ".pub")
	sshOpts := []string{"-i", sshKey, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10"}
	target := "root@" + ip

	// Rsync latest backend binary.
	rsyncSSH := "ssh " + strings.Join(sshOpts, " ")
	rsyncArgs := []string{"-e", rsyncSSH, s.backendBinary, target + ":/root/backend"}
	if out, err := exec.Command("rsync", rsyncArgs...).CombinedOutput(); err != nil {
		log.Printf("[WARN] rsync backend to %s (%s) failed: %v: %s", serverID, ip, err, string(out))
		http.Error(w, "rsync failed: "+string(out), http.StatusInternalServerError)
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
		http.Error(w, "restart failed: "+string(out), http.StatusInternalServerError)
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

// ---------------------------------------------------------------------------
// Admin: /admin/quota/{user_id} — get, set, or adjust a user's quota
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Admin: /admin/traffic — view all traffic
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Admin: /admin/overview — combined view of all users for the dashboard
// ---------------------------------------------------------------------------

type UserOverview struct {
	ID       string   `json:"id"`
	Token    string   `json:"token"`
	TX       int64    `json:"tx"`
	RX       int64    `json:"rx"`
	Quota    int64    `json:"quota"`
	LastSeen string   `json:"last_seen"`
	Servers  []string `json:"servers"`
	Groups   []string `json:"groups"`
}

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

// ---------------------------------------------------------------------------
// Admin: /admin/ — dashboard HTML page
// ---------------------------------------------------------------------------

// handleAdmin validates the admin token and dispatches to sub-handlers.
// All admin paths are: /admin/{token}/...
func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/admin/")
	parts := strings.SplitN(path, "/", 2) // token [, rest]
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	token := parts[0]
	if token != s.adminToken {
		http.NotFound(w, r)
		return
	}

	rest := ""
	if len(parts) == 2 {
		rest = parts[1]
	}

	switch {
	case rest == "" || rest == "/":
		// /admin/{token}/ — dashboard page
		s.handleAdminPage(w, r)
	case rest == "overview":
		s.handleAdminOverview(w, r)
	case rest == "server-overview":
		s.handleAdminServerOverview(w, r)
	case rest == "traffic":
		s.handleAdminTrafficAll(w, r)
	case rest == "users":
		s.handleAdminUsers(w, r)
	case strings.HasPrefix(rest, "users/"):
		r.URL.Path = "/admin/users/" + strings.TrimPrefix(rest, "users/")
		s.handleAdminUser(w, r)
	case strings.HasPrefix(rest, "servers/") || rest == "servers":
		r.URL.Path = "/admin/servers/" + strings.TrimPrefix(rest, "servers/")
		s.handleAdminServers(w, r)
	case strings.HasPrefix(rest, "quota/"):
		r.URL.Path = "/admin/quota/" + strings.TrimPrefix(rest, "quota/")
		s.handleAdminQuota(w, r)
	case strings.HasPrefix(rest, "traffic/"):
		r.URL.Path = "/admin/traffic/" + strings.TrimPrefix(rest, "traffic/")
		s.handleAdminTrafficUser(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleAdminPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := strings.ReplaceAll(adminPageHTML, "{{ADMIN_TOKEN}}", s.adminToken)
	fmt.Fprint(w, html)
}

const adminPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hysteria Admin</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f5f5f5; color: #333; padding: 24px; }
  h1 { font-size: 20px; margin-bottom: 4px; }
  .meta { color: #888; font-size: 13px; margin-bottom: 16px; }
  table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
  th, td { padding: 10px 14px; text-align: left; border-bottom: 1px solid #eee; font-size: 14px; }
  th { background: #fafafa; font-weight: 600; color: #555; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: #f9f9f9; }
  .num { text-align: right; font-variant-numeric: tabular-nums; }
  .pct { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }
  .pct-green { background: #e6f4ea; color: #1a7f37; }
  .pct-yellow { background: #fff8e1; color: #b08800; }
  .pct-red { background: #fce8e6; color: #c5221f; }
  .pct-gray { background: #f0f0f0; color: #888; }
  .servers { font-size: 12px; color: #666; }
  .server-tag { display: inline-block; background: #e8eaf6; color: #3949ab; padding: 2px 6px; border-radius: 3px; margin: 1px 2px; font-size: 11px; }
  .group-tag { display: inline-block; background: #e8f5e9; color: #2e7d32; padding: 2px 6px; border-radius: 3px; margin: 1px 2px; font-size: 11px; }
  .group-tag .remove { cursor: pointer; margin-left: 3px; opacity: 0.5; }
  .group-tag .remove:hover { opacity: 1; }
  .group-tag-default { display: inline-block; background: #e0f2f1; color: #00695c; padding: 2px 6px; border-radius: 3px; margin: 1px 2px; font-size: 11px; font-style: italic; }
  .tag-chip { display: inline-block; background: #e8f5e9; color: #2e7d32; padding: 2px 6px; border-radius: 3px; margin: 1px 2px; font-size: 11px; }
  .tag-chip .remove { cursor: pointer; margin-left: 3px; opacity: 0.5; }
  .tag-chip .remove:hover { opacity: 1; }
  .tag-suggestions { display: flex; gap: 4px; flex-wrap: wrap; margin-top: 4px; }
  .tag-suggestions button { padding: 2px 8px; border-radius: 3px; border: 1px solid #c8e6c9; background: #f1f8e9; cursor: pointer; font-size: 11px; color: #2e7d32; }
  .tag-suggestions button:hover { background: #c8e6c9; }
  .empty { text-align: center; padding: 40px; color: #999; }
  #error { color: #c5221f; margin-bottom: 12px; display: none; }
  .quota-actions { display: inline-flex; gap: 4px; margin-left: 6px; }
  .quota-actions button { border: none; cursor: pointer; padding: 2px 7px; border-radius: 3px; font-size: 11px; font-weight: 600; }
  .btn-set { background: #e8eaf6; color: #3949ab; }
  .btn-set:hover { background: #c5cae9; }
  .btn-add { background: #e6f4ea; color: #1a7f37; }
  .btn-add:hover { background: #c8e6c9; }
  .btn-del { background: #fce8e6; color: #c5221f; }
  .btn-del:hover { background: #f8d7da; }
  .btn-edit { background: #fff8e1; color: #b08800; }
  .btn-edit:hover { background: #fff3cd; }
  .server-tag .remove { cursor: pointer; margin-left: 3px; opacity: 0.5; }
  .server-tag .remove:hover { opacity: 1; }
  .btn-add-srv { display: inline-block; background: #fff; border: 1px dashed #bbb; color: #888; padding: 2px 6px; border-radius: 3px; margin: 1px 2px; font-size: 11px; cursor: pointer; }
  .btn-add-srv:hover { border-color: #3949ab; color: #3949ab; }
  .modal-bg { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.3); z-index: 100; justify-content: center; align-items: center; }
  .modal-bg.open { display: flex; }
  .modal { background: #fff; border-radius: 10px; padding: 24px; min-width: 320px; max-width: 480px; box-shadow: 0 8px 30px rgba(0,0,0,0.15); }
  .modal h2 { font-size: 16px; margin-bottom: 16px; }
  .modal label { display: block; font-size: 13px; color: #555; margin-bottom: 4px; }
  .modal input { width: 100%; padding: 8px 10px; border: 1px solid #ddd; border-radius: 5px; font-size: 14px; margin-bottom: 8px; }
  .modal input:focus { outline: none; border-color: #3949ab; }
  .modal .hint { font-size: 11px; color: #999; margin-bottom: 12px; }
  .modal .btns { display: flex; gap: 8px; justify-content: flex-end; margin-top: 16px; }
  .modal .btns button { padding: 7px 16px; border-radius: 5px; border: none; cursor: pointer; font-size: 13px; font-weight: 500; }
  .modal .btns .cancel { background: #f0f0f0; color: #555; }
  .modal .btns .cancel:hover { background: #e0e0e0; }
  .modal .btns .confirm { background: #3949ab; color: #fff; }
  .modal .btns .confirm:hover { background: #303f9f; }
  .modal .error { color: #c5221f; font-size: 12px; margin-top: 8px; display: none; }
  .presets { display: flex; gap: 6px; margin-bottom: 12px; flex-wrap: wrap; }
  .presets button { padding: 4px 10px; border-radius: 4px; border: 1px solid #ddd; background: #fff; cursor: pointer; font-size: 12px; color: #333; }
  .presets button:hover { background: #e8eaf6; border-color: #3949ab; }
  .tabs { display: flex; gap: 0; margin-bottom: 16px; border-bottom: 2px solid #e0e0e0; }
  .tab { padding: 8px 20px; cursor: pointer; font-size: 14px; font-weight: 500; color: #888; border-bottom: 2px solid transparent; margin-bottom: -2px; }
  .tab:hover { color: #333; }
  .tab.active { color: #3949ab; border-bottom-color: #3949ab; }
  .tab-content { display: none; }
  .tab-content.active { display: block; }
  .status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }
  .status-green { background: #1a7f37; }
  .status-yellow { background: #b08800; }
  .status-red { background: #c5221f; }
  .status-gray { background: #999; }
</style>
</head>
<body>
<h1>Hysteria Admin Dashboard</h1>

<div class="tabs">
  <div class="tab active" onclick="switchTab('users')">Users</div>
  <div class="tab" onclick="switchTab('servers')">Servers</div>
</div>

<!-- Users Tab -->
<div class="tab-content active" id="tab-users">
<div style="display:flex;align-items:center;gap:12px;margin-bottom:16px">
<div class="meta" id="status" style="margin:0">Loading...</div>
<button onclick="openAddUserModal()" style="padding:5px 14px;border-radius:5px;border:none;background:#3949ab;color:#fff;cursor:pointer;font-size:13px;font-weight:500">+ Add User</button>
</div>
<div id="error"></div>
<table>
<thead>
<tr>
  <th>User</th>
  <th>Token</th>
  <th class="num">TX</th>
  <th class="num">RX</th>
  <th class="num">Total</th>
  <th class="num">Quota</th>
  <th>Used</th>
  <th>Last Seen</th>
  <th>Servers</th>
  <th>Actions</th>
</tr>
</thead>
<tbody id="tbody"></tbody>
</table>
</div>

<!-- Servers Tab -->
<div class="tab-content" id="tab-servers">
<div style="display:flex;align-items:center;gap:12px;margin-bottom:16px">
<div class="meta" id="srv-status" style="margin:0">Loading...</div>
<button onclick="openAddSrvModal()" style="padding:5px 14px;border-radius:5px;border:none;background:#3949ab;color:#fff;cursor:pointer;font-size:13px;font-weight:500">+ Add Server</button>
</div>
<div id="srv-error" style="color:#c5221f;margin-bottom:12px;display:none"></div>
<table>
<thead>
<tr>
  <th>ID</th>
  <th>Token</th>
  <th>Domain</th>
  <th>IP</th>
  <th>Provision</th>
  <th>Status</th>
  <th>Hysteria</th>
  <th>Uptime</th>
  <th>Last Seen</th>
  <th class="num">TX</th>
  <th class="num">RX</th>
  <th class="num">Total</th>
  <th class="num">Users</th>
  <th>Groups</th>
  <th>Actions</th>
</tr>
</thead>
<tbody id="srv-tbody"></tbody>
</table>
</div>

<!-- Quota Modal -->
<div class="modal-bg" id="modal">
<div class="modal">
  <h2 id="modal-title">Set Quota</h2>
  <label id="modal-label">Quota (GiB)</label>
  <input type="number" id="modal-input" step="any" min="0" placeholder="e.g. 10">
  <div class="hint" id="modal-hint"></div>
  <div class="presets" id="modal-presets"></div>
  <div class="error" id="modal-error"></div>
  <div class="btns">
    <button class="cancel" onclick="closeModal()">Cancel</button>
    <button class="confirm" id="modal-confirm">Confirm</button>
  </div>
</div>
</div>

<!-- Add User Modal -->
<div class="modal-bg" id="add-user-modal">
<div class="modal">
  <h2>Add User</h2>
  <label>User ID</label>
  <input type="text" id="add-user-id" placeholder="e.g. alice">
  <label>Quota (GiB)</label>
  <input type="number" id="add-user-quota" step="any" min="0" placeholder="e.g. 10">
  <div class="hint">Quota 0 = blocked. Leave empty for 0.</div>
  <div class="presets" id="add-user-presets"></div>
  <div class="error" id="add-user-error"></div>
  <div class="btns">
    <button class="cancel" onclick="closeAddUserModal()">Cancel</button>
    <button class="confirm" id="add-user-confirm">Add</button>
  </div>
</div>
</div>

<!-- Assign Server/Group to User Modal -->
<div class="modal-bg" id="add-server-modal">
<div class="modal">
  <h2 id="add-server-title">Assign Server or Group</h2>
  <div style="margin-bottom:8px">
    <label style="display:inline;margin-right:12px"><input type="radio" name="assign-type" value="server" checked onchange="updateAssignHint()"> Server</label>
    <label style="display:inline"><input type="radio" name="assign-type" value="group" onchange="updateAssignHint()"> Group</label>
  </div>
  <label id="assign-label">Server ID</label>
  <input type="text" id="add-server-id" placeholder="e.g. srv1">
  <div class="hint" id="assign-hint">Enter the server_id to assign this user to.</div>
  <div class="error" id="add-server-error"></div>
  <div class="btns">
    <button class="cancel" onclick="closeAddServerModal()">Cancel</button>
    <button class="confirm" id="add-server-confirm">Assign</button>
  </div>
</div>
</div>

<!-- Add/Edit Server Modal -->
<div class="modal-bg" id="srv-modal">
<div class="modal" style="min-width:400px">
  <h2 id="srv-modal-title">Add Server</h2>
  <label>Server ID</label>
  <input type="text" id="srv-m-id" placeholder="auto-generated if empty">
  <label>ACME Domain</label>
  <input type="text" id="srv-m-domain" placeholder="default: p1.yundong.dev">
  <label>ACME Email</label>
  <input type="text" id="srv-m-email" placeholder="default: admin@yundong.dev">
  <label>Region</label>
  <input type="text" id="srv-m-region" placeholder="default: sfo3">
  <label>Size</label>
  <input type="text" id="srv-m-size" placeholder="default: s-1vcpu-1gb">
  <label>Auth URL</label>
  <input type="text" id="srv-m-auth-url" placeholder="default: {base-url}/backend/auth">
  <label>Traffic URL</label>
  <input type="text" id="srv-m-traffic-url" placeholder="default: {base-url}/backend/traffic">
  <label>Groups</label>
  <div id="srv-m-groups-chips" style="margin-bottom:4px"></div>
  <div id="srv-m-groups-suggest" class="tag-suggestions" style="margin-bottom:4px"></div>
  <div style="display:flex;gap:4px;margin-bottom:8px">
    <input type="text" id="srv-m-group-input" placeholder="custom group name" style="flex:1;margin-bottom:0">
    <button type="button" onclick="addSrvModalGroup(document.getElementById('srv-m-group-input').value.trim())" style="padding:4px 10px;border-radius:5px;border:1px solid #c8e6c9;background:#e8f5e9;color:#2e7d32;cursor:pointer;font-size:12px">Add</button>
  </div>
  <div class="error" id="srv-m-error"></div>
  <div class="btns">
    <button class="cancel" onclick="closeSrvModal()">Cancel</button>
    <button class="confirm" id="srv-m-confirm">Save</button>
  </div>
</div>
</div>

<!-- Add Group to Server Modal -->
<div class="modal-bg" id="add-group-modal">
<div class="modal">
  <h2 id="add-group-title">Add Group to Server</h2>
  <label>Group Name</label>
  <input type="text" id="add-group-name" placeholder="e.g. us-east">
  <div class="hint">Enter a group name. Users assigned to this group will be authorized on this server.</div>
  <div class="error" id="add-group-error"></div>
  <div class="btns">
    <button class="cancel" onclick="closeAddGroupModal()">Cancel</button>
    <button class="confirm" id="add-group-confirm">Add</button>
  </div>
</div>
</div>

<script>
var GiB = 1073741824;
var adminToken = "{{ADMIN_TOKEN}}";
var A = "/admin/" + adminToken;
var modalState = {};
var currentTab = "users";

function switchTab(tab) {
  currentTab = tab;
  document.querySelectorAll(".tab").forEach(function(t) { t.classList.remove("active"); });
  document.querySelectorAll(".tab-content").forEach(function(t) { t.classList.remove("active"); });
  document.querySelector('.tab[onclick="switchTab(\'' + tab + '\')"]').classList.add("active");
  document.getElementById("tab-" + tab).classList.add("active");
  if (tab === "servers") loadServers();
  else load();
}

// ---- Users Tab ----
function openAddUserModal() {
  document.getElementById("add-user-id").value = "";
  document.getElementById("add-user-quota").value = "";
  document.getElementById("add-user-error").style.display = "none";
  var presets = document.getElementById("add-user-presets");
  presets.innerHTML = "";
  [1, 5, 10, 50, 100, 500].forEach(function(g) {
    var btn = document.createElement("button");
    btn.textContent = g + " GiB";
    btn.onclick = function() { document.getElementById("add-user-quota").value = g; };
    presets.appendChild(btn);
  });
  document.getElementById("add-user-modal").classList.add("open");
  document.getElementById("add-user-id").focus();
}
function closeAddUserModal() {
  document.getElementById("add-user-modal").classList.remove("open");
}
document.getElementById("add-user-modal").addEventListener("click", function(e) {
  if (e.target === this) closeAddUserModal();
});
document.getElementById("add-user-confirm").addEventListener("click", function() {
  var uid = document.getElementById("add-user-id").value.trim();
  var errEl = document.getElementById("add-user-error");
  if (!uid) { errEl.textContent = "User ID is required."; errEl.style.display = "block"; return; }
  var qVal = document.getElementById("add-user-quota").value;
  var quota = qVal ? Math.round(parseFloat(qVal) * GiB) : 0;
  if (isNaN(quota) || quota < 0) { errEl.textContent = "Invalid quota."; errEl.style.display = "block"; return; }
  fetch(A + "/users", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({id: uid, quota: quota})
  }).then(function(r) {
    if (!r.ok) throw new Error("HTTP " + r.status);
    closeAddUserModal();
    load();
  }).catch(function(e) {
    errEl.textContent = "Failed: " + e.message;
    errEl.style.display = "block";
  });
});

function deleteUser(uid) {
  if (!confirm("Delete user \"" + uid + "\"? This removes all their server assignments and traffic data.")) return;
  fetch(A + "/users/" + encodeURIComponent(uid), { method: "DELETE" })
    .then(function(r) { if (!r.ok) throw new Error("HTTP " + r.status); load(); })
    .catch(function(e) { alert("Failed to delete: " + e.message); });
}
function removeServer(uid, sid) {
  if (!confirm("Remove " + uid + " from server " + sid + "?")) return;
  fetch(A + "/servers/" + encodeURIComponent(sid) + "/users/" + encodeURIComponent(uid), { method: "DELETE" })
    .then(function(r) { if (!r.ok) throw new Error("HTTP " + r.status); load(); })
    .catch(function(e) { alert("Failed: " + e.message); });
}
function removeGroup(uid, gname) {
  if (!confirm("Remove " + uid + " from group " + gname + "?")) return;
  fetch(A + "/users/" + encodeURIComponent(uid) + "/groups/" + encodeURIComponent(gname), { method: "DELETE" })
    .then(function(r) { if (!r.ok) throw new Error("HTTP " + r.status); load(); })
    .catch(function(e) { alert("Failed: " + e.message); });
}
function updateAssignHint() {
  var isGroup = document.querySelector('input[name="assign-type"]:checked').value === "group";
  document.getElementById("assign-label").textContent = isGroup ? "Group Name" : "Server ID";
  document.getElementById("add-server-id").placeholder = isGroup ? "e.g. all, us-east" : "e.g. srv1";
  document.getElementById("assign-hint").textContent = isGroup ? "Enter a group name. \"all\" matches every server." : "Enter the server_id to assign this user to.";
}
var addServerUid = "";
function openAddServerModal(uid) {
  addServerUid = uid;
  document.getElementById("add-server-title").textContent = "Assign to " + uid;
  document.getElementById("add-server-id").value = "";
  document.querySelector('input[name="assign-type"][value="server"]').checked = true;
  updateAssignHint();
  document.getElementById("add-server-error").style.display = "none";
  document.getElementById("add-server-modal").classList.add("open");
  document.getElementById("add-server-id").focus();
}
function closeAddServerModal() {
  document.getElementById("add-server-modal").classList.remove("open");
}
document.getElementById("add-server-modal").addEventListener("click", function(e) {
  if (e.target === this) closeAddServerModal();
});
document.getElementById("add-server-confirm").addEventListener("click", function() {
  var val = document.getElementById("add-server-id").value.trim();
  var errEl = document.getElementById("add-server-error");
  if (!val) { errEl.textContent = "Value is required."; errEl.style.display = "block"; return; }
  var isGroup = document.querySelector('input[name="assign-type"]:checked').value === "group";
  var url, body;
  if (isGroup) {
    url = A + "/users/" + encodeURIComponent(addServerUid) + "/groups";
    body = JSON.stringify({group: val});
  } else {
    url = A + "/servers/" + encodeURIComponent(val) + "/users";
    body = JSON.stringify({id: addServerUid});
  }
  fetch(url, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: body
  }).then(function(r) {
    if (!r.ok) throw new Error("HTTP " + r.status);
    closeAddServerModal();
    load();
  }).catch(function(e) {
    errEl.textContent = "Failed: " + e.message;
    errEl.style.display = "block";
  });
});

function fmt(b) {
  if (b === 0) return "0 B";
  var units = ["B","KiB","MiB","GiB","TiB"];
  var i = Math.min(Math.floor(Math.log(b) / Math.log(1024)), units.length - 1);
  var v = b / Math.pow(1024, i);
  return v.toFixed(i === 0 ? 0 : 1) + " " + units[i];
}
function pctClass(p, quota) {
  if (quota === 0) return "pct-gray";
  if (p >= 90) return "pct-red";
  if (p >= 70) return "pct-yellow";
  return "pct-green";
}

function openSetModal(uid, currentQuota) {
  modalState = { uid: uid, mode: "set" };
  document.getElementById("modal-title").textContent = "Set Quota for " + uid;
  document.getElementById("modal-label").textContent = "New quota (GiB)";
  document.getElementById("modal-input").value = currentQuota > 0 ? (currentQuota / GiB).toFixed(2) : "";
  document.getElementById("modal-input").placeholder = "e.g. 10";
  document.getElementById("modal-hint").textContent = "Current: " + fmt(currentQuota) + ". Set to 0 to block.";
  document.getElementById("modal-error").style.display = "none";
  var presets = document.getElementById("modal-presets");
  presets.innerHTML = "";
  [1, 5, 10, 50, 100, 500].forEach(function(g) {
    var btn = document.createElement("button");
    btn.textContent = g + " GiB";
    btn.onclick = function() { document.getElementById("modal-input").value = g; };
    presets.appendChild(btn);
  });
  document.getElementById("modal").classList.add("open");
  document.getElementById("modal-input").focus();
}

function openAddModal(uid, currentQuota) {
  modalState = { uid: uid, mode: "add" };
  document.getElementById("modal-title").textContent = "Add Quota for " + uid;
  document.getElementById("modal-label").textContent = "Amount to add (GiB)";
  document.getElementById("modal-input").value = "";
  document.getElementById("modal-input").placeholder = "e.g. 10";
  document.getElementById("modal-hint").textContent = "Current: " + fmt(currentQuota) + ". Use negative to subtract.";
  document.getElementById("modal-error").style.display = "none";
  var presets = document.getElementById("modal-presets");
  presets.innerHTML = "";
  [1, 5, 10, 50, 100].forEach(function(g) {
    var btn = document.createElement("button");
    btn.textContent = "+" + g + " GiB";
    btn.onclick = function() { document.getElementById("modal-input").value = g; };
    presets.appendChild(btn);
  });
  document.getElementById("modal").classList.add("open");
  document.getElementById("modal-input").focus();
}

function closeModal() {
  document.getElementById("modal").classList.remove("open");
}

document.getElementById("modal").addEventListener("click", function(e) {
  if (e.target === this) closeModal();
});

document.getElementById("modal-confirm").addEventListener("click", function() {
  var val = parseFloat(document.getElementById("modal-input").value);
  var errEl = document.getElementById("modal-error");
  if (isNaN(val)) {
    errEl.textContent = "Please enter a valid number.";
    errEl.style.display = "block";
    return;
  }
  var bytes = Math.round(val * GiB);
  if (modalState.mode === "set") {
    if (bytes < 0) { errEl.textContent = "Quota cannot be negative."; errEl.style.display = "block"; return; }
    fetch(A + "/quota/" + encodeURIComponent(modalState.uid), {
      method: "PUT",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({quota: bytes})
    }).then(function(r) {
      if (!r.ok) throw new Error("HTTP " + r.status);
      closeModal();
      load();
    }).catch(function(e) {
      errEl.textContent = "Failed: " + e.message;
      errEl.style.display = "block";
    });
  } else {
    if (bytes === 0) { errEl.textContent = "Delta cannot be zero."; errEl.style.display = "block"; return; }
    fetch(A + "/quota/" + encodeURIComponent(modalState.uid), {
      method: "PATCH",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({delta: bytes})
    }).then(function(r) {
      if (!r.ok) throw new Error("HTTP " + r.status);
      closeModal();
      load();
    }).catch(function(e) {
      errEl.textContent = "Failed: " + e.message;
      errEl.style.display = "block";
    });
  }
});

function render(users) {
  var tb = document.getElementById("tbody");
  if (!users || users.length === 0) {
    tb.innerHTML = '<tr><td colspan="10" class="empty">No users found</td></tr>';
    return;
  }
  var html = "";
  for (var i = 0; i < users.length; i++) {
    var u = users[i];
    var total = u.tx + u.rx;
    var pct = u.quota > 0 ? Math.min((total / u.quota) * 100, 100) : 0;
    var pctText = u.quota > 0 ? pct.toFixed(1) + "%" : "blocked";
    var servers = "";
    for (var j = 0; j < u.servers.length; j++) {
      servers += '<span class="server-tag">' + u.servers[j] + '<span class="remove" onclick="removeServer(\'' + u.id + '\',\'' + u.servers[j] + '\')">&times;</span></span>';
    }
    if (u.groups) {
      for (var g = 0; g < u.groups.length; g++) {
        servers += '<span class="group-tag">' + u.groups[g] + '<span class="remove" onclick="removeGroup(\'' + u.id + '\',\'' + u.groups[g] + '\')">&times;</span></span>';
      }
    }
    servers += '<span class="btn-add-srv" onclick="openAddServerModal(\'' + u.id + '\')">+</span>';
    html += "<tr>"
      + '<td><a href="/user/' + encodeURIComponent(u.token) + '" target="_blank" style="color:#333;text-decoration:none"><strong>' + u.id + '</strong></a></td>'
      + '<td><a href="/user/' + encodeURIComponent(u.token) + '" target="_blank" style="font-family:monospace;font-size:12px;color:#666;text-decoration:none">' + u.token + '</a></td>'
      + '<td class="num">' + fmt(u.tx) + "</td>"
      + '<td class="num">' + fmt(u.rx) + "</td>"
      + '<td class="num">' + fmt(total) + "</td>"
      + '<td class="num">' + (u.quota > 0 ? fmt(u.quota) : '<span style="color:#ccc">0</span>') + "</td>"
      + '<td><span class="pct ' + pctClass(pct, u.quota) + '">' + pctText + "</span></td>"
      + "<td>" + (u.last_seen ? new Date(u.last_seen).toLocaleTimeString() + ' <span style="color:#888;font-size:11px">(' + fmtAgo(u.last_seen) + ')</span>' : "-") + "</td>"
      + '<td class="servers">' + servers + "</td>"
      + '<td class="quota-actions">'
      + '<button class="btn-set" onclick="openSetModal(\'' + u.id + '\',' + u.quota + ')">Set</button>'
      + '<button class="btn-add" onclick="openAddModal(\'' + u.id + '\',' + u.quota + ')">+ Add</button>'
      + '<button class="btn-del" onclick="deleteUser(\'' + u.id + '\')">Del</button>'
      + "</td>"
      + "</tr>";
  }
  tb.innerHTML = html;
}
function load() {
  fetch(A + "/overview")
    .then(function(r) { if (!r.ok) throw new Error(r.status); return r.json(); })
    .then(function(data) {
      render(data);
      document.getElementById("status").textContent = data.length + " users \u00b7 updated " + new Date().toLocaleTimeString();
      document.getElementById("error").style.display = "none";
    })
    .catch(function(e) {
      document.getElementById("error").textContent = "Failed to load: " + e.message;
      document.getElementById("error").style.display = "block";
    });
}

// ---- Servers Tab ----
var adjectives = ["alpine","amber","ancient","arctic","autumn","blazing","bold","brave","bright","calm","cedar","clever","cobalt","coral","cosmic","crimson","crystal","dancing","dark","dawn","deep","dusty","eager","echo","electric","emerald","fading","fern","fierce","floral","foggy","frozen","gentle","gilded","glacial","golden","granite","hollow","humble","icy","iron","ivory","jade","jasper","keen","lemon","light","lime","lofty","lunar","marble","meadow","misty","mossy","noble","oak","obsidian","olive","opal","pale","pearl","pine","polar","proud","quiet","rapid","raven","rocky","rosy","royal","ruby","rustic","sage","sandy","scarlet","shadow","sharp","silent","silver","slate","snowy","solar","spicy","steady","stone","stormy","sunny","swift","teal","thorn","timber","topaz","twin","velvet","violet","vivid","warm","wild","windy","winter","witty","zen"];
var nouns = ["badger","bear","bison","brook","canyon","cedar","cliff","cloud","condor","coral","crane","creek","crow","dawn","deer","delta","dove","dusk","eagle","elk","falcon","fern","finch","flame","flora","forge","fox","frost","grove","hawk","haze","heron","hill","horse","island","jade","jay","lake","lark","leaf","lion","lotus","lynx","maple","marsh","mesa","mist","moon","moose","nest","oak","ocean","orchid","osprey","otter","owl","palm","panther","peak","pebble","pine","pond","quail","rain","raven","reef","ridge","river","robin","sage","seal","shore","sky","snow","sparrow","spring","spruce","star","stone","storm","stream","summit","swan","thorn","tide","trail","trout","tulip","vale","wave","whale","willow","wolf","wren"];
function generateServerId() {
  var a = adjectives[Math.floor(Math.random() * adjectives.length)];
  var n = nouns[Math.floor(Math.random() * nouns.length)];
  return a + "-" + n;
}
var srvEditId = "";
var srvModalGroups = [];
var srvModalOrigGroups = [];

function collectExistingGroups() {
  var gs = {};
  for (var i = 0; i < srvDataCache.length; i++) {
    if (srvDataCache[i].groups) {
      for (var j = 0; j < srvDataCache[i].groups.length; j++) {
        gs[srvDataCache[i].groups[j]] = true;
      }
    }
  }
  return Object.keys(gs).sort();
}

function renderSrvModalGroups() {
  var chips = document.getElementById("srv-m-groups-chips");
  var html = '<span class="group-tag-default">all</span>';
  for (var i = 0; i < srvModalGroups.length; i++) {
    var g = srvModalGroups[i];
    html += '<span class="tag-chip">' + g + '<span class="remove" onclick="removeSrvModalGroup(\'' + g + '\')">&times;</span></span>';
  }
  chips.innerHTML = html;
  var suggest = document.getElementById("srv-m-groups-suggest");
  var existing = collectExistingGroups();
  var shtml = "";
  for (var i = 0; i < existing.length; i++) {
    if (srvModalGroups.indexOf(existing[i]) === -1) {
      shtml += '<button type="button" onclick="addSrvModalGroup(\'' + existing[i] + '\')">' + existing[i] + '</button>';
    }
  }
  suggest.innerHTML = shtml;
}

function addSrvModalGroup(name) {
  if (!name || name === "all") return;
  if (srvModalGroups.indexOf(name) !== -1) return;
  srvModalGroups.push(name);
  document.getElementById("srv-m-group-input").value = "";
  renderSrvModalGroups();
}

function removeSrvModalGroup(name) {
  srvModalGroups = srvModalGroups.filter(function(g) { return g !== name; });
  renderSrvModalGroups();
}

function openAddSrvModal() {
  srvEditId = "";
  document.getElementById("srv-modal-title").textContent = "Add Server";
  document.getElementById("srv-m-id").value = generateServerId();
  document.getElementById("srv-m-id").disabled = false;
  document.getElementById("srv-m-domain").value = "";
  document.getElementById("srv-m-email").value = "";
  document.getElementById("srv-m-region").value = "";
  document.getElementById("srv-m-size").value = "";
  document.getElementById("srv-m-auth-url").value = "";
  document.getElementById("srv-m-traffic-url").value = "";
  document.getElementById("srv-m-error").style.display = "none";
  srvModalGroups = [];
  srvModalOrigGroups = [];
  renderSrvModalGroups();
  document.getElementById("srv-modal").classList.add("open");
  document.getElementById("srv-m-id").focus();
}
function openEditSrvModal(srv) {
  srvEditId = srv.id;
  document.getElementById("srv-modal-title").textContent = "Edit Server: " + srv.id;
  document.getElementById("srv-m-id").value = srv.id;
  document.getElementById("srv-m-id").disabled = true;
  document.getElementById("srv-m-domain").value = srv.acme_domain || "";
  document.getElementById("srv-m-email").value = srv.acme_email || "";
  document.getElementById("srv-m-region").value = srv.region || "";
  document.getElementById("srv-m-size").value = srv.size || "";
  document.getElementById("srv-m-auth-url").value = srv.auth_url || "";
  document.getElementById("srv-m-traffic-url").value = srv.traffic_url || "";
  document.getElementById("srv-m-error").style.display = "none";
  srvModalGroups = (srv.groups || []).slice();
  srvModalOrigGroups = (srv.groups || []).slice();
  renderSrvModalGroups();
  document.getElementById("srv-modal").classList.add("open");
  document.getElementById("srv-m-domain").focus();
}
function closeSrvModal() {
  document.getElementById("srv-modal").classList.remove("open");
}
document.getElementById("srv-modal").addEventListener("click", function(e) {
  if (e.target === this) closeSrvModal();
});
document.getElementById("srv-m-confirm").addEventListener("click", function() {
  var errEl = document.getElementById("srv-m-error");
  var id = document.getElementById("srv-m-id").value.trim() || generateServerId();
  var body = {
    id: id,
    acme_domain: document.getElementById("srv-m-domain").value.trim(),
    acme_email: document.getElementById("srv-m-email").value.trim(),
    region: document.getElementById("srv-m-region").value.trim(),
    size: document.getElementById("srv-m-size").value.trim(),
    auth_url: document.getElementById("srv-m-auth-url").value.trim(),
    traffic_url: document.getElementById("srv-m-traffic-url").value.trim()
  };
  var method, url;
  if (srvEditId) {
    method = "PUT";
    url = A + "/servers/" + encodeURIComponent(srvEditId);
  } else {
    method = "POST";
    url = A + "/servers/";
  }
  fetch(url, {
    method: method,
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(body)
  }).then(function(r) {
    if (!r.ok) throw new Error("HTTP " + r.status);
    var serverId = id;
    var toAdd = srvModalGroups.filter(function(g) { return srvModalOrigGroups.indexOf(g) === -1; });
    var toRemove = srvModalOrigGroups.filter(function(g) { return srvModalGroups.indexOf(g) === -1; });
    var promises = [];
    for (var i = 0; i < toAdd.length; i++) {
      promises.push(fetch(A + "/servers/" + encodeURIComponent(serverId) + "/groups", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({group: toAdd[i]})
      }));
    }
    for (var i = 0; i < toRemove.length; i++) {
      promises.push(fetch(A + "/servers/" + encodeURIComponent(serverId) + "/groups/" + encodeURIComponent(toRemove[i]), {
        method: "DELETE"
      }));
    }
    return Promise.all(promises);
  }).then(function() {
    closeSrvModal();
    loadServers();
  }).catch(function(e) {
    errEl.textContent = "Failed: " + e.message;
    errEl.style.display = "block";
  });
});

function restartBackend(id, btn) {
  if (!confirm("Restart backend on \"" + id + "\"?")) return;
  btn.disabled = true;
  btn.textContent = "...";
  fetch(A + "/servers/" + encodeURIComponent(id) + "/restart", { method: "POST" })
    .then(function(r) {
      if (!r.ok) return r.text().then(function(t) { throw new Error(t); });
      btn.textContent = "OK";
      setTimeout(function() { btn.textContent = "Restart"; btn.disabled = false; }, 2000);
    })
    .catch(function(e) {
      alert("Restart failed: " + e.message);
      btn.textContent = "Restart";
      btn.disabled = false;
    });
}
function deleteServer(id) {
  if (!confirm("Delete server \"" + id + "\"? This removes the server config and status.")) return;
  fetch(A + "/servers/" + encodeURIComponent(id), { method: "DELETE" })
    .then(function(r) { if (!r.ok) throw new Error("HTTP " + r.status); loadServers(); })
    .catch(function(e) { alert("Failed to delete: " + e.message); });
}

var addGroupServerId = "";
function openAddGroupModal(serverId) {
  addGroupServerId = serverId;
  document.getElementById("add-group-title").textContent = "Add Group to " + serverId;
  document.getElementById("add-group-name").value = "";
  document.getElementById("add-group-error").style.display = "none";
  document.getElementById("add-group-modal").classList.add("open");
  document.getElementById("add-group-name").focus();
}
function closeAddGroupModal() {
  document.getElementById("add-group-modal").classList.remove("open");
}
document.getElementById("add-group-modal").addEventListener("click", function(e) {
  if (e.target === this) closeAddGroupModal();
});
document.getElementById("add-group-confirm").addEventListener("click", function() {
  var gname = document.getElementById("add-group-name").value.trim();
  var errEl = document.getElementById("add-group-error");
  if (!gname) { errEl.textContent = "Group name is required."; errEl.style.display = "block"; return; }
  fetch(A + "/servers/" + encodeURIComponent(addGroupServerId) + "/groups", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({group: gname})
  }).then(function(r) {
    if (!r.ok) throw new Error("HTTP " + r.status);
    closeAddGroupModal();
    loadServers();
  }).catch(function(e) {
    errEl.textContent = "Failed: " + e.message;
    errEl.style.display = "block";
  });
});
document.getElementById("srv-m-group-input").addEventListener("keydown", function(e) {
  if (e.key === "Enter") { e.preventDefault(); addSrvModalGroup(this.value.trim()); }
});
function removeServerGroup(serverId, gname) {
  if (!confirm("Remove group \"" + gname + "\" from server " + serverId + "?")) return;
  fetch(A + "/servers/" + encodeURIComponent(serverId) + "/groups/" + encodeURIComponent(gname), { method: "DELETE" })
    .then(function(r) { if (!r.ok) throw new Error("HTTP " + r.status); loadServers(); })
    .catch(function(e) { alert("Failed: " + e.message); });
}

function fmtAgo(dateStr) {
  if (!dateStr) return "-";
  var ago = (Date.now() - new Date(dateStr).getTime()) / 1000;
  if (ago < 0) ago = 0;
  if (ago < 60) return Math.floor(ago) + "s ago";
  if (ago < 3600) return Math.floor(ago / 60) + "m ago";
  if (ago < 86400) return Math.floor(ago / 3600) + "h ago";
  return Math.floor(ago / 86400) + "d ago";
}

function fmtUptime(s) {
  if (!s || s <= 0) return "-";
  var d = Math.floor(s / 86400);
  var h = Math.floor((s % 86400) / 3600);
  var m = Math.floor((s % 3600) / 60);
  if (d > 0) return d + "d " + h + "h";
  if (h > 0) return h + "h " + m + "m";
  return m + "m";
}

function statusBadge(lastSeen) {
  if (!lastSeen) return '<span class="status-dot status-gray"></span>never';
  var ago = (Date.now() - new Date(lastSeen).getTime()) / 1000;
  var cls = ago < 60 ? "status-green" : ago < 300 ? "status-yellow" : "status-red";
  var text = ago < 60 ? "online" : ago < 300 ? "recent" : "offline";
  return '<span class="status-dot ' + cls + '"></span>' + text;
}

var srvDataCache = [];
function provisionBadge(status) {
  if (!status) return '<span style="color:#ccc">-</span>';
  var color = "#888";
  if (status === "running") color = "#2e7d32";
  else if (status === "creating" || status === "dns" || status === "deploying") color = "#e65100";
  else if (status.indexOf("error") === 0) color = "#c5221f";
  return '<span style="color:' + color + ';font-weight:500;font-size:12px">' + status + '</span>';
}
function renderServers(servers) {
  srvDataCache = servers;
  var tb = document.getElementById("srv-tbody");
  if (!servers || servers.length === 0) {
    tb.innerHTML = '<tr><td colspan="11" class="empty">No servers configured</td></tr>';
    return;
  }
  var html = "";
  for (var i = 0; i < servers.length; i++) {
    var s = servers[i];
    var groups = '<span class="group-tag-default">all</span>';
    if (s.groups) {
      for (var g = 0; g < s.groups.length; g++) {
        groups += '<span class="group-tag">' + s.groups[g] + '<span class="remove" onclick="removeServerGroup(\'' + s.id + '\',\'' + s.groups[g] + '\')">&times;</span></span>';
      }
    }
    groups += '<span class="btn-add-srv" onclick="openAddGroupModal(\'' + s.id + '\')">+</span>';
    html += "<tr>"
      + "<td><strong>" + s.id + "</strong></td>"
      + '<td style="font-family:monospace;font-size:12px;color:#666">' + s.token + "</td>"
      + "<td>" + (s.acme_domain || '<span style="color:#ccc">-</span>') + "</td>"
      + "<td>" + (s.ip || '<span style="color:#ccc">-</span>') + "</td>"
      + "<td>" + provisionBadge(s.provision_status) + "</td>"
      + "<td>" + statusBadge(s.last_seen) + "</td>"
      + "<td>" + (s.hysteria_version || '<span style="color:#ccc">-</span>') + "</td>"
      + "<td>" + fmtUptime(s.uptime_seconds) + "</td>"
      + "<td>" + (s.last_seen ? new Date(s.last_seen).toLocaleTimeString() + ' <span style="color:#888;font-size:11px">(' + fmtAgo(s.last_seen) + ')</span>' : "-") + "</td>"
      + '<td class="num">' + fmt(s.tx) + "</td>"
      + '<td class="num">' + fmt(s.rx) + "</td>"
      + '<td class="num">' + fmt(s.tx + s.rx) + "</td>"
      + '<td class="num">' + s.user_count + "</td>"
      + '<td class="servers">' + groups + "</td>"
      + '<td class="quota-actions">'
      + '<button class="btn-edit" onclick="openEditSrvModal(srvDataCache[' + i + '])">Edit</button>'
      + '<button class="btn-edit" onclick="restartBackend(\'' + s.id + '\', this)">Restart</button>'
      + '<button class="btn-del" onclick="deleteServer(\'' + s.id + '\')">Del</button>'
      + "</td>"
      + "</tr>";
  }
  tb.innerHTML = html;
}
function loadServers() {
  fetch(A + "/server-overview")
    .then(function(r) { if (!r.ok) throw new Error(r.status); return r.json(); })
    .then(function(data) {
      renderServers(data);
      document.getElementById("srv-status").textContent = data.length + " servers \u00b7 updated " + new Date().toLocaleTimeString();
      document.getElementById("srv-error").style.display = "none";
    })
    .catch(function(e) {
      document.getElementById("srv-error").textContent = "Failed to load: " + e.message;
      document.getElementById("srv-error").style.display = "block";
    });
}

// ---- Global keyboard shortcuts ----
document.addEventListener("keydown", function(e) {
  if (e.key === "Escape") { closeModal(); closeAddUserModal(); closeAddServerModal(); closeSrvModal(); closeAddGroupModal(); }
  if (e.key === "Enter" && document.getElementById("modal").classList.contains("open")) {
    document.getElementById("modal-confirm").click();
  }
  if (e.key === "Enter" && document.getElementById("add-user-modal").classList.contains("open")) {
    document.getElementById("add-user-confirm").click();
  }
  if (e.key === "Enter" && document.getElementById("add-server-modal").classList.contains("open")) {
    document.getElementById("add-server-confirm").click();
  }
  if (e.key === "Enter" && document.getElementById("srv-modal").classList.contains("open")) {
    document.getElementById("srv-m-confirm").click();
  }
  if (e.key === "Enter" && document.getElementById("add-group-modal").classList.contains("open")) {
    document.getElementById("add-group-confirm").click();
  }
});

// Initial load
load();
setInterval(function() { if (currentTab === "users") load(); else loadServers(); }, 30000);
</script>
</body>
</html>
`

// resolveServerToken looks up a server ID by its token. Returns "" if not found.
func (s *Server) resolveServerToken(token string) string {
	var id string
	err := s.db.QueryRow("SELECT id FROM servers WHERE token = ?", token).Scan(&id)
	if err != nil {
		return ""
	}
	return id
}

// ---------------------------------------------------------------------------
// GET /backend/config/{server_token} — return server config for backend node
// ---------------------------------------------------------------------------

func (s *Server) handleServerConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := strings.TrimPrefix(r.URL.Path, "/backend/config/")
	if token == "" {
		http.Error(w, "missing server token", http.StatusBadRequest)
		return
	}
	serverID := s.resolveServerToken(token)
	if serverID == "" {
		http.Error(w, "server not found", http.StatusNotFound)
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
		log.Printf("[DEBUG] GET /server/config/%s: %+v", serverID, cfg)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cfg)
}

// ---------------------------------------------------------------------------
// POST /server/status/{server_id} — receive status from backend node
// ---------------------------------------------------------------------------

func (s *Server) handleServerStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := strings.TrimPrefix(r.URL.Path, "/backend/status/")
	if token == "" {
		http.Error(w, "missing server token", http.StatusBadRequest)
		return
	}
	serverID := s.resolveServerToken(token)
	if serverID == "" {
		http.Error(w, "server not found", http.StatusNotFound)
		return
	}

	var body struct {
		Status          string `json:"status"`
		HysteriaVersion string `json:"hysteria_version"`
		BackendVersion  string `json:"backend_version"`
		LastConfigUpdate string `json:"last_config_update"`
		UptimeSeconds   int64  `json:"uptime_seconds"`
	}
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

// ensureDNSRecord creates or updates a Cloudflare DNS A record.
func (s *Server) ensureDNSRecord(domain, ip string) error {
	apiBase := "https://api.cloudflare.com/client/v4/zones/" + s.cfZoneID + "/dns_records"

	// List existing A records for this domain.
	req, _ := http.NewRequest("GET", apiBase+"?type=A&name="+domain, nil)
	req.Header.Set("Authorization", "Bearer "+s.cfAPIToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("cloudflare list request: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	var listResp struct {
		Success bool `json:"success"`
		Result  []struct {
			ID      string `json:"id"`
			Content string `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(respBody, &listResp); err != nil {
		return fmt.Errorf("cloudflare list parse: %w", err)
	}
	if !listResp.Success {
		return fmt.Errorf("cloudflare list failed: %s", string(respBody))
	}

	record := map[string]interface{}{
		"type":    "A",
		"name":    domain,
		"content": ip,
		"ttl":     1,
		"proxied": false,
	}
	recordJSON, _ := json.Marshal(record)

	if len(listResp.Result) > 0 {
		existing := listResp.Result[0]
		if existing.Content == ip {
			log.Printf("[INFO] DNS: A record %s already points to %s, skipping", domain, ip)
			return nil
		}
		// Update existing record.
		req, _ = http.NewRequest("PUT", apiBase+"/"+existing.ID, bytes.NewReader(recordJSON))
		req.Header.Set("Authorization", "Bearer "+s.cfAPIToken)
		req.Header.Set("Content-Type", "application/json")

		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("cloudflare update request: %w", err)
		}
		defer resp.Body.Close()
		respBody, _ = io.ReadAll(resp.Body)

		var updateResp struct {
			Success bool `json:"success"`
		}
		json.Unmarshal(respBody, &updateResp)
		if !updateResp.Success {
			return fmt.Errorf("cloudflare update failed: %s", string(respBody))
		}
		log.Printf("[INFO] DNS: updated A record %s → %s", domain, ip)
	} else {
		// Create new record.
		req, _ = http.NewRequest("POST", apiBase, bytes.NewReader(recordJSON))
		req.Header.Set("Authorization", "Bearer "+s.cfAPIToken)
		req.Header.Set("Content-Type", "application/json")

		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("cloudflare create request: %w", err)
		}
		defer resp.Body.Close()
		respBody, _ = io.ReadAll(resp.Body)

		var createResp struct {
			Success bool `json:"success"`
		}
		json.Unmarshal(respBody, &createResp)
		if !createResp.Success {
			return fmt.Errorf("cloudflare create failed: %s", string(respBody))
		}
		log.Printf("[INFO] DNS: created A record %s → %s", domain, ip)
	}

	return nil
}

// deleteDNSRecord removes a Cloudflare DNS A record for the given domain.
func (s *Server) deleteDNSRecord(domain string) error {
	apiBase := "https://api.cloudflare.com/client/v4/zones/" + s.cfZoneID + "/dns_records"

	req, _ := http.NewRequest("GET", apiBase+"?type=A&name="+domain, nil)
	req.Header.Set("Authorization", "Bearer "+s.cfAPIToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("cloudflare list request: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	var listResp struct {
		Success bool `json:"success"`
		Result  []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := json.Unmarshal(respBody, &listResp); err != nil {
		return fmt.Errorf("cloudflare list parse: %w", err)
	}
	if !listResp.Success || len(listResp.Result) == 0 {
		log.Printf("[INFO] DNS: no A record found for %s, nothing to delete", domain)
		return nil
	}

	recordID := listResp.Result[0].ID
	req, _ = http.NewRequest("DELETE", apiBase+"/"+recordID, nil)
	req.Header.Set("Authorization", "Bearer "+s.cfAPIToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("cloudflare delete request: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ = io.ReadAll(resp.Body)

	var delResp struct {
		Success bool `json:"success"`
	}
	json.Unmarshal(respBody, &delResp)
	if !delResp.Success {
		return fmt.Errorf("cloudflare delete failed: %s", string(respBody))
	}
	log.Printf("[INFO] DNS: deleted A record for %s", domain)
	return nil
}

// ---------------------------------------------------------------------------
// DigitalOcean API helpers
// ---------------------------------------------------------------------------

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
	sshOpts := []string{"-i", sshKey, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=5"}
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

// ---------------------------------------------------------------------------
// GET /admin/server-overview — list all servers with config + status + user count
// ---------------------------------------------------------------------------

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
