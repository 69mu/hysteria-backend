package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
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

const (
	adminSessionCookieName       = "hysteria_admin_session"
	userSessionCookieName        = "hysteria_user_token"
	maxJSONBodyBytes       int64 = 1 << 20
)

type Server struct {
	db            *sql.DB
	debug         bool
	baseURL       string
	adminToken    string
	adminSession  string
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

// userServerInfo holds server data for the user page and subscription.
type userServerInfo struct {
	ID     string `json:"id"`
	Domain string `json:"domain"`
	IP     string `json:"ip"`
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

	log.SetFlags(log.Ldate | log.Ltime)

	if *adminToken == "" {
		tok, err := randomHex(32)
		if err != nil {
			log.Fatalf("[FATAL] failed to generate admin token: %v", err)
		}
		*adminToken = tok
		const tokenFile = "central.admin.token"
		if err := os.WriteFile(tokenFile, []byte(tok+"\n"), 0600); err != nil {
			log.Fatalf("[FATAL] failed to persist generated admin token: %v", err)
		}
		log.Printf("[INFO] generated admin token and wrote it to %s (mode 0600)", tokenFile)
	}

	adminSession, err := randomHex(32)
	if err != nil {
		log.Fatalf("[FATAL] failed to generate admin session secret: %v", err)
	}

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
		adminSession:  adminSession,
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
	mux.HandleFunc("/backend/auth", srv.handleAuth)
	mux.HandleFunc("/backend/traffic", srv.handleTraffic)
	mux.HandleFunc("/backend/config", srv.handleServerConfig)
	mux.HandleFunc("/backend/status", srv.handleServerStatus)

	// User-facing
	mux.HandleFunc("/user", srv.handleUser)
	mux.HandleFunc("/user/", srv.handleUser)

	// Admin
	mux.HandleFunc("/admin", srv.handleAdmin)
	mux.HandleFunc("/admin/", srv.handleAdmin)

	log.Printf("[INFO] admin dashboard: http://localhost%s/admin", *listenAddr)
	log.Printf("[INFO] central server listening on %s (db: %s)", *listenAddr, *dbPath)
	log.Fatal(http.ListenAndServe(*listenAddr, mux))
}
