package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

const backendVersion = "2.0.0"

const banner = `
 _               _            _
| |_ _   _ ___| |_ ___ _ __(_) __ _
| __| | | / __| __/ _ \ '__| |/ _' |
| |_| |_| \__ \ ||  __/ |  | | (_| |
 \__|\__, |___/\__\___|_|  |_|\__,_|
     |___/
      _                _                  _
     | |__   __ _  ___| | _____ _ __   __| |
     | '_ \ / _' |/ __| |/ / _ \ '_ \ / _' |
     | |_) | (_| | (__|   <  __/ | | | (_| |
     |_.__/ \__,_|\___|_|\_\___|_| |_|\__,_|

  Hysteria proxy authentication & traffic manager
`

// ServerConfig mirrors the central server's config response.
type ServerConfig struct {
	ID                       string `json:"id"`
	AcmeDomain               string `json:"acme_domain"`
	AcmeEmail                string `json:"acme_email"`
	AuthURL                  string `json:"auth_url"`
	TrafficURL               string `json:"traffic_url"`
	IntervalAuth             string `json:"interval_auth"`
	IntervalKick             string `json:"interval_kick"`
	IntervalTrafficFromProxy string `json:"interval_traffic_from_proxy"`
	IntervalTrafficToCentral string `json:"interval_traffic_to_central"`
}

// TrafficStats holds tx/rx byte counts for a user.
type TrafficStats struct {
	TX int64 `json:"tx"`
	RX int64 `json:"rx"`
}

// AuthRequest is the POST body Hysteria sends when a client connects.
type AuthRequest struct {
	Addr string `json:"addr"`
	Auth string `json:"auth"`
	TX   int64  `json:"tx"`
}

// AuthResponse is what we return to Hysteria.
type AuthResponse struct {
	OK bool   `json:"ok"`
	ID string `json:"id,omitempty"`
}

// App holds all shared state.
type App struct {
	authMu   sync.RWMutex
	authList map[string]bool

	trafficMu    sync.Mutex
	trafficTable map[string]*TrafficStats

	configMu sync.RWMutex
	config   ServerConfig

	centralServer    string
	serverID         string
	secret           string
	listenAddr       string // backend auth HTTP listen address (127.0.0.1:4xxxx)
	trafficStatsAddr string // hysteria trafficStats listen address (127.0.0.1:4xxxx)
	debug            bool
	startTime        time.Time
	lastConfigUpdate time.Time
}

func generateSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("[FATAL] failed to generate secret: %v", err)
	}
	return hex.EncodeToString(b)
}

func randomAddr() string {
	b := make([]byte, 2)
	rand.Read(b)
	port := 40000 + int(uint16(b[0])<<8|uint16(b[1]))%10000
	return fmt.Sprintf("127.0.0.1:%d", port)
}

func main() {
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), banner)
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", flag.CommandLine.Name())
		flag.PrintDefaults()
	}

	serverID := flag.String("server-id", "", "Server token (required)")
	centralServer := flag.String("central-server", "", "Central server base URL (required, e.g. https://central.yundong.dev)")
	debug := flag.Bool("debug", false, "Enable debug logging")
	intervalConfigFromCentral := flag.Duration("interval-config-from-central", 10*time.Second, "Interval to fetch config from central server")

	flag.Parse()

	log.SetFlags(log.Ldate | log.Ltime)

	// Validate required flags.
	var missing []string
	if *serverID == "" {
		missing = append(missing, "  -server-id: Server token (from central admin dashboard)")
	}
	if *centralServer == "" {
		missing = append(missing, "  -central-server: Central server base URL (e.g. -central-server https://central.yundong.dev)")
	}
	if len(missing) > 0 {
		log.Fatalf("[FATAL] missing required flags:\n%s", strings.Join(missing, "\n"))
	}

	secret := generateSecret()
	log.Printf("[INFO] generated secret: %s...%s", secret[:8], secret[len(secret)-8:])

	listenAddr := randomAddr()
	trafficStatsAddr := randomAddr()
	log.Printf("[INFO] backend listen address: %s", listenAddr)
	log.Printf("[INFO] proxy stat API address: %s", trafficStatsAddr)

	// Check if Hysteria is installed; auto-install if not.
	ensureHysteriaInstalled(*debug)

	// Fetch initial config from central.
	centralBase := strings.TrimRight(*centralServer, "/")
	cfg, err := fetchConfig(centralBase, *serverID, *debug)
	if err != nil {
		log.Fatalf("[FATAL] failed to fetch initial config: %v", err)
	}
	log.Printf("[INFO] fetched initial config from central: acme_domain=%s", cfg.AcmeDomain)

	app := &App{
		authList:         make(map[string]bool),
		trafficTable:     make(map[string]*TrafficStats),
		config:           *cfg,
		centralServer:    centralBase,
		serverID:         *serverID,
		secret:           secret,
		listenAddr:       listenAddr,
		trafficStatsAddr: trafficStatsAddr,
		debug:            *debug,
		startTime:        time.Now(),
		lastConfigUpdate: time.Now(),
	}

	// Write Hysteria config and start the service (retry with new ports on conflict).
	app.startWithRetry()

	// Start background goroutines.
	go app.periodicConfigFetch(*intervalConfigFromCentral)
	go app.periodicAuthFetch()
	go app.periodicKickCheck()
	go app.periodicTrafficFetch()
	go app.periodicTrafficReport()
	go app.periodicStatusReport(*intervalConfigFromCentral)

	// Start the local auth HTTP server (retry with new port on conflict).
	app.startHTTPServerWithRetry()
}

// startWithRetry writes the Hysteria config and restarts the service, retrying with new ports on conflict.
func (a *App) startWithRetry() {
	for {
		if err := a.writeHysteriaConfig(); err != nil {
			log.Fatalf("[FATAL] failed to write hysteria config: %v", err)
		}
		err := restartHysteria()
		if err == nil {
			return
		}
		// Assume port conflict — pick a new trafficStats port and retry.
		a.trafficStatsAddr = randomAddr()
		log.Printf("[INFO] hysteria failed to start, retrying with new proxy stat API address: %s", a.trafficStatsAddr)
	}
}

func (a *App) startHTTPServerWithRetry() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", a.handleAuth)

	for {
		srv := &http.Server{Addr: a.listenAddr, Handler: mux}
		log.Printf("[INFO] backend listen address: %s", a.listenAddr)
		err := srv.ListenAndServe()
		if err == nil {
			return
		}
		// Assume port conflict — pick a new listen port and retry.
		a.listenAddr = randomAddr()
		log.Printf("[INFO] listen failed (%v), retrying with new address: %s", err, a.listenAddr)
		// Rewrite hysteria config so it points to the new auth port.
		if err := a.writeHysteriaConfig(); err != nil {
			log.Printf("[INFO] failed to rewrite hysteria config: %v", err)
		} else {
			restartHysteria()
		}
	}
}
