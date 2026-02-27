package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
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

// ---------------------------------------------------------------------------
// Hysteria installation and management
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Config fetch from central
// ---------------------------------------------------------------------------

func fetchConfig(centralBase, serverID string, debug bool) (*ServerConfig, error) {
	url := centralBase + "/backend/config/" + serverID
	if debug {
		log.Printf("[DEBUG] config fetch: GET %s", url)
	}

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GET %s: status %d: %s", url, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var cfg ServerConfig
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	return &cfg, nil
}

func (a *App) periodicConfigFetch(interval time.Duration) {
	for {
		time.Sleep(interval)

		cfg, err := fetchConfig(a.centralServer, a.serverID, a.debug)
		if err != nil {
			log.Printf("[INFO] config fetch error: %v", err)
			continue
		}

		a.configMu.Lock()
		old := a.config
		a.config = *cfg
		a.lastConfigUpdate = time.Now()
		a.configMu.Unlock()

		// Check if Hysteria-relevant config changed (ACME settings).
		if old.AcmeDomain != cfg.AcmeDomain || old.AcmeEmail != cfg.AcmeEmail {
			log.Printf("[INFO] hysteria config changed, rewriting and restarting")
			if err := a.writeHysteriaConfig(); err != nil {
				log.Printf("[INFO] failed to write hysteria config: %v", err)
			} else if err := restartHysteria(); err != nil {
				log.Printf("[INFO] failed to restart hysteria: %v", err)
			}
		}

		if a.debug {
			log.Printf("[DEBUG] config updated: %+v", cfg)
		}
	}
}

// ---------------------------------------------------------------------------
// Startup with port-conflict retry
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Auth fetch from central
// ---------------------------------------------------------------------------

func (a *App) centralAuthURL() string {
	a.configMu.RLock()
	u := a.config.AuthURL
	a.configMu.RUnlock()
	if u == "" {
		u = a.centralServer + "/backend/auth"
	}
	return strings.TrimRight(u, "/") + "/" + a.serverID
}

func (a *App) centralTrafficURL() string {
	a.configMu.RLock()
	u := a.config.TrafficURL
	a.configMu.RUnlock()
	if u == "" {
		u = a.centralServer + "/backend/traffic"
	}
	return strings.TrimRight(u, "/") + "/" + a.serverID
}

func (a *App) periodicAuthFetch() {
	a.fetchAuthList()
	for {
		a.configMu.RLock()
		d, _ := time.ParseDuration(a.config.IntervalAuth)
		a.configMu.RUnlock()
		if d <= 0 {
			d = 10 * time.Second
		}
		time.Sleep(d)
		a.fetchAuthList()
	}
}

func (a *App) fetchAuthList() {
	url := a.centralAuthURL()
	if a.debug {
		log.Printf("[DEBUG] auth fetch: GET %s", url)
	}
	resp, err := http.Get(url)
	if err != nil {
		log.Printf("[INFO] auth fetch error: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[INFO] auth fetch: central server returned %d (url: %s)", resp.StatusCode, url)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[INFO] auth fetch: read body error: %v", err)
		return
	}

	var users []string
	if err := json.Unmarshal(body, &users); err != nil {
		log.Printf("[INFO] auth fetch: json decode error: %v", err)
		return
	}

	newList := make(map[string]bool, len(users))
	for _, u := range users {
		newList[u] = true
	}

	a.authMu.Lock()
	a.authList = newList
	a.authMu.Unlock()

	log.Printf("[INFO] auth list updated: %d users", len(newList))
	if a.debug {
		log.Printf("[DEBUG] auth list: %v", users)
	}
}

// ---------------------------------------------------------------------------
// Kick check
// ---------------------------------------------------------------------------

func (a *App) periodicKickCheck() {
	for {
		a.configMu.RLock()
		d, _ := time.ParseDuration(a.config.IntervalKick)
		a.configMu.RUnlock()
		if d <= 0 {
			d = 10 * time.Second
		}
		time.Sleep(d)
		a.kickUnauthorized()
	}
}

func (a *App) trafficServerAddr() string {
	return a.trafficStatsAddr
}

func (a *App) kickUnauthorized() {
	addr := a.trafficServerAddr()
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s/online", addr), nil)
	req.Header.Set("Authorization", a.secret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("[INFO] kick check: GET /online error: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			log.Printf("[INFO] kick check: /online returned 401 Unauthorized. Check that the secret matches the Hysteria trafficStats config.")
		} else {
			log.Printf("[INFO] kick check: /online returned %d", resp.StatusCode)
		}
		return
	}

	var online map[string]int
	if err := json.NewDecoder(resp.Body).Decode(&online); err != nil {
		log.Printf("[INFO] kick check: decode /online error: %v", err)
		return
	}

	log.Printf("[INFO] online: %d users", len(online))
	if a.debug {
		log.Printf("[DEBUG] GET /online: %v", online)
	}

	a.authMu.RLock()
	var toKick []string
	for user := range online {
		if !a.authList[user] {
			toKick = append(toKick, user)
		}
	}
	a.authMu.RUnlock()

	if len(toKick) == 0 {
		return
	}

	log.Printf("[INFO] kicking %d unauthorized users: %v", len(toKick), toKick)

	body, _ := json.Marshal(toKick)
	kickReq, _ := http.NewRequest("POST", fmt.Sprintf("http://%s/kick", addr), bytes.NewReader(body))
	kickReq.Header.Set("Authorization", a.secret)
	kickReq.Header.Set("Content-Type", "application/json")

	kickResp, err := http.DefaultClient.Do(kickReq)
	if err != nil {
		log.Printf("[INFO] kick check: POST /kick error: %v", err)
		return
	}
	kickResp.Body.Close()

	if kickResp.StatusCode != http.StatusOK {
		log.Printf("[INFO] kick check: /kick returned %d", kickResp.StatusCode)
	} else {
		log.Printf("[INFO] kicked %d unauthorized users: %v", len(toKick), toKick)
	}
}

// ---------------------------------------------------------------------------
// Local auth API (Hysteria HTTP authentication backend)
// ---------------------------------------------------------------------------

func (a *App) handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var authReq AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&authReq); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	a.authMu.RLock()
	allowed := a.authList[authReq.Auth]
	a.authMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")

	if allowed {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(AuthResponse{OK: true, ID: authReq.Auth})
		if a.debug {
			log.Printf("[DEBUG] auth request from %s: user=%s allowed=true", authReq.Addr, authReq.Auth)
		}
	} else {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(AuthResponse{OK: false})
		if a.debug {
			log.Printf("[DEBUG] auth request from %s: user=%s allowed=false", authReq.Addr, authReq.Auth)
		}
	}
}

// ---------------------------------------------------------------------------
// Traffic fetch from Hysteria
// ---------------------------------------------------------------------------

func (a *App) periodicTrafficFetch() {
	for {
		a.configMu.RLock()
		d, _ := time.ParseDuration(a.config.IntervalTrafficFromProxy)
		a.configMu.RUnlock()
		if d <= 0 {
			d = 10 * time.Second
		}
		time.Sleep(d)
		a.fetchTraffic()
	}
}

func (a *App) fetchTraffic() {
	addr := a.trafficServerAddr()
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s/traffic?clear=1", addr), nil)
	req.Header.Set("Authorization", a.secret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("[INFO] traffic fetch: error: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			log.Printf("[INFO] traffic fetch: returned 401 Unauthorized. Check that the secret matches the Hysteria trafficStats config.")
		} else {
			log.Printf("[INFO] traffic fetch: returned %d", resp.StatusCode)
		}
		return
	}

	var stats map[string]*TrafficStats
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		log.Printf("[INFO] traffic fetch: decode error: %v", err)
		return
	}

	if a.debug {
		log.Printf("[DEBUG] GET /traffic: %d users with traffic", len(stats))
		for user, s := range stats {
			log.Printf("[DEBUG]   %s: tx=%d rx=%d", user, s.TX, s.RX)
		}
	}

	a.trafficMu.Lock()
	for user, s := range stats {
		existing, ok := a.trafficTable[user]
		if !ok {
			a.trafficTable[user] = &TrafficStats{TX: s.TX, RX: s.RX}
		} else {
			existing.TX += s.TX
			existing.RX += s.RX
		}
	}
	a.trafficMu.Unlock()
}

// ---------------------------------------------------------------------------
// Traffic report to central
// ---------------------------------------------------------------------------

func (a *App) periodicTrafficReport() {
	for {
		a.configMu.RLock()
		d, _ := time.ParseDuration(a.config.IntervalTrafficToCentral)
		a.configMu.RUnlock()
		if d <= 0 {
			d = 10 * time.Second
		}
		time.Sleep(d)
		a.reportTraffic()
	}
}

func (a *App) reportTraffic() {
	a.trafficMu.Lock()
	snapshot := a.trafficTable
	a.trafficTable = make(map[string]*TrafficStats)
	a.trafficMu.Unlock()

	if len(snapshot) == 0 {
		return
	}

	// Only send users with non-zero traffic to minimize load.
	filtered := make(map[string]*TrafficStats, len(snapshot))
	for user, s := range snapshot {
		if s.TX > 0 || s.RX > 0 {
			filtered[user] = s
		}
	}
	if len(filtered) == 0 {
		return
	}
	snapshot = filtered

	url := a.centralTrafficURL()
	if a.debug {
		log.Printf("[DEBUG] traffic report: POST %s", url)
	}
	body, _ := json.Marshal(snapshot)
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("[INFO] traffic report: POST error: %v", err)
		a.mergeTraffic(snapshot)
		return
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[INFO] traffic report: central returned %d, keeping data", resp.StatusCode)
		a.mergeTraffic(snapshot)
	} else if a.debug {
		log.Printf("[DEBUG] POST traffic report: sent %d users to central server", len(snapshot))
		for user, s := range snapshot {
			log.Printf("[DEBUG]   %s: tx=%d rx=%d", user, s.TX, s.RX)
		}
	}
}

func (a *App) mergeTraffic(snapshot map[string]*TrafficStats) {
	a.trafficMu.Lock()
	defer a.trafficMu.Unlock()

	for user, s := range snapshot {
		existing, ok := a.trafficTable[user]
		if !ok {
			a.trafficTable[user] = &TrafficStats{TX: s.TX, RX: s.RX}
		} else {
			existing.TX += s.TX
			existing.RX += s.RX
		}
	}
}

// ---------------------------------------------------------------------------
// Status report to central
// ---------------------------------------------------------------------------

func (a *App) periodicStatusReport(interval time.Duration) {
	hysteriaVersion := getHysteriaVersion()
	for {
		time.Sleep(interval)
		a.reportStatus(hysteriaVersion)
	}
}

func (a *App) reportStatus(hysteriaVersion string) {
	a.configMu.RLock()
	lastCfg := a.lastConfigUpdate
	a.configMu.RUnlock()

	url := a.centralServer + "/backend/status/" + a.serverID
	body, _ := json.Marshal(map[string]interface{}{
		"status":             "active",
		"hysteria_version":   hysteriaVersion,
		"backend_version":    backendVersion,
		"last_config_update": lastCfg.UTC().Format(time.RFC3339),
		"uptime_seconds":     int64(time.Since(a.startTime).Seconds()),
	})

	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("[INFO] status report: POST error: %v", err)
		return
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[INFO] status report: central returned %d", resp.StatusCode)
	} else if a.debug {
		log.Printf("[DEBUG] status reported to central (uptime=%ds)", int64(time.Since(a.startTime).Seconds()))
	}
}
