package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

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
	authList map[string]bool // set of allowed user IDs

	trafficMu    sync.Mutex
	trafficTable map[string]*TrafficStats // accumulated traffic per user

	proxyServer          string
	centralServerAuth    string
	centralServerTraffic string
	trafficServer        string
	secret   string
	serverID string
	debug    bool
}

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

func main() {
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), banner)
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", flag.CommandLine.Name())
		flag.PrintDefaults()
	}

	centralServerAuth := flag.String("central-server-auth", "", "URL to GET the authentication user list (e.g. http://10.0.0.1:8080/users)")
	centralServerTraffic := flag.String("central-server-traffic", "", "URL to POST accumulated traffic (e.g. http://10.0.0.1:8080/traffic)")
	proxyServer := flag.String("proxy-server", "127.0.0.1:9000", "Hysteria proxy API address (ip:port)")
	trafficServer := flag.String("traffic-server", "127.0.0.1:9000", "Hysteria traffic API address (ip:port)")
	secret := flag.String("secret", "abcdefg", "API secret for proxy/traffic server")
	serverID := flag.String("server-id", "", "Server ID sent to central server as path segment")
	listenAddr := flag.String("listen", ":8080", "Listen address for the local auth API")

	intervalAuth := flag.Duration("interval-auth", 10*time.Second, "Interval to refresh auth list from central server")
	intervalKick := flag.Duration("interval-kick", 10*time.Second, "Interval to check and kick unauthorized users")
	intervalTrafficFromProxy := flag.Duration("interval-traffic-from-proxy", 10*time.Second, "Interval to fetch traffic from proxy")
	intervalTrafficToCentral := flag.Duration("interval-traffic-to-central", 10*time.Second, "Interval to report traffic to central server")
	debug := flag.Bool("debug", false, "Enable debug logging (show response bodies for all requests)")

	flag.Parse()

	log.SetFlags(log.Ldate | log.Ltime)

	app := &App{
		authList:             make(map[string]bool),
		trafficTable:         make(map[string]*TrafficStats),
		proxyServer:          *proxyServer,
		centralServerAuth:    *centralServerAuth,
		centralServerTraffic: *centralServerTraffic,
		trafficServer:        *trafficServer,
		secret:               *secret,
		serverID: *serverID,
		debug:    *debug,
	}

	// Start periodic background tasks.
	go app.periodicAuthFetch(*intervalAuth)
	go app.periodicKickCheck(*intervalKick)
	go app.periodicTrafficFetch(*intervalTrafficFromProxy)
	go app.periodicTrafficReport(*intervalTrafficToCentral)

	// Start the local auth HTTP server.
	mux := http.NewServeMux()
	mux.HandleFunc("/", app.handleAuth)

	log.Printf("auth server listening on %s", *listenAddr)
	log.Fatal(http.ListenAndServe(*listenAddr, mux))
}

// ---------------------------------------------------------------------------
// 1. Periodic auth list fetch from central server
// ---------------------------------------------------------------------------

func (a *App) periodicAuthFetch(interval time.Duration) {
	if a.centralServerAuth == "" {
		log.Println("central-server-auth not set, skipping auth fetch")
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	a.fetchAuthList() // run once immediately
	for range ticker.C {
		a.fetchAuthList()
	}
}

func (a *App) centralURL(base string) string {
	return strings.TrimRight(base, "/") + "/" + a.serverID
}

func (a *App) fetchAuthList() {
	resp, err := http.Get(a.centralURL(a.centralServerAuth))
	if err != nil {
		log.Printf("auth fetch error: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("auth fetch: central server returned %d", resp.StatusCode)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("auth fetch: read body error: %v", err)
		return
	}

	var users []string
	if err := json.Unmarshal(body, &users); err != nil {
		log.Printf("auth fetch: json decode error: %v", err)
		return
	}

	newList := make(map[string]bool, len(users))
	for _, u := range users {
		newList[u] = true
	}

	a.authMu.Lock()
	a.authList = newList
	a.authMu.Unlock()

	log.Printf("auth list updated: %d users", len(newList))
	if a.debug {
		log.Printf("[DEBUG] auth list: %v", users)
	}
}

// ---------------------------------------------------------------------------
// 2. Periodic kick check against proxy server
// ---------------------------------------------------------------------------

func (a *App) periodicKickCheck(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		a.kickUnauthorized()
	}
}

func (a *App) kickUnauthorized() {
	// GET /online from proxy
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s/online", a.proxyServer), nil)
	req.Header.Set("Authorization", a.secret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("kick check: GET /online error: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			log.Printf("kick check: /online returned 401 Unauthorized. Make sure the -secret flag matches the trafficStats secret in the Hysteria server config.")
		} else {
			log.Printf("kick check: /online returned %d", resp.StatusCode)
		}
		return
	}

	var online map[string]int
	if err := json.NewDecoder(resp.Body).Decode(&online); err != nil {
		log.Printf("kick check: decode /online error: %v", err)
		return
	}

	if a.debug {
		log.Printf("[DEBUG] GET /online: %d users online: %v", len(online), online)
	}

	// Build list of users to kick.
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

	log.Printf("kicking %d unauthorized users: %v", len(toKick), toKick)

	// POST /kick to proxy
	body, _ := json.Marshal(toKick)
	kickReq, _ := http.NewRequest("POST", fmt.Sprintf("http://%s/kick", a.proxyServer), bytes.NewReader(body))
	kickReq.Header.Set("Authorization", a.secret)
	kickReq.Header.Set("Content-Type", "application/json")

	kickResp, err := http.DefaultClient.Do(kickReq)
	if err != nil {
		log.Printf("kick check: POST /kick error: %v", err)
		return
	}
	kickResp.Body.Close()

	if kickResp.StatusCode != http.StatusOK {
		log.Printf("kick check: /kick returned %d", kickResp.StatusCode)
	} else if a.debug {
		log.Printf("[DEBUG] POST /kick: successfully kicked %d users", len(toKick))
	}
}

// ---------------------------------------------------------------------------
// 4. Local auth API (Hysteria HTTP authentication backend)
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
// 5. Periodic traffic fetch from proxy/traffic server
// ---------------------------------------------------------------------------

func (a *App) periodicTrafficFetch(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		a.fetchTraffic()
	}
}

func (a *App) fetchTraffic() {
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s/traffic?clear=1", a.trafficServer), nil)
	req.Header.Set("Authorization", a.secret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("traffic fetch: error: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			log.Printf("traffic fetch: returned 401 Unauthorized. Make sure the -secret flag matches the trafficStats secret in the Hysteria server config.")
		} else {
			log.Printf("traffic fetch: returned %d", resp.StatusCode)
		}
		return
	}

	var stats map[string]*TrafficStats
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		log.Printf("traffic fetch: decode error: %v", err)
		return
	}

	if a.debug {
		log.Printf("[DEBUG] GET /traffic: %d users with traffic", len(stats))
		for user, s := range stats {
			log.Printf("[DEBUG]   %s: tx=%d rx=%d", user, s.TX, s.RX)
		}
	}

	// Accumulate into our traffic table.
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
// 6. Periodic traffic report to central server
// ---------------------------------------------------------------------------

func (a *App) periodicTrafficReport(interval time.Duration) {
	if a.centralServerTraffic == "" {
		log.Println("central-server-traffic not set, skipping traffic report")
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		a.reportTraffic()
	}
}

func (a *App) reportTraffic() {
	// Atomically swap the traffic table with a fresh one so concurrent
	// fetches (step 5) write into the new table while we send the old one.
	a.trafficMu.Lock()
	snapshot := a.trafficTable
	a.trafficTable = make(map[string]*TrafficStats)
	a.trafficMu.Unlock()

	if len(snapshot) == 0 {
		return
	}

	body, _ := json.Marshal(snapshot)
	resp, err := http.Post(a.centralURL(a.centralServerTraffic), "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("traffic report: POST error: %v", err)
		// Merge snapshot back so data is not lost.
		a.mergeTraffic(snapshot)
		return
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("traffic report: central returned %d, keeping data", resp.StatusCode)
		// Merge snapshot back so data is not lost.
		a.mergeTraffic(snapshot)
	} else if a.debug {
		log.Printf("[DEBUG] POST traffic report: sent %d users to central server", len(snapshot))
		for user, s := range snapshot {
			log.Printf("[DEBUG]   %s: tx=%d rx=%d", user, s.TX, s.RX)
		}
	}
}

// mergeTraffic adds a snapshot back into the live traffic table (used when
// the central server did not accept the report).
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
