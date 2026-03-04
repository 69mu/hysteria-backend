package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"
)

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
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		log.Printf("[INFO] auth fetch: build request error: %v", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+a.serverID)

	resp, err := http.DefaultClient.Do(req)
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

// handleAuth is the local HTTP handler that Hysteria calls to authenticate clients.
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
