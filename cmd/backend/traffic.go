package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

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
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		log.Printf("[INFO] traffic report: build request error: %v", err)
		a.mergeTraffic(snapshot)
		return
	}
	req.Header.Set("Authorization", "Bearer "+a.serverID)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
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
