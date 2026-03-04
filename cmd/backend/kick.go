package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

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
