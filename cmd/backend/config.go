package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

func fetchConfig(centralBase, serverID string, debug bool) (*ServerConfig, error) {
	url := centralBase + "/backend/config"
	if debug {
		log.Printf("[DEBUG] config fetch: GET %s", url)
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("new request %s: %w", url, err)
	}
	req.Header.Set("Authorization", "Bearer "+serverID)

	resp, err := http.DefaultClient.Do(req)
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

func (a *App) centralAuthURL() string {
	a.configMu.RLock()
	u := a.config.AuthURL
	a.configMu.RUnlock()
	if u == "" {
		u = a.centralServer + "/backend/auth"
	}
	return strings.TrimRight(u, "/")
}

func (a *App) centralTrafficURL() string {
	a.configMu.RLock()
	u := a.config.TrafficURL
	a.configMu.RUnlock()
	if u == "" {
		u = a.centralServer + "/backend/traffic"
	}
	return strings.TrimRight(u, "/")
}
