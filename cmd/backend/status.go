package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

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

	url := a.centralServer + "/backend/status"
	body, _ := json.Marshal(map[string]interface{}{
		"status":             "active",
		"hysteria_version":   hysteriaVersion,
		"backend_version":    backendVersion,
		"last_config_update": lastCfg.UTC().Format(time.RFC3339),
		"uptime_seconds":     int64(time.Since(a.startTime).Seconds()),
	})

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		log.Printf("[INFO] status report: build request error: %v", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+a.serverID)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
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
