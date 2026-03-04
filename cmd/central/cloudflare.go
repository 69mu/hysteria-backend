package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

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
