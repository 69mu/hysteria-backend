package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

func (s *Server) setAdminSession(w http.ResponseWriter, r *http.Request) {
	writeSessionCookie(w, r, adminSessionCookieName, s.adminSession, 12*60*60)
}

func (s *Server) clearAdminSession(w http.ResponseWriter, r *http.Request) {
	writeSessionCookie(w, r, adminSessionCookieName, "", -1)
}

func (s *Server) isAdminAuthenticated(r *http.Request) bool {
	c, err := r.Cookie(adminSessionCookieName)
	if err != nil || c.Value == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(s.adminSession)) == 1
}

func (s *Server) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(body.Token)), []byte(s.adminToken)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	s.setAdminSession(w, r)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.clearAdminSession(w, r)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/admin/login":
		s.handleAdminLogin(w, r)
		return
	case "/admin/logout":
		s.handleAdminLogout(w, r)
		return
	case "/admin", "/admin/":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !s.isAdminAuthenticated(r) {
			s.handleAdminLoginPage(w, r)
			return
		}
		s.handleAdminPage(w, r)
		return
	}

	if !strings.HasPrefix(r.URL.Path, "/admin/api/") {
		http.NotFound(w, r)
		return
	}
	if !s.isAdminAuthenticated(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	rest := strings.TrimPrefix(r.URL.Path, "/admin/api/")
	switch {
	case rest == "overview":
		s.handleAdminOverview(w, r)
	case rest == "server-overview":
		s.handleAdminServerOverview(w, r)
	case rest == "traffic":
		s.handleAdminTrafficAll(w, r)
	case rest == "users":
		s.handleAdminUsers(w, r)
	case strings.HasPrefix(rest, "users/"):
		r.URL.Path = "/admin/users/" + strings.TrimPrefix(rest, "users/")
		s.handleAdminUser(w, r)
	case rest == "servers":
		r.URL.Path = "/admin/servers/"
		s.handleAdminServers(w, r)
	case strings.HasPrefix(rest, "servers/"):
		r.URL.Path = "/admin/servers/" + strings.TrimPrefix(rest, "servers/")
		s.handleAdminServers(w, r)
	case strings.HasPrefix(rest, "quota/"):
		r.URL.Path = "/admin/quota/" + strings.TrimPrefix(rest, "quota/")
		s.handleAdminQuota(w, r)
	case strings.HasPrefix(rest, "traffic/"):
		r.URL.Path = "/admin/traffic/" + strings.TrimPrefix(rest, "traffic/")
		s.handleAdminTrafficUser(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleAdminLoginPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, adminLoginPageHTML)
}

func (s *Server) handleAdminPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, adminPageHTML)
}
