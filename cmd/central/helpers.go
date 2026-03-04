package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
)

func randomHex(numBytes int) (string, error) {
	if numBytes <= 0 {
		return "", fmt.Errorf("invalid random length: %d", numBytes)
	}
	b := make([]byte, numBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// isValidIP checks that s is a well-formed IPv4 or IPv6 address.
// Used to prevent command injection via crafted IP values in SSH/rsync args.
func isValidIP(s string) bool {
	return net.ParseIP(s) != nil
}

// isSafeShellArg checks that a string is safe to embed as a systemd ExecStart
// argument (no shell metacharacters, newlines, or control characters).
func isSafeShellArg(s string) bool {
	for _, c := range s {
		if c < 0x20 || c == '\x7f' {
			return false // control characters / newlines
		}
		switch c {
		case '`', '$', '\\', '"', '\'', ';', '&', '|', '(', ')', '{', '}', '<', '>', '!', '#':
			return false
		}
	}
	return len(s) > 0
}

func isSecureRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	proto := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0])
	return strings.EqualFold(proto, "https")
}

func writeSessionCookie(w http.ResponseWriter, r *http.Request, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   isSecureRequest(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   maxAge,
	})
}

func readBearerToken(r *http.Request) string {
	if auth := strings.TrimSpace(r.Header.Get("Authorization")); auth != "" {
		const prefix = "bearer "
		if len(auth) >= len(prefix) && strings.EqualFold(auth[:len(prefix)], prefix) {
			return strings.TrimSpace(auth[len(prefix):])
		}
	}
	return strings.TrimSpace(r.Header.Get("X-Server-Token"))
}

// resolveServerToken looks up a server ID by its token. Returns "" if not found.
func (s *Server) resolveServerToken(token string) string {
	var id string
	err := s.db.QueryRow("SELECT id FROM servers WHERE token = ?", token).Scan(&id)
	if err != nil {
		return ""
	}
	return id
}
