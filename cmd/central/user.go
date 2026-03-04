package main

import (
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/http"
	"strings"
)

func (s *Server) setUserSession(w http.ResponseWriter, r *http.Request, token string) {
	writeSessionCookie(w, r, userSessionCookieName, token, 30*24*60*60)
}

func (s *Server) clearUserSession(w http.ResponseWriter, r *http.Request) {
	writeSessionCookie(w, r, userSessionCookieName, "", -1)
}

func (s *Server) resolveUserSession(r *http.Request) (userID, userToken string, ok bool) {
	c, err := r.Cookie(userSessionCookieName)
	if err != nil || strings.TrimSpace(c.Value) == "" {
		return "", "", false
	}
	userToken = strings.TrimSpace(c.Value)
	if err := s.db.QueryRow("SELECT id FROM users WHERE token = ?", userToken).Scan(&userID); err != nil {
		return "", "", false
	}
	return userID, userToken, true
}

func (s *Server) handleUserLoginSubmit(w http.ResponseWriter, r *http.Request) {
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
	token := strings.TrimSpace(body.Token)
	if token == "" {
		http.Error(w, "missing token", http.StatusBadRequest)
		return
	}
	var userID string
	if err := s.db.QueryRow("SELECT id FROM users WHERE token = ?", token).Scan(&userID); err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	s.setUserSession(w, r, token)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleUserLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.clearUserSession(w, r)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleUser(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/user", "/user/":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		userID, userToken, ok := s.resolveUserSession(r)
		if !ok {
			s.handleUserLogin(w, r, false)
			return
		}
		s.handleUserPage(w, r, userID, userToken)
		return

	case "/user/login":
		s.handleUserLoginSubmit(w, r)
		return

	case "/user/logout":
		s.handleUserLogout(w, r)
		return

	case "/user/sub/shadowrocket", "/user/sub/shadowrocket/":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		userID, userToken, ok := s.resolveUserSession(r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.handleSubShadowrocket(w, r, userID, userToken)
		return

	case "/user/sub/clash", "/user/sub/clash/":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		userID, userToken, ok := s.resolveUserSession(r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.handleSubClash(w, r, userID, userToken)
		return
	}

	if strings.HasPrefix(r.URL.Path, "/user/") {
		http.Error(w, "token-in-url access removed; use /user login", http.StatusGone)
		return
	}
	http.NotFound(w, r)
}

func (s *Server) queryUserServers(userID string) ([]userServerInfo, error) {
	rows, err := s.db.Query(`
		SELECT DISTINCT srv.id, srv.acme_domain, COALESCE(ss.ip, '')
		FROM servers srv
		LEFT JOIN server_status ss ON ss.server_id = srv.id
		WHERE (
		    EXISTS (SELECT 1 FROM server_users su WHERE su.server_id = srv.id AND su.user_id = ?)
		    OR EXISTS (
		      SELECT 1 FROM server_groups sg
		      JOIN group_users gu ON gu.group_name = sg.group_name
		      WHERE sg.server_id = srv.id AND gu.user_id = ?
		    )
		    OR EXISTS (SELECT 1 FROM group_users gu WHERE gu.group_name = 'all' AND gu.user_id = ?)
		)
		ORDER BY srv.id
	`, userID, userID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var servers []userServerInfo
	for rows.Next() {
		var si userServerInfo
		rows.Scan(&si.ID, &si.Domain, &si.IP)
		servers = append(servers, si)
	}
	return servers, nil
}

func (s *Server) isUserAssignedToServer(serverID, userID string) (bool, error) {
	var allowed int
	err := s.db.QueryRow(`
		SELECT CASE WHEN (
			EXISTS (SELECT 1 FROM server_users su WHERE su.server_id = ? AND su.user_id = ?)
			OR EXISTS (
				SELECT 1 FROM server_groups sg
				JOIN group_users gu ON gu.group_name = sg.group_name
				WHERE sg.server_id = ? AND gu.user_id = ?
			)
			OR EXISTS (SELECT 1 FROM group_users gu WHERE gu.group_name = 'all' AND gu.user_id = ?)
		) THEN 1 ELSE 0 END
	`, serverID, userID, serverID, userID, userID).Scan(&allowed)
	if err != nil {
		return false, err
	}
	return allowed == 1, nil
}

// GET /user/{id}/sub/shadowrocket/ — plain text subscription
func (s *Server) handleSubShadowrocket(w http.ResponseWriter, r *http.Request, userID string, userToken string) {
	var exists int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM users WHERE id = ?", userID).Scan(&exists); err != nil || exists == 0 {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	servers, err := s.queryUserServers(userID)
	if err != nil {
		log.Printf("[INFO] sub query error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	var lines []string
	for _, si := range servers {
		if si.IP == "" || si.Domain == "" {
			continue
		}
		lines = append(lines, fmt.Sprintf("hysteria2://%s@%s:443?peer=%s&obfs=none#%s", userToken, si.IP, si.Domain, si.ID))
	}

	log.Printf("[INFO] GET /user/%s/sub/shadowrocket/: %d servers", userID, len(lines))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, strings.Join(lines, "\n"))
}

// GET /user/sub/clash — Clash YAML subscription
func (s *Server) handleSubClash(w http.ResponseWriter, r *http.Request, userID string, userToken string) {
	var exists int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM users WHERE id = ?", userID).Scan(&exists); err != nil || exists == 0 {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	servers, err := s.queryUserServers(userID)
	if err != nil {
		log.Printf("[INFO] clash sub query error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	var proxies, names strings.Builder
	for i, si := range servers {
		if si.IP == "" || si.Domain == "" {
			continue
		}
		name := si.ID + "-hysteria2"
		if i > 0 {
			names.WriteString("\n")
		}
		names.WriteString("  - " + name)
		proxies.WriteString(fmt.Sprintf(`- name: %s
  type: hysteria2
  server: %s
  port: 443
  password: %s
`, name, si.Domain, userToken))
	}

	nameList := names.String()

	log.Printf("[INFO] GET /user/%s/sub/clash/: %d servers", userID, len(servers))
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	// Sanitize filename to prevent header injection: strip control chars, quotes, and backslashes.
	safeID := strings.Map(func(r rune) rune {
		if r < 0x20 || r == '"' || r == '\\' || r == '\x7f' {
			return '_'
		}
		return r
	}, userID)
	w.Header().Set("Content-Disposition", `attachment; filename="`+safeID+`.yaml"`)
	fmt.Fprintf(w, `port: 7890
allow-lan: true
mode: rule
log-level: info
unified-delay: true
global-client-fingerprint: chrome
dns:
  enable: true
  listen: :53
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  default-nameserver:
  - 1.1.1.1
  - 223.5.5.5
  - 114.114.114.114
  - 8.8.8.8
  nameserver:
  - https://dns.alidns.com/dns-query
  - https://doh.pub/dns-query
  fallback:
  - https://1.0.0.1/dns-query
  - tls://dns.google
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
    - 240.0.0.0/4

proxies:
%sproxy-groups:
- name: 负载均衡
  type: load-balance
  url: http://www.gstatic.com/generate_204
  interval: 300
  proxies:
%s
- name: 自动选择
  type: url-test
  url: http://www.gstatic.com/generate_204
  interval: 300
  tolerance: 50
  proxies:
%s
- name: 🌍选择代理
  type: select
  proxies:
  - 负载均衡
  - 自动选择
  - DIRECT
%s
rules:
- GEOIP,LAN,DIRECT
- GEOIP,CN,DIRECT
- MATCH,🌍选择代理
`, proxies.String(), nameList, nameList, nameList)
}

// GET /user/ — token login page
func (s *Server) handleUserLogin(w http.ResponseWriter, r *http.Request, invalid bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	errMsg := ""
	inputClass := ""
	if invalid {
		errMsg = "Invalid token. Please try again."
		inputClass = "err"
	}
	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hysteria</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f5f5f5; color: #333; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
  .card { background: #fff; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,0.08); padding: 40px 36px; max-width: 400px; width: 100%%; text-align: center; }
  h1 { font-size: 22px; color: #1a237e; margin-bottom: 6px; }
  .sub { color: #888; font-size: 13px; margin-bottom: 28px; }
  .input-wrap { position: relative; margin-bottom: 16px; }
  input[type="text"] { width: 100%%; padding: 14px 16px; border: 2px solid #e0e0e0; border-radius: 8px; font-size: 15px; font-family: monospace; letter-spacing: 1px; text-align: center; outline: none; transition: border-color 0.2s; }
  input[type="text"]:focus { border-color: #3949ab; }
  input[type="text"].err { border-color: #f44336; }
  .err-msg { color: #f44336; font-size: 13px; margin-bottom: 12px; min-height: 18px; }
  button { width: 100%%; padding: 13px; background: #3949ab; color: #fff; border: none; border-radius: 8px; font-size: 15px; font-weight: 500; cursor: pointer; transition: background 0.2s; }
  button:hover { background: #303f9f; }
</style>
</head>
<body>
<div class="card">
  <h1>Hysteria</h1>
  <p class="sub">Enter your access token to continue</p>
  <div class="err-msg" id="err">%s</div>
  <form onsubmit="go(event)">
    <div class="input-wrap">
      <input type="text" id="tok" placeholder="Your token" autocomplete="off" autofocus spellcheck="false" class="%s">
    </div>
    <button type="submit">Continue</button>
  </form>
</div>
<script>
function go(e) {
  e.preventDefault();
  var t = document.getElementById("tok").value.trim();
  if (!t) return;
  fetch("/user/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token: t })
  }).then(function(resp) {
    if (!resp.ok) throw new Error("invalid");
    window.location.href = "/user";
  }).catch(function() {
    document.getElementById("err").textContent = "Invalid token. Please try again.";
    var input = document.getElementById("tok");
    input.classList.add("err");
    input.focus();
  });
}
</script>
</body>
</html>`, errMsg, inputClass)
}

// GET /user — user overview HTML page
func (s *Server) handleUserPage(w http.ResponseWriter, r *http.Request, userID string, userToken string) {
	var quota int64
	var lastSeen string
	err := s.db.QueryRow("SELECT quota, COALESCE(last_seen, '') FROM users WHERE id = ?", userID).Scan(&quota, &lastSeen)
	if err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	var tx, rx int64
	s.db.QueryRow("SELECT COALESCE(tx, 0), COALESCE(rx, 0) FROM traffic WHERE user_id = ?", userID).Scan(&tx, &rx)

	servers, err := s.queryUserServers(userID)
	if err != nil {
		log.Printf("[INFO] user page query error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Build servers JSON for embedding.
	serversJSON, _ := json.Marshal(servers)

	subURL := s.baseURL + "/user/sub/shadowrocket"
	clashURL := s.baseURL + "/user/sub/clash"
	userIDHTML := html.EscapeString(userID)
	userTokenHTML := html.EscapeString(userToken)
	lastSeenJS, _ := json.Marshal(lastSeen)
	subURLJS, _ := json.Marshal(subURL)
	clashURLJS, _ := json.Marshal(clashURL)
	userTokenJS, _ := json.Marshal(userToken)

	total := tx + rx
	var pct float64
	if quota > 0 {
		pct = float64(total) / float64(quota) * 100
		if pct > 100 {
			pct = 100
		}
	}

	log.Printf("[INFO] GET /user: serving user page for %s", userID)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s — Hysteria</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f5f5f5; color: #333; padding: 24px; }
  .card { background: #fff; border-radius: 10px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); padding: 24px; max-width: 540px; margin: 0 auto; }
  h1 { font-size: 20px; margin-bottom: 20px; color: #1a237e; }
  .row { display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid #f0f0f0; font-size: 14px; }
  .row:last-child { border-bottom: none; }
  .label { color: #888; }
  .value { font-weight: 500; text-align: right; }
  .section { margin-top: 20px; }
  .section h2 { font-size: 15px; color: #555; margin-bottom: 10px; }
  .server { display: flex; justify-content: space-between; padding: 8px 12px; background: #f8f9fa; border-radius: 6px; margin-bottom: 6px; font-size: 13px; }
  .server .name { font-weight: 500; }
  .server .domain { color: #888; }
  .token-box { background: #f8f9fa; border: 1px dashed #ccc; border-radius: 8px; padding: 14px 16px; margin-bottom: 20px; text-align: center; cursor: pointer; transition: border-color 0.2s, background 0.2s; position: relative; }
  .token-box:hover { border-color: #3949ab; background: #f0f1fa; }
  .token-box.copied { border-color: #2e7d32; background: #e6f4ea; }
  .token-code { font-family: monospace; font-size: 18px; letter-spacing: 2px; color: #1a237e; font-weight: 600; }
  .token-hint { font-size: 11px; color: #999; margin-top: 6px; }
  .token-hint.copied { color: #2e7d32; }
  .sub-btn { display: block; width: 100%%; margin-top: 20px; padding: 12px; background: #3949ab; color: #fff; border: none; border-radius: 8px; font-size: 14px; font-weight: 500; cursor: pointer; text-align: center; }
  .sub-btn:hover { background: #303f9f; }
  .sub-btn.copied { background: #2e7d32; }
  .pct-bar { height: 6px; border-radius: 3px; background: #e0e0e0; margin-top: 4px; }
  .pct-fill { height: 100%%; border-radius: 3px; }
  .pct-green { background: #4caf50; }
  .pct-yellow { background: #ff9800; }
  .pct-red { background: #f44336; }
</style>
</head>
<body>
<div class="card">
  <h1>%s</h1>
  <div class="token-box" onclick="copyToken(this)">
    <div class="token-code">%s</div>
    <div class="token-hint" id="token-hint">This is your access token — click to copy. Bookmark this page or save the token.</div>
  </div>
  <div class="row"><span class="label">TX</span><span class="value" id="tx"></span></div>
  <div class="row"><span class="label">RX</span><span class="value" id="rx"></span></div>
  <div class="row"><span class="label">Total</span><span class="value" id="total"></span></div>
  <div class="row"><span class="label">Quota</span><span class="value" id="quota"></span></div>
  <div class="row" style="display:block">
    <div style="display:flex;justify-content:space-between"><span class="label">Used</span><span class="value" id="pct"></span></div>
    <div class="pct-bar"><div class="pct-fill" id="pct-fill"></div></div>
  </div>
  <div class="row"><span class="label">Last Seen</span><span class="value" id="last-seen"></span></div>

  <div class="section">
    <h2>Servers</h2>
    <div id="servers"></div>
  </div>

  <div style="display:flex;gap:10px;margin-top:20px">
    <button class="sub-btn" style="margin:0" onclick="copySub(this, subURL)">Copy Shadowrocket Subscription</button>
    <button class="sub-btn" style="margin:0;background:#5c6bc0" onclick="copySub(this, clashURL)">Copy Clash Subscription</button>
  </div>
</div>
<script>
var GiB = 1073741824;
var tx = %d, rx = %d, quota = %d;
var pct = %f;
var lastSeen = %s;
var servers = %s;
var subURL = %s;
var clashURL = %s;
var userToken = %s;

function escHtml(v) {
  return String(v === undefined || v === null ? "" : v)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function copyToken(box) {
  navigator.clipboard.writeText(userToken).then(function() {
    box.classList.add("copied");
    var hint = document.getElementById("token-hint");
    hint.textContent = "Copied!";
    hint.classList.add("copied");
    setTimeout(function() { box.classList.remove("copied"); hint.textContent = "This is your access token \u2014 click to copy. Bookmark this page or save the token."; hint.classList.remove("copied"); }, 2000);
  });
}

function fmtBytes(b) {
  if (b >= GiB) return (b / GiB).toFixed(2) + " GiB";
  if (b >= 1048576) return (b / 1048576).toFixed(1) + " MiB";
  if (b >= 1024) return (b / 1024).toFixed(0) + " KiB";
  return b + " B";
}
function fmtAgo(ts) {
  var d = (Date.now() - new Date(ts).getTime()) / 1000;
  if (d < 60) return Math.floor(d) + "s ago";
  if (d < 3600) return Math.floor(d/60) + "m ago";
  if (d < 86400) return Math.floor(d/3600) + "h ago";
  return Math.floor(d/86400) + "d ago";
}

document.getElementById("tx").textContent = fmtBytes(tx);
document.getElementById("rx").textContent = fmtBytes(rx);
document.getElementById("total").textContent = fmtBytes(tx + rx);
document.getElementById("quota").textContent = quota > 0 ? fmtBytes(quota) : "blocked";
document.getElementById("pct").textContent = quota > 0 ? pct.toFixed(1) + "%%" : "N/A";
var fill = document.getElementById("pct-fill");
fill.style.width = (quota > 0 ? pct : 0) + "%%";
fill.className = "pct-fill " + (pct < 70 ? "pct-green" : pct < 90 ? "pct-yellow" : "pct-red");
document.getElementById("last-seen").textContent = lastSeen ? new Date(lastSeen).toLocaleString() + " (" + fmtAgo(lastSeen) + ")" : "-";

var sh = document.getElementById("servers");
if (!servers || servers.length === 0) {
  sh.innerHTML = '<div class="server" style="color:#aaa">No servers assigned</div>';
} else {
  var h = "";
  for (var i = 0; i < servers.length; i++) {
    h += '<div class="server"><span class="name">' + escHtml(servers[i].id) + '</span><span class="domain">' + escHtml(servers[i].domain || "-") + '</span></div>';
  }
  sh.innerHTML = h;
}

function copySub(btn, url) {
  var orig = btn.textContent;
  navigator.clipboard.writeText(url).then(function() {
    btn.textContent = "Copied!";
    btn.classList.add("copied");
    setTimeout(function() { btn.textContent = orig; btn.classList.remove("copied"); }, 2000);
  });
}
</script>
</body>
</html>`, userIDHTML, userIDHTML, userTokenHTML, tx, rx, quota, pct, string(lastSeenJS), string(serversJSON), string(subURLJS), string(clashURLJS), string(userTokenJS))
}
