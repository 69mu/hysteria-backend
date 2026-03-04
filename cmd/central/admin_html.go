package main

const adminLoginPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hysteria Admin Login</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f5f5f5; color: #333; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
  .card { background: #fff; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,0.08); padding: 40px 36px; max-width: 420px; width: 100%; text-align: center; }
  h1 { font-size: 22px; color: #1a237e; margin-bottom: 6px; }
  .sub { color: #888; font-size: 13px; margin-bottom: 28px; }
  input[type="password"] { width: 100%; padding: 14px 16px; border: 2px solid #e0e0e0; border-radius: 8px; font-size: 15px; font-family: monospace; text-align: center; outline: none; transition: border-color 0.2s; margin-bottom: 12px; }
  input[type="password"]:focus { border-color: #3949ab; }
  .err { color: #f44336; font-size: 13px; min-height: 18px; margin-bottom: 12px; }
  button { width: 100%; padding: 13px; background: #3949ab; color: #fff; border: none; border-radius: 8px; font-size: 15px; font-weight: 500; cursor: pointer; transition: background 0.2s; }
  button:hover { background: #303f9f; }
</style>
</head>
<body>
<div class="card">
  <h1>Hysteria Admin</h1>
  <p class="sub">Enter your admin token</p>
  <div id="err" class="err"></div>
  <form onsubmit="login(event)">
    <input type="password" id="token" placeholder="Admin token" autocomplete="off" autofocus>
    <button type="submit">Sign In</button>
  </form>
</div>
<script>
function login(e) {
  e.preventDefault();
  var token = document.getElementById("token").value.trim();
  if (!token) return;
  fetch("/admin/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token: token })
  }).then(function(resp) {
    if (!resp.ok) throw new Error("invalid");
    window.location.href = "/admin";
  }).catch(function() {
    document.getElementById("err").textContent = "Invalid token.";
  });
}
</script>
</body>
</html>
`

const adminPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hysteria Admin</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f5f5f5; color: #333; padding: 24px; }
  h1 { font-size: 20px; margin-bottom: 4px; }
  .meta { color: #888; font-size: 13px; margin-bottom: 16px; }
  table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
  th, td { padding: 10px 14px; text-align: left; border-bottom: 1px solid #eee; font-size: 14px; }
  th { background: #fafafa; font-weight: 600; color: #555; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: #f9f9f9; }
  .num { text-align: right; font-variant-numeric: tabular-nums; }
  .pct { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }
  .pct-green { background: #e6f4ea; color: #1a7f37; }
  .pct-yellow { background: #fff8e1; color: #b08800; }
  .pct-red { background: #fce8e6; color: #c5221f; }
  .pct-gray { background: #f0f0f0; color: #888; }
  .servers { font-size: 12px; color: #666; }
  .server-tag { display: inline-block; background: #e8eaf6; color: #3949ab; padding: 2px 6px; border-radius: 3px; margin: 1px 2px; font-size: 11px; }
  .group-tag { display: inline-block; background: #e8f5e9; color: #2e7d32; padding: 2px 6px; border-radius: 3px; margin: 1px 2px; font-size: 11px; }
  .group-tag .remove { cursor: pointer; margin-left: 3px; opacity: 0.5; }
  .group-tag .remove:hover { opacity: 1; }
  .group-tag-default { display: inline-block; background: #e0f2f1; color: #00695c; padding: 2px 6px; border-radius: 3px; margin: 1px 2px; font-size: 11px; font-style: italic; }
  .tag-chip { display: inline-block; background: #e8f5e9; color: #2e7d32; padding: 2px 6px; border-radius: 3px; margin: 1px 2px; font-size: 11px; }
  .tag-chip .remove { cursor: pointer; margin-left: 3px; opacity: 0.5; }
  .tag-chip .remove:hover { opacity: 1; }
  .tag-suggestions { display: flex; gap: 4px; flex-wrap: wrap; margin-top: 4px; }
  .tag-suggestions button { padding: 2px 8px; border-radius: 3px; border: 1px solid #c8e6c9; background: #f1f8e9; cursor: pointer; font-size: 11px; color: #2e7d32; }
  .tag-suggestions button:hover { background: #c8e6c9; }
  .empty { text-align: center; padding: 40px; color: #999; }
  #error { color: #c5221f; margin-bottom: 12px; display: none; }
  .quota-actions { display: inline-flex; gap: 4px; margin-left: 6px; }
  .quota-actions button { border: none; cursor: pointer; padding: 2px 7px; border-radius: 3px; font-size: 11px; font-weight: 600; }
  .btn-set { background: #e8eaf6; color: #3949ab; }
  .btn-set:hover { background: #c5cae9; }
  .btn-add { background: #e6f4ea; color: #1a7f37; }
  .btn-add:hover { background: #c8e6c9; }
  .btn-del { background: #fce8e6; color: #c5221f; }
  .btn-del:hover { background: #f8d7da; }
  .btn-edit { background: #fff8e1; color: #b08800; }
  .btn-edit:hover { background: #fff3cd; }
  .server-tag .remove { cursor: pointer; margin-left: 3px; opacity: 0.5; }
  .server-tag .remove:hover { opacity: 1; }
  .btn-add-srv { display: inline-block; background: #fff; border: 1px dashed #bbb; color: #888; padding: 2px 6px; border-radius: 3px; margin: 1px 2px; font-size: 11px; cursor: pointer; }
  .btn-add-srv:hover { border-color: #3949ab; color: #3949ab; }
  .modal-bg { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.3); z-index: 100; justify-content: center; align-items: center; }
  .modal-bg.open { display: flex; }
  .modal { background: #fff; border-radius: 10px; padding: 24px; min-width: 320px; max-width: 480px; box-shadow: 0 8px 30px rgba(0,0,0,0.15); }
  .modal h2 { font-size: 16px; margin-bottom: 16px; }
  .modal label { display: block; font-size: 13px; color: #555; margin-bottom: 4px; }
  .modal input { width: 100%; padding: 8px 10px; border: 1px solid #ddd; border-radius: 5px; font-size: 14px; margin-bottom: 8px; }
  .modal input:focus { outline: none; border-color: #3949ab; }
  .modal .hint { font-size: 11px; color: #999; margin-bottom: 12px; }
  .modal .btns { display: flex; gap: 8px; justify-content: flex-end; margin-top: 16px; }
  .modal .btns button { padding: 7px 16px; border-radius: 5px; border: none; cursor: pointer; font-size: 13px; font-weight: 500; }
  .modal .btns .cancel { background: #f0f0f0; color: #555; }
  .modal .btns .cancel:hover { background: #e0e0e0; }
  .modal .btns .confirm { background: #3949ab; color: #fff; }
  .modal .btns .confirm:hover { background: #303f9f; }
  .modal .error { color: #c5221f; font-size: 12px; margin-top: 8px; display: none; }
  .presets { display: flex; gap: 6px; margin-bottom: 12px; flex-wrap: wrap; }
  .presets button { padding: 4px 10px; border-radius: 4px; border: 1px solid #ddd; background: #fff; cursor: pointer; font-size: 12px; color: #333; }
  .presets button:hover { background: #e8eaf6; border-color: #3949ab; }
  .tabs { display: flex; gap: 0; margin-bottom: 16px; border-bottom: 2px solid #e0e0e0; }
  .tab { padding: 8px 20px; cursor: pointer; font-size: 14px; font-weight: 500; color: #888; border-bottom: 2px solid transparent; margin-bottom: -2px; }
  .tab:hover { color: #333; }
  .tab.active { color: #3949ab; border-bottom-color: #3949ab; }
  .tab-content { display: none; }
  .tab-content.active { display: block; }
  .status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }
  .status-green { background: #1a7f37; }
  .status-yellow { background: #b08800; }
  .status-red { background: #c5221f; }
  .status-gray { background: #999; }
</style>
</head>
<body>
<h1>Hysteria Admin Dashboard</h1>

<div class="tabs">
  <div class="tab active" onclick="switchTab('users')">Users</div>
  <div class="tab" onclick="switchTab('servers')">Servers</div>
</div>

<!-- Users Tab -->
<div class="tab-content active" id="tab-users">
<div style="display:flex;align-items:center;gap:12px;margin-bottom:16px">
<div class="meta" id="status" style="margin:0">Loading...</div>
<button onclick="openAddUserModal()" style="padding:5px 14px;border-radius:5px;border:none;background:#3949ab;color:#fff;cursor:pointer;font-size:13px;font-weight:500">+ Add User</button>
</div>
<div id="error"></div>
<table>
<thead>
<tr>
  <th>User</th>
  <th>Token</th>
  <th class="num">TX</th>
  <th class="num">RX</th>
  <th class="num">Total</th>
  <th class="num">Quota</th>
  <th>Used</th>
  <th>Last Seen</th>
  <th>Servers</th>
  <th>Actions</th>
</tr>
</thead>
<tbody id="tbody"></tbody>
</table>
</div>

<!-- Servers Tab -->
<div class="tab-content" id="tab-servers">
<div style="display:flex;align-items:center;gap:12px;margin-bottom:16px">
<div class="meta" id="srv-status" style="margin:0">Loading...</div>
<button onclick="openAddSrvModal()" style="padding:5px 14px;border-radius:5px;border:none;background:#3949ab;color:#fff;cursor:pointer;font-size:13px;font-weight:500">+ Add Server</button>
</div>
<div id="srv-error" style="color:#c5221f;margin-bottom:12px;display:none"></div>
<table>
<thead>
<tr>
  <th>ID</th>
  <th>Token</th>
  <th>Domain</th>
  <th>IP</th>
  <th>Provision</th>
  <th>Status</th>
  <th>Hysteria</th>
  <th>Uptime</th>
  <th>Last Seen</th>
  <th class="num">TX</th>
  <th class="num">RX</th>
  <th class="num">Total</th>
  <th class="num">Users</th>
  <th>Groups</th>
  <th>Actions</th>
</tr>
</thead>
<tbody id="srv-tbody"></tbody>
</table>
</div>

<!-- Quota Modal -->
<div class="modal-bg" id="modal">
<div class="modal">
  <h2 id="modal-title">Set Quota</h2>
  <label id="modal-label">Quota (GiB)</label>
  <input type="number" id="modal-input" step="any" min="0" placeholder="e.g. 10">
  <div class="hint" id="modal-hint"></div>
  <div class="presets" id="modal-presets"></div>
  <div class="error" id="modal-error"></div>
  <div class="btns">
    <button class="cancel" onclick="closeModal()">Cancel</button>
    <button class="confirm" id="modal-confirm">Confirm</button>
  </div>
</div>
</div>

<!-- Add User Modal -->
<div class="modal-bg" id="add-user-modal">
<div class="modal">
  <h2>Add User</h2>
  <label>User ID</label>
  <input type="text" id="add-user-id" placeholder="e.g. alice">
  <label>Quota (GiB)</label>
  <input type="number" id="add-user-quota" step="any" min="0" placeholder="e.g. 10">
  <div class="hint">Quota 0 = blocked. Leave empty for 0.</div>
  <div class="presets" id="add-user-presets"></div>
  <div class="error" id="add-user-error"></div>
  <div class="btns">
    <button class="cancel" onclick="closeAddUserModal()">Cancel</button>
    <button class="confirm" id="add-user-confirm">Add</button>
  </div>
</div>
</div>

<!-- Assign Server/Group to User Modal -->
<div class="modal-bg" id="add-server-modal">
<div class="modal">
  <h2 id="add-server-title">Assign Server or Group</h2>
  <div style="margin-bottom:8px">
    <label style="display:inline;margin-right:12px"><input type="radio" name="assign-type" value="server" checked onchange="updateAssignHint()"> Server</label>
    <label style="display:inline"><input type="radio" name="assign-type" value="group" onchange="updateAssignHint()"> Group</label>
  </div>
  <label id="assign-label">Server ID</label>
  <input type="text" id="add-server-id" placeholder="e.g. srv1">
  <div class="hint" id="assign-hint">Enter the server_id to assign this user to.</div>
  <div class="error" id="add-server-error"></div>
  <div class="btns">
    <button class="cancel" onclick="closeAddServerModal()">Cancel</button>
    <button class="confirm" id="add-server-confirm">Assign</button>
  </div>
</div>
</div>

<!-- Add/Edit Server Modal -->
<div class="modal-bg" id="srv-modal">
<div class="modal" style="min-width:400px">
  <h2 id="srv-modal-title">Add Server</h2>
  <label>Server ID</label>
  <input type="text" id="srv-m-id" placeholder="auto-generated if empty">
  <label>ACME Domain</label>
  <input type="text" id="srv-m-domain" placeholder="default: p1.yundong.dev">
  <label>ACME Email</label>
  <input type="text" id="srv-m-email" placeholder="default: admin@yundong.dev">
  <label>Region</label>
  <input type="text" id="srv-m-region" placeholder="default: sfo3">
  <label>Size</label>
  <input type="text" id="srv-m-size" placeholder="default: s-1vcpu-1gb">
  <label>Auth URL</label>
  <input type="text" id="srv-m-auth-url" placeholder="default: {base-url}/backend/auth">
  <label>Traffic URL</label>
  <input type="text" id="srv-m-traffic-url" placeholder="default: {base-url}/backend/traffic">
  <label>Groups</label>
  <div id="srv-m-groups-chips" style="margin-bottom:4px"></div>
  <div id="srv-m-groups-suggest" class="tag-suggestions" style="margin-bottom:4px"></div>
  <div style="display:flex;gap:4px;margin-bottom:8px">
    <input type="text" id="srv-m-group-input" placeholder="custom group name" style="flex:1;margin-bottom:0">
    <button type="button" onclick="addSrvModalGroup(document.getElementById('srv-m-group-input').value.trim())" style="padding:4px 10px;border-radius:5px;border:1px solid #c8e6c9;background:#e8f5e9;color:#2e7d32;cursor:pointer;font-size:12px">Add</button>
  </div>
  <div class="error" id="srv-m-error"></div>
  <div class="btns">
    <button class="cancel" onclick="closeSrvModal()">Cancel</button>
    <button class="confirm" id="srv-m-confirm">Save</button>
  </div>
</div>
</div>

<!-- Add Group to Server Modal -->
<div class="modal-bg" id="add-group-modal">
<div class="modal">
  <h2 id="add-group-title">Add Group to Server</h2>
  <label>Group Name</label>
  <input type="text" id="add-group-name" placeholder="e.g. us-east">
  <div class="hint">Enter a group name. Users assigned to this group will be authorized on this server.</div>
  <div class="error" id="add-group-error"></div>
  <div class="btns">
    <button class="cancel" onclick="closeAddGroupModal()">Cancel</button>
    <button class="confirm" id="add-group-confirm">Add</button>
  </div>
</div>
</div>

<script>
var GiB = 1073741824;
var A = "/admin/api";
var modalState = {};
var currentTab = "users";
var userDataCache = [];

function escHtml(v) {
  return String(v === undefined || v === null ? "" : v)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function switchTab(tab) {
  currentTab = tab;
  document.querySelectorAll(".tab").forEach(function(t) { t.classList.remove("active"); });
  document.querySelectorAll(".tab-content").forEach(function(t) { t.classList.remove("active"); });
  document.querySelector('.tab[onclick="switchTab(\'' + tab + '\')"]').classList.add("active");
  document.getElementById("tab-" + tab).classList.add("active");
  if (tab === "servers") loadServers();
  else load();
}

// ---- Users Tab ----
function openAddUserModal() {
  document.getElementById("add-user-id").value = "";
  document.getElementById("add-user-quota").value = "";
  document.getElementById("add-user-error").style.display = "none";
  var presets = document.getElementById("add-user-presets");
  presets.innerHTML = "";
  [1, 5, 10, 50, 100, 500].forEach(function(g) {
    var btn = document.createElement("button");
    btn.textContent = g + " GiB";
    btn.onclick = function() { document.getElementById("add-user-quota").value = g; };
    presets.appendChild(btn);
  });
  document.getElementById("add-user-modal").classList.add("open");
  document.getElementById("add-user-id").focus();
}
function closeAddUserModal() {
  document.getElementById("add-user-modal").classList.remove("open");
}
document.getElementById("add-user-modal").addEventListener("click", function(e) {
  if (e.target === this) closeAddUserModal();
});
document.getElementById("add-user-confirm").addEventListener("click", function() {
  var uid = document.getElementById("add-user-id").value.trim();
  var errEl = document.getElementById("add-user-error");
  if (!uid) { errEl.textContent = "User ID is required."; errEl.style.display = "block"; return; }
  var qVal = document.getElementById("add-user-quota").value;
  var quota = qVal ? Math.round(parseFloat(qVal) * GiB) : 0;
  if (isNaN(quota) || quota < 0) { errEl.textContent = "Invalid quota."; errEl.style.display = "block"; return; }
  fetch(A + "/users", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({id: uid, quota: quota})
  }).then(function(r) {
    if (!r.ok) throw new Error("HTTP " + r.status);
    closeAddUserModal();
    load();
  }).catch(function(e) {
    errEl.textContent = "Failed: " + e.message;
    errEl.style.display = "block";
  });
});

function deleteUser(uid) {
  if (!confirm("Delete user \"" + uid + "\"? This removes all their server assignments and traffic data.")) return;
  fetch(A + "/users/" + encodeURIComponent(uid), { method: "DELETE" })
    .then(function(r) { if (!r.ok) throw new Error("HTTP " + r.status); load(); })
    .catch(function(e) { alert("Failed to delete: " + e.message); });
}
function removeServer(uid, sid) {
  if (!confirm("Remove " + uid + " from server " + sid + "?")) return;
  fetch(A + "/servers/" + encodeURIComponent(sid) + "/users/" + encodeURIComponent(uid), { method: "DELETE" })
    .then(function(r) { if (!r.ok) throw new Error("HTTP " + r.status); load(); })
    .catch(function(e) { alert("Failed: " + e.message); });
}
function removeGroup(uid, gname) {
  if (!confirm("Remove " + uid + " from group " + gname + "?")) return;
  fetch(A + "/users/" + encodeURIComponent(uid) + "/groups/" + encodeURIComponent(gname), { method: "DELETE" })
    .then(function(r) { if (!r.ok) throw new Error("HTTP " + r.status); load(); })
    .catch(function(e) { alert("Failed: " + e.message); });
}

function deleteUserByIdx(i) {
  var u = userDataCache[i];
  if (!u) return;
  deleteUser(u.id);
}
function removeServerByIdx(i, j) {
  var u = userDataCache[i];
  if (!u || !u.servers || u.servers[j] === undefined) return;
  removeServer(u.id, u.servers[j]);
}
function removeGroupByIdx(i, j) {
  var u = userDataCache[i];
  if (!u || !u.groups || u.groups[j] === undefined) return;
  removeGroup(u.id, u.groups[j]);
}
function openAddServerModalByIdx(i) {
  var u = userDataCache[i];
  if (!u) return;
  openAddServerModal(u.id);
}
function openSetModalByIdx(i) {
  var u = userDataCache[i];
  if (!u) return;
  openSetModal(u.id, u.quota);
}
function openAddModalByIdx(i) {
  var u = userDataCache[i];
  if (!u) return;
  openAddModal(u.id, u.quota);
}
function updateAssignHint() {
  var isGroup = document.querySelector('input[name="assign-type"]:checked').value === "group";
  document.getElementById("assign-label").textContent = isGroup ? "Group Name" : "Server ID";
  document.getElementById("add-server-id").placeholder = isGroup ? "e.g. all, us-east" : "e.g. srv1";
  document.getElementById("assign-hint").textContent = isGroup ? "Enter a group name. \"all\" matches every server." : "Enter the server_id to assign this user to.";
}
var addServerUid = "";
function openAddServerModal(uid) {
  addServerUid = uid;
  document.getElementById("add-server-title").textContent = "Assign to " + uid;
  document.getElementById("add-server-id").value = "";
  document.querySelector('input[name="assign-type"][value="server"]').checked = true;
  updateAssignHint();
  document.getElementById("add-server-error").style.display = "none";
  document.getElementById("add-server-modal").classList.add("open");
  document.getElementById("add-server-id").focus();
}
function closeAddServerModal() {
  document.getElementById("add-server-modal").classList.remove("open");
}
document.getElementById("add-server-modal").addEventListener("click", function(e) {
  if (e.target === this) closeAddServerModal();
});
document.getElementById("add-server-confirm").addEventListener("click", function() {
  var val = document.getElementById("add-server-id").value.trim();
  var errEl = document.getElementById("add-server-error");
  if (!val) { errEl.textContent = "Value is required."; errEl.style.display = "block"; return; }
  var isGroup = document.querySelector('input[name="assign-type"]:checked').value === "group";
  var url, body;
  if (isGroup) {
    url = A + "/users/" + encodeURIComponent(addServerUid) + "/groups";
    body = JSON.stringify({group: val});
  } else {
    url = A + "/servers/" + encodeURIComponent(val) + "/users";
    body = JSON.stringify({id: addServerUid});
  }
  fetch(url, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: body
  }).then(function(r) {
    if (!r.ok) throw new Error("HTTP " + r.status);
    closeAddServerModal();
    load();
  }).catch(function(e) {
    errEl.textContent = "Failed: " + e.message;
    errEl.style.display = "block";
  });
});

function fmt(b) {
  if (b === 0) return "0 B";
  var units = ["B","KiB","MiB","GiB","TiB"];
  var i = Math.min(Math.floor(Math.log(b) / Math.log(1024)), units.length - 1);
  var v = b / Math.pow(1024, i);
  return v.toFixed(i === 0 ? 0 : 1) + " " + units[i];
}
function pctClass(p, quota) {
  if (quota === 0) return "pct-gray";
  if (p >= 90) return "pct-red";
  if (p >= 70) return "pct-yellow";
  return "pct-green";
}

function openSetModal(uid, currentQuota) {
  modalState = { uid: uid, mode: "set" };
  document.getElementById("modal-title").textContent = "Set Quota for " + uid;
  document.getElementById("modal-label").textContent = "New quota (GiB)";
  document.getElementById("modal-input").value = currentQuota > 0 ? (currentQuota / GiB).toFixed(2) : "";
  document.getElementById("modal-input").placeholder = "e.g. 10";
  document.getElementById("modal-hint").textContent = "Current: " + fmt(currentQuota) + ". Set to 0 to block.";
  document.getElementById("modal-error").style.display = "none";
  var presets = document.getElementById("modal-presets");
  presets.innerHTML = "";
  [1, 5, 10, 50, 100, 500].forEach(function(g) {
    var btn = document.createElement("button");
    btn.textContent = g + " GiB";
    btn.onclick = function() { document.getElementById("modal-input").value = g; };
    presets.appendChild(btn);
  });
  document.getElementById("modal").classList.add("open");
  document.getElementById("modal-input").focus();
}

function openAddModal(uid, currentQuota) {
  modalState = { uid: uid, mode: "add" };
  document.getElementById("modal-title").textContent = "Add Quota for " + uid;
  document.getElementById("modal-label").textContent = "Amount to add (GiB)";
  document.getElementById("modal-input").value = "";
  document.getElementById("modal-input").placeholder = "e.g. 10";
  document.getElementById("modal-hint").textContent = "Current: " + fmt(currentQuota) + ". Use negative to subtract.";
  document.getElementById("modal-error").style.display = "none";
  var presets = document.getElementById("modal-presets");
  presets.innerHTML = "";
  [1, 5, 10, 50, 100].forEach(function(g) {
    var btn = document.createElement("button");
    btn.textContent = "+" + g + " GiB";
    btn.onclick = function() { document.getElementById("modal-input").value = g; };
    presets.appendChild(btn);
  });
  document.getElementById("modal").classList.add("open");
  document.getElementById("modal-input").focus();
}

function closeModal() {
  document.getElementById("modal").classList.remove("open");
}

document.getElementById("modal").addEventListener("click", function(e) {
  if (e.target === this) closeModal();
});

document.getElementById("modal-confirm").addEventListener("click", function() {
  var val = parseFloat(document.getElementById("modal-input").value);
  var errEl = document.getElementById("modal-error");
  if (isNaN(val)) {
    errEl.textContent = "Please enter a valid number.";
    errEl.style.display = "block";
    return;
  }
  var bytes = Math.round(val * GiB);
  if (modalState.mode === "set") {
    if (bytes < 0) { errEl.textContent = "Quota cannot be negative."; errEl.style.display = "block"; return; }
    fetch(A + "/quota/" + encodeURIComponent(modalState.uid), {
      method: "PUT",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({quota: bytes})
    }).then(function(r) {
      if (!r.ok) throw new Error("HTTP " + r.status);
      closeModal();
      load();
    }).catch(function(e) {
      errEl.textContent = "Failed: " + e.message;
      errEl.style.display = "block";
    });
  } else {
    if (bytes === 0) { errEl.textContent = "Delta cannot be zero."; errEl.style.display = "block"; return; }
    fetch(A + "/quota/" + encodeURIComponent(modalState.uid), {
      method: "PATCH",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({delta: bytes})
    }).then(function(r) {
      if (!r.ok) throw new Error("HTTP " + r.status);
      closeModal();
      load();
    }).catch(function(e) {
      errEl.textContent = "Failed: " + e.message;
      errEl.style.display = "block";
    });
  }
});

function render(users) {
  userDataCache = users || [];
  var tb = document.getElementById("tbody");
  if (!users || users.length === 0) {
    tb.innerHTML = '<tr><td colspan="10" class="empty">No users found</td></tr>';
    return;
  }
  var html = "";
  for (var i = 0; i < users.length; i++) {
    var u = users[i];
    var total = u.tx + u.rx;
    var pct = u.quota > 0 ? Math.min((total / u.quota) * 100, 100) : 0;
    var pctText = u.quota > 0 ? pct.toFixed(1) + "%" : "blocked";
    var servers = "";
    for (var j = 0; j < u.servers.length; j++) {
      servers += '<span class="server-tag">' + escHtml(u.servers[j]) + '<span class="remove" onclick="removeServerByIdx(' + i + ',' + j + ')">&times;</span></span>';
    }
    if (u.groups) {
      for (var g = 0; g < u.groups.length; g++) {
        servers += '<span class="group-tag">' + escHtml(u.groups[g]) + '<span class="remove" onclick="removeGroupByIdx(' + i + ',' + g + ')">&times;</span></span>';
      }
    }
    servers += '<span class="btn-add-srv" onclick="openAddServerModalByIdx(' + i + ')">+</span>';
    html += "<tr>"
      + '<td><strong>' + escHtml(u.id) + '</strong></td>'
      + '<td style="font-family:monospace;font-size:12px;color:#666">' + escHtml(u.token) + '</td>'
      + '<td class="num">' + fmt(u.tx) + "</td>"
      + '<td class="num">' + fmt(u.rx) + "</td>"
      + '<td class="num">' + fmt(total) + "</td>"
      + '<td class="num">' + (u.quota > 0 ? fmt(u.quota) : '<span style="color:#ccc">0</span>') + "</td>"
      + '<td><span class="pct ' + pctClass(pct, u.quota) + '">' + pctText + "</span></td>"
      + "<td>" + (u.last_seen ? new Date(u.last_seen).toLocaleTimeString() + ' <span style="color:#888;font-size:11px">(' + fmtAgo(u.last_seen) + ')</span>' : "-") + "</td>"
      + '<td class="servers">' + servers + "</td>"
      + '<td class="quota-actions">'
      + '<button class="btn-set" onclick="openSetModalByIdx(' + i + ')">Set</button>'
      + '<button class="btn-add" onclick="openAddModalByIdx(' + i + ')">+ Add</button>'
      + '<button class="btn-del" onclick="deleteUserByIdx(' + i + ')">Del</button>'
      + "</td>"
      + "</tr>";
  }
  tb.innerHTML = html;
}
function load() {
  fetch(A + "/overview")
    .then(function(r) { if (!r.ok) throw new Error(r.status); return r.json(); })
    .then(function(data) {
      render(data);
      document.getElementById("status").textContent = data.length + " users \u00b7 updated " + new Date().toLocaleTimeString();
      document.getElementById("error").style.display = "none";
    })
    .catch(function(e) {
      document.getElementById("error").textContent = "Failed to load: " + e.message;
      document.getElementById("error").style.display = "block";
    });
}

// ---- Servers Tab ----
var adjectives = ["alpine","amber","ancient","arctic","autumn","blazing","bold","brave","bright","calm","cedar","clever","cobalt","coral","cosmic","crimson","crystal","dancing","dark","dawn","deep","dusty","eager","echo","electric","emerald","fading","fern","fierce","floral","foggy","frozen","gentle","gilded","glacial","golden","granite","hollow","humble","icy","iron","ivory","jade","jasper","keen","lemon","light","lime","lofty","lunar","marble","meadow","misty","mossy","noble","oak","obsidian","olive","opal","pale","pearl","pine","polar","proud","quiet","rapid","raven","rocky","rosy","royal","ruby","rustic","sage","sandy","scarlet","shadow","sharp","silent","silver","slate","snowy","solar","spicy","steady","stone","stormy","sunny","swift","teal","thorn","timber","topaz","twin","velvet","violet","vivid","warm","wild","windy","winter","witty","zen"];
var nouns = ["badger","bear","bison","brook","canyon","cedar","cliff","cloud","condor","coral","crane","creek","crow","dawn","deer","delta","dove","dusk","eagle","elk","falcon","fern","finch","flame","flora","forge","fox","frost","grove","hawk","haze","heron","hill","horse","island","jade","jay","lake","lark","leaf","lion","lotus","lynx","maple","marsh","mesa","mist","moon","moose","nest","oak","ocean","orchid","osprey","otter","owl","palm","panther","peak","pebble","pine","pond","quail","rain","raven","reef","ridge","river","robin","sage","seal","shore","sky","snow","sparrow","spring","spruce","star","stone","storm","stream","summit","swan","thorn","tide","trail","trout","tulip","vale","wave","whale","willow","wolf","wren"];
function generateServerId() {
  var a = adjectives[Math.floor(Math.random() * adjectives.length)];
  var n = nouns[Math.floor(Math.random() * nouns.length)];
  return a + "-" + n;
}
var srvEditId = "";
var srvModalGroups = [];
var srvModalOrigGroups = [];
var srvModalSuggestGroups = [];

function collectExistingGroups() {
  var gs = {};
  for (var i = 0; i < srvDataCache.length; i++) {
    if (srvDataCache[i].groups) {
      for (var j = 0; j < srvDataCache[i].groups.length; j++) {
        gs[srvDataCache[i].groups[j]] = true;
      }
    }
  }
  return Object.keys(gs).sort();
}

function renderSrvModalGroups() {
  var chips = document.getElementById("srv-m-groups-chips");
  var html = '<span class="group-tag-default">all</span>';
  for (var i = 0; i < srvModalGroups.length; i++) {
    html += '<span class="tag-chip">' + escHtml(srvModalGroups[i]) + '<span class="remove" onclick="removeSrvModalGroupByIdx(' + i + ')">&times;</span></span>';
  }
  chips.innerHTML = html;
  var suggest = document.getElementById("srv-m-groups-suggest");
  var existing = collectExistingGroups();
  var shtml = "";
  srvModalSuggestGroups = [];
  for (var i = 0; i < existing.length; i++) {
    if (srvModalGroups.indexOf(existing[i]) === -1) {
      srvModalSuggestGroups.push(existing[i]);
      shtml += '<button type="button" onclick="addSrvModalSuggested(' + (srvModalSuggestGroups.length - 1) + ')">' + escHtml(existing[i]) + '</button>';
    }
  }
  suggest.innerHTML = shtml;
}

function removeSrvModalGroupByIdx(i) {
  if (i < 0 || i >= srvModalGroups.length) return;
  removeSrvModalGroup(srvModalGroups[i]);
}

function addSrvModalSuggested(i) {
  if (i < 0 || i >= srvModalSuggestGroups.length) return;
  addSrvModalGroup(srvModalSuggestGroups[i]);
}

function addSrvModalGroup(name) {
  if (!name || name === "all") return;
  if (srvModalGroups.indexOf(name) !== -1) return;
  srvModalGroups.push(name);
  document.getElementById("srv-m-group-input").value = "";
  renderSrvModalGroups();
}

function removeSrvModalGroup(name) {
  srvModalGroups = srvModalGroups.filter(function(g) { return g !== name; });
  renderSrvModalGroups();
}

function openAddSrvModal() {
  srvEditId = "";
  document.getElementById("srv-modal-title").textContent = "Add Server";
  document.getElementById("srv-m-id").value = generateServerId();
  document.getElementById("srv-m-id").disabled = false;
  document.getElementById("srv-m-domain").value = "";
  document.getElementById("srv-m-email").value = "";
  document.getElementById("srv-m-region").value = "";
  document.getElementById("srv-m-size").value = "";
  document.getElementById("srv-m-auth-url").value = "";
  document.getElementById("srv-m-traffic-url").value = "";
  document.getElementById("srv-m-error").style.display = "none";
  srvModalGroups = [];
  srvModalOrigGroups = [];
  renderSrvModalGroups();
  document.getElementById("srv-modal").classList.add("open");
  document.getElementById("srv-m-id").focus();
}
function openEditSrvModal(srv) {
  srvEditId = srv.id;
  document.getElementById("srv-modal-title").textContent = "Edit Server: " + srv.id;
  document.getElementById("srv-m-id").value = srv.id;
  document.getElementById("srv-m-id").disabled = true;
  document.getElementById("srv-m-domain").value = srv.acme_domain || "";
  document.getElementById("srv-m-email").value = srv.acme_email || "";
  document.getElementById("srv-m-region").value = srv.region || "";
  document.getElementById("srv-m-size").value = srv.size || "";
  document.getElementById("srv-m-auth-url").value = srv.auth_url || "";
  document.getElementById("srv-m-traffic-url").value = srv.traffic_url || "";
  document.getElementById("srv-m-error").style.display = "none";
  srvModalGroups = (srv.groups || []).slice();
  srvModalOrigGroups = (srv.groups || []).slice();
  renderSrvModalGroups();
  document.getElementById("srv-modal").classList.add("open");
  document.getElementById("srv-m-domain").focus();
}
function closeSrvModal() {
  document.getElementById("srv-modal").classList.remove("open");
}
document.getElementById("srv-modal").addEventListener("click", function(e) {
  if (e.target === this) closeSrvModal();
});
document.getElementById("srv-m-confirm").addEventListener("click", function() {
  var errEl = document.getElementById("srv-m-error");
  var id = document.getElementById("srv-m-id").value.trim() || generateServerId();
  var body = {
    id: id,
    acme_domain: document.getElementById("srv-m-domain").value.trim(),
    acme_email: document.getElementById("srv-m-email").value.trim(),
    region: document.getElementById("srv-m-region").value.trim(),
    size: document.getElementById("srv-m-size").value.trim(),
    auth_url: document.getElementById("srv-m-auth-url").value.trim(),
    traffic_url: document.getElementById("srv-m-traffic-url").value.trim()
  };
  var method, url;
  if (srvEditId) {
    method = "PUT";
    url = A + "/servers/" + encodeURIComponent(srvEditId);
  } else {
    method = "POST";
    url = A + "/servers/";
  }
  fetch(url, {
    method: method,
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(body)
  }).then(function(r) {
    if (!r.ok) throw new Error("HTTP " + r.status);
    var serverId = id;
    var toAdd = srvModalGroups.filter(function(g) { return srvModalOrigGroups.indexOf(g) === -1; });
    var toRemove = srvModalOrigGroups.filter(function(g) { return srvModalGroups.indexOf(g) === -1; });
    var promises = [];
    for (var i = 0; i < toAdd.length; i++) {
      promises.push(fetch(A + "/servers/" + encodeURIComponent(serverId) + "/groups", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({group: toAdd[i]})
      }));
    }
    for (var i = 0; i < toRemove.length; i++) {
      promises.push(fetch(A + "/servers/" + encodeURIComponent(serverId) + "/groups/" + encodeURIComponent(toRemove[i]), {
        method: "DELETE"
      }));
    }
    return Promise.all(promises);
  }).then(function() {
    closeSrvModal();
    loadServers();
  }).catch(function(e) {
    errEl.textContent = "Failed: " + e.message;
    errEl.style.display = "block";
  });
});

function restartBackend(id, btn) {
  if (!confirm("Restart backend on \"" + id + "\"?")) return;
  btn.disabled = true;
  btn.textContent = "...";
  fetch(A + "/servers/" + encodeURIComponent(id) + "/restart", { method: "POST" })
    .then(function(r) {
      if (!r.ok) return r.text().then(function(t) { throw new Error(t); });
      btn.textContent = "OK";
      setTimeout(function() { btn.textContent = "Restart"; btn.disabled = false; }, 2000);
    })
    .catch(function(e) {
      alert("Restart failed: " + e.message);
      btn.textContent = "Restart";
      btn.disabled = false;
    });
}
function deleteServer(id) {
  if (!confirm("Delete server \"" + id + "\"? This removes the server config and status.")) return;
  fetch(A + "/servers/" + encodeURIComponent(id), { method: "DELETE" })
    .then(function(r) { if (!r.ok) throw new Error("HTTP " + r.status); loadServers(); })
    .catch(function(e) { alert("Failed to delete: " + e.message); });
}

var addGroupServerId = "";
function openAddGroupModal(serverId) {
  addGroupServerId = serverId;
  document.getElementById("add-group-title").textContent = "Add Group to " + serverId;
  document.getElementById("add-group-name").value = "";
  document.getElementById("add-group-error").style.display = "none";
  document.getElementById("add-group-modal").classList.add("open");
  document.getElementById("add-group-name").focus();
}
function closeAddGroupModal() {
  document.getElementById("add-group-modal").classList.remove("open");
}
document.getElementById("add-group-modal").addEventListener("click", function(e) {
  if (e.target === this) closeAddGroupModal();
});
document.getElementById("add-group-confirm").addEventListener("click", function() {
  var gname = document.getElementById("add-group-name").value.trim();
  var errEl = document.getElementById("add-group-error");
  if (!gname) { errEl.textContent = "Group name is required."; errEl.style.display = "block"; return; }
  fetch(A + "/servers/" + encodeURIComponent(addGroupServerId) + "/groups", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({group: gname})
  }).then(function(r) {
    if (!r.ok) throw new Error("HTTP " + r.status);
    closeAddGroupModal();
    loadServers();
  }).catch(function(e) {
    errEl.textContent = "Failed: " + e.message;
    errEl.style.display = "block";
  });
});
document.getElementById("srv-m-group-input").addEventListener("keydown", function(e) {
  if (e.key === "Enter") { e.preventDefault(); addSrvModalGroup(this.value.trim()); }
});
function removeServerGroup(serverId, gname) {
  if (!confirm("Remove group \"" + gname + "\" from server " + serverId + "?")) return;
  fetch(A + "/servers/" + encodeURIComponent(serverId) + "/groups/" + encodeURIComponent(gname), { method: "DELETE" })
    .then(function(r) { if (!r.ok) throw new Error("HTTP " + r.status); loadServers(); })
    .catch(function(e) { alert("Failed: " + e.message); });
}

function removeServerGroupByIdx(i, j) {
  var s = srvDataCache[i];
  if (!s || !s.groups || s.groups[j] === undefined) return;
  removeServerGroup(s.id, s.groups[j]);
}

function openAddGroupModalByIdx(i) {
  var s = srvDataCache[i];
  if (!s) return;
  openAddGroupModal(s.id);
}

function restartBackendByIdx(i, btn) {
  var s = srvDataCache[i];
  if (!s) return;
  restartBackend(s.id, btn);
}

function deleteServerByIdx(i) {
  var s = srvDataCache[i];
  if (!s) return;
  deleteServer(s.id);
}

function fmtAgo(dateStr) {
  if (!dateStr) return "-";
  var ago = (Date.now() - new Date(dateStr).getTime()) / 1000;
  if (ago < 0) ago = 0;
  if (ago < 60) return Math.floor(ago) + "s ago";
  if (ago < 3600) return Math.floor(ago / 60) + "m ago";
  if (ago < 86400) return Math.floor(ago / 3600) + "h ago";
  return Math.floor(ago / 86400) + "d ago";
}

function fmtUptime(s) {
  if (!s || s <= 0) return "-";
  var d = Math.floor(s / 86400);
  var h = Math.floor((s % 86400) / 3600);
  var m = Math.floor((s % 3600) / 60);
  if (d > 0) return d + "d " + h + "h";
  if (h > 0) return h + "h " + m + "m";
  return m + "m";
}

function statusBadge(lastSeen) {
  if (!lastSeen) return '<span class="status-dot status-gray"></span>never';
  var ago = (Date.now() - new Date(lastSeen).getTime()) / 1000;
  var cls = ago < 60 ? "status-green" : ago < 300 ? "status-yellow" : "status-red";
  var text = ago < 60 ? "online" : ago < 300 ? "recent" : "offline";
  return '<span class="status-dot ' + cls + '"></span>' + text;
}

var srvDataCache = [];
function provisionBadge(status) {
  if (!status) return '<span style="color:#ccc">-</span>';
  var color = "#888";
  if (status === "running") color = "#2e7d32";
  else if (status === "creating" || status === "dns" || status === "deploying") color = "#e65100";
  else if (status.indexOf("error") === 0) color = "#c5221f";
  return '<span style="color:' + color + ';font-weight:500;font-size:12px">' + escHtml(status) + '</span>';
}
function renderServers(servers) {
  srvDataCache = servers;
  var tb = document.getElementById("srv-tbody");
  if (!servers || servers.length === 0) {
    tb.innerHTML = '<tr><td colspan="11" class="empty">No servers configured</td></tr>';
    return;
  }
  var html = "";
  for (var i = 0; i < servers.length; i++) {
    var s = servers[i];
    var groups = '<span class="group-tag-default">all</span>';
    if (s.groups) {
      for (var g = 0; g < s.groups.length; g++) {
        groups += '<span class="group-tag">' + escHtml(s.groups[g]) + '<span class="remove" onclick="removeServerGroupByIdx(' + i + ',' + g + ')">&times;</span></span>';
      }
    }
    groups += '<span class="btn-add-srv" onclick="openAddGroupModalByIdx(' + i + ')">+</span>';
    html += "<tr>"
      + "<td><strong>" + escHtml(s.id) + "</strong></td>"
      + '<td style="font-family:monospace;font-size:12px;color:#666">' + escHtml(s.token) + "</td>"
      + "<td>" + (s.acme_domain ? escHtml(s.acme_domain) : '<span style="color:#ccc">-</span>') + "</td>"
      + "<td>" + (s.ip ? escHtml(s.ip) : '<span style="color:#ccc">-</span>') + "</td>"
      + "<td>" + provisionBadge(s.provision_status) + "</td>"
      + "<td>" + statusBadge(s.last_seen) + "</td>"
      + "<td>" + (s.hysteria_version ? escHtml(s.hysteria_version) : '<span style="color:#ccc">-</span>') + "</td>"
      + "<td>" + fmtUptime(s.uptime_seconds) + "</td>"
      + "<td>" + (s.last_seen ? new Date(s.last_seen).toLocaleTimeString() + ' <span style="color:#888;font-size:11px">(' + fmtAgo(s.last_seen) + ')</span>' : "-") + "</td>"
      + '<td class="num">' + fmt(s.tx) + "</td>"
      + '<td class="num">' + fmt(s.rx) + "</td>"
      + '<td class="num">' + fmt(s.tx + s.rx) + "</td>"
      + '<td class="num">' + s.user_count + "</td>"
      + '<td class="servers">' + groups + "</td>"
      + '<td class="quota-actions">'
      + '<button class="btn-edit" onclick="openEditSrvModal(srvDataCache[' + i + '])">Edit</button>'
      + '<button class="btn-edit" onclick="restartBackendByIdx(' + i + ', this)">Restart</button>'
      + '<button class="btn-del" onclick="deleteServerByIdx(' + i + ')">Del</button>'
      + "</td>"
      + "</tr>";
  }
  tb.innerHTML = html;
}
function loadServers() {
  fetch(A + "/server-overview")
    .then(function(r) { if (!r.ok) throw new Error(r.status); return r.json(); })
    .then(function(data) {
      renderServers(data);
      document.getElementById("srv-status").textContent = data.length + " servers \u00b7 updated " + new Date().toLocaleTimeString();
      document.getElementById("srv-error").style.display = "none";
    })
    .catch(function(e) {
      document.getElementById("srv-error").textContent = "Failed to load: " + e.message;
      document.getElementById("srv-error").style.display = "block";
    });
}

// ---- Global keyboard shortcuts ----
document.addEventListener("keydown", function(e) {
  if (e.key === "Escape") { closeModal(); closeAddUserModal(); closeAddServerModal(); closeSrvModal(); closeAddGroupModal(); }
  if (e.key === "Enter" && document.getElementById("modal").classList.contains("open")) {
    document.getElementById("modal-confirm").click();
  }
  if (e.key === "Enter" && document.getElementById("add-user-modal").classList.contains("open")) {
    document.getElementById("add-user-confirm").click();
  }
  if (e.key === "Enter" && document.getElementById("add-server-modal").classList.contains("open")) {
    document.getElementById("add-server-confirm").click();
  }
  if (e.key === "Enter" && document.getElementById("srv-modal").classList.contains("open")) {
    document.getElementById("srv-m-confirm").click();
  }
  if (e.key === "Enter" && document.getElementById("add-group-modal").classList.contains("open")) {
    document.getElementById("add-group-confirm").click();
  }
});

// Initial load
load();
setInterval(function() { if (currentTab === "users") load(); else loadServers(); }, 30000);
</script>
</body>
</html>
`
