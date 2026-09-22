# app.py - Bronx Ultra API Management System
# Deploy on Render.com

import os
import json
import time
import secrets
import hashlib
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict
from threading import Lock
import requests as http_requests
from flask import Flask, request, jsonify, render_template_string, session, redirect, url_for

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# ==================== CONFIG ====================
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "bronx-admin-op")
DATA_FILE = "data.json"
DDOS_WINDOW = 10  # seconds
DDOS_THRESHOLD = 15  # requests in window

# ==================== DATA STORAGE ====================
data_lock = Lock()

def load_data():
    if not os.path.exists(DATA_FILE):
        default = {
            "apis": [],
            "keys": [],
            "stats": {
                "total_requests": 0,
                "daily": {},
                "monthly": {},
                "banned_ips": [],
                "ip_requests": {},
                "key_usage": {},
                "live_logs": []
            }
        }
        with open(DATA_FILE, "w") as f:
            json.dump(default, f, indent=2)
        return default
    try:
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    except:
        return {"apis": [], "keys": [], "stats": {"total_requests": 0, "daily": {}, "monthly": {}, "banned_ips": [], "ip_requests": {}, "key_usage": {}, "live_logs": []}}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=2)

# ==================== RATE LIMIT TRACKER ====================
rate_tracker = defaultdict(list)  # key -> [timestamps]
ip_tracker = defaultdict(list)    # ip -> [timestamps]

def check_rate_limit(key_str, limit_per_min):
    now = time.time()
    rate_tracker[key_str] = [t for t in rate_tracker[key_str] if now - t < 60]
    if len(rate_tracker[key_str]) >= limit_per_min:
        return False
    rate_tracker[key_str].append(now)
    return True

def check_ddos(ip):
    now = time.time()
    ip_tracker[ip] = [t for t in ip_tracker[ip] if now - t < DDOS_WINDOW]
    ip_tracker[ip].append(now)
    if len(ip_tracker[ip]) >= DDOS_THRESHOLD:
        data = load_data()
        if ip not in data["stats"]["banned_ips"]:
            data["stats"]["banned_ips"].append(ip)
            save_data(data)
        return True
    return False

# ==================== AUTH DECORATOR ====================
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return decorated

# ==================== HTML TEMPLATES ====================
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Bronx Ultra - API Dashboard</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; font-family:'Segoe UI',sans-serif; }
body { background: linear-gradient(135deg,#0f0c29,#302b63,#24243e); min-height:100vh; color:#fff; padding:20px; }
.container { max-width:1100px; margin:0 auto; }
.header { text-align:center; padding:30px 20px; background:rgba(255,255,255,0.05); border-radius:20px; backdrop-filter:blur(10px); border:1px solid rgba(255,255,255,0.1); margin-bottom:20px; }
.header h1 { font-size:2.5rem; background:linear-gradient(90deg,#ff6b6b,#feca57,#48dbfb,#ff9ff3); -webkit-background-clip:text; -webkit-text-fill-color:transparent; }
.header p { color:#aaa; margin-top:8px; }
.handle { display:inline-block; margin-top:12px; padding:8px 20px; background:linear-gradient(90deg,#667eea,#764ba2); border-radius:25px; font-weight:bold; }
.card { background:rgba(255,255,255,0.05); border-radius:15px; padding:20px; margin-bottom:20px; border:1px solid rgba(255,255,255,0.1); backdrop-filter:blur(10px); }
.card h2 { margin-bottom:15px; color:#48dbfb; font-size:1.3rem; }
.api-box { background:rgba(0,0,0,0.3); border-radius:10px; padding:15px; margin-bottom:10px; font-family:monospace; word-break:break-all; font-size:0.9rem; position:relative; }
.copy-btn { background:linear-gradient(90deg,#48dbfb,#0abde3); border:none; color:#fff; padding:8px 16px; border-radius:8px; cursor:pointer; font-weight:bold; margin-top:10px; }
.copy-btn:hover { opacity:0.8; }
.stats-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:15px; }
.stat-box { background:linear-gradient(135deg,rgba(102,126,234,0.3),rgba(118,75,162,0.3)); padding:20px; border-radius:12px; text-align:center; border:1px solid rgba(255,255,255,0.1); }
.stat-box .num { font-size:2rem; font-weight:bold; color:#feca57; }
.stat-box .label { color:#aaa; margin-top:5px; font-size:0.9rem; }
.btn { display:inline-block; padding:12px 25px; background:linear-gradient(90deg,#667eea,#764ba2); color:#fff; text-decoration:none; border-radius:10px; font-weight:bold; border:none; cursor:pointer; margin:5px; transition:0.3s; }
.btn:hover { transform:translateY(-2px); box-shadow:0 10px 20px rgba(102,126,234,0.4); }
.input-group { margin-bottom:15px; }
.input-group label { display:block; margin-bottom:5px; color:#aaa; font-size:0.9rem; }
.input-group input, .input-group select, .input-group textarea { width:100%; padding:12px; border-radius:8px; border:1px solid rgba(255,255,255,0.2); background:rgba(0,0,0,0.3); color:#fff; font-size:1rem; }
.input-group input:focus, .input-group select:focus { outline:none; border-color:#48dbfb; }
.api-list-item { display:flex; justify-content:space-between; align-items:center; padding:12px; background:rgba(0,0,0,0.2); border-radius:10px; margin-bottom:8px; flex-wrap:wrap; gap:8px; }
.tag { background:linear-gradient(90deg,#48dbfb,#0abde3); padding:4px 10px; border-radius:15px; font-size:0.75rem; font-weight:bold; }
.footer { text-align:center; padding:20px; color:#666; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>🚀 Bronx Ultra</h1>
    <p>API Management Dashboard</p>
    <div class="handle">@BRONX_ULTRA</div>
  </div>

  <div class="card">
    <h2>🔗 Your API Endpoint</h2>
    <div class="api-box" id="mainApi">{{ api_url }}</div>
    <button class="copy-btn" onclick="copyText('{{ api_url }}')">📋 Copy API</button>
    <button class="copy-btn" style="background:linear-gradient(90deg,#feca57,#ff6b6b);" onclick="copyText('{{ custom_api }}')">📋 Copy Custom API</button>
  </div>

  <div class="card">
    <h2>📊 Statistics</h2>
    <div class="stats-grid">
      <div class="stat-box"><div class="num">{{ total }}</div><div class="label">Total Requests</div></div>
      <div class="stat-box"><div class="num">{{ today }}</div><div class="label">Today</div></div>
      <div class="stat-box"><div class="num">{{ monthly }}</div><div class="label">This Month</div></div>
      <div class="stat-box"><div class="num">{{ active_keys }}</div><div class="label">Active Keys</div></div>
    </div>
  </div>

  <div class="card" style="text-align:center;">
    <a href="/admin" class="btn">🔐 Admin Panel</a>
  </div>

  <div class="footer">© Bronx Ultra API System</div>
</div>
<script>
function copyText(t) { navigator.clipboard.writeText(t).then(()=>alert('✅ Copied!')); }
</script>
</body>
</html>
"""

ADMIN_LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin Login - Bronx Ultra</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; font-family:'Segoe UI',sans-serif; }
body { background:linear-gradient(135deg,#0f0c29,#302b63,#24243e); min-height:100vh; display:flex; align-items:center; justify-content:center; padding:20px; }
.box { background:rgba(255,255,255,0.05); padding:40px; border-radius:20px; backdrop-filter:blur(10px); border:1px solid rgba(255,255,255,0.1); width:100%; max-width:400px; }
h1 { color:#fff; text-align:center; margin-bottom:25px; background:linear-gradient(90deg,#ff6b6b,#feca57); -webkit-background-clip:text; -webkit-text-fill-color:transparent; }
input { width:100%; padding:14px; margin-bottom:15px; border-radius:10px; border:1px solid rgba(255,255,255,0.2); background:rgba(0,0,0,0.3); color:#fff; font-size:1rem; }
input:focus { outline:none; border-color:#48dbfb; }
button { width:100%; padding:14px; border:none; border-radius:10px; background:linear-gradient(90deg,#667eea,#764ba2); color:#fff; font-weight:bold; font-size:1rem; cursor:pointer; }
button:hover { opacity:0.9; }
.err { color:#ff6b6b; text-align:center; margin-bottom:10px; }
</style>
</head>
<body>
<div class="box">
  <h1>🔐 Admin Login</h1>
  {% if error %}<div class="err">{{ error }}</div>{% endif %}
  <form method="POST">
    <input type="password" name="password" placeholder="Enter Admin Password" required autofocus>
    <button type="submit">Login</button>
  </form>
</div>
</body>
</html>
"""

ADMIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin Panel - Bronx Ultra</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; font-family:'Segoe UI',sans-serif; }
body { background:linear-gradient(135deg,#0f0c29,#302b63,#24243e); min-height:100vh; color:#fff; padding:20px; }
.container { max-width:1300px; margin:0 auto; }
.header { display:flex; justify-content:space-between; align-items:center; padding:20px; background:rgba(255,255,255,0.05); border-radius:15px; margin-bottom:20px; flex-wrap:wrap; gap:10px; }
.header h1 { background:linear-gradient(90deg,#ff6b6b,#feca57,#48dbfb); -webkit-background-clip:text; -webkit-text-fill-color:transparent; }
.logout { background:linear-gradient(90deg,#ff6b6b,#ee5253); color:#fff; padding:10px 20px; border-radius:10px; text-decoration:none; font-weight:bold; }
.tabs { display:flex; gap:8px; margin-bottom:20px; flex-wrap:wrap; }
.tab { padding:12px 20px; background:rgba(255,255,255,0.05); border-radius:10px; cursor:pointer; font-weight:bold; border:1px solid rgba(255,255,255,0.1); transition:0.3s; }
.tab.active { background:linear-gradient(90deg,#667eea,#764ba2); }
.tab:hover { background:rgba(102,126,234,0.4); }
.panel { display:none; background:rgba(255,255,255,0.05); border-radius:15px; padding:25px; border:1px solid rgba(255,255,255,0.1); }
.panel.active { display:block; }
.card { background:rgba(0,0,0,0.2); border-radius:12px; padding:20px; margin-bottom:15px; }
.card h3 { color:#48dbfb; margin-bottom:15px; }
.stats-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:15px; margin-bottom:20px; }
.stat { background:linear-gradient(135deg,rgba(102,126,234,0.3),rgba(118,75,162,0.3)); padding:20px; border-radius:12px; text-align:center; }
.stat .num { font-size:1.8rem; font-weight:bold; color:#feca57; }
.stat .label { color:#aaa; font-size:0.85rem; margin-top:5px; }
input, select, textarea { width:100%; padding:11px; border-radius:8px; border:1px solid rgba(255,255,255,0.2); background:rgba(0,0,0,0.3); color:#fff; font-size:0.95rem; margin-bottom:10px; }
input:focus, select:focus, textarea:focus { outline:none; border-color:#48dbfb; }
label { display:block; margin-bottom:5px; color:#aaa; font-size:0.85rem; }
.btn { padding:11px 20px; border:none; border-radius:8px; font-weight:bold; cursor:pointer; color:#fff; font-size:0.9rem; margin:4px 2px; }
.btn-primary { background:linear-gradient(90deg,#667eea,#764ba2); }
.btn-success { background:linear-gradient(90deg,#10ac84,#1dd1a1); }
.btn-danger { background:linear-gradient(90deg,#ee5253,#ff6b6b); }
.btn-warn { background:linear-gradient(90deg,#feca57,#ff9f43); color:#000; }
.btn:hover { opacity:0.85; }
table { width:100%; border-collapse:collapse; margin-top:10px; }
th, td { padding:10px; text-align:left; border-bottom:1px solid rgba(255,255,255,0.1); font-size:0.88rem; word-break:break-word; }
th { background:rgba(102,126,234,0.3); color:#48dbfb; }
tr:hover { background:rgba(255,255,255,0.03); }
.tag { padding:3px 9px; border-radius:12px; font-size:0.75rem; font-weight:bold; }
.tag-active { background:#10ac84; }
.tag-expired { background:#ee5253; }
.tag-stopped { background:#feca57; color:#000; }
.grid2 { display:grid; grid-template-columns:1fr 1fr; gap:15px; }
@media(max-width:768px){ .grid2 { grid-template-columns:1fr; } }
.log-item { padding:8px; background:rgba(0,0,0,0.3); border-radius:6px; margin-bottom:5px; font-size:0.85rem; font-family:monospace; }
.modal { display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.8); z-index:1000; align-items:center; justify-content:center; padding:20px; }
.modal.show { display:flex; }
.modal-content { background:#1a1a2e; padding:30px; border-radius:15px; max-width:500px; width:100%; max-height:90vh; overflow-y:auto; border:1px solid rgba(255,255,255,0.2); }
.modal-content h3 { margin-bottom:20px; color:#48dbfb; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>🚀 Admin Panel - Bronx Ultra</h1>
    <a href="/admin/logout" class="logout">Logout</a>
  </div>

  <div class="tabs">
    <div class="tab active" onclick="showTab('stats',this)">📊 Stats</div>
    <div class="tab" onclick="showTab('apis',this)">🔌 APIs</div>
    <div class="tab" onclick="showTab('keys',this)">🔑 Keys</div>
    <div class="tab" onclick="showTab('live',this)">📡 Live Monitor</div>
    <div class="tab" onclick="showTab('ips',this)">🛡️ IP Management</div>
    <div class="tab" onclick="showTab('backup',this)">💾 Import/Export</div>
  </div>

  <!-- STATS -->
  <div class="panel active" id="stats">
    <div class="stats-grid">
      <div class="stat"><div class="num" id="s-total">0</div><div class="label">Total Requests</div></div>
      <div class="stat"><div class="num" id="s-today">0</div><div class="label">Today</div></div>
      <div class="stat"><div class="num" id="s-month">0</div><div class="label">This Month</div></div>
      <div class="stat"><div class="num" id="s-keys">0</div><div class="label">Total Keys</div></div>
      <div class="stat"><div class="num" id="s-apis">0</div><div class="label">Total APIs</div></div>
      <div class="stat"><div class="num" id="s-banned">0</div><div class="label">Banned IPs</div></div>
    </div>
    <button class="btn btn-primary" onclick="loadStats()">🔄 Refresh</button>
  </div>

  <!-- APIS -->
  <div class="panel" id="apis">
    <div class="card">
      <h3>➕ Add Custom API</h3>
      <label>API Name</label>
      <input id="api-name" placeholder="e.g. Bronx SMS API">
      <label>API Endpoint (base URL)</label>
      <input id="api-endpoint" placeholder="https://your-api.vercel.app/send">
      <label>API Example Number</label>
      <input id="api-example" placeholder="9890909851">
      <label>API Full URL Template (use {key},{number},{message},{count})</label>
      <textarea id="api-url" rows="3" placeholder="https://bronx-api-bom-v1000.vercel.app/send?key={key}&message={message}&number={number}&count={count}"></textarea>
      <button class="btn btn-success" onclick="addApi()">➕ Add API</button>
    </div>
    <div class="card">
      <h3>📋 API List</h3>
      <div id="api-list"></div>
    </div>
  </div>

  <!-- KEYS -->
  <div class="panel" id="keys">
    <div class="card">
      <h3>🔑 Generate Key</h3>
      <label>Select Custom API</label>
      <select id="key-api"></select>
      <label>Key Name</label>
      <input id="key-name" placeholder="e.g. Premium User 1">
      <label>Expiry (e.g. 1day, 7day, 30day)</label>
      <input id="key-expiry" placeholder="30day">
      <label>Rate Limit (per minute)</label>
      <input id="key-limit" type="number" value="10" min="1">
      <button class="btn btn-success" onclick="genKey()">🔑 Generate Key</button>
    </div>
    <div class="card">
      <h3>📋 Key List</h3>
      <div style="overflow-x:auto;"><table id="key-table">
        <thead><tr><th>Key</th><th>Name</th><th>API</th><th>Expires</th><th>Limit</th><th>Status</th><th>Actions</th></tr></thead>
        <tbody></tbody>
      </table></div>
    </div>
  </div>

  <!-- LIVE -->
  <div class="panel" id="live">
    <div class="card">
      <h3>📡 Live Request Monitor</h3>
      <button class="btn btn-primary" onclick="loadLive()">🔄 Refresh</button>
      <button class="btn btn-warn" onclick="toggleAuto()" id="auto-btn">▶️ Auto Refresh: OFF</button>
      <div id="live-logs" style="margin-top:15px; max-height:500px; overflow-y:auto;"></div>
    </div>
    <div class="card">
      <h3>📊 Key Usage Stats</h3>
      <div id="key-usage"></div>
    </div>
  </div>

  <!-- IPS -->
  <div class="panel" id="ips">
    <div class="card">
      <h3>🛡️ Banned IPs (Auto-ban after 15 req/10s)</h3>
      <div id="banned-list"></div>
      <label style="margin-top:15px;">Manually Ban IP</label>
      <input id="ban-ip" placeholder="e.g. 192.168.1.1">
      <button class="btn btn-danger" onclick="banIp()">🚫 Ban IP</button>
    </div>
    <div class="card">
      <h3>🌐 Active IPs (top requesters)</h3>
      <div id="ip-list"></div>
    </div>
  </div>

  <!-- BACKUP -->
  <div class="panel" id="backup">
    <div class="card">
      <h3>💾 Export Data</h3>
      <button class="btn btn-primary" onclick="exportData()">📥 Export JSON</button>
      <a href="/admin/export" class="btn btn-success" style="text-decoration:none;">⬇️ Download Export</a>
    </div>
    <div class="card">
      <h3>📤 Import Data</h3>
      <label>Paste JSON here</label>
      <textarea id="import-json" rows="8" placeholder='{"apis":[],"keys":[]}'></textarea>
      <button class="btn btn-warn" onclick="importData()">📤 Import</button>
    </div>
  </div>
</div>

<!-- Edit Key Modal -->
<div class="modal" id="edit-modal">
  <div class="modal-content">
    <h3>✏️ Edit Key</h3>
    <label>Key Name</label>
    <input id="e-name">
    <label>Expiry Date (YYYY-MM-DD)</label>
    <input id="e-expiry" type="date">
    <label>Rate Limit (per minute)</label>
    <input id="e-limit" type="number">
    <label>Status</label>
    <select id="e-status"><option value="active">Active</option><option value="stopped">Stopped</option></select>
    <button class="btn btn-success" onclick="saveEditKey()">💾 Save</button>
    <button class="btn btn-danger" onclick="closeModal()">✖ Cancel</button>
  </div>
</div>

<script>
let editKeyId = null;
let autoTimer = null;

function showTab(id, el) {
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  el.classList.add('active');
  if(id==='stats') loadStats();
  if(id==='apis') loadApis();
  if(id==='keys') { loadApis(); loadKeys(); }
  if(id==='live') { loadLive(); loadKeyUsage(); }
  if(id==='ips') { loadBanned(); loadIpList(); }
}

async function api(url, opts={}) {
  const r = await fetch(url, opts);
  return r.json();
}

// STATS
async function loadStats() {
  const d = await api('/admin/api/stats');
  document.getElementById('s-total').textContent = d.total;
  document.getElementById('s-today').textContent = d.today;
  document.getElementById('s-month').textContent = d.monthly;
  document.getElementById('s-keys').textContent = d.keys;
  document.getElementById('s-apis').textContent = d.apis;
  document.getElementById('s-banned').textContent = d.banned;
}

// APIS
async function loadApis() {
  const d = await api('/admin/api/apis');
  const list = document.getElementById('api-list');
  const sel = document.getElementById('key-api');
  list.innerHTML = '';
  sel.innerHTML = '<option value="">-- Select API --</option>';
  if(!d.apis.length) { list.innerHTML = '<p style="color:#aaa">No APIs yet</p>'; return; }
  d.apis.forEach(a=>{
    list.innerHTML += `<div class="card" style="margin-bottom:10px;">
      <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
        <div><strong>${a.name}</strong> <span class="tag">${a.endpoint}</span></div>
        <div>
          <button class="btn btn-warn" onclick="editApi('${a.id}')">✏️</button>
          <button class="btn btn-danger" onclick="delApi('${a.id}')">🗑️</button>
        </div>
      </div>
      <div style="font-family:monospace; font-size:0.8rem; color:#aaa; margin-top:8px; word-break:break-all;">${a.url}</div>
    </div>`;
    sel.innerHTML += `<option value="${a.id}">${a.name}</option>`;
  });
}

async function addApi() {
  const name = document.getElementById('api-name').value.trim();
  const endpoint = document.getElementById('api-endpoint').value.trim();
  const example = document.getElementById('api-example').value.trim();
  const url = document.getElementById('api-url').value.trim();
  if(!name || !endpoint || !url) return alert('Fill all fields');
  const d = await api('/admin/api/apis', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({name,endpoint,example,url})});
  if(d.ok) { document.getElementById('api-name').value=''; document.getElementById('api-endpoint').value=''; document.getElementById('api-example').value=''; document.getElementById('api-url').value=''; loadApis(); alert('✅ API Added'); }
}

async function delApi(id) {
  if(!confirm('Delete this API?')) return;
  await api('/admin/api/apis/'+id, {method:'DELETE'});
  loadApis();
}

async function editApi(id) {
  const name = prompt('New API name:');
  if(!name) return;
  const url = prompt('New URL template:');
  if(!url) return;
  await api('/admin/api/apis/'+id, {method:'PUT', headers:{'Content-Type':'application/json'}, body:JSON.stringify({name,url})});
  loadApis();
}

// KEYS
async function loadKeys() {
  const d = await api('/admin/api/keys');
  const tb = document.querySelector('#key-table tbody');
  tb.innerHTML = '';
  d.keys.forEach(k=>{
    const expired = k.expires_at && new Date(k.expires_at) < new Date();
    const status = expired ? 'expired' : k.status;
    const cls = status==='active'?'tag-active':status==='expired'?'tag-expired':'tag-stopped';
    tb.innerHTML += `<tr>
      <td style="font-family:monospace;font-size:0.8rem;">${k.key}</td>
      <td>${k.name}</td>
      <td>${k.api_name||'-'}</td>
      <td>${k.expires_at?new Date(k.expires_at).toLocaleDateString():'Never'}</td>
      <td>${k.rate_limit}/min</td>
      <td><span class="tag ${cls}">${status}</span></td>
      <td>
        <button class="btn btn-warn" onclick="editKey('${k.id}')">✏️</button>
        <button class="btn btn-primary" onclick="toggleKey('${k.id}')">⏯</button>
        <button class="btn btn-danger" onclick="delKey('${k.id}')">🗑️</button>
      </td>
    </tr>`;
  });
}

async function genKey() {
  const api_id = document.getElementById('key-api').value;
  const name = document.getElementById('key-name').value.trim();
  const expiry = document.getElementById('key-expiry').value.trim();
  const rate_limit = parseInt(document.getElementById('key-limit').value)||10;
  if(!api_id) return alert('Select API');
  if(!name) return alert('Enter name');
  const d = await api('/admin/api/keys', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({api_id,name,expiry,rate_limit})});
  if(d.ok) { alert('✅ Key Generated: '+d.key); document.getElementById('key-name').value=''; loadKeys(); }
  else alert('❌ '+d.error);
}

async function delKey(id) {
  if(!confirm('Delete this key?')) return;
  await api('/admin/api/keys/'+id, {method:'DELETE'});
  loadKeys();
}

async function toggleKey(id) {
  await api('/admin/api/keys/'+id+'/toggle', {method:'POST'});
  loadKeys();
}

async function editKey(id) {
  const d = await api('/admin/api/keys');
  const k = d.keys.find(x=>x.id===id);
  if(!k) return;
  editKeyId = id;
  document.getElementById('e-name').value = k.name;
  document.getElementById('e-expiry').value = k.expires_at ? k.expires_at.split('T')[0] : '';
  document.getElementById('e-limit').value = k.rate_limit;
  document.getElementById('e-status').value = k.status;
  document.getElementById('edit-modal').classList.add('show');
}

function closeModal() { document.getElementById('edit-modal').classList.remove('show'); }

async function saveEditKey() {
  const body = {
    name: document.getElementById('e-name').value,
    expires_at: document.getElementById('e-expiry').value,
    rate_limit: parseInt(document.getElementById('e-limit').value),
    status: document.getElementById('e-status').value
  };
  await api('/admin/api/keys/'+editKeyId, {method:'PUT', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
  closeModal();
  loadKeys();
}

// LIVE
async function loadLive() {
  const d = await api('/admin/api/live');
  const el = document.getElementById('live-logs');
  if(!d.logs.length) { el.innerHTML = '<p style="color:#aaa">No requests yet</p>'; return; }
  el.innerHTML = d.logs.map(l=>`<div class="log-item">[${l.time}] <b>${l.key_name||l.key}</b> | ${l.ip} | ${l.api_name} | ${l.status}</div>`).join('');
}

async function loadKeyUsage() {
  const d = await api('/admin/api/key-usage');
  const el = document.getElementById('key-usage');
  if(!Object.keys(d.usage).length) { el.innerHTML = '<p style="color:#aaa">No usage</p>'; return; }
  el.innerHTML = Object.entries(d.usage).map(([k,v])=>`<div class="log-item">🔑 ${k}: <b>${v}</b> requests</div>`).join('');
}

function toggleAuto() {
  const btn = document.getElementById('auto-btn');
  if(autoTimer) { clearInterval(autoTimer); autoTimer=null; btn.textContent='▶️ Auto Refresh: OFF'; }
  else { autoTimer = setInterval(()=>{loadLive();loadKeyUsage();},3000); btn.textContent='⏸️ Auto Refresh: ON'; }
}

// IPS
async function loadBanned() {
  const d = await api('/admin/api/banned');
  const el = document.getElementById('banned-list');
  if(!d.banned.length) { el.innerHTML = '<p style="color:#aaa">No banned IPs</p>'; return; }
  el.innerHTML = d.banned.map(ip=>`<div class="log-item">🚫 ${ip} <button class="btn btn-success" style="padding:4px 10px;font-size:0.75rem;" onclick="unbanIp('${ip}')">Unban</button></div>`).join('');
}

async function banIp() {
  const ip = document.getElementById('ban-ip').value.trim();
  if(!ip) return;
  await api('/admin/api/ban', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ip})});
  document.getElementById('ban-ip').value='';
  loadBanned();
}

async function unbanIp(ip) {
  await api('/admin/api/unban', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ip})});
  loadBanned();
}

async function loadIpList() {
  const d = await api('/admin/api/ip-list');
  const el = document.getElementById('ip-list');
  const entries = Object.entries(d.ips).sort((a,b)=>b[1]-a[1]).slice(0,20);
  if(!entries.length) { el.innerHTML = '<p style="color:#aaa">No data</p>'; return; }
  el.innerHTML = entries.map(([ip,c])=>`<div class="log-item">🌐 ${ip}: <b>${c}</b> requests</div>`).join('');
}

// BACKUP
async function exportData() {
  const d = await api('/admin/export');
  const blob = new Blob([JSON.stringify(d,null,2)], {type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'bronx-backup-'+Date.now()+'.json';
  a.click();
}

async function importData() {
  try {
    const data = JSON.parse(document.getElementById('import-json').value);
    await api('/admin/import', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(data)});
    alert('✅ Imported!');
    loadApis(); loadKeys();
  } catch(e) { alert('❌ Invalid JSON'); }
}

// INIT
loadStats();
</script>
</body>
</html>
"""

# ==================== ROUTES ====================

@app.route("/")
def index():
    data = load_data()
    host = request.host_url.rstrip('/')
    api_url = f"{host}/api/send?key=YOUR_KEY&number=9876543210&message=Hi&count=5"
    custom_api = f"{host}/api/custom?key=YOUR_KEY&api=API_ID&number=9876543210&message=Hi&count=5"
    today = datetime.now().strftime("%Y-%m-%d")
    month = datetime.now().strftime("%Y-%m")
    return render_template_string(DASHBOARD_HTML,
        api_url=api_url,
        custom_api=custom_api,
        total=data["stats"]["total_requests"],
        today=data["stats"]["daily"].get(today, 0),
        monthly=data["stats"]["monthly"].get(month, 0),
        active_keys=len([k for k in data["keys"] if k.get("status")=="active"])
    )

# ==================== PUBLIC API ====================

@app.route("/api/send")
def api_send():
    return handle_api_request()

@app.route("/api/custom")
def api_custom():
    return handle_api_request(custom=True)

def handle_api_request(custom=False):
    ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
    key_str = request.args.get("key", "").strip()
    number = request.args.get("number", "").strip()
    message = request.args.get("message", "").strip()
    count = request.args.get("count", "1").strip()
    api_id = request.args.get("api", "").strip() if custom else None

    data = load_data()

    # Check banned IP
    if ip in data["stats"]["banned_ips"]:
        return jsonify({"status": False, "error": "Your IP is banned"}), 403

    # DDoS check
    if check_ddos(ip):
        return jsonify({"status": False, "error": "DDoS detected - IP banned"}), 403

    if not key_str:
        return jsonify({"status": False, "error": "Key required"}), 400

    # Find key
    key_obj = None
    for k in data["keys"]:
        if k["key"] == key_str:
            key_obj = k
            break

    if not key_obj:
        return jsonify({"status": False, "error": "Invalid key"}), 401

    # Status check
    if key_obj.get("status") != "active":
        return jsonify({"status": False, "error": "Key stopped"}), 403

    # Expiry check
    if key_obj.get("expires_at"):
        try:
            exp = datetime.fromisoformat(key_obj["expires_at"])
            if datetime.now() > exp:
                return jsonify({"status": False, "error": "Key expired"}), 403
        except:
            pass

    # Custom API check - key must match the API
    if custom:
        if not api_id:
            return jsonify({"status": False, "error": "API ID required"}), 400
        if key_obj.get("api_id") != api_id:
            return jsonify({"status": False, "error": "Key not authorized for this API"}), 403

    # Rate limit
    rl = key_obj.get("rate_limit", 10)
    if not check_rate_limit(key_str, rl):
        return jsonify({"status": False, "error": f"Rate limit exceeded ({rl}/min)"}), 429

    # Get API
    api_obj = None
    target_api_id = api_id if custom else key_obj.get("api_id")
    for a in data["apis"]:
        if a["id"] == target_api_id:
            api_obj = a
            break

    if not api_obj:
        return jsonify({"status": False, "error": "API not found"}), 404

    # Build URL
    url = api_obj["url"]
    url = url.replace("{key}", key_str).replace("{number}", number).replace("{message}", message).replace("{count}", count)

    # Forward request
    try:
        r = http_requests.get(url, timeout=15)
        result = r.text
        status = "success" if r.status_code == 200 else f"error_{r.status_code}"
    except Exception as e:
        result = str(e)
        status = "error"

    # Update stats
    with data_lock:
        data = load_data()
        today = datetime.now().strftime("%Y-%m-%d")
        month = datetime.now().strftime("%Y-%m")
        data["stats"]["total_requests"] += 1
        data["stats"]["daily"][today] = data["stats"]["daily"].get(today, 0) + 1
        data["stats"]["monthly"][month] = data["stats"]["monthly"].get(month, 0) + 1
        data["stats"]["ip_requests"][ip] = data["stats"]["ip_requests"].get(ip, 0) + 1
        ku = data["stats"]["key_usage"]
        ku[key_obj["name"]] = ku.get(key_obj["name"], 0) + 1
        log = {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "key": key_str[:12]+"...",
            "key_name": key_obj["name"],
            "ip": ip,
            "api_name": api_obj["name"],
            "status": status
        }
        data["stats"]["live_logs"].insert(0, log)
        data["stats"]["live_logs"] = data["stats"]["live_logs"][:100]
        save_data(data)

    return jsonify({"status": status=="success", "response": result, "api": api_obj["name"]})

# ==================== ADMIN AUTH ====================

@app.route("/admin/login", methods=["GET","POST"])
def admin_login():
    if request.method == "POST":
        if request.form.get("password") == ADMIN_PASSWORD:
            session["admin_logged_in"] = True
            return redirect(url_for("admin_panel"))
        return render_template_string(ADMIN_LOGIN_HTML, error="Invalid password")
    return render_template_string(ADMIN_LOGIN_HTML, error=None)

@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))

@app.route("/admin")
@admin_required
def admin_panel():
    return render_template_string(ADMIN_HTML)

# ==================== ADMIN API ====================

@app.route("/admin/api/stats")
@admin_required
def admin_stats():
    data = load_data()
    today = datetime.now().strftime("%Y-%m-%d")
    month = datetime.now().strftime("%Y-%m")
    return jsonify({
        "total": data["stats"]["total_requests"],
        "today": data["stats"]["daily"].get(today, 0),
        "monthly": data["stats"]["monthly"].get(month, 0),
        "keys": len(data["keys"]),
        "apis": len(data["apis"]),
        "banned": len(data["stats"]["banned_ips"])
    })

@app.route("/admin/api/apis", methods=["GET","POST"])
@admin_required
def admin_apis():
    data = load_data()
    if request.method == "POST":
        body = request.json
        api = {
            "id": secrets.token_hex(8),
            "name": body["name"],
            "endpoint": body["endpoint"],
            "example": body.get("example",""),
            "url": body["url"],
            "created": datetime.now().isoformat()
        }
        data["apis"].append(api)
        save_data(data)
        return jsonify({"ok": True, "api": api})
    return jsonify({"apis": data["apis"]})

@app.route("/admin/api/apis/<api_id>", methods=["PUT","DELETE"])
@admin_required
def admin_api_edit(api_id):
    data = load_data()
    if request.method == "DELETE":
        data["apis"] = [a for a in data["apis"] if a["id"] != api_id]
        save_data(data)
        return jsonify({"ok": True})
    body = request.json
    for a in data["apis"]:
        if a["id"] == api_id:
            a["name"] = body.get("name", a["name"])
            a["url"] = body.get("url", a["url"])
            break
    save_data(data)
    return jsonify({"ok": True})

@app.route("/admin/api/keys", methods=["GET","POST"])
@admin_required
def admin_keys():
    data = load_data()
    if request.method == "POST":
        body = request.json
        api_id = body["api_id"]
        api_name = ""
        for a in data["apis"]:
            if a["id"] == api_id:
                api_name = a["name"]
                break
        if not api_name:
            return jsonify({"ok": False, "error": "API not found"})
        # Parse expiry
        expiry_str = body.get("expiry","").lower()
        expires_at = None
        if expiry_str:
            days = 0
            if "day" in expiry_str:
                try: days = int(expiry_str.replace("day","").replace("s","").strip())
                except: days = 0
            elif expiry_str.isdigit():
                days = int(expiry_str)
            if days > 0:
                expires_at = (datetime.now() + timedelta(days=days)).isoformat()
        key = {
            "id": secrets.token_hex(6),
            "key": "bronx_" + secrets.token_urlsafe(24),
            "name": body["name"],
            "api_id": api_id,
            "api_name": api_name,
            "rate_limit": int(body.get("rate_limit", 10)),
            "expires_at": expires_at,
            "status": "active",
            "created": datetime.now().isoformat()
        }
        data["keys"].append(key)
        save_data(data)
        return jsonify({"ok": True, "key": key["key"]})
    return jsonify({"keys": data["keys"]})

@app.route("/admin/api/keys/<key_id>", methods=["PUT","DELETE"])
@admin_required
def admin_key_edit(key_id):
    data = load_data()
    if request.method == "DELETE":
        data["keys"] = [k for k in data["keys"] if k["id"] != key_id]
        save_data(data)
        return jsonify({"ok": True})
    body = request.json
    for k in data["keys"]:
        if k["id"] == key_id:
            if "name" in body: k["name"] = body["name"]
            if "rate_limit" in body: k["rate_limit"] = int(body["rate_limit"])
            if "status" in body: k["status"] = body["status"]
            if "expires_at" in body:
                if body["expires_at"]:
                    k["expires_at"] = datetime.fromisoformat(body["expires_at"]).isoformat()
                else:
                    k["expires_at"] = None
            break
    save_data(data)
    return jsonify({"ok": True})

@app.route("/admin/api/keys/<key_id>/toggle", methods=["POST"])
@admin_required
def admin_key_toggle(key_id):
    data = load_data()
    for k in data["keys"]:
        if k["id"] == key_id:
            k["status"] = "stopped" if k["status"]=="active" else "active"
            break
    save_data(data)
    return jsonify({"ok": True})

@app.route("/admin/api/live")
@admin_required
def admin_live():
    data = load_data()
    return jsonify({"logs": data["stats"]["live_logs"][:50]})

@app.route("/admin/api/key-usage")
@admin_required
def admin_key_usage():
    data = load_data()
    return jsonify({"usage": data["stats"]["key_usage"]})

@app.route("/admin/api/banned")
@admin_required
def admin_banned():
    data = load_data()
    return jsonify({"banned": data["stats"]["banned_ips"]})

@app.route("/admin/api/ban", methods=["POST"])
@admin_required
def admin_ban():
    data = load_data()
    ip = request.json.get("ip","").strip()
    if ip and ip not in data["stats"]["banned_ips"]:
        data["stats"]["banned_ips"].append(ip)
        save_data(data)
    return jsonify({"ok": True})

@app.route("/admin/api/unban", methods=["POST"])
@admin_required
def admin_unban():
    data = load_data()
    ip = request.json.get("ip","").strip()
    data["stats"]["banned_ips"] = [x for x in data["stats"]["banned_ips"] if x != ip]
    if ip in ip_tracker:
        del ip_tracker[ip]
    save_data(data)
    return jsonify({"ok": True})

@app.route("/admin/api/ip-list")
@admin_required
def admin_ip_list():
    data = load_data()
    return jsonify({"ips": data["stats"]["ip_requests"]})

@app.route("/admin/export")
@admin_required
def admin_export():
    data = load_data()
    return jsonify(data)

@app.route("/admin/import", methods=["POST"])
@admin_required
def admin_import():
    try:
        new_data = request.json
        if "apis" in new_data and "keys" in new_data:
            save_data(new_data)
            return jsonify({"ok": True})
        return jsonify({"ok": False, "error": "Invalid format"})
    except:
        return jsonify({"ok": False, "error": "Invalid JSON"})

# ==================== MAIN ====================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
