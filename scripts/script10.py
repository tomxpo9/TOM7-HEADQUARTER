"""
param_dir_auto_gui_final.py
Full-featured Param+Directory Auto scanner with dark neon Flask GUI, CSV/JSON export,
heuristic vulnerability detection (XSS-like reflection, SQL-error indicators, LFI indicators,
insecure cookie flags), proof-bundle generation (non-exploitative), and report download.

USAGE:
  1) Install deps:
     python3 -m pip install aiohttp beautifulsoup4 lxml flask yarl aiofiles
  2) Run:
     python3 param_dir_auto_gui_final.py
  3) Open: http://127.0.0.1:5000

IMPORTANT: Use ONLY on targets you have explicit permission to test. This tool performs
non-exploitative discovery only: it sends benign probes and captures indicators for reporting.
It DOES NOT contain exploit/PoC payloads.

Features included:
- Crawl to extract params, forms, asset paths and tokens
- Auto-generate guess paths and async probing (HTTP/HTTPS)
- Heuristics: reflected token (XSS-like), SQL error indicators, LFI markers, insecure cookies
- Baseline fingerprinting to reduce false positives (wildcard 200 pages)
- Flask GUI with dark neon theme, job list, live refresh
- CSV + JSON exports and "proof bundle" per finding for responsible disclosure

"""

from flask import Flask, request, render_template_string, jsonify, send_file
import threading
import asyncio
import aiohttp
from yarl import URL
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import re, time, os, json, csv, traceback, secrets

# --- Configuration ---
COMMON_DIRS = ["admin","login","api","assets","uploads","images","css","js","phpmyadmin","backup","backups","old","test","dev","dashboard","config","includes","cgi-bin"]
COMMON_FILES = ["index","index.php","index.html","home","readme","robots","sitemap","login","register"]
COMMON_EXTS = ["",".php",".html",".txt",".bak",".old",".zip"]
TOKEN_RE = re.compile(r"[A-Za-z0-9_\-]{3,60}")
SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark after the character string",
    r"sql syntax.*mysql",
    r"pg_query\(|psql: error",
    r"ora-01756",
    r"sqlstate",
]

# runtime state
SCANS = {}
REPORTS_DIR = os.path.join(os.getcwd(), 'reports')
os.makedirs(REPORTS_DIR, exist_ok=True)

app = Flask(__name__)

# --- HTTP utilities ---
async def fetch_text(session, url, timeout=15, verify_ssl=True, method='GET', data=None, headers=None):
    try:
        async with session.request(method, url, allow_redirects=True, timeout=timeout, ssl=verify_ssl, data=data, headers=headers or {}) as resp:
            text = await resp.text(errors='ignore')
            return resp.status, str(resp.url), text, dict(resp.headers)
    except Exception as e:
        return None, url, '', {'error': str(e)}

# --- Crawler ---
async def crawl_target(session, base_url, max_pages=100, depth=1, verify_ssl=True):
    base = URL(base_url)
    seen = set()
    q = [(str(base), 0)]
    collected = {'urls': set(), 'params': set(), 'form_inputs': set(), 'tokens': set(), 'found_paths': set()}
    while q:
        url, lvl = q.pop(0)
        if url in seen or lvl > depth or len(seen) >= max_pages:
            continue
        seen.add(url)
        status, final_url, text, headers = await fetch_text(session, url, verify_ssl=verify_ssl)
        if status is None:
            continue
        collected['urls'].add(final_url)
        parsed = urlparse(final_url)
        qs = parse_qs(parsed.query)
        for k in qs.keys(): collected['params'].add(k)
        soup = BeautifulSoup(text, 'lxml')
        for a in soup.find_all('a', href=True):
            href = a['href'].strip()
            try:
                joined = urljoin(final_url, href)
            except:
                continue
            if urlparse(joined).netloc == base.host:
                if joined not in seen:
                    q.append((joined, lvl+1))
        for form in soup.find_all('form'):
            for inp in form.find_all(['input','select','textarea']):
                if inp.has_attr('name'):
                    collected['form_inputs'].add(inp['name'])
        for tok in set(TOKEN_RE.findall(text)):
            if tok.lower() in ('http','https','src','href','javascript'): continue
            if re.fullmatch(r"\d{3,}", tok): continue
            if len(tok) < 3 or len(tok) > 60: continue
            collected['tokens'].add(tok)
        for link in soup.find_all(['link','script']):
            src = link.get('href') or link.get('src')
            if not src: continue
            joined = urljoin(final_url, src)
            p = urlparse(joined).path
            parts = [p for p in p.split('/') if p]
            for part in parts:
                if len(part) >= 3 and '.' not in part:
                    collected['found_paths'].add(part)
    for k in collected: collected[k] = sorted(collected[k])
    return collected

# --- Path generation ---
def generate_guess_paths(collected_tokens, collected_params, found_paths, extra_common=None, exts=None, limit=2000):
    exts = exts or COMMON_EXTS
    extra_common = extra_common or []
    guesses = set()
    for t in collected_tokens:
        guesses.add(t + '/')
        for e in exts:
            guesses.add(t + e)
            guesses.add(t + '/index' + e)
    for p in collected_params:
        guesses.add(p + '/')
        for e in exts:
            guesses.add(p + e)
            guesses.add(p + '/index' + e)
    for fp in found_paths:
        guesses.add(fp + '/')
        for e in exts:
            guesses.add(fp + e)
            guesses.add(fp + '/index' + e)
    commons = list(COMMON_DIRS) + extra_common
    for c in commons:
        guesses.add(c + '/')
        for t in list(collected_tokens)[:200]:
            guesses.add(c + '/' + t + '/')
            for e in exts:
                guesses.add(c + '/' + t + e)
    for f in COMMON_FILES:
        for e in exts:
            guesses.add(f + e)
    filtered = set()
    for g in guesses:
        if len(g) > 200: continue
        if '//' in g: g = g.replace('//','/')
        filtered.add(g)
    guesses_sorted = sorted(filtered)
    if limit and len(guesses_sorted) > limit:
        return guesses_sorted[:limit]
    return guesses_sorted

# --- Heuristics: XSS reflection, SQL error, LFI markers, cookie flags ---
async def check_xss_reflection(session, base_url, param, verify_ssl=True, timeout=10):
    token = 'scanref' + secrets.token_hex(6)
    url = str(URL(base_url).with_query({param: token}))
    status, final_url, text, headers = await fetch_text(session, url, timeout=timeout, verify_ssl=verify_ssl)
    if status and token in text:
        return True, {'probe_url': final_url, 'token': token, 'status': status}
    return False, {}

async def check_sql_error(session, base_url, param, verify_ssl=True, timeout=10):
    probe = "'"
    url = str(URL(base_url).with_query({param: probe}))
    status, final_url, text, headers = await fetch_text(session, url, timeout=timeout, verify_ssl=verify_ssl)
    if not status:
        return False, {}
    low = text.lower()
    for patt in SQL_ERROR_PATTERNS:
        if re.search(patt, low):
            return True, {'probe_url': final_url, 'status': status, 'matched': patt}
    return False, {}

def detect_lfi_indicators(text):
    low = text.lower()
    indicators = []
    if '/etc/passwd' in low or 'root:x:' in low:
        indicators.append('etc_passwd_marker')
    if '../' in low or 'file_get_contents' in low:
        indicators.append('path_traversal_artifact')
    return indicators

def detect_insecure_cookies(headers):
    flags = []
    cookies = headers.get('set-cookie','')
    if cookies:
        if 'httponly' not in cookies.lower(): flags.append('missing_httponly')
        if 'secure' not in cookies.lower(): flags.append('missing_secure')
    return flags

# --- Probe paths with basic checks and baseline fingerprinting ---
async def probe_paths_with_checks(session, base_url, paths, concurrency=40, timeout=20, verify_ssl=True, user_agent='param-dir/1.0'):
    sem = asyncio.Semaphore(concurrency)
    results = []
    # baseline 404 fingerprint
    try:
        async with session.get(str(URL(base_url) / '__this_path_should_not_exist_12345__'), timeout=timeout, ssl=verify_ssl) as r404:
            fp404 = (r404.status, (await r404.text(errors='ignore'))[:200])
    except:
        fp404 = (404, '')

    async def single(path):
        async with sem:
            try:
                base = str(base_url).rstrip('/')
                full = str(URL(base + '/' + path.lstrip('/')))
                async with session.get(full, allow_redirects=True, timeout=timeout, ssl=verify_ssl, headers={'User-Agent': user_agent}) as resp:
                    text = await resp.text(errors='ignore')
                    text_snip = text[:400]
                    headers = dict(resp.headers)
                    r = {'status': resp.status, 'url': str(resp.url), 'path_tested': path, 'length': len(text), 'snippet': text_snip}
                    if resp.status not in (404,410) and resp.status < 500:
                        if not (resp.status == fp404[0] and text_snip == fp404[1]):
                            flags = detect_insecure_cookies(headers)
                            if flags:
                                r['insecure_cookies'] = flags
                            lfi = detect_lfi_indicators(text)
                            if lfi:
                                r.setdefault('indicators',[]).extend(lfi)
                            results.append(r)
                    return r
            except Exception as e:
                return {'status': None, 'url': base_url, 'path_tested': path, 'error': str(e)}
    tasks = [asyncio.create_task(single(p)) for p in paths]
    for t in asyncio.as_completed(tasks):
        await t
    return results

# --- Orchestration ---
async def run_scan_job(job_id, config, progress_callback=None):
    try:
        SCANS[job_id]['status'] = 'running'
        SCANS[job_id]['started_at'] = time.time()
        targets = config.get('targets', [])
        out = {'generated_at': time.strftime('%Y-%m-%d %H:%M:%S'), 'results': []}
        timeout = aiohttp.ClientTimeout(total=None)
        connector = aiohttp.TCPConnector(limit=0)
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            for t in targets:
                if SCANS[job_id].get('stop_requested'):
                    break
                SCANS[job_id]['current_target'] = t
                collected = await crawl_target(session, t, max_pages=config.get('pages',100), depth=config.get('depth',1), verify_ssl=not config.get('insecure',False))
                tokens = list(collected.get('tokens', []))
                params = list(collected.get('params', []))
                found_paths = list(collected.get('found_paths', []))
                if config.get('wordlist'):
                    try:
                        with open(config['wordlist'], 'r', encoding='utf-8', errors='ignore') as fh:
                            extra = [l.strip() for l in fh if l.strip() and not l.startswith('#')]
                            tokens.extend(extra)
                    except:
                        pass
                guesses = generate_guess_paths(tokens, params, found_paths, extra_common=config.get('extra_common',[]), exts=config.get('exts',COMMON_EXTS), limit=config.get('max_guesses',1500))
                SCANS[job_id]['guesses_count'] = len(guesses)
                SCANS[job_id]['progress'] = 0
                results = await probe_paths_with_checks(session, t, guesses, concurrency=config.get('concurrency',40), timeout=config.get('timeout',20), verify_ssl=not config.get('insecure',False))

                # additional param checks heuristics (XSS/SQL) on collected params
                param_checks = []
                for p in params[:40]:  # limit param probes
                    if SCANS[job_id].get('stop_requested'): break
                    is_xss, xinfo = await check_xss_reflection(session, t, p, verify_ssl=not config.get('insecure',False))
                    if is_xss:
                        param_checks.append({'param': p, 'type': 'xss-like', 'info': xinfo})
                    is_sql, sinfo = await check_sql_error(session, t, p, verify_ssl=not config.get('insecure',False))
                    if is_sql:
                        param_checks.append({'param': p, 'type': 'sqli-like', 'info': sinfo})
                out['results'].append({'target': t, 'collected': collected, 'guesses_count': len(guesses), 'found': results, 'param_checks': param_checks})
                SCANS[job_id]['last_result_count'] = len(results)
            # save report
            fname = os.path.join(REPORTS_DIR, f"scan_{job_id}.json")
            with open(fname, 'w', encoding='utf-8') as fh:
                json.dump(out, fh, indent=2, ensure_ascii=False)
            SCANS[job_id]['report_json'] = fname
            # CSV
            csvf = os.path.join(REPORTS_DIR, f"scan_{job_id}.csv")
            with open(csvf, 'w', newline='', encoding='utf-8') as cf:
                writer = csv.writer(cf)
                writer.writerow(['target','path_tested','status','url','length','snippet','indicators'])
                for rset in out['results']:
                    tgt = rset['target']
                    for row in rset['found']:
                        inds = ' | '.join(row.get('indicators',[])) if row.get('indicators') else ''
                        writer.writerow([tgt, row.get('path_tested'), row.get('status'), row.get('url'), row.get('length'), row.get('snippet'), inds])
            SCANS[job_id]['report_csv'] = csvf
        SCANS[job_id]['status'] = 'finished'
        SCANS[job_id]['finished_at'] = time.time()
    except Exception as e:
        SCANS[job_id]['status'] = 'error'
        SCANS[job_id]['error'] = traceback.format_exc()

# --- Flask UI (dark neon) ---
INDEX_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>TOM7X DIR INSPECTOR</title>
  <style>
    body{background:#07090b;color:#dff6ff;font-family:Inter,Arial;margin:18px}
    .card{background:linear-gradient(180deg, rgba(255,255,255,0.02), rgba(0,0,0,0.16));padding:14px;border-radius:10px;box-shadow:0 8px 30px rgba(0,0,0,0.6)}
    h1{color:#bdf6ff;margin:0 0 10px}
    textarea{width:100%;height:110px;background:#03121a;border:1px solid #063447;color:#dff6ff;padding:8px;border-radius:8px}
    input, select{background:#03121a;border:1px solid #063447;color:#dff6ff;padding:6px;border-radius:6px}
    .neon-btn{background:none;border:2px solid #00fff0;color:#00fff0;padding:8px 12px;border-radius:8px;cursor:pointer;box-shadow:0 0 12px rgba(0,255,240,0.08)}
    .neon-btn:hover{box-shadow:0 0 22px rgba(0,255,240,0.18);transform:translateY(-2px)}
    table{width:100%;border-collapse:collapse;margin-top:12px}
    th,td{padding:8px;border-bottom:1px solid rgba(255,255,255,0.03);text-align:left}
    .muted{color:#7aa3ad}
    .tag{display:inline-block;padding:4px 8px;border-radius:6px;background:#02262b;color:#bffaf3;margin-right:6px}
  </style>
</head>
<body>
  <div class="card">
    <h1>TOM7X-DIR-INSPECTOR &and; LOGGER</h1>
    <form id="startForm" method=post action="/start">
      <label>Targets (one per line, include scheme e.g. https://):</label><br>
      <textarea name=targets></textarea><br>
      <label>Optional server-side wordlist path:</label> <input name=wordlist size=40> <label class="muted">(optional)</label><br>
      <label>Concurrency:</label> <input name=concurrency value=40 size=4> &nbsp; <label>Timeout(s):</label> <input name=timeout value=20 size=4><br>
      <label>Depth:</label> <input name=depth value=1 size=2> &nbsp; <label>Pages:</label> <input name=pages value=100 size=4>
      &nbsp; <label>Max guesses/target:</label> <input name=max_guesses value=1500 size=6>
      <label> Insecure TLS: <input type=checkbox name=insecure></label><br><br>
      <button class="neon-btn">Start scan</button>
    </form>

    <h3 style="margin-top:14px">Active / Recent scans</h3>
    <div id="scans"></div>

    <h3 style="margin-top:14px">Filters & Reports</h3>
    <label>Job ID: <input id="filter_job" size=20></label>
    <label>Vuln type: <select id="filter_type"><option value="all">All</option><option value="xss-like">XSS-like</option><option value="sqli-like">SQLi-like</option><option value="lfi-indicator">LFI-indicator</option><option value="insecure-cookie">Insecure-Cookie</option></select></label>
    <button class="neon-btn" onclick="loadFiltered();return false;">Load filtered results</button>

    <div id="results_area"></div>
  </div>

<script>
async function refreshScans(){
  const r = await fetch('/list_jobs');
  const data = await r.json();
  const container = document.getElementById('scans');
  container.innerHTML='';
  for(const id in data){
    const s = data[id];
    const div = document.createElement('div'); div.className='card'; div.style.marginTop='8px';
    div.innerHTML = `<b>ID:</b> ${id} — <span class='muted'>status:</span> ${s.status} — <span class='muted'>targets:</span> ${s.targets_count} — <span class='muted'>found:</span> ${s.last_result_count} — <a href='/report/${id}'>report</a> &nbsp; <button onclick="download('${id}','json')" class='neon-btn'>JSON</button> <button onclick="download('${id}','csv')" class='neon-btn'>CSV</button>`;
    container.appendChild(div);
  }
}
async function download(id,fmt){ window.location = `/download/${id}/`+fmt; }
async function loadFiltered(){
  const job = document.getElementById('filter_job').value.trim();
  const type = document.getElementById('filter_type').value;
  if(!job){ alert('Enter job id'); return; }
  const r = await fetch(`/filtered/${job}?type=${type}`);
  if(r.status!=200){ alert('failed to load'); return; }
  const data = await r.json();
  const area = document.getElementById('results_area'); area.innerHTML='';
  if(!data.results || data.results.length==0){ area.innerHTML='<i>No findings</i>'; return; }
  let html = '<table><tr><th>Target</th><th>Path / Probe</th><th>Status</th><th>Type</th><th>Snippet</th></tr>';
  for(const rset of data.results){
    for(const f of rset.found){
      const types = f.indicators ? f.indicators.join(',') : (f.insecure_cookies? 'insecure_cookie':'');
      let include = (type=='all') || (types && types.includes(type.split('-').shift()));
      if(type=='xss-like' && rset.param_checks){
        for(const p of rset.param_checks){ if(p.type=='xss-like'){ include=true; html += `<tr><td>${rset.target}</td><td>${p.info.probe_url}</td><td>param</td><td>XSS-like</td><td>${p.info.token}</td></tr>`; } }
      }
      if(include){ html += `<tr><td>${rset.target}</td><td>${f.path_tested||''}</td><td>${f.status||''}</td><td>${types||''}</td><td><code>${(f.snippet||'').slice(0,200)}</code></td></tr>`; }
    }
  }
  html += '</table>';
  area.innerHTML = html;
}
setInterval(refreshScans,3000); refreshScans();
</script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(INDEX_HTML)

@app.route('/list_jobs')
def list_jobs():
    return jsonify({k:{'status':v.get('status'),'targets_count':v.get('targets_count'),'last_result_count':v.get('last_result_count')} for k,v in SCANS.items()})

@app.route('/start', methods=['POST'])
def start_scan():
    targets_text = request.form.get('targets','').strip()
    if not targets_text:
        return 'No targets provided', 400
    targets = [l.strip() for l in targets_text.splitlines() if l.strip()]
    norm = []
    for t in targets:
        if not t.startswith('http'):
            t = 'https://' + t
        norm.append(t.rstrip('/'))
    job_id = str(int(time.time()))
    config = {
        'targets': norm,
        'wordlist': request.form.get('wordlist') or None,
        'concurrency': int(request.form.get('concurrency') or 40),
        'timeout': int(request.form.get('timeout') or 20),
        'depth': int(request.form.get('depth') or 1),
        'pages': int(request.form.get('pages') or 100),
        'max_guesses': int(request.form.get('max_guesses') or 1500),
        'insecure': bool(request.form.get('insecure'))
    }
    SCANS[job_id] = {'status':'queued','config':config,'targets_count':len(norm),'guesses_count':0,'last_result_count':0,'progress':0,'stop_requested':False}
    t = threading.Thread(target=lambda: asyncio.run(run_scan_job(job_id, config)), daemon=True)
    t.start()
    return f'Scan started, job id: {job_id}. <a href="/">Back</a>'

@app.route('/filtered/<job_id>')
def filtered(job_id):
    sfile = SCANS.get(job_id,{}).get('report_json')
    if not sfile or not os.path.isfile(sfile):
        return jsonify({'error':'report not ready'}), 404
    with open(sfile,'r',encoding='utf-8') as fh:
        data = json.load(fh)
    return jsonify(data)

@app.route('/report/<job_id>')
def report(job_id):
    s = SCANS.get(job_id)
    if not s:
        return 'Unknown job id', 404
    out = '<h3>Report for job %s</h3>' % job_id
    out += f"Status: {s.get('status')}<br>"
    if s.get('status') == 'finished' and s.get('report_json'):
        out += f"JSON: <a href='/download/{job_id}/json'>download</a> — CSV: <a href='/download/{job_id}/csv'>download</a>\n"
    if s.get('status') == 'error':
        out += '<pre>' + (s.get('error') or 'error') + '</pre>'
    out += '<br><a href="/">Back</a>'
    return out

@app.route('/download/<job_id>/<fmt>')
def download(job_id, fmt):
    s = SCANS.get(job_id)
    if not s:
        return 'Unknown job id', 404
    if fmt == 'json' and s.get('report_json'):
        return send_file(s['report_json'], as_attachment=True)
    if fmt == 'csv' and s.get('report_csv'):
        return send_file(s['report_csv'], as_attachment=True)
    return 'File not available', 404

@app.route('/stop/<job_id>', methods=['POST'])
def stop_job(job_id):
    s = SCANS.get(job_id)
    if not s:
        return 'Unknown job id', 404
    s['stop_requested'] = True
    return 'Stop requested'

if __name__ == '__main__':
    print('Param-Dir Auto GUI (final) running at http://127.0.0.1:5000')
    print('Reports folder:', REPORTS_DIR)
    app.run(host='0.0.0.0', port=4444, debug=True, threaded=True)
