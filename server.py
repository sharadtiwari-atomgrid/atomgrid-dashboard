#!/usr/bin/env python3
"""Atomgrid Domestic MIS Dashboard — Render-ready Flask server with Google Workspace access control."""
import os
import secrets
import urllib.parse
import urllib.request
import urllib.error

from flask import Flask, Response, jsonify, redirect, render_template_string, request, session, send_from_directory, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

try:
    import requests
    from google.auth.transport import requests as google_requests
    from google.oauth2 import id_token
except ImportError:  # pragma: no cover
    requests = None
    google_requests = None
    id_token = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, static_folder=BASE_DIR, static_url_path='')
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# ---------------------------------------------------------------------------
# Authentication configuration
# ---------------------------------------------------------------------------
# Anyone whose Google account email ends with @atomgrid.in is allowed.
# Keep the domain configurable so it can be changed without editing code.
ALLOWED_EMAIL_DOMAIN = os.environ.get('ALLOWED_EMAIL_DOMAIN', 'atomgrid.in').strip().lower().lstrip('@')
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', '').strip()
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '').strip()
GOOGLE_REDIRECT_URI = os.environ.get('GOOGLE_REDIRECT_URI', '').strip()
SESSION_SECRET = os.environ.get('SESSION_SECRET', '').strip()

app.secret_key = SESSION_SECRET or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=60 * 60 * 12,
)

# Google only returns to an explicitly registered redirect URI. If not set,
# derive it from the public Render request URL; configure GOOGLE_REDIRECT_URI
# in production for a fixed, predictable value.
def oauth_redirect_uri():
    return GOOGLE_REDIRECT_URI or url_for('oauth_callback', _external=True)


def auth_configured():
    return bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)


def user_allowed(email):
    email = (email or '').strip().lower()
    return bool(email and '@' in email and email.rsplit('@', 1)[1] == ALLOWED_EMAIL_DOMAIN)


def login_url():
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state
    session.permanent = True
    params = {
        'client_id': GOOGLE_CLIENT_ID,
        'redirect_uri': oauth_redirect_uri(),
        'response_type': 'code',
        'scope': 'openid email profile',
        'state': state,
        'prompt': 'select_account',
    }
    return 'https://accounts.google.com/o/oauth2/v2/auth?' + urllib.parse.urlencode(params)


LOGIN_PAGE = r"""<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Atomgrid Dashboard — Sign in</title>
<style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f5f3ee;color:#17243a;font-family:Inter,system-ui,-apple-system,Segoe UI,Arial,sans-serif}
.card{width:min(440px,calc(100% - 32px));background:#fff;border:1px solid #e1ddd2;border-radius:18px;padding:34px;box-shadow:0 10px 35px rgba(23,36,58,.08);text-align:center}
.logo{width:46px;height:46px;margin:0 auto 18px;border-radius:12px;background:#17243a;color:#fff;display:grid;place-items:center;font-weight:800;font-size:20px}
h1{font-size:23px;margin:0 0 8px}p{margin:0 0 24px;color:#657084;font-size:14px;line-height:1.5}
.input{width:100%;padding:12px 14px;border:1px solid #d7d9df;border-radius:10px;font:inherit;font-size:15px;outline:none}.input:focus{border-color:#17243a;box-shadow:0 0 0 3px rgba(23,36,58,.08)}
.btn{display:inline-flex;align-items:center;justify-content:center;width:100%;padding:12px 16px;margin-top:12px;border:0;border-radius:10px;background:#17243a;color:#fff;font-weight:650;font-size:15px;cursor:pointer}
.note{margin-top:16px;font-size:12px;color:#8a93a2}.err{margin:0 0 18px;padding:10px 12px;border-radius:9px;background:#fff0ef;color:#a23b35;font-size:13px}
</style></head><body><main class="card"><div class="logo">AG</div><h1>Atomgrid Dashboard</h1><p>Enter your Atomgrid email address to access the dashboard.</p>
{% if error %}<div class="err">{{ error }}</div>{% endif %}
<form method="post" action="{{ url_for('login') }}">
<input class="input" type="email" name="email" placeholder="name@atomgrid.in" autocomplete="email" required>
<button class="btn" type="submit">Continue</button>
</form>
<div class="note">Access is limited to @{{ domain }} email addresses.</div></main></body></html>"""


@app.before_request
def require_auth():
    # Public endpoints needed for Render health checks and OAuth itself.
    if request.path == '/health' or request.path.startswith('/auth/'):
        return None
    if session.get('user'):
        return None
    return redirect(url_for('login', next=request.full_path if request.query_string else request.path))


@app.after_request
def add_no_cache_headers(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    return response


@app.get('/health')
def health():
    return jsonify(status='ok', service='atomgrid-dashboard')


@app.route('/auth/login', methods=['GET', 'POST'])
def login():
    if session.get('user'):
        return redirect(url_for('index'))
    error = request.args.get('error')
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        if not user_allowed(email):
            error = f'Please use an email address ending in @{ALLOWED_EMAIL_DOMAIN}.'
        else:
            session.clear()
            session.permanent = True
            session['user'] = {
                'email': email,
                'name': email.split('@')[0],
            }
            return redirect(request.args.get('next') or url_for('index'))
    return render_template_string(LOGIN_PAGE, error=error, domain=ALLOWED_EMAIL_DOMAIN)


@app.get('/auth/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


DEFAULT_PUBLISHED_CSV_URL = 'https://docs.google.com/spreadsheets/d/e/2PACX-1vRexCOYViGE7Jk8t95Yr7t_NaxZcyrZzguKD9hN6MBRHcONsneckfFMpOki6xYlHFE3Evx8CdbTZz_R/pub?gid=0&single=true&output=csv'


@app.get('/api/sheet-csv')
def sheet_csv():
    sheet_id = (request.args.get('sheet_id') or '').strip()
    gid = (request.args.get('gid') or '').strip()
    tab = (request.args.get('tab') or '').strip()
    published_url = (request.args.get('published_url') or DEFAULT_PUBLISHED_CSV_URL).strip()

    if not sheet_id and not published_url:
        return jsonify(error='Missing Google Sheet connection details'), 400

    candidates = []
    if published_url:
        try:
            p = urllib.parse.urlparse(published_url)
            if p.scheme in ('http', 'https') and p.netloc == 'docs.google.com':
                path = p.path
                existing_q = urllib.parse.parse_qs(p.query)
                if existing_q.get('output', [''])[0].lower() == 'csv':
                    existing_q['_'] = [os.urandom(6).hex()]
                    candidates.append(urllib.parse.urlunparse((p.scheme, p.netloc, path, '', urllib.parse.urlencode(existing_q, doseq=True), '')))
                if '/pubhtml' in path:
                    path = path.replace('/pubhtml', '/pub')
                elif not path.endswith('/pub') and '/spreadsheets/d/e/' in path:
                    path = path.rstrip('/') + '/pub'
                q = urllib.parse.parse_qs(p.query)
                if gid:
                    q['gid'] = [gid]
                q['single'] = ['true']
                q['output'] = ['csv']
                q['_'] = [os.urandom(6).hex()]
                candidates.append(urllib.parse.urlunparse((p.scheme, p.netloc, path, '', urllib.parse.urlencode(q, doseq=True), '')))
        except Exception:
            pass

    if sheet_id.startswith('2PACX-'):
        g = gid or '0'
        candidates.append(f'https://docs.google.com/spreadsheets/d/e/{urllib.parse.quote(sheet_id, safe="")}/pub?gid={urllib.parse.quote(g, safe="")}&single=true&output=csv&_={os.urandom(6).hex()}')

    if sheet_id and not sheet_id.startswith('2PACX-'):
        if gid:
            gid_q = urllib.parse.quote(gid, safe='')
            candidates.append(f'https://docs.google.com/spreadsheets/d/{sheet_id}/gviz/tq?tqx=out:csv&gid={gid_q}&_={os.urandom(6).hex()}')
            candidates.append(f'https://docs.google.com/spreadsheets/d/{sheet_id}/export?format=csv&gid={gid_q}&_={os.urandom(6).hex()}')
        elif tab:
            tab_q = urllib.parse.quote(tab, safe='')
            candidates.append(f'https://docs.google.com/spreadsheets/d/{sheet_id}/gviz/tq?tqx=out:csv&sheet={tab_q}&_={os.urandom(6).hex()}')
        else:
            candidates.append(f'https://docs.google.com/spreadsheets/d/{sheet_id}/gviz/tq?tqx=out:csv&_={os.urandom(6).hex()}')
            candidates.append(f'https://docs.google.com/spreadsheets/d/{sheet_id}/export?format=csv&_={os.urandom(6).hex()}')

    last_error = None
    for url in candidates:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 AtomgridDashboard/1.0', 'Cache-Control': 'no-cache', 'Accept': 'text/csv,text/plain,*/*'})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read()
                content_type = resp.headers.get('Content-Type', '')
            if not data:
                last_error = 'Google returned an empty response.'
                continue
            if b'<html' in data[:1000].lower() or 'text/html' in content_type.lower():
                last_error = 'Google returned HTML instead of CSV. Confirm the tab is published to web.'
                continue
            return Response(data, status=200, mimetype='text/csv')
        except urllib.error.HTTPError as exc:
            last_error = f'HTTP {exc.code} from Google'
        except Exception as exc:
            last_error = str(exc)
    return jsonify(error='Could not fetch the Google Sheet. ' + (last_error or 'Unknown error') + ' Use the published-to-web URL (ending in /pubhtml) or publish the exact tab as CSV.'), 502


@app.get('/')
def index():
    return send_from_directory(BASE_DIR, 'index.html')


@app.get('/<path:path>')
def static_files(path):
    return send_from_directory(BASE_DIR, path)


if __name__ == '__main__':
    port = int(os.environ.get('PORT', '10000'))
    app.run(host='0.0.0.0', port=port)
