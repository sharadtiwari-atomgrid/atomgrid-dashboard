#!/usr/bin/env python3
"""Atomgrid Domestic MIS Dashboard — Render-ready Flask server with Google Workspace access control."""
import os
import secrets
import urllib.parse
import urllib.request
import urllib.error

from flask import Flask, Response, jsonify, redirect, render_template_string, request, session, send_from_directory, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

import base64
import hashlib
import hmac
import json
import threading
from datetime import datetime, timezone

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:  # pragma: no cover
    serialization = padding = Cipher = algorithms = modes = None

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

# E-Way Bill API configuration. Keep all credentials on the backend/Render.
EWB_API_BASE_URL = os.environ.get('EWB_API_BASE_URL', '').strip().rstrip('/')
EWB_AUTH_PATH = os.environ.get('EWB_AUTH_PATH', '/v1.03/auth').strip()
EWB_GET_PATH = os.environ.get('EWB_GET_PATH', '/v1.03/ewayapi/GetEwayBill').strip()
EWB_CLIENT_ID = os.environ.get('EWB_CLIENT_ID', '').strip()
EWB_CLIENT_SECRET = os.environ.get('EWB_CLIENT_SECRET', '').strip()
EWB_GSTIN = os.environ.get('EWB_GSTIN', '').strip().upper()
EWB_USERNAME = os.environ.get('EWB_USERNAME', '').strip()
EWB_PASSWORD = os.environ.get('EWB_PASSWORD', '').strip()
EWB_PUBLIC_KEY = os.environ.get('EWB_PUBLIC_KEY', '').strip()
EWB_TIMEOUT_SECONDS = int(os.environ.get('EWB_TIMEOUT_SECONDS', '30'))
VAYANA_BASE_URL = os.environ.get('VAYANA_BASE_URL', 'https://solo.enriched-api.vayana.com').strip().rstrip('/')
VAYANA_AUTH_URL = os.environ.get('VAYANA_AUTH_URL', 'https://sandbox.services.vayananet.com/theodore/apis/v1/authtokens').strip().rstrip('/')
VAYANA_EMAIL = os.environ.get('VAYANA_EMAIL', '').strip()
VAYANA_PASSWORD = os.environ.get('VAYANA_PASSWORD', '').strip()
VAYANA_ORG_ID = os.environ.get('VAYANA_ORG_ID', '').strip()
VAYANA_USER_TOKEN = os.environ.get('VAYANA_USER_TOKEN', '').strip()
VAYANA_EWB_GSTIN = os.environ.get('VAYANA_EWB_GSTIN', '').strip().upper()
VAYANA_EWB_USERNAME = os.environ.get('VAYANA_EWB_USERNAME', '').strip()
VAYANA_EWB_PASSWORD = os.environ.get('VAYANA_EWB_PASSWORD', '').strip()
VAYANA_EWB_GSP_CODE = os.environ.get('VAYANA_EWB_GSP_CODE', 'vay').strip()
VAYANA_EWB_PROVIDER = os.environ.get('VAYANA_EWB_PROVIDER', 'ew1').strip()
VAYANA_TIMEOUT_SECONDS = int(os.environ.get('VAYANA_TIMEOUT_SECONDS', '30'))

_ewb_token = {'authtoken': '', 'sek': b'', 'expires_at': 0}
_ewb_token_lock = threading.Lock()
_vayana_token = {'token': '', 'org_id': '', 'expires_at': 0}
_vayana_token_lock = threading.Lock()

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


def _vayana_configured():
    return bool(
        requests
        and VAYANA_EMAIL
        and VAYANA_PASSWORD
        and VAYANA_EWB_GSTIN
        and VAYANA_EWB_USERNAME
        and VAYANA_EWB_PASSWORD
    )


def _ewb_configured():
    return all([EWB_API_BASE_URL, EWB_CLIENT_ID, EWB_CLIENT_SECRET, EWB_GSTIN, EWB_USERNAME, EWB_PASSWORD, EWB_PUBLIC_KEY]) and bool(Cipher and serialization and padding)


def _aes_ecb_decrypt(ciphertext_b64, key):
    raw = base64.b64decode(ciphertext_b64)
    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    padded = decryptor.update(raw) + decryptor.finalize()
    pad_len = padded[-1]
    if pad_len < 1 or pad_len > 16 or padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError('Invalid AES padding from E-Way Bill API')
    return padded[:-pad_len]


def _rsa_encrypt_base64(data_b64_text):
    key_text = EWB_PUBLIC_KEY
    if 'BEGIN PUBLIC KEY' in key_text:
        public_key = serialization.load_pem_public_key(key_text.encode('utf-8'))
    else:
        public_key = serialization.load_der_public_key(base64.b64decode(key_text))
    encrypted = public_key.encrypt(data_b64_text.encode('utf-8'), padding.PKCS1v15())
    return base64.b64encode(encrypted).decode('ascii')


def _vayana_authenticate():
    now = datetime.now(timezone.utc).timestamp()
    with _vayana_token_lock:
        if _vayana_token['token'] and now < _vayana_token['expires_at']:
            return _vayana_token['token'], _vayana_token['org_id']

        response = requests.post(
            VAYANA_AUTH_URL + '/authtokens',
            json={
                'handle': VAYANA_EMAIL,
                'password': VAYANA_PASSWORD,
                'handleType': 'email',
                'tokenDurationInMins': 360,
            },
            headers={'Content-Type': 'application/json', 'Accept': 'application/json'},
            timeout=VAYANA_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        body = response.json()
        data = body.get('data') or {}
        token = data.get('token')
        associated = data.get('associatedOrgs') or []
        org_id = VAYANA_ORG_ID
        if not org_id and associated:
            org = associated[0].get('organisation') or {}
            org_id = org.get('id') or ''
        if not token or not org_id:
            raise RuntimeError('Vayana authentication succeeded but token or organisation ID was not returned.')
        expiry = data.get('expiry')
        expires_at = float(expiry) if expiry else now + (350 * 60)
        _vayana_token.update({'token': token, 'org_id': org_id, 'expires_at': expires_at})
        return token, org_id


def _vayana_get_details(ewb_no):
    token, org_id = _vayana_authenticate()
    url = VAYANA_BASE_URL + '/basic/eway/v3.0/' + urllib.parse.quote(VAYANA_EWB_PROVIDER, safe='') + '/v1.03/ewayapi/GetEwayBill'
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'X-FLYNN-N-ORG-ID': org_id,
        'X-FLYNN-N-USER-TOKEN': token,
        'X-FLYNN-N-EWB-GSP-CODE': VAYANA_EWB_GSP_CODE,
        'X-FLYNN-N-EWB-GSTIN': VAYANA_EWB_GSTIN,
        'X-FLYNN-N-EWB-USERNAME': VAYANA_EWB_USERNAME,
        'X-FLYNN-N-EWB-PWD': VAYANA_EWB_PASSWORD,
    }
    response = requests.get(
        url,
        params={'ewbNo': ewb_no},
        headers=headers,
        timeout=VAYANA_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    body = response.json()
    if str(body.get('status', '0')) != '1':
        error = body.get('error') or body.get('errorDetails') or body.get('additionalInfo') or body
        raise RuntimeError('Vayana EWB lookup failed: ' + json.dumps(error))
    return body.get('data') or body


def _vayana_normalize(details):
    vehicles = details.get('VehiclListDetails') or details.get('vehicleListDetails') or []
    latest_vehicle = vehicles[-1] if vehicles else {}
    return {
        'success': True,
        'provider': 'vayana',
        'status': details.get('status'),
        'ewbNo': details.get('ewbNo') or details.get('EwbNo') or details.get('ewayBillNo'),
        'vehicleNo': latest_vehicle.get('vehicleNo') or details.get('vehicleNo'),
        'fromPlace': latest_vehicle.get('fromPlace') or details.get('fromPlace'),
        'toPlace': details.get('toPlace'),
        'actualDist': details.get('actualDist'),
        'validUpto': details.get('validUpto'),
        'lastUpdated': latest_vehicle.get('enteredDate') or details.get('ewayBillDate'),
        'transporterName': details.get('transporterName'),
        'transporterId': details.get('transporterId'),
        'vehicleUpdates': vehicles,
        'raw': details,
    }


@app.get('/api/vayana-test')
def vayana_test():
    if not _vayana_configured():
        return jsonify(success=False, configured=False, error='Vayana credentials are not configured on the Render backend.'), 503
    try:
        token, org_id = _vayana_authenticate()
        return jsonify(success=True, provider='vayana', organisationId=org_id, tokenConfigured=bool(token))
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else 502
        return jsonify(success=False, provider='vayana', error=f'Vayana authentication returned HTTP {status}.'), 502
    except Exception as exc:
        app.logger.exception('Vayana authentication test failed')
        return jsonify(success=False, provider='vayana', error=str(exc)), 502


def _ewb_authenticate():
    now = datetime.now(timezone.utc).timestamp()
    with _ewb_token_lock:
        if _ewb_token['authtoken'] and _ewb_token['sek'] and now < _ewb_token['expires_at']:
            return _ewb_token['authtoken'], _ewb_token['sek']
        app_key = os.urandom(32)
        app_key_b64 = base64.b64encode(app_key).decode('ascii')
        auth_json = json.dumps({'action': 'ACCESSTOKEN', 'username': EWB_USERNAME, 'password': EWB_PASSWORD, 'app_key': app_key_b64}, separators=(',', ':'))
        encoded_auth = base64.b64encode(auth_json.encode('utf-8')).decode('ascii')
        response = requests.post(
            EWB_API_BASE_URL + EWB_AUTH_PATH,
            json={'Data': _rsa_encrypt_base64(encoded_auth)},
            headers={'client-id': EWB_CLIENT_ID, 'client-secret': EWB_CLIENT_SECRET, 'gstin': EWB_GSTIN, 'Content-Type': 'application/json'},
            timeout=EWB_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        body = response.json()
        if str(body.get('status', '0')) != '1':
            raise RuntimeError('E-Way Bill authentication failed: ' + json.dumps(body.get('errorDetails') or body.get('error') or body))
        data = body.get('data') if isinstance(body.get('data'), dict) else body
        authtoken = data.get('authToken') or data.get('authtoken')
        encrypted_sek = data.get('sek') or data.get('Sek')
        if not authtoken or not encrypted_sek:
            raise RuntimeError('E-Way Bill authentication response did not contain authtoken/sek')
        sek = _aes_ecb_decrypt(encrypted_sek, app_key)
        _ewb_token.update({'authtoken': authtoken, 'sek': sek, 'expires_at': now + (350 * 60)})
        return authtoken, sek


def _ewb_get_details(ewb_no):
    authtoken, sek = _ewb_authenticate()
    response = requests.get(
        EWB_API_BASE_URL + EWB_GET_PATH,
        params={'ewbNo': ewb_no},
        headers={'client-id': EWB_CLIENT_ID, 'client-secret': EWB_CLIENT_SECRET, 'gstin': EWB_GSTIN, 'authtoken': authtoken, 'Content-Type': 'application/json'},
        timeout=EWB_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    body = response.json()
    if str(body.get('status', '0')) != '1':
        raise RuntimeError('E-Way Bill lookup failed: ' + json.dumps(body.get('errorDetails') or body.get('error') or body))
    encrypted_rek = body.get('rek')
    encrypted_data = body.get('data')
    if not encrypted_rek or not encrypted_data:
        raise RuntimeError('E-Way Bill response is missing encrypted data')
    rek = _aes_ecb_decrypt(encrypted_rek, sek)
    encoded_data = _aes_ecb_decrypt(encrypted_data, rek)
    expected_hmac = base64.b64encode(hmac.new(rek, encoded_data, hashlib.sha256).digest()).decode('ascii')
    supplied_hmac = body.get('hmac') or ''
    if supplied_hmac and not hmac.compare_digest(supplied_hmac, expected_hmac):
        raise RuntimeError('E-Way Bill response HMAC verification failed')
    return json.loads(base64.b64decode(encoded_data).decode('utf-8'))


def _ewb_normalize(details):
    vehicles = details.get('VehiclListDetails') or details.get('vehicleListDetails') or []
    latest_vehicle = vehicles[-1] if vehicles else {}
    return {
        'success': True,
        'status': details.get('status'),
        'ewbNo': details.get('ewbNo') or details.get('ewayBillNo'),
        'vehicleNo': latest_vehicle.get('vehicleNo') or details.get('vehicleNo'),
        'fromPlace': latest_vehicle.get('fromPlace') or details.get('fromPlace'),
        'toPlace': details.get('toPlace'),
        'actualDist': details.get('actualDist'),
        'validUpto': details.get('validUpto'),
        'lastUpdated': latest_vehicle.get('enteredDate') or details.get('ewayBillDate'),
        'vehicleUpdates': vehicles,
    }


@app.get('/api/ewaybill-details')
def ewaybill_details():
    ewb_no = ''.join(ch for ch in (request.args.get('ewb_no') or '').strip() if ch.isdigit())
    if len(ewb_no) != 12:
        return jsonify(success=False, error='E-Way Bill number must be a 12-digit number.'), 400
    if _vayana_configured():
        try:
            return jsonify(_vayana_normalize(_vayana_get_details(ewb_no)))
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else 502
            return jsonify(success=False, provider='vayana', error=f'Vayana EWB API returned HTTP {status}.'), 502
        except Exception as exc:
            app.logger.exception('Vayana EWB lookup failed for %s', ewb_no)
            return jsonify(success=False, provider='vayana', error=str(exc)), 502

    if not _ewb_configured():
        return jsonify(success=False, configured=False, error='Vayana EWB credentials are not configured on the Render backend.'), 503
    try:
        return jsonify(_ewb_normalize(_ewb_get_details(ewb_no)))
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else 502
        return jsonify(success=False, error=f'E-Way Bill API returned HTTP {status}.'), 502
    except Exception as exc:
        app.logger.exception('E-Way Bill lookup failed for %s', ewb_no)
        return jsonify(success=False, error=str(exc)), 502


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


@app.get('/transporter-finder')
def transporter_finder():
    return send_from_directory(BASE_DIR, 'transporter_finder.html')


@app.get('/<path:path>')
def static_files(path):
    return send_from_directory(BASE_DIR, path)


if __name__ == '__main__':
    port = int(os.environ.get('PORT', '10000'))
    app.run(host='0.0.0.0', port=port)
