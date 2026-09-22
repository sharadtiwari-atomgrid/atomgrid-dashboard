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
except ImportError:  # pragma: no cover
    requests = None

try:
    from google.auth.transport import requests as google_requests
    from google.oauth2 import id_token
except ImportError:  # pragma: no cover
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
# ClearTax E-Way Bill API configuration. Keep credentials on Render.
CLEARTAX_API_BASE_URL = os.environ.get('CLEARTAX_API_BASE_URL', 'https://api.cleartax.in').strip().rstrip('/')
CLEARTAX_EWB_PATH = os.environ.get('CLEARTAX_EWB_PATH', '/einv/v1/ewaybill/sync').strip()
CLEARTAX_AUTH_TOKEN = os.environ.get('CLEARTAX_AUTH_TOKEN', '').strip()
CLEARTAX_GSTIN = os.environ.get('CLEARTAX_GSTIN', '').strip().upper()
CLEARTAX_TIMEOUT_SECONDS = int(os.environ.get('CLEARTAX_TIMEOUT_SECONDS', '30'))
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
# Backend-only provider selection; the frontend keeps one stable EWB endpoint.
EWB_PROVIDER = os.environ.get('EWB_PROVIDER', 'cleartax').strip().lower()
EWB_FALLBACK_PROVIDER = os.environ.get('EWB_FALLBACK_PROVIDER', '').strip().lower()
PERIONE_BASE_URL = os.environ.get('PERIONE_BASE_URL', 'https://staging.perione.in').strip().rstrip('/')
PERIONE_AUTH_PATH = os.environ.get('PERIONE_AUTH_PATH', '/ewaybillapi/v1.03/authenticate').strip()
PERIONE_EWB_PATH = os.environ.get('PERIONE_EWB_PATH', '/ewaybillapi/v1.03/ewayapi/GetEwayBill').strip()
PERIONE_EMAIL = os.environ.get('PERIONE_EMAIL', '').strip()
PERIONE_GSTIN = os.environ.get('PERIONE_GSTIN', '').strip().upper()
PERIONE_USERNAME = os.environ.get('PERIONE_USERNAME', '').strip()
PERIONE_PASSWORD = os.environ.get('PERIONE_PASSWORD', '').strip()
PERIONE_IP_ADDRESS = os.environ.get('PERIONE_IP_ADDRESS', '').strip()
PERIONE_CLIENT_ID = os.environ.get('PERIONE_CLIENT_ID', '').strip()
PERIONE_CLIENT_SECRET = os.environ.get('PERIONE_CLIENT_SECRET', '').strip()
PERIONE_TOKEN = os.environ.get('PERIONE_TOKEN', '').strip()
PERIONE_TIMEOUT_SECONDS = int(os.environ.get('PERIONE_TIMEOUT_SECONDS', '30'))
_perione_token = {'token': '', 'expires_at': 0}
_perione_token_lock = threading.Lock()

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
    if request.path in ('/health', '/api/vayana-config-status') or request.path.startswith('/auth/'):
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


def _cleartax_configured():
    return bool(CLEARTAX_AUTH_TOKEN and CLEARTAX_GSTIN and requests is not None)


def _cleartax_get_details(ewb_no):
    """Fetch the latest government E-Way Bill status through ClearTax."""
    url = CLEARTAX_API_BASE_URL + CLEARTAX_EWB_PATH
    response = requests.get(
        url,
        params={'ewb_number': ewb_no},
        headers={
            'X-Cleartax-Auth-Token': CLEARTAX_AUTH_TOKEN,
            'x-cleartax-product': 'EInvoice',
            'gstin': CLEARTAX_GSTIN,
            'Accept': 'application/json',
        },
        timeout=CLEARTAX_TIMEOUT_SECONDS,
    )
    if response.status_code >= 400:
        try:
            payload = response.json()
            detail = payload.get('message') or payload.get('error') or payload.get('errorDetails') or payload
        except ValueError:
            detail = (response.text or '').strip()[:2000]
        raise RuntimeError(
            f'ClearTax EWB API returned HTTP {response.status_code}: '
            f'{json.dumps(detail, ensure_ascii=False) if isinstance(detail, (dict, list)) else detail}'
        )
    try:
        body = response.json()
    except ValueError:
        raise RuntimeError(f'ClearTax EWB API returned a non-JSON response (HTTP {response.status_code}).')
    if isinstance(body, dict):
        if str(body.get('status', '1')).lower() in ('0', 'false', 'error'):
            detail = body.get('message') or body.get('error') or body.get('errorDetails') or body
            raise RuntimeError('ClearTax EWB lookup failed: ' + json.dumps(detail, ensure_ascii=False))
        data = body.get('data')
        if isinstance(data, dict):
            return data
    return body


def _cleartax_normalize(details):
    if not isinstance(details, dict):
        raise RuntimeError('ClearTax EWB response was not a JSON object.')
    vehicles = (
        details.get('VehiclListDetails')
        or details.get('vehicleListDetails')
        or details.get('vehicleUpdates')
        or details.get('vehicleList')
        or []
    )
    if isinstance(vehicles, dict):
        vehicles = [vehicles]
    latest_vehicle = vehicles[-1] if vehicles else {}

    def first(*keys):
        for key in keys:
            value = details.get(key)
            if value not in (None, ''):
                return value
            value = latest_vehicle.get(key) if isinstance(latest_vehicle, dict) else None
            if value not in (None, ''):
                return value
        return None

    return {
        'success': True,
        'provider': 'cleartax',
        'status': first('status', 'ewbStatus', 'ewayBillStatus'),
        'ewbNo': first('ewbNo', 'ewayBillNo', 'ewbNumber', 'ewb_number'),
        'vehicleNo': first('vehicleNo', 'vehicleNumber'),
        'fromPlace': first('fromPlace', 'from'),
        'toPlace': first('toPlace', 'toPlace', 'to'),
        'actualDist': first('actualDist', 'actualDistance', 'distance'),
        'validUpto': first('validUpto', 'validUntil', 'validity'),
        'lastUpdated': first('enteredDate', 'lastUpdated', 'updatedAt', 'ewbDate'),
        'transporterName': first('transporterName'),
        'transporterId': first('transporterId'),
        'vehicleUpdates': vehicles,
        'raw': details,
    }


@app.get('/api/cleartax-config-status')
def cleartax_config_status():
    return jsonify(
        success=_cleartax_configured(),
        configured=_cleartax_configured(),
        variables={
            'CLEARTAX_AUTH_TOKEN': bool(CLEARTAX_AUTH_TOKEN),
            'CLEARTAX_GSTIN': bool(CLEARTAX_GSTIN),
            'CLEARTAX_API_BASE_URL': CLEARTAX_API_BASE_URL,
            'CLEARTAX_EWB_PATH': CLEARTAX_EWB_PATH,
            'requests_package': requests is not None,
        },
    )


def _vayana_missing_config():
    values = {
        'VAYANA_EMAIL': VAYANA_EMAIL,
        'VAYANA_PASSWORD': VAYANA_PASSWORD,
        'VAYANA_EWB_GSTIN': VAYANA_EWB_GSTIN,
        'VAYANA_EWB_USERNAME': VAYANA_EWB_USERNAME,
        'VAYANA_EWB_PASSWORD': VAYANA_EWB_PASSWORD,
    }
    missing = [key for key, value in values.items() if not value]
    if requests is None:
        missing.append('python requests package')
    return missing


def _vayana_configured():
    return not _vayana_missing_config()


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

        # Vayana documents the authentication base as .../theodore/apis/v1
        # and the actual login route as /authtokens. Support either form in
        # Render so a configured URL ending in /authtokens is not duplicated.
        auth_url = VAYANA_AUTH_URL if VAYANA_AUTH_URL.endswith('/authtokens') else VAYANA_AUTH_URL + '/authtokens'
        response = requests.post(
            auth_url,
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
        try:
            body = response.json()
        except ValueError:
            content_type = response.headers.get('Content-Type', '')
            app.logger.error(
                'Vayana authentication returned non-JSON: HTTP %s, Content-Type=%s, URL=%s',
                response.status_code, content_type, response.url
            )
            raise RuntimeError(
                f'Vayana authentication returned a non-JSON response (HTTP {response.status_code}, '
                f'Content-Type: {content_type or "unknown"}). Check Vayana sandbox access/endpoint.'
            )
        data = body.get('data') or {}
        token = data.get('token')
        associated = data.get('associatedOrgs') or []
        org_id = VAYANA_ORG_ID
        org_source = 'env' if org_id else ''
        if not org_id and associated:
            org = associated[0].get('organisation') or {}
            org_id = org.get('id') or ''
            if org_id:
                org_source = 'associatedOrgs'

        # Some Vayana deployments may embed the organisation identifier in
        # the JWT even when associatedOrgs is empty. Decode only the payload
        # to discover an org id; Vayana still validates the token signature.
        if not org_id and isinstance(token, str) and token.count('.') == 2:
            try:
                jwt_payload = token.split('.')[1]
                jwt_payload += '=' * (-len(jwt_payload) % 4)
                claims = json.loads(base64.urlsafe_b64decode(jwt_payload.encode('ascii')).decode('utf-8'))
                candidate_paths = [
                    ('org_id', claims.get('org_id')),
                    ('orgId', claims.get('orgId')),
                    ('organisation_id', claims.get('organisation_id')),
                    ('organisationId', claims.get('organisationId')),
                ]
                organisation = claims.get('organisation')
                if isinstance(organisation, dict):
                    candidate_paths.append(('organisation.id', organisation.get('id')))
                for key, candidate in candidate_paths:
                    if candidate:
                        org_id = str(candidate).strip()
                        org_source = 'jwt:' + key
                        break
            except Exception:
                pass

        if not token or not org_id:
            missing_parts = []
            if not token:
                missing_parts.append('token')
            if not org_id:
                missing_parts.append('organisation ID')
            app.logger.error(
                'Vayana authentication response missing %s; data_keys=%s associated_orgs_count=%s jwt_org_source=%s',
                ', '.join(missing_parts),
                sorted(data.keys()) if isinstance(data, dict) else [],
                len(associated) if isinstance(associated, list) else 0,
                org_source or 'none',
            )
            raise RuntimeError(
                'Vayana authentication succeeded but missing: ' + ', '.join(missing_parts) +
                '. Check that the Vayana user is linked to an active organisation.'
            )
        expiry = data.get('expiry')
        expires_at = float(expiry) if expiry else now + (350 * 60)
        _vayana_token.update({'token': token, 'org_id': org_id, 'expires_at': expires_at})
        return token, org_id


def _vayana_get_details(ewb_no):
    token, org_id = _vayana_authenticate()
    headers = {
        'Content-Type': 'application/json; charset=UTF-8',
        'Accept': 'application/json; charset=UTF-8',
        'X-FLYNN-N-ORG-ID': org_id,
        'X-FLYNN-N-USER-TOKEN': token,
        'X-FLYNN-N-EWB-GSP-CODE': VAYANA_EWB_GSP_CODE,
        'X-FLYNN-N-EWB-GSTIN': VAYANA_EWB_GSTIN,
        'X-FLYNN-N-EWB-USERNAME': VAYANA_EWB_USERNAME,
        'X-FLYNN-N-EWB-PWD': VAYANA_EWB_PASSWORD,
    }

    # Vayana documents both ew1 and ew2 as valid EWB providers. If the
    # configured provider returns a route-level 404, retry the alternate
    # provider before treating it as a hard failure.
    providers = [VAYANA_EWB_PROVIDER]
    alternate = 'ew2' if VAYANA_EWB_PROVIDER == 'ew1' else 'ew1'
    if alternate not in providers:
        providers.append(alternate)

    last_response = None
    attempts = []
    for provider in providers:
        url = VAYANA_BASE_URL + '/basic/eway/v3.0/' + urllib.parse.quote(provider, safe='') + '/v1.03/ewayapi/GetEwayBill'
        response = requests.get(
            url,
            params={'ewbNo': ewb_no},
            headers=headers,
            timeout=VAYANA_TIMEOUT_SECONDS,
        )
        last_response = response
        try:
            parsed = response.json()
            body_preview = json.dumps(parsed, ensure_ascii=False)[:1000]
        except ValueError:
            body_preview = (response.text or '').strip()[:1000]
        attempts.append({'provider': provider, 'status': response.status_code, 'body': body_preview})
        app.logger.info('Vayana EWB provider=%s status=%s body=%s', provider, response.status_code, body_preview)

        if response.status_code == 404 and provider != providers[-1]:
            app.logger.warning(
                'Vayana EWB provider %s returned HTTP 404; retrying with provider %s',
                provider, providers[-1]
            )
            continue
        if response.status_code == 404:
            raise RuntimeError('Vayana EWB provider route check: ' + json.dumps(attempts, ensure_ascii=False))
        response.raise_for_status()
        try:
            body = response.json()
        except ValueError:
            content_type = response.headers.get('Content-Type', '')
            raise RuntimeError(
                f'Vayana EWB API returned a non-JSON response (HTTP {response.status_code}, '
                f'Content-Type: {content_type or "unknown"}). Check Vayana sandbox/API access.'
            )
        if str(body.get('status', '0')) != '1':
            error = body.get('error') or body.get('errorDetails') or body.get('additionalInfo') or body
            raise RuntimeError('Vayana EWB lookup failed: ' + json.dumps(error))
        return body.get('data') or body

    if last_response is not None:
        last_response.raise_for_status()
    raise RuntimeError('Vayana EWB lookup failed: no provider response.')


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


@app.get('/api/vayana-config-status')
def vayana_config_status():
    missing = _vayana_missing_config()
    return jsonify(
        success=not missing,
        configured=not missing,
        missing=missing,
        variables={
            'VAYANA_EMAIL': bool(VAYANA_EMAIL),
            'VAYANA_PASSWORD': bool(VAYANA_PASSWORD),
            'VAYANA_EWB_GSTIN': bool(VAYANA_EWB_GSTIN),
            'VAYANA_EWB_USERNAME': bool(VAYANA_EWB_USERNAME),
            'VAYANA_EWB_PASSWORD': bool(VAYANA_EWB_PASSWORD),
            'requests_package': requests is not None,
        },
    )


@app.get('/api/vayana-ewb-diagnostic')
def vayana_ewb_diagnostic():
    """Safely test Vayana EWB provider routes without exposing credentials."""
    ewb_no = ''.join(ch for ch in (request.args.get('ewb_no') or '152556544924').strip() if ch.isdigit())
    if len(ewb_no) != 12:
        return jsonify(success=False, error='E-Way Bill number must be a 12-digit number.'), 400
    missing = _vayana_missing_config()
    if missing:
        return jsonify(success=False, configured=False, missing=missing), 503
    try:
        token, org_id = _vayana_authenticate()
        headers = {
            'Content-Type': 'application/json; charset=UTF-8',
            'Accept': 'application/json; charset=UTF-8',
            'X-FLYNN-N-ORG-ID': org_id,
            'X-FLYNN-N-USER-TOKEN': token,
            'X-FLYNN-N-EWB-GSP-CODE': VAYANA_EWB_GSP_CODE,
            'X-FLYNN-N-EWB-GSTIN': VAYANA_EWB_GSTIN,
            'X-FLYNN-N-EWB-USERNAME': VAYANA_EWB_USERNAME,
            'X-FLYNN-N-EWB-PWD': VAYANA_EWB_PASSWORD,
        }
        results=[]
        for provider in ('ew1','ew2'):
            url = VAYANA_BASE_URL + '/basic/eway/v3.0/' + provider + '/v1.03/ewayapi/GetEwayBill'
            try:
                resp=requests.get(url, params={'ewbNo':ewb_no}, headers=headers, timeout=VAYANA_TIMEOUT_SECONDS)
                body=None
                try: body=resp.json()
                except ValueError: body=(resp.text or '')[:1000]
                results.append({'provider':provider,'status_code':resp.status_code,'url':url,'body':body})
            except Exception as exc:
                results.append({'provider':provider,'status_code':None,'url':url,'error':str(exc)})
        return jsonify(success=True, authenticated=True, baseUrl=VAYANA_BASE_URL, ewbNo=ewb_no, providers=results)
    except requests.HTTPError as exc:
        return jsonify(success=False, stage='authentication', status_code=exc.response.status_code if exc.response is not None else 502), 502
    except Exception as exc:
        app.logger.exception('Vayana EWB diagnostic failed')
        return jsonify(success=False, stage='authentication', error=str(exc)), 502


@app.get('/api/vayana-test')
def vayana_test():
    missing = _vayana_missing_config()
    if missing:
        return jsonify(success=False, configured=False, error='Vayana configuration is incomplete.', missing=missing), 503
    try:
        token, org_id = _vayana_authenticate()
        return jsonify(
            success=True,
            provider='vayana',
            organisationId=org_id,
            tokenConfigured=bool(token),
        )
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



def _perione_configured():
    required = [
        PERIONE_GSTIN, PERIONE_USERNAME, PERIONE_PASSWORD,
        PERIONE_IP_ADDRESS, PERIONE_CLIENT_ID, PERIONE_CLIENT_SECRET
    ]
    return bool(requests is not None and all(required))


def _perione_authenticate():
    """Authenticate against the current PeriOne sandbox contract.

    PeriOne's current Swagger sandbox uses GET /ewaybillapi/v1.03/authenticate
    with email/username/password as query parameters and IP/client/GSTIN
    headers. Some PeriOne environments also issue a bearer token separately;
    PERIONE_TOKEN can be supplied through Render for that flow.
    """
    now = datetime.now(timezone.utc).timestamp()
    with _perione_token_lock:
        if PERIONE_TOKEN:
            return PERIONE_TOKEN
        if _perione_token['token'] and now < _perione_token['expires_at']:
            return _perione_token['token']

        url = PERIONE_BASE_URL + PERIONE_AUTH_PATH
        headers = {
            'Accept': 'application/json',
            'ip_address': PERIONE_IP_ADDRESS,
            'client_id': PERIONE_CLIENT_ID,
            'client_secret': PERIONE_CLIENT_SECRET,
            'gstin': PERIONE_GSTIN,
        }
        params = {
            'email': PERIONE_EMAIL,
            'username': PERIONE_USERNAME,
            'password': PERIONE_PASSWORD,
        }
        response = requests.get(url, params=params, headers=headers, timeout=PERIONE_TIMEOUT_SECONDS)
        response.raise_for_status()
        body = response.json()
        token = (
            body.get('token')
            or body.get('access_token')
            or body.get('auth_token')
            or (body.get('data') or {}).get('token')
            or (body.get('data') or {}).get('access_token')
            or (body.get('data') or {}).get('auth_token')
        )
        if token:
            expires_in = (
                body.get('expires_in')
                or (body.get('data') or {}).get('expires_in')
                or 3600
            )
            _perione_token.update({
                'token': token,
                'expires_at': now + max(300, float(expires_in) - 60),
            })
            return token

        # Current PeriOne Swagger authentication can return status_cd=1
        # without embedding the bearer token in the JSON body. In that case
        # the token must be supplied via PERIONE_TOKEN from the PeriOne
        # Auth Tokens area.
        if str(body.get('status_cd', '0')) == '1':
            raise RuntimeError(
                'PeriOne authentication endpoint returned status_cd=1 but did not issue a bearer token. '
                'The PeriOne Swagger request is using an existing Authorization bearer token, so '
                'Atomgrid must receive that token through the PERIONE_TOKEN Render environment variable.'
            )
        raise RuntimeError(
            'PeriOne authentication failed: ' +
            json.dumps(body.get('status_desc') or body.get('message') or body, ensure_ascii=False)
        )


def _perione_get_details(ewb_no):
    token = _perione_authenticate()
    url = PERIONE_BASE_URL + PERIONE_EWB_PATH
    headers = {
        'Authorization': 'Bearer ' + token,
        'Accept': 'application/json',
        'ip_address': PERIONE_IP_ADDRESS,
        'client_id': PERIONE_CLIENT_ID,
        'client_secret': PERIONE_CLIENT_SECRET,
        'gstin': PERIONE_GSTIN,
    }
    response = requests.get(
        url,
        params={'ewbNo': ewb_no},
        headers=headers,
        timeout=PERIONE_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    return response.json()


def _perione_normalize(body):
    if not isinstance(body, dict):
        raise RuntimeError('PeriOne EWB response was not a JSON object.')

    # Support both the documented wrapper and the NIC-style payload.
    details = body
    if isinstance(body.get('data'), dict):
        details = body.get('data')
        if isinstance(details.get('data'), dict):
            details = details.get('data')

    if not isinstance(details, dict):
        raise RuntimeError('PeriOne EWB response did not contain EWB data.')

    vehicles = (
        details.get('VehiclListDetails')
        or details.get('vehicleListDetails')
        or details.get('vehicleUpdates')
        or details.get('vehicle_updates')
        or details.get('vehicles')
        or []
    )
    if isinstance(vehicles, dict):
        vehicles = [vehicles]
    latest = vehicles[-1] if vehicles else {}

    def first(*keys):
        for source in (details, latest, body):
            if not isinstance(source, dict):
                continue
            for key in keys:
                value = source.get(key)
                if value not in (None, ''):
                    return value
        return None

    return {
        'success': True,
        'provider': 'perione',
        'status': first('status', 'ewbStatus', 'ewayBillStatus'),
        'ewbNo': first('ewbNo', 'ewayBillNo', 'ewaybill_no', 'ewayBillNumber'),
        'vehicleNo': first('vehicleNo', 'vehicleNumber', 'vehicle_no'),
        'fromPlace': first('fromPlace', 'from_place', 'from'),
        'toPlace': first('toPlace', 'to_place', 'to'),
        'actualDist': first('actualDist', 'actualDistance', 'distance_km', 'distance'),
        'validUpto': first('validUpto', 'validUntil', 'valid_upto', 'validity'),
        'lastUpdated': first('enteredDate', 'lastUpdated', 'updatedAt', 'ewayBillDate', 'ewaybill_date'),
        'transporterName': first('transporterName', 'transporter_name'),
        'transporterId': first('transporterId', 'transporter_id'),
        'vehicleUpdates': vehicles,
        'raw': body,
    }

def _ewb_provider_attempt(provider, ewb_no):
    """Run one provider adapter and return the dashboard's common EWB shape."""
    provider = (provider or '').strip().lower()
    if provider == 'cleartax':
        if not _cleartax_configured():
            raise RuntimeError('ClearTax is not configured.')
        return _cleartax_normalize(_cleartax_get_details(ewb_no))
    if provider == 'vayana':
        if not _vayana_configured():
            raise RuntimeError('Vayana is not configured.')
        return _vayana_normalize(_vayana_get_details(ewb_no))
    if provider == 'perione':
        if not _perione_configured():
            raise RuntimeError('PeriOne is not configured.')
        return _perione_normalize(_perione_get_details(ewb_no))
    if provider == 'nic':
        if not _ewb_configured():
            raise RuntimeError('NIC/GSTN E-Way Bill API is not configured.')
        return _ewb_normalize(_ewb_get_details(ewb_no))
    raise RuntimeError('Unsupported E-Way Bill provider: ' + (provider or '(empty)'))


def _ewb_provider_candidates():
    candidates = []
    for provider in (EWB_PROVIDER, EWB_FALLBACK_PROVIDER):
        provider = (provider or '').strip().lower()
        if provider and provider not in candidates:
            candidates.append(provider)
    return candidates or ['cleartax']


@app.get('/api/ewaybill-provider-status')
def ewaybill_provider_status():
    """Safe diagnostics: reports configured providers without exposing credentials."""
    statuses = {
        'cleartax': _cleartax_configured(),
        'vayana': _vayana_configured(),
        'perione': _perione_configured(),
        'nic': _ewb_configured(),
    }
    return jsonify(
        success=True,
        activeProvider=EWB_PROVIDER,
        fallbackProvider=EWB_FALLBACK_PROVIDER or None,
        configured=statuses,
    )


@app.get('/api/ewaybill-details')
def ewaybill_details():
    ewb_no = ''.join(ch for ch in (request.args.get('ewb_no') or '').strip() if ch.isdigit())
    if len(ewb_no) != 12:
        return jsonify(success=False, error='E-Way Bill number must be a 12-digit number.'), 400

    attempts = []
    for provider in _ewb_provider_candidates():
        try:
            result = _ewb_provider_attempt(provider, ewb_no)
            result['provider'] = provider
            return jsonify(result)
        except requests.HTTPError as exc:
            response = exc.response
            status = response.status_code if response is not None else 502
            detail = ''
            if response is not None:
                try:
                    payload = response.json()
                    if isinstance(payload, dict):
                        detail = (
                            payload.get('message')
                            or payload.get('status_desc')
                            or payload.get('error')
                            or payload.get('error_message')
                            or payload.get('errorDetails')
                            or ''
                        )
                    elif isinstance(payload, str):
                        detail = payload
                except ValueError:
                    detail = (response.text or '').strip()[:500]
            attempt = {'provider': provider, 'status': status, 'error': 'HTTP ' + str(status)}
            if detail:
                attempt['detail'] = str(detail)[:500]
            attempts.append(attempt)
            app.logger.warning(
                'EWB provider %s failed for %s with HTTP %s%s',
                provider, ewb_no, status, ': ' + str(detail)[:500] if detail else ''
            )
        except Exception as exc:
            attempts.append({'provider': provider, 'error': str(exc)})
            app.logger.warning('EWB provider %s failed for %s: %s', provider, ewb_no, exc)

    return jsonify(
        success=False,
        provider=EWB_PROVIDER,
        error='All configured E-Way Bill providers failed.',
        attempts=attempts,
    ), 502


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