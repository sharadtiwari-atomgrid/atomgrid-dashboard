#!/usr/bin/env python3
"""Atomgrid Domestic MIS Dashboard — Render-ready Flask server."""
import os
import urllib.parse
import urllib.request
import urllib.error
from flask import Flask, Response, jsonify, send_from_directory, request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, static_folder=BASE_DIR, static_url_path='')

@app.after_request
def add_no_cache_headers(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    return response

@app.get('/health')
def health():
    return jsonify(status='ok', service='atomgrid-dashboard')

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

    # Preferred path for a Google "Publish to web" URL.
    # The published CSV endpoint is public and avoids the 401 that can occur
    # when the normal /d/<spreadsheet-id>/gviz endpoint is not anonymously readable.
    if published_url:
        try:
            p = urllib.parse.urlparse(published_url)
            if p.scheme in ('http', 'https') and p.netloc == 'docs.google.com':
                path = p.path
                existing_q = urllib.parse.parse_qs(p.query)
                if existing_q.get('output', [''])[0].lower() == 'csv':
                    existing_q['_'] = [os.urandom(6).hex()]
                    candidates.append(urllib.parse.urlunparse((
                        p.scheme, p.netloc, path, '', urllib.parse.urlencode(existing_q, doseq=True), ''
                    )))
                if '/pubhtml' in path:
                    path = path.replace('/pubhtml', '/pub')
                elif not path.endswith('/pub'):
                    # If the user pasted a normal published URL, convert it.
                    if '/spreadsheets/d/e/' in path:
                        path = path.rstrip('/') + '/pub'
                q = urllib.parse.parse_qs(p.query)
                if gid:
                    q['gid'] = [gid]
                q['single'] = ['true']
                q['output'] = ['csv']
                q['_'] = [os.urandom(6).hex()]
                candidates.append(urllib.parse.urlunparse((
                    p.scheme, p.netloc, path, '', urllib.parse.urlencode(q, doseq=True), ''
                )))
        except Exception:
            pass

    # Also accept a published ID in the Sheet ID field (2PACX-...).
    if sheet_id.startswith('2PACX-'):
        g = gid or '0'
        candidates.append(
            f'https://docs.google.com/spreadsheets/d/e/{urllib.parse.quote(sheet_id, safe="")}/pub'
            f'?gid={urllib.parse.quote(g, safe="")}&single=true&output=csv&_={os.urandom(6).hex()}'
        )

    # Legacy normal spreadsheet-ID fallbacks.
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
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 AtomgridDashboard/1.0',
                'Cache-Control': 'no-cache',
                'Accept': 'text/csv,text/plain,*/*',
            })
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read()
                content_type = resp.headers.get('Content-Type', '')

            if not data:
                last_error = 'Google returned an empty response.'
                continue

            if b'<html' in data[:1000].lower() or 'text/html' in content_type.lower():
                last_error = 'Google returned HTML instead of CSV. Confirm the tab is published to web.'
                continue

            return Response(data, status=200, mimetype='text/csv', headers={
                'Access-Control-Allow-Origin': '*',
                'X-Atomgrid-Source': 'google-sheets-published-csv',
            })
        except urllib.error.HTTPError as exc:
            last_error = f'HTTP {exc.code} from Google'
        except Exception as exc:
            last_error = str(exc)

    return jsonify(error=(
        'Could not fetch the Google Sheet. ' + (last_error or 'Unknown error') +
        ' Use the published-to-web URL (ending in /pubhtml) or publish the exact tab as CSV.'
    )), 502

@app.get('/')
def index():
    return send_from_directory(BASE_DIR, 'index.html')

@app.get('/<path:path>')
def static_files(path):
    return send_from_directory(BASE_DIR, path)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', '10000'))
    app.run(host='0.0.0.0', port=port)
