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

@app.get('/api/sheet-csv')
def sheet_csv():
    sheet_id = (request.args.get('sheet_id') or '').strip()
    gid = (request.args.get('gid') or '').strip()
    tab = (request.args.get('tab') or '').strip()

    if not sheet_id:
        return jsonify(error='Missing sheet_id'), 400

    candidates = []
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
            })
            with urllib.request.urlopen(req, timeout=25) as resp:
                data = resp.read()
                content_type = resp.headers.get('Content-Type', '')

            if b'<html' in data[:500].lower() or 'text/html' in content_type.lower():
                last_error = 'Google returned HTML instead of CSV. The sheet may not be published to web, or the tab name/gid may be incorrect.'
                continue

            return Response(data, status=200, mimetype='text/csv', headers={
                'Access-Control-Allow-Origin': '*',
                'X-Atomgrid-Source': 'google-sheets',
            })
        except urllib.error.HTTPError as exc:
            last_error = f'HTTP {exc.code} from Google'
        except Exception as exc:
            last_error = str(exc)

    return jsonify(error=(
        'Could not fetch the Google Sheet. ' + (last_error or 'Unknown error') +
        ' Check File → Share → Publish to web for the exact tab, and verify the Sheet ID/tab name.'
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
