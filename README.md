# Atomgrid — Domestic MIS Live Dashboard (Render)

This version is prepared for Render and a **public Google Sheet**.

## Architecture

Google Sheet → Render Flask server → dashboard browser

The browser polls `/api/sheet-csv` automatically. Default refresh interval is **30 seconds**. You can change it to 15 seconds, 30 seconds, 60 seconds, 5 minutes, or manual in **Google Sheet → Refresh every**.

## Google Sheet setup

The exact tab must be publicly published:

**Google Sheets → File → Share → Publish to web → select the `Domestics MIS` tab → Publish**

Copy the Sheet ID from the URL:

`https://docs.google.com/spreadsheets/d/SHEET_ID/edit`

## Deploy to Render

### Option A — Blueprint (recommended)

1. Put this folder in a GitHub repository.
2. In Render choose **New → Blueprint**.
3. Select the GitHub repository.
4. Render reads `render.yaml` and creates the web service.

### Option B — Web Service

Use:

- Runtime: **Python 3**
- Build Command: `pip install -r requirements.txt`
- Start Command: `gunicorn server:app --bind 0.0.0.0:$PORT --workers 2 --timeout 60`
- Health Check Path: `/health`

## After deployment

1. Open the Render `onrender.com` URL.
2. Click **Google Sheet — live connection**.
3. Enter your Sheet ID.
4. Enter the tab name, normally `Domestics MIS`.
5. Choose **30 seconds**.
6. Click **Save & connect**.

Change a value in Google Sheets, wait for the next refresh, and the dashboard will update.

## Important: what “realtime” means here

This is **polling**, not a Google push/webhook. The dashboard checks the public Google Sheet every 30 seconds by default. For a MIS dashboard this is usually the simplest and most reliable approach.

Render's free web services can spin down after 15 minutes without incoming traffic. When a user opens the dashboard again, Render starts the service back up. For a dashboard that must stay continuously warm, use a paid instance. See Render's current service documentation for plan limitations.
