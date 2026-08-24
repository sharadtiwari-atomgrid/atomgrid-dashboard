# Atomgrid Domestic MIS Dashboard

Render-ready Flask dashboard for the Atomgrid Domestic MIS.

## Access control

The dashboard is protected by Google OAuth. Only Google accounts whose email domain exactly matches `@atomgrid.com` can access it. The domain is configurable with `ALLOWED_EMAIL_DOMAIN`.

### Render environment variables

Set these in Render:

- `GOOGLE_CLIENT_ID` — Google OAuth Web application client ID
- `GOOGLE_CLIENT_SECRET` — Google OAuth Web application client secret
- `GOOGLE_REDIRECT_URI` — exact callback URL, e.g. `https://YOUR-SERVICE.onrender.com/auth/callback`
- `SESSION_SECRET` — generated automatically by `render.yaml`
- `ALLOWED_EMAIL_DOMAIN` — defaults to `atomgrid.com`

In Google Cloud Console, create a **Web application** OAuth client and add the exact Render callback URL to **Authorized redirect URIs**. Google requires the redirect URI used by the app to exactly match an authorized URI.

The app requests only OpenID, email and profile identity scopes. It does not request access to the user's Drive, Gmail, Calendar, or other Google data.

## Run locally

Set the OAuth environment variables, add `http://localhost:10000/auth/callback` as an authorized redirect URI for local testing, then run:

```bash
pip install -r requirements.txt
python server.py
```
