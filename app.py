import os
import json
import time
import threading
import requests
import ipaddress
import pandas as pd
from flask import Flask, redirect, request, jsonify, send_from_directory
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

app = Flask(__name__, static_folder="static", static_url_path="")

# Load credentials from .env (or directly set below if preferred)
UPSTOX_API_KEY = os.getenv("UPSTOX_API_KEY") or "1986aab2-dcc6-4af4-a00d-97b7d07b08aa"
UPSTOX_API_SECRET = os.getenv("UPSTOX_API_SECRET") or "k0qh7us85x"
# IMPORTANT: This redirect_uri MUST match exactly what's registered in your Upstox app settings
# Check your Upstox Developer Portal: https://account.upstox.com/developer/apps
# 
# If you see SSL errors, you have two options:
# 1. Use HTTPS: Set redirect_uri to "https://127.0.0.1:5000/callback" in Upstox AND ensure SSL certs exist
# 2. Use HTTP: Set redirect_uri to "http://127.0.0.1:5000/callback" in Upstox (simpler for local dev)
#
# The app will auto-detect SSL certificates and run in HTTPS mode if available
# Note: Upstox redirects to /callback/ (with trailing slash), so we handle both
REDIRECT_URI = os.getenv("UPSTOX_REDIRECT_URI") or "https://127.0.0.1:5000/callback/"
TOKEN_FILE = "access_token.json"

# Upstox authorization uses v2 API, not v3
# Build auth URL with proper encoding
AUTH_PARAMS = {
    "response_type": "code",
    "client_id": UPSTOX_API_KEY,
    "redirect_uri": REDIRECT_URI
}
AUTH_URL = f"https://api.upstox.com/v2/login/authorization/dialog?{urlencode(AUTH_PARAMS)}"
TOKEN_URL = "https://api.upstox.com/v2/login/authorization/token"

# In-memory storage for access token
access_token = None

# ---------------------------------------
# STEP 1 — AUTHORIZATION + TOKEN HANDLING
# ---------------------------------------

def save_token(data):
    with open(TOKEN_FILE, "w") as f:
        json.dump(data, f, indent=4)

def load_token():
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, "r") as f:
            return json.load(f)
    return None

def get_valid_token():
    global access_token
    data = load_token()

    # If we already have one, check if expired and refresh if needed
    if data and "access_token" in data:
        # Check if token is expired (if expires_at is stored)
        expires_at = data.get("expires_at", 0)
        current_time = time.time()
        
        # If token is still valid, return it
        if expires_at and current_time < expires_at:
            access_token = data["access_token"]
            expires_in_seconds = expires_at - current_time
            expires_in_minutes = expires_in_seconds / 60
            expires_in_hours = expires_in_minutes / 60
            
            print("=" * 70)
            print("✅ TOKEN STATUS: VALID")
            print(f"   Token expires in: {int(expires_in_hours)}h {int(expires_in_minutes % 60)}m")
            print("=" * 70)
            return access_token
        
        # Token is expired, try to refresh if we have refresh_token
        if "refresh_token" in data and data["refresh_token"]:
            try:
                print("=" * 70)
                print("🔄 TOKEN STATUS: EXPIRED - Attempting to refresh...")
                print("=" * 70)
                
                payload = {
                    "client_id": UPSTOX_API_KEY,
                    "client_secret": UPSTOX_API_SECRET,
                    "refresh_token": data["refresh_token"],
                    "grant_type": "refresh_token"
                }
                response = requests.post(TOKEN_URL, data=payload)
                
                if response.status_code == 200:
                    new_data = response.json()
                    if "access_token" in new_data:
                        # Calculate expiration time
                        expires_in = new_data.get("expires_in", 86400)
                        new_data["expires_at"] = time.time() + expires_in - 60
                        
                        # Preserve refresh_token if not in new response
                        if "refresh_token" not in new_data and data.get("refresh_token"):
                            new_data["refresh_token"] = data["refresh_token"]
                        
                        save_token(new_data)
                        access_token = new_data["access_token"]
                        
                        print("=" * 70)
                        print("✅ TOKEN REFRESHED SUCCESSFULLY!")
                        print(f"   New token expires in: {int(expires_in / 3600)}h {int((expires_in % 3600) / 60)}m")
                        print("=" * 70)
                        return access_token
                    else:
                        print(f"❌ Token refresh response missing access_token: {new_data}")
                else:
                    print(f"❌ Token refresh failed with status {response.status_code}: {response.text}")
            except Exception as e:
                print(f"❌ Token refresh exception: {e}")
        
        # If refresh failed or no refresh token, token is expired and can't be refreshed
        print("=" * 70)
        print("⚠️  TOKEN STATUS: EXPIRED AND CANNOT BE REFRESHED")
        print("=" * 70)
        print("\n📋 MANUAL AUTHORIZATION REQUIRED")
        print("\nPlease follow these steps:")
        print("1. Open the authorization URL in your browser:")
        print(f"   {AUTH_URL}")
        print("\n2. Log in to your Upstox account")
        print("3. Authorize the application")
        print("4. You will be redirected back to the callback URL")
        print("\n" + "=" * 70)
        
        # Don't return expired token - return None to force re-authorization
        access_token = None
        return None

    # If missing, start auth
    print("=" * 70)
    print("⚠️  TOKEN STATUS: NO TOKEN FOUND")
    print("=" * 70)
    print("\n📋 INITIAL AUTHORIZATION REQUIRED")
    print("\nPlease follow these steps:")
    print("1. Open the authorization URL in your browser:")
    print(f"   {AUTH_URL}")
    print("\n2. Log in to your Upstox account")
    print("3. Authorize the application")
    print("4. You will be redirected back to the callback URL")
    print("\n" + "=" * 70)
    return None

@app.route("/callback")
@app.route("/callback/")  # Handle both with and without trailing slash
def callback():
    """Handle Upstox redirect & exchange code for token automatically."""
    code = request.args.get("code")
    if not code:
        return "Missing authorization code!", 400

    print("\n" + "=" * 70)
    print("✅ Received authorization code. Exchanging for token...")
    print("=" * 70)
    
    # Get the actual redirect URI that was used (from request URL)
    # This ensures we use the exact same redirect_uri that Upstox redirected to
    actual_redirect_uri = request.url.split('?')[0]  # Get URL without query params
    # Remove trailing slash if present for consistency
    if actual_redirect_uri.endswith('/'):
        actual_redirect_uri = actual_redirect_uri[:-1]
    
    # Try with the actual redirect URI first, then fallback to configured one
    redirect_uris_to_try = [
        actual_redirect_uri,
        REDIRECT_URI.rstrip('/'),  # Remove trailing slash
        REDIRECT_URI,
        actual_redirect_uri + '/',  # With trailing slash
        REDIRECT_URI.rstrip('/') + '/',  # Without then with
    ]
    
    # Remove duplicates while preserving order
    seen = set()
    redirect_uris_to_try = [x for x in redirect_uris_to_try if not (x in seen or seen.add(x))]
    
    print(f"   Trying redirect URIs: {redirect_uris_to_try[:3]}...")  # Show first 3
    
    for redirect_uri_attempt in redirect_uris_to_try:
        payload = {
            "code": code,
            "client_id": UPSTOX_API_KEY,
            "client_secret": UPSTOX_API_SECRET,
            "redirect_uri": redirect_uri_attempt,
            "grant_type": "authorization_code"
        }
        
        print(f"   Attempting with redirect_uri: {redirect_uri_attempt}")
        response = requests.post(TOKEN_URL, data=payload)
        
        if response.status_code == 200:
            data = response.json()
            if "access_token" in data:
                # Calculate expiration time
                expires_in = data.get("expires_in", 86400)
                data["expires_at"] = time.time() + expires_in - 60
                save_token(data)
                global access_token
                access_token = data["access_token"]
                
                print("=" * 70)
                print("✅ ACCESS TOKEN GENERATED AND SAVED SUCCESSFULLY!")
                print(f"   Token expires in: {int(expires_in / 3600)}h {int((expires_in % 3600) / 60)}m")
                print(f"   Working redirect_uri: {redirect_uri_attempt}")
                print("=" * 70)
                
                return """<h2>✅ Upstox connected successfully!</h2>
                <p>You can now close this tab and return to the dashboard.</p>
                <script>
                setTimeout(function() {
                    window.close();
                }, 2000);
                </script>"""
        
        # If we got an error, check if it's the invalid credentials error
        try:
            error_data = response.json()
            errors = error_data.get("errors", [])
            for err in errors:
                error_code = err.get("errorCode") or err.get("error_code")
                if error_code == "UDAPI100016":
                    print(f"   ❌ Invalid Credentials with redirect_uri: {redirect_uri_attempt}")
                    print(f"      Error: {err.get('message', 'Unknown error')}")
                    continue  # Try next redirect URI
        except:
            pass
    
    # If all attempts failed, show detailed error
    print("=" * 70)
    print("❌ TOKEN EXCHANGE FAILED - All redirect_uri attempts failed")
    print("=" * 70)
    
    # Get the last error for display
    try:
        last_response = requests.post(TOKEN_URL, data={
            "code": code,
            "client_id": UPSTOX_API_KEY,
            "client_secret": UPSTOX_API_SECRET,
            "redirect_uri": REDIRECT_URI,
            "grant_type": "authorization_code"
        })
        error_data = last_response.json()
    except:
        error_data = {"error": "Could not parse error response"}
    
    error_html = f"""
    <html>
    <head><title>Authorization Failed</title></head>
    <body style="font-family: Arial; padding: 20px; max-width: 800px; margin: 0 auto;">
        <h2 style="color: #dc2626;">❌ Token Exchange Failed</h2>
        <div style="background: #fee2e2; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #dc2626;">
            <h3>Error Details:</h3>
            <pre style="background: white; padding: 10px; border-radius: 3px; overflow-x: auto;">{json.dumps(error_data, indent=2)}</pre>
        </div>
        
        <div style="background: #fef3c7; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #f59e0b;">
            <h3>⚠️ Common Causes:</h3>
            <ol>
                <li><strong>Redirect URI Mismatch:</strong> The redirect_uri in your code must <strong>exactly match</strong> what's registered in Upstox.</li>
                <li><strong>Client ID/Secret:</strong> Verify your API credentials are correct.</li>
                <li><strong>Trailing Slash:</strong> Check if your redirect_uri has a trailing slash - it must match exactly.</li>
            </ol>
        </div>
        
        <div style="background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0;">
            <h3>Current Configuration:</h3>
            <p><strong>Client ID:</strong> <code>{UPSTOX_API_KEY}</code></p>
            <p><strong>Redirect URI (configured):</strong> <code>{REDIRECT_URI}</code></p>
            <p><strong>Redirect URI (actual):</strong> <code>{actual_redirect_uri}</code></p>
            <p><strong>Token URL:</strong> <code>{TOKEN_URL}</code></p>
        </div>
        
        <div style="background: #dbeafe; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #3b82f6;">
            <h3>📋 Steps to Fix:</h3>
            <ol>
                <li>Go to <a href="https://account.upstox.com/developer/apps" target="_blank">Upstox Developer Portal</a></li>
                <li>Find your app (Client ID: <code>{UPSTOX_API_KEY}</code>)</li>
                <li>Check the <strong>Redirect URI</strong> field - it must match one of these exactly:
                    <ul>
                        <li><code>{REDIRECT_URI}</code></li>
                        <li><code>{actual_redirect_uri}</code></li>
                        <li><code>{REDIRECT_URI.rstrip('/')}</code> (without trailing slash)</li>
                        <li><code>{REDIRECT_URI.rstrip('/') + '/'}</code> (with trailing slash)</li>
                    </ul>
                </li>
                <li>Update the Redirect URI in Upstox to match exactly, or update the code to match Upstox</li>
                <li>Try authorizing again</li>
            </ol>
        </div>
        
        <p><a href="/authorize" style="display: inline-block; padding: 10px 20px; background: #3b82f6; color: white; text-decoration: none; border-radius: 5px; margin-right: 10px;">Try Again</a>
        <a href="/auth_debug" style="display: inline-block; padding: 10px 20px; background: #6b7280; color: white; text-decoration: none; border-radius: 5px;">Debug Config</a>
        <a href="/" style="display: inline-block; padding: 10px 20px; background: #6b7280; color: white; text-decoration: none; border-radius: 5px;">Back to Dashboard</a></p>
    </body>
    </html>
    """
    
    return error_html, 400

# ---------------------------------------
# STEP 2 — FETCH LIVE LTP DATA
# ---------------------------------------

def fetch_ltp(symbol):
    """Fetch live LTP for any stock/index/option using v2 API (as shown in notebook)."""
    global access_token
    
    # Always get a valid token (checks expiration and refreshes if needed)
    access_token = get_valid_token()
    if not access_token:
        return {"error": "No valid access token. Please authorize first.", "auth_required": True, "auth_url": AUTH_URL}

    # Use v2 API like the notebook (v2/market-quote/ltp with params)
    url = "https://api.upstox.com/v2/market-quote/ltp"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
        "Api-Version": "2.0"
    }
    params = {"symbol": symbol}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=15)
        if response.status_code == 200:
            data = response.json()
            # Check if data is empty (common for stocks when market is closed)
            if data.get("status") == "success" and (not data.get("data") or len(data.get("data", {})) == 0):
                # For stocks, try quotes API as fallback
                if "NSE_EQ" in symbol:
                    print(f"   🔄 LTP API returned empty data, trying quotes API for stock: {symbol}")
                    
                    # Try multiple API endpoints and parameter formats
                    endpoints_to_try = [
                        ("https://api.upstox.com/v2/market-quote/quotes", {"symbol": symbol}),
                        ("https://api.upstox.com/v2/market-quote/quotes", {"symbol": symbol.replace("|", ":")}),
                        ("https://api.upstox.com/v2/market-quote/full", {"symbol": symbol}),
                        ("https://api.upstox.com/v2/market-quote/full", {"symbol": symbol.replace("|", ":")}),
                    ]
                    
                    for quotes_url, quotes_params in endpoints_to_try:
                        try:
                            print(f"      Trying: {quotes_url} with params: {quotes_params}")
                            quotes_response = requests.get(quotes_url, headers=headers, params=quotes_params, timeout=15)
                            
                            if quotes_response.status_code == 200:
                                quotes_data = quotes_response.json()
                                print(f"      ✅ Quotes API response status: {quotes_data.get('status')}")
                                print(f"      📊 Quotes API data keys: {list(quotes_data.get('data', {}).keys())}")
                                
                                quotes_ltp_data = quotes_data.get("data", {})
                                
                                # Try multiple key variations
                                key_variations = [
                                    symbol.replace("|", ":"),  # NSE_EQ:RELIANCE
                                    symbol,  # NSE_EQ|RELIANCE
                                    symbol.split("|")[-1] if "|" in symbol else symbol,  # RELIANCE
                                    symbol.replace("NSE_EQ|", ""),  # RELIANCE (without exchange)
                                ]
                                
                                for key_var in key_variations:
                                    if key_var in quotes_ltp_data:
                                        item = quotes_ltp_data[key_var]
                                        if isinstance(item, dict):
                                            ltp = item.get("last_price") or item.get("ltp") or item.get("ltp_price")
                                            if ltp:
                                                print(f"   ✅ Found LTP from quotes API: {ltp} (key: {key_var})")
                                                # Return in same format as LTP API
                                                return {
                                                    "status": "success",
                                                    "data": {
                                                        key_var: {
                                                            "last_price": ltp,
                                                            "ltp": ltp
                                                        }
                                                    }
                                                }
                                
                                # Try iterating through all keys
                                if quotes_ltp_data:
                                    for key, item in quotes_ltp_data.items():
                                        if isinstance(item, dict):
                                            ltp = item.get("last_price") or item.get("ltp") or item.get("ltp_price")
                                            if ltp:
                                                print(f"   ✅ Found LTP from quotes API: {ltp} (key: {key})")
                                                return {
                                                    "status": "success",
                                                    "data": {
                                                        key: {
                                                            "last_price": ltp,
                                                            "ltp": ltp
                                                        }
                                                    }
                                                }
                                
                                # If we got here, this endpoint didn't work, try next
                                print(f"      ⚠️ No LTP found in response from {quotes_url}")
                            else:
                                print(f"      ⚠️ Quotes API returned status {quotes_response.status_code}: {quotes_response.text[:200]}")
                        except Exception as e:
                            print(f"      ⚠️ Quotes API fallback failed for {quotes_url}: {e}")
                            import traceback
                            traceback.print_exc()
                    
                    print(f"   ❌ All quotes API endpoints failed for stock: {symbol}")
            return data
        else:
            error_msg = response.text
            error_json = None
            try:
                error_json = response.json()
                error_msg = error_json.get("message", error_json.get("error", error_msg))
                
                # Check if it's an invalid token error
                errors = error_json.get("errors", [])
                if errors:
                    for err in errors:
                        error_code = err.get("errorCode") or err.get("error_code")
                        if error_code == "UDAPI100050":  # Invalid token error
                            print("🔄 Token expired or invalid. Attempting to refresh...")
                            # Clear the cached token and try to get a new one
                            access_token = None
                            # Force reload from file and refresh
                            token_data = load_token()
                            if token_data and "refresh_token" in token_data:
                                # Try to refresh
                                try:
                                    payload = {
                                        "client_id": UPSTOX_API_KEY,
                                        "client_secret": UPSTOX_API_SECRET,
                                        "refresh_token": token_data["refresh_token"],
                                        "grant_type": "refresh_token"
                                    }
                                    refresh_response = requests.post(TOKEN_URL, data=payload)
                                    if refresh_response.status_code == 200:
                                        new_data = refresh_response.json()
                                        if "access_token" in new_data:
                                            expires_in = new_data.get("expires_in", 86400)
                                            new_data["expires_at"] = time.time() + expires_in - 60
                                            # Preserve refresh_token if not in new response
                                            if "refresh_token" not in new_data and token_data.get("refresh_token"):
                                                new_data["refresh_token"] = token_data["refresh_token"]
                                            save_token(new_data)
                                            access_token = new_data["access_token"]
                                            print("✅ Token refreshed successfully. Retrying request...")
                                            # Retry the request with new token
                                            headers["Authorization"] = f"Bearer {access_token}"
                                            retry_response = requests.get(url, headers=headers, params=params, timeout=15)
                                            if retry_response.status_code == 200:
                                                return retry_response.json()
                                            else:
                                                return {"error": f"Request failed after token refresh: {retry_response.text}"}
                                    else:
                                        print(f"❌ Token refresh failed: {refresh_response.text}")
                                        return {"error": "Token expired and refresh failed. Please re-authorize.", "auth_required": True, "auth_url": AUTH_URL}
                                except Exception as refresh_error:
                                    print(f"❌ Token refresh exception: {refresh_error}")
                                    return {"error": "Token expired and refresh failed. Please re-authorize.", "auth_required": True, "auth_url": AUTH_URL}
                            else:
                                return {"error": "Token expired and no refresh token available. Please re-authorize.", "auth_required": True, "auth_url": AUTH_URL}
            except:
                pass
            print(f"❌ LTP API Error ({response.status_code}): {error_msg}")
            return {"error": error_msg}
    except Exception as e:
        print(f"❌ LTP API Exception: {str(e)}")
        return {"error": str(e)}

@app.route("/ltp/<symbol>")
def get_ltp(symbol):
    """Flask route for LTP."""
    data = fetch_ltp(symbol)
    return jsonify(data)

@app.route("/api/ltp")
def api_ltp():
    """API endpoint for LTP."""
    friendly = request.args.get("symbol", "NIFTY")
    symbol_map = {
        "NIFTY": "NSE_INDEX%7CNifty%2050",
        "BANKNIFTY": "NSE_INDEX%7CNifty%20Bank",
        "FINNIFTY": "NSE_INDEX%7CNifty%20Fin%20Service",
        "RELIANCE": "NSE_EQ%7CRELIANCE",
        "TCS": "NSE_EQ%7CTCS",
        "INFY": "NSE_EQ%7CINFY"
    }
    sym = symbol_map.get(friendly, friendly)
    try:
        data = fetch_ltp(sym)
        if "error" in data:
            # Preserve auth_required and auth_url if present
            response_data = {"error": data["error"]}
            if "auth_required" in data:
                response_data["auth_required"] = data["auth_required"]
            if "auth_url" in data:
                response_data["auth_url"] = data["auth_url"]
            status_code = 401 if data.get("auth_required") else 500
            return jsonify(response_data), status_code
        ltp_data = data.get("data", {})
        if isinstance(ltp_data, dict) and sym in ltp_data:
            ltp = ltp_data[sym].get("last_price") or ltp_data[sym].get("ltp")
        else:
            ltp = ltp_data.get("last_price") or ltp_data.get("ltp") if isinstance(ltp_data, dict) else None
        return jsonify({"ltp": ltp})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Cache for instrument master data
_instrument_master_cache = None
_instrument_master_cache_time = None
INSTRUMENT_MASTER_CACHE_TTL = 3600  # Cache for 1 hour

def load_instrument_master():
    """Load instrument master CSV from Upstox (cached)"""
    global _instrument_master_cache, _instrument_master_cache_time
    
    # Return cached data if still valid
    if _instrument_master_cache is not None and _instrument_master_cache_time is not None:
        if time.time() - _instrument_master_cache_time < INSTRUMENT_MASTER_CACHE_TTL:
            return _instrument_master_cache
    
    try:
        print("📥 Loading instrument master CSV from Upstox...")
        df = pd.read_csv("https://assets.upstox.com/market-quote/instruments/exchange/complete.csv.gz")
        _instrument_master_cache = df
        _instrument_master_cache_time = time.time()
        print(f"✅ Loaded {len(df)} instruments from master CSV")
        return df
    except Exception as e:
        print(f"⚠️ Failed to load instrument master: {e}")
        if _instrument_master_cache is not None:
            print("   Using cached instrument master data")
            return _instrument_master_cache
        return None

def get_option_instruments(symbol_name, index_code):
    """Get option instruments from master CSV for given symbol/index"""
    df = load_instrument_master()
    if df is None:
        return None
    
    try:
        # Filter for options: NSE_FO exchange
        # For indices: OPTIDX, for stocks: OPTSTK
        # Try both to support both indices and stocks
        filtered = df[
            (df['exchange'] == 'NSE_FO') &
            (df['instrument_type'].isin(['OPTIDX', 'OPTSTK'])) &
            (df['tradingsymbol'].str.startswith(symbol_name, na=False))
        ]
        
        if len(filtered) == 0:
            print(f"⚠️ No options found for {symbol_name} (tried both OPTIDX and OPTSTK)")
            return None
        
        # Get nearest expiry automatically
        nearest_expiry = min(filtered['expiry'].unique())
        filtered = filtered[filtered['expiry'] == nearest_expiry]
        
        print(f"✅ Found {len(filtered)} {symbol_name} option instruments for expiry {nearest_expiry}")
        return filtered.reset_index(drop=True)
    except Exception as e:
        print(f"⚠️ Error filtering instrument master: {e}")
        return None

def aggregate_candles(candles, target_interval):
    """Aggregate 1minute candles to target timeframe (5min, 15min, 30min, 60min, 75min)
    
    Args:
        candles: List of 1minute candles [[timestamp, open, high, low, close, volume, oi], ...]
        target_interval: Target interval ("5minute", "15minute", "30minute", "60minute", "75minute")
    
    Returns:
        List of aggregated candles in same format
    """
    if not candles:
        return []
    
    # Determine aggregation factor
    if target_interval == "5minute":
        factor = 5
    elif target_interval == "15minute":
        factor = 15
    elif target_interval == "30minute":
        factor = 30
    elif target_interval == "60minute":
        factor = 60
    elif target_interval == "75minute":
        factor = 75
    else:
        return candles  # No aggregation needed
    
    aggregated = []
    i = 0
    
    while i < len(candles):
        # Group candles for this timeframe
        group = candles[i:i+factor]
        if not group:
            break
        
        # First candle's timestamp and open
        first_candle = group[0]
        timestamp = first_candle[0]
        open_price = first_candle[1] if len(first_candle) > 1 else None
        
        # Last candle's close
        last_candle = group[-1]
        close_price = last_candle[4] if len(last_candle) > 4 else None
        
        # High and low from all candles in group
        high_price = max([c[2] for c in group if len(c) > 2 and c[2] is not None], default=None)
        low_price = min([c[3] for c in group if len(c) > 3 and c[3] is not None], default=None)
        
        # Sum volume and OI (use last candle's OI)
        volume = sum([c[5] for c in group if len(c) > 5 and c[5] is not None])
        oi = last_candle[6] if len(last_candle) > 6 else None
        
        aggregated.append([timestamp, open_price, high_price, low_price, close_price, volume, oi])
        i += factor
    
    return aggregated

def get_previous_day_high_low(instrument_key, interval, access_token):
    """Get the HIGH and LOW from the last 225 minutes (last 3 × 75min candles) of the previous trading day
    According to M75 Strategy formula:
    - PL3H: Highest high from last 225 minutes (last 3 × 75min candles) of previous trading day
    - PL3L: Lowest low from last 225 minutes (last 3 × 75min candles) of previous trading day
    - PL3M: (PL3H + PL3L) / 2 (mid price)
    
    Returns dict with pl3h, pl3l, pl3m
    
    Args:
        instrument_key: Instrument key (e.g., "NSE_INDEX|Nifty 50", "NSE_EQ|RELIANCE", "NSE_FO|40083")
        interval: Timeframe (should be "75minute")
        access_token: Upstox access token
    """
    try:
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
            "Api-Version": "2.0"
        }
        
        # For 75minute, we need to aggregate from 1minute candles
        api_interval = "1minute"
        needs_aggregation = interval == "75minute"
        
        # Get data for last 10 days to ensure we get 3 trading days
        to_date = datetime.now().date()
        from_date = to_date - timedelta(days=10)
        
        url = f"https://api.upstox.com/v2/historical-candle/{instrument_key}/{api_interval}/{to_date}/{from_date}"
        response = requests.get(url, headers=headers, timeout=15)
        
        # If that fails, try URL encoding
        if response.status_code != 200:
            instrument_key_encoded = instrument_key.replace("|", "%7C")
            url = f"https://api.upstox.com/v2/historical-candle/{instrument_key_encoded}/{api_interval}/{to_date}/{from_date}"
            response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            candles = data.get("data", {}).get("candles", [])
            if not candles:
                print(f"   ⚠️ No candles returned from API for {instrument_key}")
                return {"pl3h": None, "pl3l": None, "pl3m": None}
            
            print(f"   📥 Received {len(candles)} raw candles from API")
            
            # Sort by timestamp
            candles_sorted = sorted(candles, key=lambda x: x[0] if len(x) > 0 else 0)
            
            if needs_aggregation:
                # Aggregate to 75minute candles
                print(f"   🔄 Aggregating {len(candles_sorted)} 1min candles to 75min candles...")
                aggregated = aggregate_candles(candles_sorted, interval)
                candles_sorted = aggregated
                print(f"   ✅ Aggregated to {len(candles_sorted)} 75min candles")
            
            # Group candles by date and get last candle of each day
            # Format: [timestamp, open, high, low, close, volume, oi]
            candles_by_date = {}
            for candle in candles_sorted:
                if len(candle) < 1:
                    continue
                timestamp = candle[0]
                # Parse timestamp (format: "2025-11-08T09:15:00+05:30" or Unix timestamp)
                try:
                    if isinstance(timestamp, (int, float)):
                        # Unix timestamp in milliseconds - convert to IST
                        dt_utc = datetime.fromtimestamp(timestamp / 1000, tz=timezone.utc)
                        # IST is UTC+5:30
                        ist_offset = timedelta(hours=5, minutes=30)
                        dt = dt_utc.replace(tzinfo=None) + ist_offset
                    else:
                        # ISO format string - may already have timezone
                        ts_str = str(timestamp)
                        if '+' in ts_str and '05:30' in ts_str:
                            # Already in IST format
                            dt = datetime.fromisoformat(ts_str.replace('+05:30', ''))
                        elif 'Z' in ts_str or '+00:00' in ts_str:
                            # UTC format - convert to IST
                            dt_utc = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                            ist_offset = timedelta(hours=5, minutes=30)
                            dt = dt_utc.replace(tzinfo=None) + ist_offset
                        else:
                            # No timezone, assume IST
                            dt = datetime.fromisoformat(ts_str)
                    
                    # Use date for grouping (IST date)
                    date_key = dt.date() if isinstance(dt, datetime) else dt
                    if date_key not in candles_by_date:
                        candles_by_date[date_key] = []
                    candles_by_date[date_key].append(candle)
                except Exception as e:
                    print(f"   ⚠️ Error parsing timestamp {timestamp}: {e}")
                    import traceback
                    traceback.print_exc()
                    continue
            
            # Get the previous trading day (not today)
            # Sort dates in reverse order (most recent first)
            sorted_dates = sorted(candles_by_date.keys(), reverse=True)
            
            # Get today's date in IST (current date)
            # IST is UTC+5:30, so we need to account for this
            now_utc = datetime.now(timezone.utc)
            ist_offset = timedelta(hours=5, minutes=30)
            now_ist = now_utc.replace(tzinfo=None) + ist_offset
            today = now_ist.date()
            
            print(f"   🔍 Today's date (IST): {today}, Available dates: {sorted_dates}")
            
            # Skip today and get the previous trading day
            previous_day_candles = None
            previous_day_date = None
            
            for date_key in sorted_dates:
                if date_key < today:  # Previous trading day
                    previous_day_candles = candles_by_date[date_key]
                    previous_day_date = date_key
                    print(f"   ✅ Found previous trading day: {previous_day_date} with {len(previous_day_candles)} candles")
                    break
            
            if not previous_day_candles:
                # If no previous day found, try to get from most recent day (excluding today)
                if len(sorted_dates) > 0 and sorted_dates[0] < today:
                    previous_day_candles = candles_by_date[sorted_dates[0]]
                    previous_day_date = sorted_dates[0]
                    print(f"   ✅ Using most recent day (excluding today): {previous_day_date}")
                elif len(sorted_dates) > 1:
                    previous_day_candles = candles_by_date[sorted_dates[1]]
                    previous_day_date = sorted_dates[1]
                    print(f"   ✅ Using second most recent day: {previous_day_date}")
                else:
                    print(f"   ⚠️ No previous trading day found. Today: {today}, Available: {sorted_dates}")
            
            if previous_day_candles:
                # Sort candles by timestamp to get chronological order
                sorted_day_candles = sorted(previous_day_candles, key=lambda x: x[0] if len(x) > 0 else 0)
                
                print(f"   📊 Total candles for {previous_day_date}: {len(sorted_day_candles)}")
                if len(sorted_day_candles) > 0:
                    # Show first and last candle timestamps for debugging
                    first_ts = sorted_day_candles[0][0] if len(sorted_day_candles[0]) > 0 else "N/A"
                    last_ts = sorted_day_candles[-1][0] if len(sorted_day_candles[-1]) > 0 else "N/A"
                    first_high = sorted_day_candles[0][2] if len(sorted_day_candles[0]) > 2 else "N/A"
                    first_low = sorted_day_candles[0][3] if len(sorted_day_candles[0]) > 3 else "N/A"
                    last_high = sorted_day_candles[-1][2] if len(sorted_day_candles[-1]) > 2 else "N/A"
                    last_low = sorted_day_candles[-1][3] if len(sorted_day_candles[-1]) > 3 else "N/A"
                    print(f"   📅 First candle: TS={first_ts}, High={first_high}, Low={first_low}")
                    print(f"   📅 Last candle: TS={last_ts}, High={last_high}, Low={last_low}")
                
                # Get the LAST 3 candles (last 225 minutes = 3 × 75min)
                last_3_candles = sorted_day_candles[-3:] if len(sorted_day_candles) >= 3 else sorted_day_candles
                
                # Debug: Print details of last 3 candles
                print(f"   🔍 Last {len(last_3_candles)} candles (last 225min):")
                for i, candle in enumerate(last_3_candles):
                    if len(candle) >= 5:
                        ts = candle[0] if len(candle) > 0 else "N/A"
                        high = candle[2] if len(candle) > 2 else "N/A"
                        low = candle[3] if len(candle) > 3 else "N/A"
                        print(f"      Candle {i+1}: TS={ts}, High={high}, Low={low}")
                
                # Get HIGH and LOW from the last 3 candles (last 225 minutes)
                # Format: [timestamp, open, high, low, close, volume, oi]
                highs = []
                lows = []
                for candle in last_3_candles:
                    if len(candle) > 2:
                        highs.append(candle[2])  # high
                    if len(candle) > 3:
                        lows.append(candle[3])   # low
                
                if highs and lows:
                    pl3h = max(highs)  # Highest high from last 225 minutes
                    pl3l = min(lows)   # Lowest low from last 225 minutes
                    pl3m = (pl3h + pl3l) / 2  # Mid price
                    
                    print(f"   ✅ Previous day ({previous_day_date}) - Last 225min: PL3H={pl3h:.2f}, PL3L={pl3l:.2f}, PL3M={pl3m:.2f} (from {len(last_3_candles)} candles)")
                    
                    return {
                        "pl3h": round(pl3h, 2),
                        "pl3l": round(pl3l, 2),
                        "pl3m": round(pl3m, 2)
                    }
                else:
                    print(f"   ⚠️ No valid high/low data in last 3 candles")
            
            return {"pl3h": None, "pl3l": None, "pl3m": None}  # No previous day data found
        else:
            try:
                error_data = response.json()
                error_msg = error_data.get("message", error_data.get("error", str(error_data)))
            except:
                error_msg = response.text[:200] if response.text else "No error message"
            print(f"   ⚠️ Last candle API returned status {response.status_code} for {instrument_key}: {error_msg}")
    except Exception as e:
        print(f"   ⚠️ Last candle fetch error for {instrument_key}: {e}")
        import traceback
        traceback.print_exc()
    return {"pl3h": None, "pl3l": None, "pl3m": None}

def calculate_m75_conditions(ltp, pl3h, pl3m, pl3l, previous_ltp=None):
    """Calculate M75 Strategy conditions and signals based on price levels
    
    Args:
        ltp: Current spot price LTP
        pl3h: PL3H value (highest high from last 225min of previous day)
        pl3m: PL3M value (mid price)
        pl3l: PL3L value (lowest low from last 225min of previous day)
        previous_ltp: Previous LTP to determine price movement direction (optional)
    
    Returns:
        dict with conditions, signals, and alerts
    """
    if not ltp or not pl3h or not pl3m or not pl3l:
        return {
            "pl3h_condition": None,
            "pl3m_condition": None,
            "pl3l_condition": None,
            "pl3h_signal": None,
            "pl3m_signal": None,
            "pl3l_signal": None,
            "pl3h_alert": False,
            "pl3m_alert": False,
            "pl3l_alert": False
        }
    
    ltp_float = float(ltp)
    pl3h_float = float(pl3h)
    pl3m_float = float(pl3m)
    pl3l_float = float(pl3l)
    
    # Calculate percentage distance from each level (for "nearing" detection)
    # Consider "nearing" if within 0.5% of the level
    near_threshold = 0.005  # 0.5%
    
    # PL3H Conditions
    pl3h_condition = None
    pl3h_signal = None
    pl3h_alert = False
    
    if ltp_float > pl3h_float:
        pl3h_condition = "bullish"
        pl3h_signal = "B"  # Changed from "BUY"
    else:
        # Check if nearing PL3H (within 0.5%)
        distance_to_pl3h = abs(ltp_float - pl3h_float) / pl3h_float
        if distance_to_pl3h <= near_threshold:
            pl3h_alert = True
    
    # PL3L Conditions
    pl3l_condition = None
    pl3l_signal = None
    pl3l_alert = False
    
    if ltp_float < pl3l_float:
        pl3l_condition = "bearish"
        pl3l_signal = "BO-S"  # Changed from "BUY_OPPOSITE"
    else:
        # Check if nearing PL3L (within 0.5%)
        distance_to_pl3l = abs(ltp_float - pl3l_float) / pl3l_float
        if distance_to_pl3l <= near_threshold:
            pl3l_alert = True
    
    # PL3M Conditions (more complex - depends on price movement direction)
    pl3m_condition = None
    pl3m_signal = None
    pl3m_alert = False
    
    # Check if price is breaking PL3M
    if previous_ltp:
        prev_ltp_float = float(previous_ltp)
        # Breaking from high to low (bearish)
        if prev_ltp_float > pl3m_float and ltp_float <= pl3m_float:
            pl3m_condition = "bearish_break"
            pl3m_signal = "W"  # Changed from "WATCH"
        # Breaking from low to high (bullish)
        elif prev_ltp_float < pl3m_float and ltp_float >= pl3m_float:
            pl3m_condition = "bullish_break"
            pl3m_signal = "W"  # Changed from "WATCH"
        # Already broken (check current position)
        elif ltp_float < pl3m_float and prev_ltp_float < pl3m_float:
            pl3m_condition = "below"
            pl3m_signal = "W"  # Changed from "WATCH"
        elif ltp_float > pl3m_float and prev_ltp_float > pl3m_float:
            pl3m_condition = "above"
            pl3m_signal = "W"  # Changed from "WATCH"
    else:
        # No previous LTP - just check current position
        if ltp_float < pl3m_float:
            pl3m_condition = "below"
        elif ltp_float > pl3m_float:
            pl3m_condition = "above"
        pl3m_signal = "W"  # Changed from "WATCH"
    
    # Check if nearing PL3M (within 0.5%)
    distance_to_pl3m = abs(ltp_float - pl3m_float) / pl3m_float
    if distance_to_pl3m <= near_threshold:
        pl3m_alert = True
    
    return {
        "pl3h_condition": pl3h_condition,
        "pl3m_condition": pl3m_condition,
        "pl3l_condition": pl3l_condition,
        "pl3h_signal": pl3h_signal,
        "pl3m_signal": pl3m_signal,
        "pl3l_signal": pl3l_signal,
        "pl3h_alert": pl3h_alert,
        "pl3m_alert": pl3m_alert,
        "pl3l_alert": pl3l_alert
    }

# calculate_pl3_values function is no longer needed - we use get_previous_day_high_low directly

def get_previous_trading_day_ohlc(instrument_key, access_token):
    """Get the previous trading day's full day OHLC (not just first candle)
    
    Args:
        instrument_key: Instrument key (e.g., "NSE_INDEX|Nifty 50")
        access_token: Upstox access token
    
    Returns:
        dict with o, h, l, c for previous trading day
    """
    try:
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
            "Api-Version": "2.0"
        }
        
        # Get daily candles for last 10 days to find previous trading day
        to_date = datetime.now().date()
        from_date = to_date - timedelta(days=10)
        
        url = f"https://api.upstox.com/v2/historical-candle/{instrument_key}/day/{to_date}/{from_date}"
        response = requests.get(url, headers=headers, timeout=15)
        
        # If that fails, try URL encoding
        if response.status_code != 200:
            instrument_key_encoded = instrument_key.replace("|", "%7C")
            url = f"https://api.upstox.com/v2/historical-candle/{instrument_key_encoded}/day/{to_date}/{from_date}"
            response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            candles = data.get("data", {}).get("candles", [])
            if candles:
                # Sort by timestamp to ensure chronological order
                candles_sorted = sorted(candles, key=lambda x: x[0] if len(x) > 0 else 0)
                
                # Group candles by date
                candles_by_date = {}
                for candle in candles_sorted:
                    if len(candle) < 1:
                        continue
                    timestamp = candle[0]
                    try:
                        # Parse timestamp
                        if isinstance(timestamp, (int, float)):
                            dt = datetime.fromtimestamp(timestamp / 1000)
                        else:
                            ts_str = str(timestamp)
                            if '+' in ts_str and '05:30' in ts_str:
                                dt = datetime.fromisoformat(ts_str.replace('+05:30', ''))
                            elif 'Z' in ts_str or '+00:00' in ts_str:
                                dt_utc = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                                ist_offset = timedelta(hours=5, minutes=30)
                                dt = dt_utc.replace(tzinfo=None) + ist_offset
                            else:
                                dt = datetime.fromisoformat(ts_str)
                        
                        date_key = dt.date() if isinstance(dt, datetime) else dt
                        if date_key not in candles_by_date:
                            candles_by_date[date_key] = []
                        candles_by_date[date_key].append(candle)
                    except:
                        continue
                
                # Get today's date (local time)
                today = datetime.now().date()
                
                # Find previous trading day (not today)
                sorted_dates = sorted(candles_by_date.keys(), reverse=True)
                previous_day_candle = None
                
                for date_key in sorted_dates:
                    if date_key < today:  # Previous trading day
                        day_candles = candles_by_date[date_key]
                        if day_candles:
                            # For daily candles, there should be one candle per day
                            # Get the full day OHLC from that candle
                            previous_day_candle = day_candles[0]  # Daily candle has full day OHLC
                            print(f"   📅 Found previous trading day: {date_key}")
                            break
                
                if previous_day_candle and len(previous_day_candle) >= 5:
                    # Daily candle format: [timestamp, open, high, low, close, volume, oi]
                    return {
                        "o": previous_day_candle[1] if len(previous_day_candle) > 1 else None,
                        "h": previous_day_candle[2] if len(previous_day_candle) > 2 else None,
                        "l": previous_day_candle[3] if len(previous_day_candle) > 3 else None,
                        "c": previous_day_candle[4] if len(previous_day_candle) > 4 else None
                    }
        else:
            try:
                error_data = response.json()
                error_msg = error_data.get("message", error_data.get("error", str(error_data)))
            except:
                error_msg = response.text[:200] if response.text else "No error message"
            print(f"   ⚠️ Previous day OHLC API returned status {response.status_code}: {error_msg}")
    except Exception as e:
        print(f"   ⚠️ Previous day OHLC fetch error: {e}")
        import traceback
        traceback.print_exc()
    return {}

def calculate_box_strategy_values(instrument_key, interval, access_token, current_ltp, previous_day_ohlc=None):
    """Calculate Box Strategy values: FCH, FCL, BR.T, BR.R, BE.T, BE.R, PL3H, PL3L, PL3M, PDH, PDL, PDO, PDC
    
    Args:
        instrument_key: Instrument key (e.g., "NSE_INDEX|Nifty 50")
        interval: Timeframe (e.g., "5minute", "15minute", "30minute", "60minute", "day")
        access_token: Upstox access token
        current_ltp: Current LTP (close price)
        previous_day_ohlc: Optional dict with previous day OHLC (PDH, PDL, PDO, PDC)
    
    Returns:
        dict with all Box Strategy values
    """
    result = {
        "fch": None,  # First Candle High
        "fcl": None,  # First Candle Low
        "fcm": None,  # First Candle Midpoint (FCH + FCL) / 2
        "br_t": None,  # Bullish Target
        "br_r": None,  # Bullish Reversal
        "be_t": None,  # Bearish Target
        "be_r": None,  # Bearish Reversal
        "pl3h": None,  # PL3H (from last 225min)
        "pl3l": None,  # PL3L (from last 225min)
        "pl3m": None,  # PL3M (midpoint)
        "pdh": None,  # Previous Day High
        "pdl": None,  # Previous Day Low
        "pdo": None,  # Previous Day Open
        "pdc": None,  # Previous Day Close
        "bias": "Neutral"  # Neutral, Bullish, Bearish
    }
    
    try:
        # Get first candle of the session (FCH, FCL)
        first_candle = get_underlying_ohlc_from_candles(instrument_key, interval, access_token)
        if first_candle:
            result["fch"] = first_candle.get("h")
            result["fcl"] = first_candle.get("l")
        
        # Get PL3H, PL3L, PL3M from last 225 minutes (3 × 75min candles)
        pl3_data = get_previous_day_high_low(instrument_key, "75minute", access_token)
        if pl3_data:
            result["pl3h"] = pl3_data.get("pl3h")
            result["pl3l"] = pl3_data.get("pl3l")
            result["pl3m"] = pl3_data.get("pl3m")
        
        # Get previous day OHLC (PDH, PDL, PDO, PDC) - full day OHLC
        if previous_day_ohlc:
            result["pdh"] = previous_day_ohlc.get("h")
            result["pdl"] = previous_day_ohlc.get("l")
            result["pdo"] = previous_day_ohlc.get("o")
            result["pdc"] = previous_day_ohlc.get("c")
        else:
            # Fetch previous trading day's full day OHLC
            prev_day_ohlc = get_previous_trading_day_ohlc(instrument_key, access_token)
            if prev_day_ohlc:
                result["pdh"] = prev_day_ohlc.get("h")
                result["pdl"] = prev_day_ohlc.get("l")
                result["pdo"] = prev_day_ohlc.get("o")
                result["pdc"] = prev_day_ohlc.get("c")
        
        # Calculate targets and reversals based on FCH and FCL
        # Always calculate both bullish and bearish values when FCH and FCL are available
        if result["fch"] and result["fcl"]:
            fch_float = float(result["fch"])
            fcl_float = float(result["fcl"])
            
            # Calculate FCM (First Candle Midpoint) = (FCH + FCL) / 2
            result["fcm"] = (fch_float + fcl_float) / 2
            
            # Calculate dist_a = FCH - FCL (used for both bullish and bearish)
            dist_a = fch_float - fcl_float
            
            # Always calculate BULLISH values (regardless of current LTP)
            # BR.T (Bullish Target) = FCH + (dist_a * 2)
            result["br_t"] = fch_float + (dist_a * 2)
            # BR.R (Bullish Reversal) = FCL + (fib_range * 0.75)
            # Where fib_range = BR.T - FCL
            fib_range_bull = result["br_t"] - fcl_float
            result["br_r"] = fcl_float + (fib_range_bull * 0.75)
            
            # Always calculate BEARISH values (regardless of current LTP)
            # BE.T (Bearish Target) = FCL - (dist_a * 2)
            result["be_t"] = fcl_float - (dist_a * 2)
            # BE.R (Bearish Reversal) = FCH - (fib_range * 0.75)
            # Where fib_range = FCH - BE.T (range from FCH to BE.T)
            # Reversal = FCH - 75% of the range from FCH to BE.T
            fib_range_bear = fch_float - result["be_t"]  # Range from FCH to BE.T
            result["be_r"] = fch_float - (fib_range_bear * 0.75)
        else:
            result["fcm"] = None
        
        # Round all numeric values to 2 decimal places
        for key in ["fch", "fcl", "fcm", "br_t", "br_r", "be_t", "be_r", "pl3h", "pl3l", "pl3m", "pdh", "pdl", "pdo", "pdc"]:
            if result[key] is not None:
                try:
                    result[key] = round(float(result[key]), 2)
                except:
                    pass
        
    except Exception as e:
        print(f"   ⚠️ Box Strategy calculation error: {e}")
        import traceback
        traceback.print_exc()
    
    return result

def get_underlying_ohlc_from_candles(instrument_key, interval, access_token):
    """Fetch OHLC data for underlying stock/index from historical candle API
    Returns the FIRST candle of the trading day for the specified timeframe
    
    Args:
        instrument_key: Instrument key (e.g., "NSE_INDEX|Nifty 50", "NSE_EQ|RELIANCE")
        interval: Timeframe (e.g., "5minute")
        access_token: Upstox access token
    """
    try:
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
            "Api-Version": "2.0"
        }
        
        # The API only accepts: 1minute, 30minute, day, week, month
        # For 5minute, 15minute, 30minute, 60minute: fetch 1minute candles and aggregate them
        to_date = datetime.now().date()
        
        # Determine which interval to request from API
        api_interval = interval
        needs_aggregation = False
        
        if interval in ["5minute", "15minute", "30minute", "60minute"]:
            # Need to fetch 1minute candles and aggregate
            api_interval = "1minute"
            needs_aggregation = True
            # Try intraday endpoint first (for today's data), then fallback to historical
            use_intraday = True
        elif interval == "1minute":
            use_intraday = True
            needs_aggregation = False
        else:
            # For day, week, month
            use_intraday = False
            days_back = 5  # Get last 5 days
            needs_aggregation = False
        
        # Try intraday endpoint first for intraday timeframes
        if use_intraday:
            url = f"https://api.upstox.com/v2/historical-candle/intraday/{instrument_key}/{api_interval}"
            response = requests.get(url, headers=headers, timeout=10)
            
            # If intraday fails or returns empty, try historical endpoint with date range
            if response.status_code == 200:
                data = response.json()
                candles = data.get("data", {}).get("candles", [])
                if not candles or len(candles) == 0:
                    # No data from intraday, try historical endpoint (yesterday to today)
                    print(f"   ⚠️ Intraday endpoint returned no data, trying historical endpoint...")
                    from_date = to_date - timedelta(days=2)  # Get last 2 days
                    url = f"https://api.upstox.com/v2/historical-candle/{instrument_key}/{api_interval}/{to_date}/{from_date}"
                    response = requests.get(url, headers=headers, timeout=10)
                    
                    # If that fails, try URL encoding
                    if response.status_code != 200:
                        instrument_key_encoded = instrument_key.replace("|", "%7C")
                        url = f"https://api.upstox.com/v2/historical-candle/{instrument_key_encoded}/{api_interval}/{to_date}/{from_date}"
                        response = requests.get(url, headers=headers, timeout=10)
            elif response.status_code != 200:
                # Intraday endpoint failed, try historical endpoint
                print(f"   ⚠️ Intraday endpoint failed ({response.status_code}), trying historical endpoint...")
                from_date = to_date - timedelta(days=2)  # Get last 2 days
                url = f"https://api.upstox.com/v2/historical-candle/{instrument_key}/{api_interval}/{to_date}/{from_date}"
                response = requests.get(url, headers=headers, timeout=10)
                
                # If that fails, try URL encoding
                if response.status_code != 200:
                    instrument_key_encoded = instrument_key.replace("|", "%7C")
                    url = f"https://api.upstox.com/v2/historical-candle/{instrument_key_encoded}/{api_interval}/{to_date}/{from_date}"
                    response = requests.get(url, headers=headers, timeout=10)
        else:
            # Use historical endpoint with date range for daily/weekly/monthly
            from_date = to_date - timedelta(days=days_back)
            url = f"https://api.upstox.com/v2/historical-candle/{instrument_key}/{api_interval}/{to_date}/{from_date}"
            response = requests.get(url, headers=headers, timeout=10)
            
            # If that fails, try URL encoding
            if response.status_code != 200:
                instrument_key_encoded = instrument_key.replace("|", "%7C")
                url = f"https://api.upstox.com/v2/historical-candle/{instrument_key_encoded}/{api_interval}/{to_date}/{from_date}"
                response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            candles = data.get("data", {}).get("candles", [])
            if candles:
                # Sort by timestamp to ensure chronological order
                candles_sorted = sorted(candles, key=lambda x: x[0] if len(x) > 0 else 0)
                
                # Group candles by date to find the most recent trading day with data
                candles_by_date = {}
                for candle in candles_sorted:
                    if len(candle) < 1:
                        continue
                    timestamp = candle[0]
                    try:
                        # Parse timestamp
                        if isinstance(timestamp, (int, float)):
                            dt = datetime.fromtimestamp(timestamp / 1000)
                        else:
                            ts_str = str(timestamp)
                            if '+' in ts_str and '05:30' in ts_str:
                                dt = datetime.fromisoformat(ts_str.replace('+05:30', ''))
                            elif 'Z' in ts_str or '+00:00' in ts_str:
                                dt_utc = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                                ist_offset = timedelta(hours=5, minutes=30)
                                dt = dt_utc.replace(tzinfo=None) + ist_offset
                            else:
                                dt = datetime.fromisoformat(ts_str)
                        
                        date_key = dt.date() if isinstance(dt, datetime) else dt
                        if date_key not in candles_by_date:
                            candles_by_date[date_key] = []
                        candles_by_date[date_key].append(candle)
                    except:
                        continue
                
                # Get the most recent date with candles (handles market closed/holidays)
                if candles_by_date:
                    most_recent_date = max(candles_by_date.keys())
                    day_candles = sorted(candles_by_date[most_recent_date], key=lambda x: x[0] if len(x) > 0 else 0)
                    print(f"   📅 Using candles from {most_recent_date} ({len(day_candles)} candles)")
                else:
                    day_candles = candles_sorted
                
                if needs_aggregation:
                    # Aggregate 1minute candles to desired timeframe
                    aggregated = aggregate_candles(day_candles, interval)
                    if aggregated:
                        # Get first aggregated candle (first candle of trading day for this timeframe)
                        first_candle = aggregated[0]
                        return {
                            "o": first_candle[1] if len(first_candle) > 1 else None,
                            "h": first_candle[2] if len(first_candle) > 2 else None,
                            "l": first_candle[3] if len(first_candle) > 3 else None,
                            "c": first_candle[4] if len(first_candle) > 4 else None
                        }
                else:
                    # Get FIRST candle of the trading day (earliest timestamp)
                    first_candle = day_candles[0]
                    return {
                        "o": first_candle[1] if len(first_candle) > 1 else None,
                        "h": first_candle[2] if len(first_candle) > 2 else None,
                        "l": first_candle[3] if len(first_candle) > 3 else None,
                        "c": first_candle[4] if len(first_candle) > 4 else None
                    }
            else:
                print(f"   ⚠️ No candles returned for {instrument_key} ({interval})")
        else:
            try:
                error_data = response.json()
                error_msg = error_data.get("message", error_data.get("error", str(error_data)))
            except:
                error_msg = response.text[:200] if response.text else "No error message"
            print(f"   ⚠️ Underlying candle API returned status {response.status_code} for {instrument_key} ({interval}): {error_msg}")
    except Exception as e:
        print(f"   ⚠️ Underlying candle fetch error for {instrument_key} ({interval}): {e}")
        import traceback
        traceback.print_exc()
    return {}

def get_option_ohlc_from_candles(instrument_key, interval, access_token, exchange_token=None):
    """Fetch OHLC data for a single option instrument from historical candle API
    Returns the FIRST candle of the trading day for the specified timeframe
    
    Args:
        instrument_key: Instrument key (e.g., "NSE_FO|40083")
        interval: Timeframe (e.g., "5minute")
        access_token: Upstox access token
        exchange_token: Optional exchange_token (some APIs prefer this)
    """
    try:
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
            "Api-Version": "2.0"
        }
        
        # The API only accepts: 1minute, 30minute, day, week, month
        # For 5minute, 15minute, 30minute, 60minute: fetch 1minute candles and aggregate them
        # This ensures consistency across all timeframes
        to_date = datetime.now().date()
        
        # Determine which interval to request from API
        api_interval = interval
        needs_aggregation = False
        
        if interval in ["5minute", "15minute", "30minute", "60minute"]:
            # Need to fetch 1minute candles and aggregate
            api_interval = "1minute"
            needs_aggregation = True
            use_intraday = True
        elif interval == "1minute":
            # Use API's 1minute directly
            use_intraday = True
            needs_aggregation = False
        else:
            # For day, week, month
            use_intraday = False
            days_back = 5  # Get last 5 days
            needs_aggregation = False
        
        # Try intraday endpoint first for intraday timeframes
        if use_intraday:
            if exchange_token:
                url = f"https://api.upstox.com/v2/historical-candle/intraday/NSE_FO|{exchange_token}/{api_interval}"
            else:
                url = f"https://api.upstox.com/v2/historical-candle/intraday/{instrument_key}/{api_interval}"
            response = requests.get(url, headers=headers, timeout=10)
            
            # If intraday fails or returns empty, try historical endpoint with date range
            if response.status_code == 200:
                data = response.json()
                candles = data.get("data", {}).get("candles", [])
                if not candles or len(candles) == 0:
                    # No data from intraday, try historical endpoint (yesterday to today)
                    print(f"   ⚠️ Intraday endpoint returned no data, trying historical endpoint...")
                    from_date = to_date - timedelta(days=2)  # Get last 2 days
                    
                    if exchange_token:
                        url = f"https://api.upstox.com/v2/historical-candle/NSE_FO|{exchange_token}/{api_interval}/{to_date}/{from_date}"
                    else:
                        url = f"https://api.upstox.com/v2/historical-candle/{instrument_key}/{api_interval}/{to_date}/{from_date}"
                    response = requests.get(url, headers=headers, timeout=10)
                    
                    # If that fails, try URL encoding
                    if response.status_code != 200:
                        if exchange_token:
                            url = f"https://api.upstox.com/v2/historical-candle/NSE_FO%7C{exchange_token}/{api_interval}/{to_date}/{from_date}"
                        else:
                            instrument_key_encoded = instrument_key.replace("|", "%7C")
                            url = f"https://api.upstox.com/v2/historical-candle/{instrument_key_encoded}/{api_interval}/{to_date}/{from_date}"
                        response = requests.get(url, headers=headers, timeout=10)
            elif response.status_code != 200:
                # Intraday endpoint failed, try historical endpoint
                print(f"   ⚠️ Intraday endpoint failed ({response.status_code}), trying historical endpoint...")
                from_date = to_date - timedelta(days=2)  # Get last 2 days
                
                if exchange_token:
                    url = f"https://api.upstox.com/v2/historical-candle/NSE_FO|{exchange_token}/{api_interval}/{to_date}/{from_date}"
                else:
                    url = f"https://api.upstox.com/v2/historical-candle/{instrument_key}/{api_interval}/{to_date}/{from_date}"
                response = requests.get(url, headers=headers, timeout=10)
                
                # If that fails, try URL encoding
                if response.status_code != 200:
                    if exchange_token:
                        url = f"https://api.upstox.com/v2/historical-candle/NSE_FO%7C{exchange_token}/{api_interval}/{to_date}/{from_date}"
                    else:
                        instrument_key_encoded = instrument_key.replace("|", "%7C")
                        url = f"https://api.upstox.com/v2/historical-candle/{instrument_key_encoded}/{api_interval}/{to_date}/{from_date}"
                    response = requests.get(url, headers=headers, timeout=10)
        else:
            # Use historical endpoint with date range for daily/weekly/monthly
            from_date = to_date - timedelta(days=days_back)
            
            if exchange_token:
                url = f"https://api.upstox.com/v2/historical-candle/NSE_FO|{exchange_token}/{api_interval}/{to_date}/{from_date}"
            else:
                url = f"https://api.upstox.com/v2/historical-candle/{instrument_key}/{api_interval}/{to_date}/{from_date}"
            response = requests.get(url, headers=headers, timeout=10)
            
            # If that fails, try URL encoding
            if response.status_code != 200:
                if exchange_token:
                    url = f"https://api.upstox.com/v2/historical-candle/NSE_FO%7C{exchange_token}/{api_interval}/{to_date}/{from_date}"
                else:
                    instrument_key_encoded = instrument_key.replace("|", "%7C")
                    url = f"https://api.upstox.com/v2/historical-candle/{instrument_key_encoded}/{api_interval}/{to_date}/{from_date}"
                response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            candles = data.get("data", {}).get("candles", [])
            if candles:
                # Sort by timestamp to ensure chronological order
                candles_sorted = sorted(candles, key=lambda x: x[0] if len(x) > 0 else 0)
                
                # Group candles by date to find the most recent trading day with data
                candles_by_date = {}
                for candle in candles_sorted:
                    if len(candle) < 1:
                        continue
                    timestamp = candle[0]
                    try:
                        # Parse timestamp
                        if isinstance(timestamp, (int, float)):
                            dt = datetime.fromtimestamp(timestamp / 1000)
                        else:
                            ts_str = str(timestamp)
                            if '+' in ts_str and '05:30' in ts_str:
                                dt = datetime.fromisoformat(ts_str.replace('+05:30', ''))
                            elif 'Z' in ts_str or '+00:00' in ts_str:
                                dt_utc = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                                ist_offset = timedelta(hours=5, minutes=30)
                                dt = dt_utc.replace(tzinfo=None) + ist_offset
                            else:
                                dt = datetime.fromisoformat(ts_str)
                        
                        date_key = dt.date() if isinstance(dt, datetime) else dt
                        if date_key not in candles_by_date:
                            candles_by_date[date_key] = []
                        candles_by_date[date_key].append(candle)
                    except:
                        continue
                
                # Get the most recent date with candles (handles market closed/holidays)
                if candles_by_date:
                    most_recent_date = max(candles_by_date.keys())
                    day_candles = sorted(candles_by_date[most_recent_date], key=lambda x: x[0] if len(x) > 0 else 0)
                    print(f"   📅 Using candles from {most_recent_date} ({len(day_candles)} candles)")
                else:
                    day_candles = candles_sorted
                
                if needs_aggregation:
                    # Aggregate 1minute candles to desired timeframe
                    aggregated = aggregate_candles(day_candles, interval)
                    if aggregated:
                        # Get first aggregated candle (first candle of trading day for this timeframe)
                        first_candle = aggregated[0]
                        return {
                            "o": first_candle[1] if len(first_candle) > 1 else None,
                            "h": first_candle[2] if len(first_candle) > 2 else None,
                            "l": first_candle[3] if len(first_candle) > 3 else None,
                            "c": first_candle[4] if len(first_candle) > 4 else None
                        }
                else:
                    # Get FIRST candle of the trading day (earliest timestamp)
                    # Format: [timestamp, open, high, low, close, volume, oi]
                    first_candle = day_candles[0]
                    
                    return {
                        "o": first_candle[1] if len(first_candle) > 1 else None,
                        "h": first_candle[2] if len(first_candle) > 2 else None,
                        "l": first_candle[3] if len(first_candle) > 3 else None,
                        "c": first_candle[4] if len(first_candle) > 4 else None
                    }
        else:
            try:
                error_data = response.json()
                error_msg = error_data.get("message", error_data.get("error", str(error_data)))
            except:
                error_msg = response.text[:200] if response.text else "No error message"
            print(f"   ⚠️ API returned status {response.status_code} for {instrument_key}: {error_msg}")
            print(f"   🔍 URL: {url}")
    except Exception as e:
        print(f"   ⚠️ Candle fetch error for {instrument_key}: {e}")
        import traceback
        traceback.print_exc()
    return {}

def get_option_ohlc_batch(instrument_keys, access_token, interval, key_to_tradingsymbol=None, key_to_exchange_token=None):
    """Fetch OHLC and LTP data for multiple option instruments at once
    
    Args:
        instrument_keys: List of instrument keys (e.g., ["NSE_FO|64008"])
        access_token: Upstox access token
        interval: Timeframe interval (e.g., "5minute", "15minute")
        key_to_tradingsymbol: Optional dict mapping instrument_key -> tradingsymbol for response matching
    """
    if not instrument_keys:
        return {}
    
    results = {}
    quotes_data = {}  # Store quotes data for fallback OHLC
    
    # First, get LTP and daily OHLC from quotes API (real-time)
    try:
        instrument_key_str = ",".join(instrument_keys)
        url = "https://api.upstox.com/v2/market-quote/quotes"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
            "Api-Version": "2.0"
        }
        params = {"symbol": instrument_key_str}
        response = requests.get(url, headers=headers, params=params, timeout=15)
        
        if response.status_code == 200:
            response_data = response.json()
            data = response_data.get("data", {})
            
            # Extract LTP and daily OHLC from quotes response
            for key in instrument_keys:
                found = False
                
                # If we have tradingsymbol mapping, use it to find response key
                if key_to_tradingsymbol and key in key_to_tradingsymbol:
                    tradingsymbol = key_to_tradingsymbol[key]
                    response_key = f"NSE_FO:{tradingsymbol}"
                    
                    if response_key in data:
                        q = data[response_key]
                        last_price = q.get("last_price") or q.get("ltp")
                        if last_price:
                            results[key] = {"ltp": last_price}
                            quotes_data[key] = q  # Store for OHLC fallback
                            found = True
                
                # Fallback: Try exact match or colon variant
                if not found:
                    for test_key in [key, key.replace("|", ":")]:
                        if test_key in data:
                            q = data[test_key]
                            last_price = q.get("last_price") or q.get("ltp")
                            if last_price:
                                results[key] = {"ltp": last_price}
                                quotes_data[key] = q  # Store for OHLC fallback
                                break
    except Exception as e:
        print(f"   ⚠️ LTP fetch error: {e}")
    
    # Now fetch OHLC from historical candle API for each instrument
    # This gets the FIRST candle of the trading day for the selected timeframe
    print(f"   📊 Fetching OHLC from candles for {len(instrument_keys)} instruments (interval: {interval})...")
    print(f"   📅 Getting FIRST candle of trading day for timeframe: {interval}")
    
    for key in instrument_keys:
        # Try to get exchange_token if available
        exchange_token = key_to_exchange_token.get(key) if key_to_exchange_token else None
        
        ohlc_data = get_option_ohlc_from_candles(key, interval, access_token, exchange_token)
        if ohlc_data and any(ohlc_data.values()):  # Check if we got valid data
            if key not in results:
                results[key] = {}
            results[key].update(ohlc_data)
            print(f"   ✅ Got OHLC for {key}: O={ohlc_data.get('o')}, H={ohlc_data.get('h')}, L={ohlc_data.get('l')}, C={ohlc_data.get('c')}")
        else:
            # Fallback: Try to get OHLC from quotes API (daily OHLC) if candle API fails
            # This happens when market is closed or candle API doesn't work
            if key not in results:
                results[key] = {}
            # Try to get daily OHLC from quotes response (already fetched above)
            if key in quotes_data:
                q = quotes_data[key]
                ohlc = q.get("ohlc", {})
                if ohlc:
                    results[key].update({
                        "o": ohlc.get("open"),
                        "h": ohlc.get("high"),
                        "l": ohlc.get("low"),
                        "c": ohlc.get("close") or results[key].get("ltp")
                    })
                    print(f"   ⚠️ Using daily OHLC fallback for {key} (candle API failed)")
                else:
                    print(f"   ⚠️ No OHLC data from candles or quotes for {key}")
            else:
                print(f"   ⚠️ No OHLC data from candles for {key}")
    
    print(f"   📈 Total results: {len([k for k in results.keys() if results[k]])}/{len(instrument_keys)}")
    return results

def get_option_ohlc(instrument_key, interval, access_token):
    """Fetch OHLC data for a single option instrument"""
    result = get_option_ohlc_batch([instrument_key], access_token, interval)
    return result.get(instrument_key, {})

@app.route("/api/auth_status")
def auth_status():
    """Check authorization status"""
    global access_token
    if not access_token:
        access_token = get_valid_token()
    
    if access_token:
        return jsonify({"authorized": True, "message": "Authorized"})
    else:
        return jsonify({
            "authorized": False, 
            "message": "Not authorized",
            "auth_url": AUTH_URL
        })

@app.route("/api/debug/ltp")
def debug_ltp():
    """Debug endpoint to see raw LTP API response"""
    friendly = request.args.get("symbol", "NIFTY")
    symbol_map = {
        "NIFTY": "NSE_INDEX%7CNifty%2050",
        "BANKNIFTY": "NSE_INDEX%7CNifty%20Bank",
        "FINNIFTY": "NSE_INDEX%7CNifty%20Fin%20Service",
        "RELIANCE": "NSE_EQ%7CRELIANCE",
        "TCS": "NSE_EQ%7CTCS",
        "INFY": "NSE_EQ%7CINFY"
    }
    sym = symbol_map.get(friendly, friendly)
    
    global access_token
    if not access_token:
        access_token = get_valid_token()
        if not access_token:
            return jsonify({"error": "No access token"}), 401
    
    quote_data = fetch_ltp(sym)
    return jsonify({
        "symbol": friendly,
        "instrument_key": sym,
        "raw_response": quote_data,
        "has_error": "error" in quote_data
    })

@app.route("/api/debug/csv")
def debug_csv():
    """Debug endpoint to see what's in the instrument master CSV"""
    friendly = request.args.get("symbol", "NIFTY")
    
    # Determine index code
    if "NIFTY" in friendly.upper() and "BANK" not in friendly.upper():
        index_code = "NIFTY"
    elif "BANK" in friendly.upper():
        index_code = "BANKNIFTY"
    elif "FIN" in friendly.upper():
        index_code = "FINNIFTY"
    else:
        index_code = friendly.upper()
    
    try:
        option_instruments_df = get_option_instruments(index_code, index_code)
        
        if option_instruments_df is None or len(option_instruments_df) == 0:
            return jsonify({
                "error": f"No instruments found for {index_code}",
                "symbol": friendly,
                "index_code": index_code
            }), 404
        
        # Get sample rows
        sample_rows = option_instruments_df.head(20).to_dict('records')
        
        # Get unique columns
        columns = list(option_instruments_df.columns)
        
        # Get unique strikes
        unique_strikes = sorted(option_instruments_df['strike'].unique().tolist())
        
        # Get expiry info
        unique_expiries = sorted(option_instruments_df['expiry'].unique().tolist())
        nearest_expiry = min(option_instruments_df['expiry'].unique())
        
        # Get sample instrument keys for a specific strike
        sample_strike = unique_strikes[0] if unique_strikes else None
        strike_samples = {}
        if sample_strike:
            strike_df = option_instruments_df[option_instruments_df['strike'] == float(sample_strike)]
            for _, row in strike_df.iterrows():
                strike_samples[row['option_type']] = {
                    "instrument_key": row.get('instrument_key'),
                    "tradingsymbol": row.get('tradingsymbol'),
                    "strike": row.get('strike'),
                    "expiry": str(row.get('expiry')),
                }
        
        return jsonify({
            "symbol": friendly,
            "index_code": index_code,
            "total_instruments": len(option_instruments_df),
            "columns": columns,
            "nearest_expiry": str(nearest_expiry),
            "unique_expiries": [str(e) for e in unique_expiries],
            "unique_strikes_count": len(unique_strikes),
            "strike_range": {
                "min": float(unique_strikes[0]) if unique_strikes else None,
                "max": float(unique_strikes[-1]) if unique_strikes else None,
                "sample_strikes": [float(s) for s in unique_strikes[:10]]
            },
            "sample_rows": sample_rows,
            "sample_strike_instruments": {
                "strike": sample_strike,
                "instruments": strike_samples
            }
        })
    except Exception as e:
        import traceback
        return jsonify({
            "error": str(e),
            "traceback": traceback.format_exc(),
            "symbol": friendly,
            "index_code": index_code
        }), 500

@app.route("/api/debug/options")
def debug_options():
    """Debug endpoint to see option premium data and instrument keys"""
    friendly = request.args.get("symbol", "NIFTY")
    strike = request.args.get("strike", None)
    
    global access_token
    if not access_token:
        access_token = get_valid_token()
        if not access_token:
            return jsonify({"error": "No access token"}), 401
    
    # Get symbol mapping
    symbol_map = {
        "NIFTY": "NSE_INDEX%7CNifty%2050",
        "BANKNIFTY": "NSE_INDEX%7CNifty%20Bank",
        "FINNIFTY": "NSE_INDEX%7CNifty%20Fin%20Service",
        "RELIANCE": "NSE_EQ%7CRELIANCE",
        "TCS": "NSE_EQ%7CTCS",
        "INFY": "NSE_EQ%7CINFY"
    }
    underlying_sym = symbol_map.get(friendly, friendly)
    
    # Get LTP first
    quote_data = fetch_ltp(underlying_sym)
    ltp = None
    ltp_data = quote_data.get("data", {})
    if isinstance(ltp_data, dict):
        for key, item in ltp_data.items():
            if isinstance(item, dict):
                ltp = item.get("last_price") or item.get("ltp")
                if ltp:
                    break
    
    if not ltp:
        return jsonify({
            "error": "Could not fetch LTP",
            "ltp_response": quote_data
        }), 500
    
    ltp = float(ltp)
    
    # Determine strike interval and index code
    if "NIFTY" in friendly.upper() and "BANK" not in friendly.upper():
        strike_interval = 50
        index_code = "NIFTY"
    elif "BANK" in friendly.upper():
        strike_interval = 100
        index_code = "BANKNIFTY"
    elif "FIN" in friendly.upper():
        strike_interval = 50
        index_code = "FINNIFTY"
    else:
        strike_interval = 50
        index_code = friendly.upper()
    
    # Calculate ATM strike
    atm_strike = round(ltp / strike_interval) * strike_interval
    
    # Get strikes: 3 above ATM, ATM, 3 below ATM
    strikes = []
    for i in range(-3, 4):
        strike_val = atm_strike + (i * strike_interval)
        strikes.append(strike_val)
    
    # Calculate expiry based on symbol type
    current_date = datetime.now()
    expiry_date = None
    
    if "NIFTY" in friendly.upper() and "BANK" not in friendly.upper() and "FIN" not in friendly.upper():
        # NIFTY: Weekly expiry (every Thursday)
        days_until_thursday = (3 - current_date.weekday()) % 7
        if days_until_thursday == 0:
            if current_date.hour >= 15:
                days_until_thursday = 7
        if days_until_thursday == 0:
            days_until_thursday = 7
        expiry_date = current_date + timedelta(days=days_until_thursday)
    elif "BANK" in friendly.upper():
        # BANKNIFTY: Weekly expiry (every Wednesday)
        days_until_wednesday = (2 - current_date.weekday()) % 7
        if days_until_wednesday == 0:
            if current_date.hour >= 15:
                days_until_wednesday = 7
        if days_until_wednesday == 0:
            days_until_wednesday = 7
        expiry_date = current_date + timedelta(days=days_until_wednesday)
    elif "FIN" in friendly.upper():
        # FINNIFTY: Weekly expiry (every Tuesday)
        days_until_tuesday = (1 - current_date.weekday()) % 7
        if days_until_tuesday == 0:
            if current_date.hour >= 15:
                days_until_tuesday = 7
        if days_until_tuesday == 0:
            days_until_tuesday = 7
        expiry_date = current_date + timedelta(days=days_until_tuesday)
    else:
        # Stocks: Monthly expiry (last Thursday of month)
        last_day = (current_date.replace(day=28) + timedelta(days=4)).replace(day=1) - timedelta(days=1)
        last_thursday = last_day
        while last_thursday.weekday() != 3:
            last_thursday -= timedelta(days=1)
        if last_thursday < current_date:
            next_month = (current_date.replace(day=28) + timedelta(days=4))
            last_day = (next_month.replace(day=28) + timedelta(days=4)).replace(day=1) - timedelta(days=1)
            last_thursday = last_day
            while last_thursday.weekday() != 3:
                last_thursday -= timedelta(days=1)
        expiry_date = last_thursday
    
    expiry_str = expiry_date.strftime("%d%b%Y").upper()
    
    # Build instrument keys
    all_keys = []
    strike_keys_map = {}
    
    for strike_val in strikes:
        if strike and int(strike) != strike_val:
            continue  # Filter to specific strike if provided
        
        ce_key_pipe = f"NSE_OPTIDX|{index_code}|{expiry_str}|{strike_val}|CE"
        pe_key_pipe = f"NSE_OPTIDX|{index_code}|{expiry_str}|{strike_val}|PE"
        ce_key_colon = f"NSE_OPTIDX:{index_code}:{expiry_str}:{strike_val}:CE"
        pe_key_colon = f"NSE_OPTIDX:{index_code}:{expiry_str}:{strike_val}:PE"
        
        strike_keys_map[strike_val] = {
            "ce": [ce_key_pipe, ce_key_colon],
            "pe": [pe_key_pipe, pe_key_colon]
        }
        all_keys.extend([ce_key_pipe, pe_key_pipe, ce_key_colon, pe_key_colon])
    
    # Fetch option data
    batch_ohlc = get_option_ohlc_batch(all_keys, access_token)
    
    # Build response
    result = {
        "symbol": friendly,
        "ltp": ltp,
        "atm_strike": atm_strike,
        "expiry_date": expiry_str,
        "expiry_date_readable": last_thursday.strftime("%d-%b-%Y"),
        "strikes": [],
        "instrument_keys_used": all_keys[:10],  # First 10 keys as sample
        "total_keys": len(all_keys),
        "keys_with_data": len([k for k in batch_ohlc.keys() if batch_ohlc[k]])
    }
    
    for strike_val in strikes:
        if strike and int(strike) != strike_val:
            continue
        
        strike_info = {
            "strike": strike_val,
            "distance_from_atm": strike_val - atm_strike,
            "ce": {},
            "pe": {}
        }
        
        keys = strike_keys_map[strike_val]
        for ce_key in keys["ce"]:
            if ce_key in batch_ohlc and batch_ohlc[ce_key]:
                strike_info["ce"] = {
                    "instrument_key": ce_key,
                    "ohlc": batch_ohlc[ce_key],
                    "premium": batch_ohlc[ce_key].get("c")  # Close/Last price = premium
                }
                break
        
        for pe_key in keys["pe"]:
            if pe_key in batch_ohlc and batch_ohlc[pe_key]:
                strike_info["pe"] = {
                    "instrument_key": pe_key,
                    "ohlc": batch_ohlc[pe_key],
                    "premium": batch_ohlc[pe_key].get("c")  # Close/Last price = premium
                }
                break
        
        result["strikes"].append(strike_info)
    
    return jsonify(result)

@app.route("/api/underlying_ohlc")
def api_underlying_ohlc():
    """Fetch underlying stock/index OHLC data for multiple timeframes"""
    friendly = request.args.get("symbol", "NIFTY")
    strategy = request.args.get("strategy", "box")  # strategy: m75, box
    
    global access_token
    if not access_token:
        access_token = get_valid_token()
        if not access_token:
            return jsonify({
                "error": "No valid access token. Please authorize first.",
                "auth_required": True,
                "auth_url": AUTH_URL
            }), 401
    
    try:
        # Symbol mapping (same as option_chain)
        symbol_map = {
            "NIFTY": "NSE_INDEX|Nifty 50",
            "BANKNIFTY": "NSE_INDEX|Nifty Bank",
            "FINNIFTY": "NSE_INDEX|Nifty Fin Service",
            "RELIANCE": "NSE_EQ|RELIANCE",
            "TCS": "NSE_EQ|TCS",
            "INFY": "NSE_EQ|INFY",
            "HDFCBANK": "NSE_EQ|HDFCBANK",
            "HINDUNILVR": "NSE_EQ|HINDUNILVR",
            "ICICIBANK": "NSE_EQ|ICICIBANK",
            "BHARTIARTL": "NSE_EQ|BHARTIARTL",
            "SBIN": "NSE_EQ|SBIN",
            "BAJFINANCE": "NSE_EQ|BAJFINANCE",
            "ITC": "NSE_EQ|ITC",
            "KOTAKBANK": "NSE_EQ|KOTAKBANK",
            "LT": "NSE_EQ|LT",
            "AXISBANK": "NSE_EQ|AXISBANK",
            "ASIANPAINT": "NSE_EQ|ASIANPAINT",
            "MARUTI": "NSE_EQ|MARUTI",
            "TITAN": "NSE_EQ|TITAN",
            "ULTRACEMCO": "NSE_EQ|ULTRACEMCO",
            "SUNPHARMA": "NSE_EQ|SUNPHARMA",
            "NESTLEIND": "NSE_EQ|NESTLEIND",
            "ONGC": "NSE_EQ|ONGC",
            "WIPRO": "NSE_EQ|WIPRO",
            "HCLTECH": "NSE_EQ|HCLTECH",
            "POWERGRID": "NSE_EQ|POWERGRID",
            "NTPC": "NSE_EQ|NTPC",
            "TATAMOTORS": "NSE_EQ|TATAMOTORS",
            "INDUSINDBK": "NSE_EQ|INDUSINDBK",
            "JSWSTEEL": "NSE_EQ|JSWSTEEL",
            "TECHM": "NSE_EQ|TECHM",
            "ADANIENT": "NSE_EQ|ADANIENT",
            "TATASTEEL": "NSE_EQ|TATASTEEL",
            "BAJAJFINSV": "NSE_EQ|BAJAJFINSV",
            "DIVISLAB": "NSE_EQ|DIVISLAB",
            "HDFCLIFE": "NSE_EQ|HDFCLIFE",
            "DRREDDY": "NSE_EQ|DRREDDY",
            "CIPLA": "NSE_EQ|CIPLA",
            "APOLLOHOSP": "NSE_EQ|APOLLOHOSP",
            "M&M": "NSE_EQ|M&M",
            "COALINDIA": "NSE_EQ|COALINDIA",
            "BPCL": "NSE_EQ|BPCL",
            "HEROMOTOCO": "NSE_EQ|HEROMOTOCO",
            "EICHERMOT": "NSE_EQ|EICHERMOT",
            "ADANIPORTS": "NSE_EQ|ADANIPORTS",
            "GRASIM": "NSE_EQ|GRASIM",
            "MARICO": "NSE_EQ|MARICO",
            "VEDL": "NSE_EQ|VEDL",
            "PIDILITIND": "NSE_EQ|PIDILITIND",
            "GODREJCP": "NSE_EQ|GODREJCP",
            "DABUR": "NSE_EQ|DABUR"
        }
        underlying_sym = symbol_map.get(friendly, friendly)
        
        # Get current LTP
        quote_data = fetch_ltp(underlying_sym)
        ltp = None
        if "error" not in quote_data:
            ltp_data = quote_data.get("data", {})
            if ltp_data and isinstance(ltp_data, dict):
                key_variations = [underlying_sym.replace("|", ":"), underlying_sym]
                for key in key_variations:
                    if key in ltp_data:
                        item = ltp_data[key]
                        if isinstance(item, dict):
                            ltp = item.get("last_price") or item.get("ltp")
                            if ltp:
                                break
        
        # Fetch OHLC for all timeframes
        timeframes = ["1minute", "5minute", "15minute", "30minute", "60minute", "day"]
        timeframe_labels = {
            "1minute": "1m",
            "5minute": "5m",
            "15minute": "15m",
            "30minute": "30m",
            "60minute": "1h",
            "day": "1D"
        }
        
        result = {
            "symbol": friendly,
            "ltp": ltp,
            "timeframes": [],
            "strategy": strategy
        }
        
        # For M75 Strategy, calculate PL3H/PL3M/PL3L and conditions
        if strategy == "m75":
            underlying_pl3 = get_previous_day_high_low(underlying_sym, "75minute", access_token)
            result["pl3h"] = underlying_pl3["pl3h"]
            result["pl3m"] = underlying_pl3["pl3m"]
            result["pl3l"] = underlying_pl3["pl3l"]
            
            # Calculate M75 conditions
            m75_conditions = calculate_m75_conditions(
                ltp=ltp,
                pl3h=underlying_pl3.get("pl3h"),
                pl3m=underlying_pl3.get("pl3m"),
                pl3l=underlying_pl3.get("pl3l"),
                previous_ltp=None
            )
            result["m75_conditions"] = m75_conditions
        
        print(f"📊 Fetching underlying OHLC for {friendly} across {len(timeframes)} timeframes...")
        for interval in timeframes:
            ohlc_data = get_underlying_ohlc_from_candles(underlying_sym, interval, access_token)
            timeframe_data = {
                "timeframe": timeframe_labels.get(interval, interval),
                "interval": interval,
                "ohlc": ohlc_data
            }
            
            # For Box Strategy, also calculate Box Strategy values for this timeframe
            if strategy == "box" and ltp:
                box_values = calculate_box_strategy_values(underlying_sym, interval, access_token, ltp)
                timeframe_data["box_values"] = box_values
            
            result["timeframes"].append(timeframe_data)
        
        return jsonify(result)
    
    except Exception as e:
        print(f"❌ Underlying OHLC fetch error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route("/api/option_chain")
def api_option_chain():
    """Fetch option chain with OHLC data for 3CE + ATM + 3PE"""
    friendly = request.args.get("symbol", "NIFTY")
    tf = request.args.get("tf", "5")  # timeframe: 1, 5, 15, 60, D
    strategy = request.args.get("strategy", "box")  # strategy: m75, box
    
    global access_token
    if not access_token:
        access_token = get_valid_token()
        if not access_token:
            return jsonify({
                "error": "No valid access token. Please authorize first.",
                "auth_required": True,
                "auth_url": AUTH_URL
            }), 401
    
    try:
        # Symbol mapping
        symbol_map = {
            "NIFTY": "NSE_INDEX|Nifty 50",
            "BANKNIFTY": "NSE_INDEX|Nifty Bank",
            "FINNIFTY": "NSE_INDEX|Nifty Fin Service",
            # NIFTY 50 Stocks
            "RELIANCE": "NSE_EQ|RELIANCE",
            "TCS": "NSE_EQ|TCS",
            "INFY": "NSE_EQ|INFY",
            "HDFCBANK": "NSE_EQ|HDFCBANK",
            "HINDUNILVR": "NSE_EQ|HINDUNILVR",
            "ICICIBANK": "NSE_EQ|ICICIBANK",
            "BHARTIARTL": "NSE_EQ|BHARTIARTL",
            "SBIN": "NSE_EQ|SBIN",
            "BAJFINANCE": "NSE_EQ|BAJFINANCE",
            "ITC": "NSE_EQ|ITC",
            "KOTAKBANK": "NSE_EQ|KOTAKBANK",
            "LT": "NSE_EQ|LT",
            "AXISBANK": "NSE_EQ|AXISBANK",
            "ASIANPAINT": "NSE_EQ|ASIANPAINT",
            "MARUTI": "NSE_EQ|MARUTI",
            "TITAN": "NSE_EQ|TITAN",
            "ULTRACEMCO": "NSE_EQ|ULTRACEMCO",
            "SUNPHARMA": "NSE_EQ|SUNPHARMA",
            "NESTLEIND": "NSE_EQ|NESTLEIND",
            "ONGC": "NSE_EQ|ONGC",
            "WIPRO": "NSE_EQ|WIPRO",
            "HCLTECH": "NSE_EQ|HCLTECH",
            "POWERGRID": "NSE_EQ|POWERGRID",
            "NTPC": "NSE_EQ|NTPC",
            "TATAMOTORS": "NSE_EQ|TATAMOTORS",
            "INDUSINDBK": "NSE_EQ|INDUSINDBK",
            "JSWSTEEL": "NSE_EQ|JSWSTEEL",
            "TECHM": "NSE_EQ|TECHM",
            "ADANIENT": "NSE_EQ|ADANIENT",
            "TATASTEEL": "NSE_EQ|TATASTEEL",
            "BAJAJFINSV": "NSE_EQ|BAJAJFINSV",
            "DIVISLAB": "NSE_EQ|DIVISLAB",
            "HDFCLIFE": "NSE_EQ|HDFCLIFE",
            "DRREDDY": "NSE_EQ|DRREDDY",
            "CIPLA": "NSE_EQ|CIPLA",
            "APOLLOHOSP": "NSE_EQ|APOLLOHOSP",
            "M&M": "NSE_EQ|M&M",
            "COALINDIA": "NSE_EQ|COALINDIA",
            "BPCL": "NSE_EQ|BPCL",
            "HEROMOTOCO": "NSE_EQ|HEROMOTOCO",
            "EICHERMOT": "NSE_EQ|EICHERMOT",
            "ADANIPORTS": "NSE_EQ|ADANIPORTS",
            "GRASIM": "NSE_EQ|GRASIM",
            "MARICO": "NSE_EQ|MARICO",
            "VEDL": "NSE_EQ|VEDL",
            "PIDILITIND": "NSE_EQ|PIDILITIND",
            "GODREJCP": "NSE_EQ|GODREJCP",
            "DABUR": "NSE_EQ|DABUR"
        }
        underlying_sym = symbol_map.get(friendly, friendly)
        
        # Get LTP of underlying
        quote_data = fetch_ltp(underlying_sym)
        if "error" in quote_data:
            error_msg = quote_data.get("error", "Unknown error")
            print(f"❌ LTP fetch error: {error_msg}")
            
            # Check if authorization is required
            if quote_data.get("auth_required"):
                return jsonify({
                    "error": f"Failed to fetch LTP: {error_msg}",
                    "auth_required": True,
                    "auth_url": quote_data.get("auth_url", AUTH_URL),
                    "original_error": error_msg
                }), 401
            
            # Check if it's a market holiday/closed error
            error_str = str(error_msg).lower()
            if any(keyword in error_str for keyword in ["holiday", "closed", "market closed", "trading closed"]):
                return jsonify({
                    "error": "Market is closed",
                    "message": "The market appears to be closed (holiday or outside trading hours). LTP data is not available when markets are closed.",
                    "original_error": error_msg
                }), 503  # Service Unavailable
            else:
                return jsonify({
                    "error": f"Failed to fetch LTP: {error_msg}",
                    "original_error": error_msg
                }), 500
        
        # Parse response - v2 API returns: {'status': 'success', 'data': {'NSE_INDEX:Nifty 50': {...}}}
        ltp = None
        ltp_data = quote_data.get("data", {})
        
        # Check if data is empty (common issue with stocks)
        if not ltp_data or not isinstance(ltp_data, dict) or len(ltp_data) == 0:
            print(f"⚠️ Could not parse LTP from response (empty data): {quote_data}")
            # Try alternative: use quotes API instead of LTP API for stocks
            if "NSE_EQ" in underlying_sym:
                print(f"   🔄 Trying quotes API as fallback for stock: {underlying_sym}")
                
                # Try multiple API endpoints and parameter formats
                endpoints_to_try = [
                    ("https://api.upstox.com/v2/market-quote/quotes", {"symbol": underlying_sym}),
                    ("https://api.upstox.com/v2/market-quote/quotes", {"symbol": underlying_sym.replace("|", ":")}),
                    ("https://api.upstox.com/v2/market-quote/full", {"symbol": underlying_sym}),
                    ("https://api.upstox.com/v2/market-quote/full", {"symbol": underlying_sym.replace("|", ":")}),
                ]
                
                headers = {
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                    "Api-Version": "2.0"
                }
                
                for quotes_url, params in endpoints_to_try:
                    try:
                        print(f"      Trying: {quotes_url} with params: {params}")
                        quotes_response = requests.get(quotes_url, headers=headers, params=params, timeout=15)
                        
                        if quotes_response.status_code == 200:
                            quotes_data = quotes_response.json()
                            print(f"      ✅ Quotes API response status: {quotes_data.get('status')}")
                            print(f"      📊 Quotes API data keys: {list(quotes_data.get('data', {}).keys())}")
                            
                            quotes_ltp_data = quotes_data.get("data", {})
                            
                            # Try multiple key variations to find LTP in quotes response
                            key_variations = [
                                underlying_sym.replace("|", ":"),  # NSE_EQ:RELIANCE
                                underlying_sym,  # NSE_EQ|RELIANCE
                                underlying_sym.replace("NSE_EQ|", "NSE_EQ:"),  # Ensure colon format
                                friendly.upper(),  # RELIANCE
                                friendly,  # Reliance
                                underlying_sym.split("|")[-1] if "|" in underlying_sym else underlying_sym,  # RELIANCE
                            ]
                            
                            for key_var in key_variations:
                                if key_var in quotes_ltp_data:
                                    item = quotes_ltp_data[key_var]
                                    if isinstance(item, dict):
                                        ltp = item.get("last_price") or item.get("ltp") or item.get("ltp_price")
                                        if ltp:
                                            print(f"   ✅ Found LTP from quotes API: {ltp} (key: {key_var})")
                                            break
                            
                            # If still not found, try iterating through all keys
                            if not ltp and quotes_ltp_data:
                                for key, item in quotes_ltp_data.items():
                                    if isinstance(item, dict):
                                        ltp = item.get("last_price") or item.get("ltp") or item.get("ltp_price")
                                        if ltp:
                                            print(f"   ✅ Found LTP from quotes API: {ltp} (key: {key})")
                                            break
                            
                            if ltp:
                                break  # Found LTP, exit loop
                            else:
                                print(f"      ⚠️ No LTP found in response from {quotes_url}")
                        else:
                            print(f"      ⚠️ Quotes API returned status {quotes_response.status_code}: {quotes_response.text[:200]}")
                    except Exception as e:
                        print(f"      ⚠️ Quotes API fallback failed for {quotes_url}: {e}")
                        import traceback
                        traceback.print_exc()
            
            if not ltp:
                # Check if it's a stock - stocks may not have options, so return a clearer error
                is_stock = "NSE_EQ" in underlying_sym
                error_msg = "Could not parse LTP from response (empty data)"
                if is_stock:
                    error_msg = f"Could not fetch LTP for stock {friendly}. The market may be closed or the symbol may not be available."
                return jsonify({
                    "error": error_msg,
                    "message": "The API returned success but with empty data. This may happen if the market is closed or the symbol is invalid.",
                    "is_stock": is_stock,
                    "raw_response": quote_data
                }), 500
        
        # v2 API uses colon format: NSE_INDEX:Nifty 50, NSE_EQ:RELIANCE, etc.
        # Try different key formats (pipe to colon conversion)
        key_variations = [
            underlying_sym.replace("|", ":"),  # NSE_INDEX:Nifty 50 (v2 API format)
            underlying_sym,  # NSE_INDEX|Nifty 50 (original)
        ]
        
        for key in key_variations:
            if key in ltp_data:
                item = ltp_data[key]
                if isinstance(item, dict):
                    ltp = item.get("last_price") or item.get("ltp")
                    if ltp:
                        break
        
        # Fallback: try to get first item if exact match fails
        if not ltp and len(ltp_data) > 0:
            first_key = list(ltp_data.keys())[0]
            item = ltp_data[first_key]
            if isinstance(item, dict):
                ltp = item.get("last_price") or item.get("ltp")
                if ltp:
                    print(f"✅ Found LTP using fallback method (key: {first_key})")
        
        # Legacy support: Check if response is flat (no "data" key)
        if not ltp and "last_price" in quote_data:
            ltp = quote_data.get("last_price") or quote_data.get("ltp")
        
        if not ltp:
            print(f"❌ Could not parse LTP from response: {quote_data}")
            # Check if it might be a market holiday or market closed
            error_msg = "Could not fetch LTP"
            if "error" in quote_data:
                error_detail = quote_data.get("error", "")
                if "holiday" in str(error_detail).lower() or "closed" in str(error_detail).lower():
                    error_msg = "Market is closed (may be a holiday or outside trading hours)"
            return jsonify({
                "error": error_msg,
                "debug": "Response structure not recognized. Check server logs.",
                "possible_reasons": [
                    "Market is closed (holiday or outside trading hours)",
                    "Invalid symbol format",
                    "API response structure changed"
                ],
                "raw_response": quote_data
            }), 500
        
        ltp = float(ltp)
        
        # Determine strike interval and index code
        if "NIFTY" in friendly.upper() and "BANK" not in friendly.upper():
            strike_interval = 50
            index_code = "NIFTY"
        elif "BANK" in friendly.upper():
            strike_interval = 100
            index_code = "BANKNIFTY"
        elif "FIN" in friendly.upper():
            strike_interval = 50
            index_code = "FINNIFTY"
        else:
            strike_interval = 50
            index_code = friendly.upper()
        
        # Calculate ATM strike (round to nearest strike)
        # Use proper rounding: if remainder >= half interval, round up, else round down
        remainder = ltp % strike_interval
        if remainder >= strike_interval / 2:
            atm_strike = int((ltp // strike_interval) + 1) * strike_interval
        else:
            atm_strike = int(ltp // strike_interval) * strike_interval
        
        # Get strikes: 3 above ATM, ATM, 3 below ATM
        strikes = []
        for i in range(-3, 4):  # -3, -2, -1, 0, 1, 2, 3
            strike = atm_strike + (i * strike_interval)
            strikes.append(strike)
        
        # Map timeframe to Upstox interval
        interval_map = {
            "1": "1minute",
            "5": "5minute", 
            "15": "15minute",
            "30": "30minute",
            "60": "60minute",
            "75": "75minute",  # For M75 Strategy
            "D": "day"
        }
        # For M75 Strategy, always use 75minute
        if strategy == "m75":
            interval = "75minute"
        else:
            interval = interval_map.get(tf, "5minute")
        
        # Check if this is a stock (NSE_EQ) - stocks may not have options
        is_stock = "NSE_EQ" in underlying_sym
        
        # Use instrument master CSV to get actual instrument keys with correct expiry
        print(f"📥 Loading instrument master for {index_code}...")
        option_instruments_df = get_option_instruments(index_code, index_code)
        
        if option_instruments_df is None or len(option_instruments_df) == 0:
            if is_stock:
                return jsonify({
                    "error": f"No option chain available for stock {friendly}",
                    "message": f"Stock {friendly} does not have options available in the instrument master. Option chains are typically available for indices (NIFTY, BANKNIFTY, FINNIFTY) and select stocks. You can still view the underlying stock data using the Stock/Index table.",
                    "is_stock": True,
                    "symbol": friendly
                }), 400  # Bad Request (not a server error)
            else:
                return jsonify({
                    "error": f"Could not load option instruments for {index_code}",
                    "message": "Failed to load instrument master CSV or no options found"
                }), 500
        
        # Get the expiry date from the filtered instruments
        nearest_expiry = option_instruments_df['expiry'].iloc[0]
        print(f"✅ Using nearest expiry: {nearest_expiry}")
        
        # Build mapping: strike -> {ce_instrument_key, pe_instrument_key}
        strike_to_keys = {}  # Map strike -> {ce_key, pe_key}
        all_instrument_keys = []
        
        for strike in strikes:
            # Find CE and PE instruments for this strike
            ce_row = option_instruments_df[
                (option_instruments_df['strike'] == float(strike)) &
                (option_instruments_df['option_type'] == 'CE')
            ]
            pe_row = option_instruments_df[
                (option_instruments_df['strike'] == float(strike)) &
                (option_instruments_df['option_type'] == 'PE')
            ]
            
            # Get instrument_key, tradingsymbol, and exchange_token
            ce_instrument_key = ce_row['instrument_key'].iloc[0] if len(ce_row) > 0 else None
            ce_tradingsymbol = ce_row['tradingsymbol'].iloc[0] if len(ce_row) > 0 else None
            ce_exchange_token = int(ce_row['exchange_token'].iloc[0]) if len(ce_row) > 0 and 'exchange_token' in ce_row.columns else None
            pe_instrument_key = pe_row['instrument_key'].iloc[0] if len(pe_row) > 0 else None
            pe_tradingsymbol = pe_row['tradingsymbol'].iloc[0] if len(pe_row) > 0 else None
            pe_exchange_token = int(pe_row['exchange_token'].iloc[0]) if len(pe_row) > 0 and 'exchange_token' in pe_row.columns else None
            
            # Use instrument_key for API call (as per notebook - uses "NSE_FO|64008" format)
            # The API request uses instrument_key, but response key is "NSE_FO:{tradingsymbol}"
            if ce_instrument_key:
                all_instrument_keys.append(ce_instrument_key)
            if pe_instrument_key:
                all_instrument_keys.append(pe_instrument_key)
            
            # Store both formats for matching response
            strike_to_keys[strike] = {
                "ce": {
                    "instrument_key": ce_instrument_key,
                    "tradingsymbol": ce_tradingsymbol,
                    "exchange_token": ce_exchange_token,
                    "response_key": f"NSE_FO:{ce_tradingsymbol}" if ce_tradingsymbol else None
                } if ce_instrument_key else None,
                "pe": {
                    "instrument_key": pe_instrument_key,
                    "tradingsymbol": pe_tradingsymbol,
                    "exchange_token": pe_exchange_token,
                    "response_key": f"NSE_FO:{pe_tradingsymbol}" if pe_tradingsymbol else None
                } if pe_instrument_key else None
            }
        
        # Build mapping from instrument_key to tradingsymbol and exchange_token for response matching
        key_to_tradingsymbol = {}
        key_to_exchange_token = {}
        for strike in strikes:
            keys = strike_to_keys[strike]
            if keys["ce"] and keys["ce"]["instrument_key"]:
                if keys["ce"]["tradingsymbol"]:
                    key_to_tradingsymbol[keys["ce"]["instrument_key"]] = keys["ce"]["tradingsymbol"]
                if keys["ce"]["exchange_token"]:
                    key_to_exchange_token[keys["ce"]["instrument_key"]] = keys["ce"]["exchange_token"]
            if keys["pe"] and keys["pe"]["instrument_key"]:
                if keys["pe"]["tradingsymbol"]:
                    key_to_tradingsymbol[keys["pe"]["instrument_key"]] = keys["pe"]["tradingsymbol"]
                if keys["pe"]["exchange_token"]:
                    key_to_exchange_token[keys["pe"]["instrument_key"]] = keys["pe"]["exchange_token"]
        
        # Batch fetch all OHLC data at once (much faster!)
        print(f"📊 Fetching OHLC for {len(strikes)} strikes (expiry: {nearest_expiry}, timeframe: {interval})...")
        print(f"   Sample keys: CE={all_instrument_keys[0] if all_instrument_keys else 'none'}, PE={all_instrument_keys[1] if len(all_instrument_keys) > 1 else 'none'}")
        batch_ohlc = get_option_ohlc_batch(all_instrument_keys, access_token, interval, key_to_tradingsymbol, key_to_exchange_token)
        
        # Debug: Show how many keys returned data
        found_count = len([k for k in batch_ohlc.keys() if batch_ohlc[k]])
        print(f"   ✅ Found OHLC data for {found_count}/{len(all_instrument_keys)} instrument keys")
        
        # Build result with OHLC data
        result_strikes = []
        for strike in strikes:
            strike_data = {
                "strike": strike,
                "ce": {"ohlc": {}, "ltp": None},
                "pe": {"ohlc": {}, "ltp": None}
            }
            
            # Find matching OHLC and LTP data from batch response
            keys = strike_to_keys[strike]
            
            # Try to find CE data
            if keys["ce"]:
                ce_info = keys["ce"]
                # Try response_key first (NSE_FO:tradingsymbol format)
                if ce_info["response_key"] and ce_info["response_key"] in batch_ohlc:
                    strike_data["ce"]["ohlc"] = batch_ohlc[ce_info["response_key"]]
                    strike_data["ce"]["ltp"] = batch_ohlc[ce_info["response_key"]].get("ltp")
                # Try tradingsymbol
                elif ce_info["tradingsymbol"] and ce_info["tradingsymbol"] in batch_ohlc:
                    strike_data["ce"]["ohlc"] = batch_ohlc[ce_info["tradingsymbol"]]
                    strike_data["ce"]["ltp"] = batch_ohlc[ce_info["tradingsymbol"]].get("ltp")
                # Try instrument_key
                elif ce_info["instrument_key"] and ce_info["instrument_key"] in batch_ohlc:
                    strike_data["ce"]["ohlc"] = batch_ohlc[ce_info["instrument_key"]]
                    strike_data["ce"]["ltp"] = batch_ohlc[ce_info["instrument_key"]].get("ltp")
            
            # Try to find PE data
            if keys["pe"]:
                pe_info = keys["pe"]
                # Try response_key first (NSE_FO:tradingsymbol format)
                if pe_info["response_key"] and pe_info["response_key"] in batch_ohlc:
                    strike_data["pe"]["ohlc"] = batch_ohlc[pe_info["response_key"]]
                    strike_data["pe"]["ltp"] = batch_ohlc[pe_info["response_key"]].get("ltp")
                # Try tradingsymbol
                elif pe_info["tradingsymbol"] and pe_info["tradingsymbol"] in batch_ohlc:
                    strike_data["pe"]["ohlc"] = batch_ohlc[pe_info["tradingsymbol"]]
                    strike_data["pe"]["ltp"] = batch_ohlc[pe_info["tradingsymbol"]].get("ltp")
                # Try instrument_key
                elif pe_info["instrument_key"] and pe_info["instrument_key"] in batch_ohlc:
                    strike_data["pe"]["ohlc"] = batch_ohlc[pe_info["instrument_key"]]
                    strike_data["pe"]["ltp"] = batch_ohlc[pe_info["instrument_key"]].get("ltp")
            
            # Calculate PL3H/PL3M/PL3L for M75 Strategy
            if strategy == "m75":
                # Get previous day's high/low for CE
                if keys["ce"] and keys["ce"]["instrument_key"]:
                    ce_pl3 = get_previous_day_high_low(keys["ce"]["instrument_key"], "75minute", access_token)
                    strike_data["ce"]["pl3h"] = ce_pl3["pl3h"]
                    strike_data["ce"]["pl3m"] = ce_pl3["pl3m"]
                    strike_data["ce"]["pl3l"] = ce_pl3["pl3l"]
                
                # Get previous day's high/low for PE
                if keys["pe"] and keys["pe"]["instrument_key"]:
                    pe_pl3 = get_previous_day_high_low(keys["pe"]["instrument_key"], "75minute", access_token)
                    strike_data["pe"]["pl3h"] = pe_pl3["pl3h"]
                    strike_data["pe"]["pl3m"] = pe_pl3["pl3m"]
                    strike_data["pe"]["pl3l"] = pe_pl3["pl3l"]
            
            result_strikes.append(strike_data)
        
        result = {
            "ltp": ltp,
            "strikes": result_strikes,
            "strategy": strategy
        }
        
        # For M75 Strategy, also calculate underlying PL3H/PL3M/PL3L and conditions
        if strategy == "m75":
            underlying_pl3 = get_previous_day_high_low(underlying_sym, "75minute", access_token)
            result["underlying_pl3"] = underlying_pl3
            
            # Calculate M75 conditions based on spot LTP vs PL3H/PL3M/PL3L
            # Note: We don't have previous_ltp in this context, so we'll only check current position
            m75_conditions = calculate_m75_conditions(
                ltp=ltp,
                pl3h=underlying_pl3.get("pl3h"),
                pl3m=underlying_pl3.get("pl3m"),
                pl3l=underlying_pl3.get("pl3l"),
                previous_ltp=None  # Could be enhanced to track previous LTP
            )
            result["m75_conditions"] = m75_conditions
        
        # For Box Strategy, calculate Box Strategy values
        if strategy == "box":
            print(f"📦 Calculating Box Strategy values for {friendly} (timeframe: {interval})...")
            box_values = calculate_box_strategy_values(underlying_sym, interval, access_token, ltp)
            result["box_strategy"] = box_values
            
            # Calculate proximity zones (default 0.2% = 0.002)
            proximity_pct = 0.002  # 0.2%
            proximity_data = {
                "is_near_bull_zone": False,
                "is_near_bear_zone": False,
                "is_near_bull_target": False,
                "is_near_bear_target": False
            }
            
            if ltp and box_values.get("br_r"):
                br_r = float(box_values["br_r"])
                distance = abs((ltp - br_r) / br_r) * 100
                proximity_data["is_near_bull_zone"] = distance < (proximity_pct * 100)
            
            if ltp and box_values.get("be_r"):
                be_r = float(box_values["be_r"])
                distance = abs((ltp - be_r) / be_r) * 100
                proximity_data["is_near_bear_zone"] = distance < (proximity_pct * 100)
            
            if ltp and box_values.get("br_t"):
                br_t = float(box_values["br_t"])
                distance = abs((ltp - br_t) / br_t) * 100
                proximity_data["is_near_bull_target"] = distance < (proximity_pct * 100)
            
            if ltp and box_values.get("be_t"):
                be_t = float(box_values["be_t"])
                distance = abs((ltp - be_t) / be_t) * 100
                proximity_data["is_near_bear_target"] = distance < (proximity_pct * 100)
            
            result["box_proximity"] = proximity_data
            
            # Calculate Box Strategy values for each option (CE and PE) separately
            print(f"📦 Calculating Box Strategy values for each option strike...")
            for strike_data in result_strikes:
                strike = strike_data["strike"]
                keys = strike_to_keys[strike]
                
                # Calculate box values for CE option
                if keys["ce"] and keys["ce"]["instrument_key"]:
                    ce_ltp = strike_data["ce"].get("ltp")
                    if ce_ltp:
                        ce_box_values = calculate_box_strategy_values(
                            keys["ce"]["instrument_key"], 
                            interval, 
                            access_token, 
                            ce_ltp
                        )
                        strike_data["ce"]["box_values"] = ce_box_values
                        print(f"   ✅ CE {strike}: BR.T={ce_box_values.get('br_t')}, BR.R={ce_box_values.get('br_r')}, BE.T={ce_box_values.get('be_t')}, BE.R={ce_box_values.get('be_r')}")
                    else:
                        strike_data["ce"]["box_values"] = {}
                else:
                    strike_data["ce"]["box_values"] = {}
                
                # Calculate box values for PE option
                if keys["pe"] and keys["pe"]["instrument_key"]:
                    pe_ltp = strike_data["pe"].get("ltp")
                    if pe_ltp:
                        pe_box_values = calculate_box_strategy_values(
                            keys["pe"]["instrument_key"], 
                            interval, 
                            access_token, 
                            pe_ltp
                        )
                        strike_data["pe"]["box_values"] = pe_box_values
                        print(f"   ✅ PE {strike}: BR.T={pe_box_values.get('br_t')}, BR.R={pe_box_values.get('br_r')}, BE.T={pe_box_values.get('be_t')}, BE.R={pe_box_values.get('be_r')}")
                    else:
                        strike_data["pe"]["box_values"] = {}
                else:
                    strike_data["pe"]["box_values"] = {}
        
        return jsonify(result)
        
    except Exception as e:
        import traceback
        return jsonify({"error": str(e), "traceback": traceback.format_exc()}), 500

# ---------------------------------------
# STEP 3 — HOME PAGE
# ---------------------------------------

@app.route("/")
def home():
    return send_from_directory("static", "index.html")

@app.route("/authorize")
def authorize():
    return redirect(AUTH_URL)

@app.route("/auth_start")
def auth_start():
    """Alternative auth route name."""
    return redirect(AUTH_URL)

@app.route("/auth_debug")
def auth_debug():
    """Debug page to show current auth configuration"""
    return f"""
    <html>
    <head><title>Upstox Auth Configuration</title></head>
    <body style="font-family: Arial; padding: 20px;">
        <h2>Upstox Authorization Configuration</h2>
        <div style="background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0;">
            <h3>Current Settings:</h3>
            <p><strong>Client ID:</strong> {UPSTOX_API_KEY}</p>
            <p><strong>Redirect URI:</strong> <code>{REDIRECT_URI}</code></p>
            <p><strong>Authorization URL:</strong> <a href="{AUTH_URL}" target="_blank">{AUTH_URL}</a></p>
        </div>
        
        <div style="background: #fff3cd; padding: 15px; border-radius: 5px; border: 1px solid #ffc107; margin: 20px 0;">
            <h3>⚠️ Error: Redirect URI Mismatch</h3>
            <p>The redirect_uri in your code must <strong>exactly match</strong> what's registered in your Upstox app.</p>
            
            <h4>Steps to Fix:</h4>
            <ol>
                <li>Go to <a href="https://account.upstox.com/developer/apps" target="_blank">Upstox Developer Portal</a></li>
                <li>Find your app (Client ID: <code>{UPSTOX_API_KEY}</code>)</li>
                <li>Check the <strong>Redirect URI</strong> field in your app settings</li>
                <li>Make sure it matches exactly: <code>{REDIRECT_URI}</code></li>
                <li>If it doesn't match, either:
                    <ul>
                        <li>Update the Redirect URI in Upstox to: <code>{REDIRECT_URI}</code></li>
                        <li>OR update the code to match what's in Upstox</li>
                    </ul>
                </li>
            </ol>
            
            <h4>Common Redirect URI Values to Try:</h4>
            <ul>
                <li><code>http://127.0.0.1:5000/callback</code> (current)</li>
                <li><code>http://localhost:5000/callback</code></li>
                <li><code>https://127.0.0.1:5000/callback</code> (if using HTTPS)</li>
                <li><code>http://127.0.0.1:5000/callback/</code> (with trailing slash)</li>
            </ul>
            
            <h4>To Change Redirect URI in Code:</h4>
            <p>Set environment variable: <code>UPSTOX_REDIRECT_URI</code></p>
            <p>Or edit <code>app.py</code> line 21 and change the default value.</p>
        </div>
        
        <p><a href="/authorize">Try Authorization Again</a> | <a href="/">Back to Dashboard</a></p>
    </body>
    </html>
    """

# ---------------------------------------
# STEP 4 — AUTO SSL FALLBACK
# ---------------------------------------

def generate_ssl_cert():
    """Generate self-signed SSL certificate for local development using Python"""
    cert_file = "cert.pem"
    key_file = "key.pem"
    
    if os.path.exists(cert_file) and os.path.exists(key_file):
        return True
    
    print("🔐 Generating SSL certificates for HTTPS...")
    
    # Try method 1: Use cryptography library (pure Python, no OpenSSL needed)
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        from datetime import datetime, timedelta, timezone
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Create certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Local"),
            x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(datetime.UTC) if hasattr(datetime, 'UTC') else datetime.utcnow()
        ).not_valid_after(
            (datetime.now(datetime.UTC) if hasattr(datetime, 'UTC') else datetime.utcnow()) + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("127.0.0.1"),
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())
        
        # Write private key
        with open(key_file, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Write certificate
        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        print("✅ SSL certificates generated successfully using Python!")
        return True
        
    except ImportError:
        # Method 2: Try using OpenSSL command line
        try:
            import subprocess
            print("   Trying OpenSSL command line...")
            subprocess.check_call([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", key_file, "-out", cert_file, "-days", "365",
                "-subj", "/C=IN/ST=State/L=City/O=Local/CN=127.0.0.1"
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print("✅ SSL certificates generated successfully using OpenSSL!")
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
    
    # If both methods failed, provide instructions
    print("❌ Could not generate SSL certificates automatically.")
    print("   Installing cryptography library...")
    print("   Run: pip install cryptography")
    print("   Then restart the app.")
    print("\n   OR change redirect_uri in Upstox to use HTTP:")
    print("   http://127.0.0.1:5000/callback")
    return False

def start_flask():
    cert_file = "cert.pem"
    key_file = "key.pem"

    # Check if we need HTTPS based on redirect URI
    needs_https = REDIRECT_URI.startswith("https://")
    
    if needs_https:
        # Try to generate certificates if they don't exist
        if not (os.path.exists(cert_file) and os.path.exists(key_file)):
            if not generate_ssl_cert():
                print("❌ HTTPS required but SSL certificates not available.")
                print(f"   Redirect URI is set to: {REDIRECT_URI}")
                print("   Please either:")
                print("   1. Install OpenSSL and restart the app")
                print("   2. Change redirect_uri in Upstox to: http://127.0.0.1:5000/callback")
                print("   3. Set UPSTOX_REDIRECT_URI=http://127.0.0.1:5000/callback")
                return
        
        if os.path.exists(cert_file) and os.path.exists(key_file):
            print("✅ SSL certificates found, starting HTTPS Flask server...")
            print("⚠️  Browser will show 'Not Secure' warning - this is normal for self-signed certs")
            print("   Click 'Advanced' -> 'Proceed to 127.0.0.1' to continue")
            app.run(host="127.0.0.1", port=5000, debug=True, ssl_context=(cert_file, key_file))
        else:
            print("❌ SSL certificates not found. Cannot start HTTPS server.")
    else:
        print("✅ Starting Flask in HTTP mode...")
        app.run(host="127.0.0.1", port=5000, debug=True)

if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("🚀 Starting Upstox Flask Auto Backend...")
    print("=" * 70 + "\n")
    print("🔍 Checking token status...\n")
    token = get_valid_token()
    print("\n" + "=" * 70)
    print("🚀 Starting Flask server...")
    print("=" * 70 + "\n")
    start_flask()