import json
from typing import Any

import time
import hmac
import hashlib
from flask import Flask, jsonify, request
from db import add_event, auth_user, add_user, check_user, chg_password, get_events, get_user_password


app = Flask(__name__)


def _get_message(message: Any, code: int = 200):
    return jsonify({'message': message, 'code': code}), code

# In-memory, demo-grade rate limiter state: { key: [timestamps] }
_RATE_STATE: dict[str, list[float]] = {}
_RATE_WINDOW_SECONDS = 60.0     # 1 dakika penceresi
_RATE_LIMIT_PER_WINDOW = 3      # pencere başına max 3 SetChargingProfile


def _rate_limit_check(key: str) -> bool:
    now = time.time()
    bucket = _RATE_STATE.get(key, [])
    # prune
    bucket = [t for t in bucket if now - t <= _RATE_WINDOW_SECONDS]
    allowed = len(bucket) < _RATE_LIMIT_PER_WINDOW
    if allowed:
        bucket.append(now)
        _RATE_STATE[key] = bucket
    else:
        _RATE_STATE[key] = bucket
    return allowed


def _verify_hmac_signature(secret: str, serial_number: str, timestamp: str, profile_json: str, signature_hex: str) -> bool:
    # Canonical message for demo
    message = f"{serial_number}|{timestamp}|{profile_json}".encode('utf-8')
    digest = hmac.new(secret.encode('utf-8'), message, hashlib.sha256).hexdigest()
    # constant-time compare
    return hmac.compare_digest(digest, signature_hex or "")


@app.route('/api/reserve_now/<serial_number>', methods=['GET', 'PUT', 'POST'])
def reserve_now(serial_number: str):

    # Get request parameters
    token = {
        'type': request.args.get('type', None, type=str),
        'id_token': request.args.get('id_token', None, type=str),
    }
    # Optional duration parameter for anomaly testing
    duration = request.args.get('duration', default=None, type=str)
    if duration is not None:
        # Validate duration is not negative
        try:
            # Accept numeric strings and numbers
            dur_val = float(duration) if isinstance(duration, str) else duration
            if dur_val < 0:
                return _get_message('Invalid record: duration cannot be negative', 400)
        except (TypeError, ValueError):
            # Non-numeric strings are allowed to pass through (kept for backward-compat)
            pass
        token['duration'] = duration

    # Check token is set correctly
    if token['type'] is None or token['id_token'] is None:
        return _get_message('Bad request', 400)

    # OWASP API2: Broken Authentication (basit doğrulama)
    # id_token'ı sistemde kayıtlı kullanıcı olarak doğrula
    if check_user(token['id_token']) is None:
        return _get_message('Unauthorized: unknown id_token', 401)

    # OWASP API1: Broken Object Level Authorization (nesne seviyesinde yetki)
    # Demo politikası: Kullanıcı sadece kendi seri numarasıyla eşleşen istasyonda işlem yapabilir
    if token['id_token'] != serial_number:
        return _get_message('Forbidden: not allowed for this charge point', 403)
    
    # Add event to DB
    try:
        add_event('reserve_now', serial_number, token)
    except AttributeError as e:
        return _get_message(str(e), 400)

    return _get_message('OK')


@app.route('/api/set_charging_profile/<serial_number>', methods=['GET', 'POST'])
def set_charging_profile(serial_number: str):
    # Params: type, id_token, ts, profile (json string), sig (hex hmac)
    token = {
        'type': request.args.get('type', None, type=str) if request.method == 'GET' else request.json.get('type') if request.is_json else None,
        'id_token': request.args.get('id_token', None, type=str) if request.method == 'GET' else request.json.get('id_token') if request.is_json else None,
    }
    ts = request.args.get('ts', None, type=str) if request.method == 'GET' else (request.json.get('ts') if request.is_json else None)
    profile = request.args.get('profile', None, type=str) if request.method == 'GET' else (request.json.get('profile') if request.is_json else None)
    sig = request.args.get('sig', None, type=str) if request.method == 'GET' else (request.json.get('sig') if request.is_json else None)

    # Basic checks
    if token['type'] is None or token['id_token'] is None or ts is None or profile is None or sig is None:
        return _get_message('Bad request', 400)

    # Auth: user must exist
    if check_user(token['id_token']) is None:
        return _get_message('Unauthorized: unknown id_token', 401)

    # Object-level authorization: only own CP
    if token['id_token'] != serial_number:
        return _get_message('Forbidden: not allowed for this charge point', 403)

    # Replay protection: ts must be fresh (<= 60s)
    try:
        ts_float = float(ts)
    except (TypeError, ValueError):
        return _get_message('Bad request: invalid ts', 400)
    if abs(time.time() - ts_float) > 60.0:
        return _get_message('Bad request: stale request', 400)

    # Rate limit (per user per window)
    rate_key = f"SCP:{token['id_token']}"
    if not _rate_limit_check(rate_key):
        return _get_message('Too Many Requests: rate limit exceeded', 429)

    # Signature verification with user's password as demo secret
    secret = get_user_password(token['id_token'])
    if secret is None:
        return _get_message('Unauthorized: secret not found', 401)
    if not _verify_hmac_signature(secret, serial_number, ts, profile, sig):
        return _get_message('Unauthorized: bad signature', 401)

    # Optional: basic profile size sanity check (prevent bulk/massive payload)
    if len(profile) > 4096:
        return _get_message('Bad request: profile too large', 400)

    # Record event
    try:
        add_event('set_charging_profile', serial_number, {
            'id_token': token['id_token'],
            'ts': ts,
            'profile': profile
        })
    except AttributeError as e:
        return _get_message(str(e), 400)

    return _get_message('OK')

@app.route('/api/list/<serial_number>', methods=['GET', 'PUT', 'POST'])
def list(serial_number: str):
    # Get request parameters
    token = {
        'type': request.args.get('type', None, type=str),
        'id_token': request.args.get('id_token', None, type=str),
    }

    # Check token is set correctly
    if token['type'] is None or token['id_token'] is None:
        return _get_message('Bad request', 400)

    # OWASP API2: Broken Authentication (basit doğrulama)
    if check_user(token['id_token']) is None:
        return _get_message('Unauthorized: unknown id_token', 401)

    # OWASP API1: Broken Object Level Authorization
    if token['id_token'] != serial_number:
        return _get_message('Forbidden: not allowed for this charge point', 403)
    
    # Add event to DB
    list = get_events(serial_number, token)
    print('*********************************************************************************************')
    print(list)

    return _get_message(list)

@app.route('/api/login', methods=['GET', 'PUT', 'POST'])
def login():
    # Get request parameters
    token = {
        'serial': request.args.get('serial', None, type=str),
        'password': request.args.get('password', None, type=str),
    }
    
    # Check token is set correctly
    if token['serial'] is None or token['password'] == '':
        return _get_message('Bad request', 400)
    
    if check_user(token['serial']) != None:
        return _get_message('User already exists', 403)

    # Add user to DB
    add_user(token['serial'], token['password'])

    return _get_message('OK')

@app.route('/api/change_password', methods=['GET', 'PUT', 'POST'])
def change_password():
    # Get request parameters
    token = {
        'serial': request.args.get('serial', None, type=str),
        'old_password': request.args.get('old_password', None, type=str),
        'new_password': request.args.get('new_password', None, type=str),
    }
    
    # Check token is set correctly
    if token['serial'] is None or token['old_password'] == '' or token['new_password'] == '':
        return _get_message('Bad request', 400)
    
    if not auth_user(token['serial'], token['old_password']):
        return _get_message('Wrong password', 404)

    # Add user to DB
    chg_password(token['serial'], token['new_password'])

    return _get_message('OK')

if __name__ == '__main__':
    # Bind to localhost on Windows
    app.run(host='127.0.0.1', port=8000)
