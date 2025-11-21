#!/usr/bin/env python3
# log_detector.py
# Log izleyici: hem plain text hem JSON log formatlarını parse eder.
# Algoritmalar:
#  - origin whitelist kontrolü
#  - rate-limit detection (aynı source/addr için kısa sürede N komut)
#  - alert logging (alerts/alerts.log) ve stdout

import re, time, json, os, sys
from pathlib import Path
from collections import defaultdict, deque

# Paths
THIS_DIR = Path(__file__).resolve().parent
ROOT_LOG = THIS_DIR / "server_run.log"
ALERTS_DIR = THIS_DIR / "alerts"
ALERTS_DIR.mkdir(parents=True, exist_ok=True)
ALERT_FILE = ALERTS_DIR / "alerts.log"

# Policy
WHITELIST_ORIGINS = {"CSMS-1", "CSMS-CORE"}  # izin verilen CSMS kimlikleri
SUSPICIOUS_ACTIONS = {"RemoteStartTransaction", "RemoteStopTransaction"}
RATE_WINDOW_SECONDS = 5
RATE_THRESHOLD = 10  # 5 saniyede 10+ komut

# regex / json helpers
json_regex = re.compile(r'^\s*\{.*\}\s*$')
ocpp_cmd_regex = re.compile(r'(Remote(Start|Stop)Transaction)', re.IGNORECASE)
origin_key_regex = re.compile(r'Origin[-_ ]?CSMS[-_ ]?ID\s*[:=]\s*([^\s|,]+)', re.IGNORECASE)
source_regex = re.compile(r'(remote|source)\s*[:=]\s*([^\s|,]+)', re.IGNORECASE)

# rate tracking: source -> deque of timestamps
rate_map = defaultdict(lambda: deque())

def follow(file):
    file.seek(0,2)
    while True:
        line = file.readline()
        if not line:
            time.sleep(0.15)
            continue
        yield line

def alert(msg, logline=None):
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    entry = f"{ts} | ALERT | {msg}"
    if logline:
        entry += " | LOG: " + logline.strip()
    print(entry)
    with open(ALERT_FILE, "a", encoding="utf-8") as f:
        f.write(entry + "\n")

def parse_json_line(line):
    try:
        obj = json.loads(line)
        action = obj.get("action") or obj.get("cmd") or obj.get("method")
        origin = obj.get("origin") or obj.get("Origin-CSMS-ID") or obj.get("origin_id")
        source = obj.get("source") or obj.get("remote")
        station_id = obj.get("station_id") or obj.get("id") or obj.get("cp") or obj.get("charge_point_id")
        return action, origin, source, station_id
    except Exception:
        return None, None, None, None

def parse_plain_line(line):
    action = None
    m = ocpp_cmd_regex.search(line)
    if m:
        action = "RemoteStartTransaction" if "RemoteStart" in m.group(0) else "RemoteStopTransaction"
    origin = None
    mo = origin_key_regex.search(line)
    if mo:
        origin = mo.group(1)
    ms = source_regex.search(line)
    source = ms.group(2) if ms else None
    station_id = None
    if "|" in line and "STATION_ID" in line:
        try:
            # Example: ... | STATION_ID=04 | ...
            for part in line.split("|"):
                part = part.strip()
                if part.startswith("STATION_ID="):
                    station_id = part.split("=",1)[1]
                    break
        except Exception:
            pass
    return action, origin, source, station_id

def rate_check(source):
    if not source:
        return
    now = time.time()
    dq = rate_map[source]
    dq.append(now)
    while dq and now - dq[0] > RATE_WINDOW_SECONDS:
        dq.popleft()
    if len(dq) > RATE_THRESHOLD:
        alert(f"Rate-limit exceeded by source={source} count={len(dq)} in {RATE_WINDOW_SECONDS}s")

def handle_line(line):
    # only process lines mentioning our suspicious actions
    if not ocpp_cmd_regex.search(line):
        return

    # try json first
    if json_regex.match(line.strip()):
        action, origin, source, station_id = parse_json_line(line)
    else:
        action, origin, source, station_id = parse_plain_line(line)

    # Normalize
    if action:
        action = str(action)

    # Decision logic
    if action in SUSPICIOUS_ACTIONS:
        # Origin validation
        if not origin or origin not in WHITELIST_ORIGINS:
            # Log per requested example format
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            station = station_id or "UNKNOWN"
            cmd = "RemoteStart" if "Start" in action else "RemoteStop"
            src = origin or "unknown"
            line_fmt = f"{ts} | STATION_ID={station} | command={cmd} | source={src} | anomaly=OCPP_CMD_SPOOF"
            alert("OCPP command origin validation failed", logline=line_fmt)

        # Rate check on source pointer (origin or remote)
        rate_check(source or origin or "unknown")

def main():
    log_path = ROOT_LOG
    if len(sys.argv) > 1:
        candidate = Path(sys.argv[1]).expanduser()
        if candidate.exists():
            log_path = candidate
    print(f"[detector] Watching: {log_path}")
    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in follow(f):
            try:
                handle_line(line)
            except Exception as exc:
                alert(f"Detector error: {exc}")

if __name__ == "__main__":
    main()
