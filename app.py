from flask import Flask, request, jsonify
import re
import time
import logging
from datetime import datetime, UTC
import os
from collections import defaultdict
from signal_model import Signal   # ✅ IMPORT ADDED

# ===============================
# Severity Engine
# ===============================

def calculate_severity(attack_type, hit_count=1):
    base_severity = {
        "SQL Injection": "HIGH",
        "Command Injection": "HIGH",
        "XSS": "MEDIUM",
        "Directory Traversal": "MEDIUM",
        "LFI/RFI": "HIGH",
        "Brute Force": "HIGH"
    }

    severity = base_severity.get(attack_type, "LOW")

    if hit_count >= 5 and severity == "MEDIUM":
        severity = "HIGH"

    if hit_count >= 10:
        severity = "CRITICAL"

    return {
        "severity": severity,
        "reason": f"{attack_type} pattern detected",
        "confidence": round(min(0.6 + hit_count * 0.05, 0.99), 2)
    }


print("RUNNING FILE:", os.path.abspath(__file__))

app = Flask(__name__)

START_TIME = time.time()
REQUEST_COUNT = defaultdict(int)

attack_events = []
ip_hits = defaultdict(int)

MAX_HIGH_ALERTS = 3
BAN_DURATION_SECONDS = 600

ip_high_alert_counter = defaultdict(int)
banned_ips = {}

def is_ip_banned(ip):
    if ip in banned_ips:
        ban_expiry = banned_ips[ip]
        if time.time() < ban_expiry:
            return True
        else:
            del banned_ips[ip]
            ip_high_alert_counter[ip] = 0
    return False


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.FileHandler("sentinelshield.log"),
        logging.StreamHandler()
    ]
)

ATTACK_SIGNATURES = {
   "SQL Injection": re.compile(
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|OR|AND)\b.*?(=|--|#|/\*|\*/))",
        re.IGNORECASE,
    ),

    "XSS": re.compile(
        r"(<script|<iframe|<object|<embed).*?>",
        re.IGNORECASE,
    ),

    "Directory Traversal": re.compile(
        r"(\.\./|\.\.\\|%2e%2e)",
        re.IGNORECASE,
    ),

    # ✅ Updated to reduce false positives
    "Command Injection": re.compile(
        r"(\b(cmd|bash|powershell|exec)\b|\|\||&&)",
        re.IGNORECASE,
    ),

    "LFI/RFI": re.compile(
        r"(=http[s]?://|=file://|=ftp://)",
        re.IGNORECASE,
    ),
}


RATE_LIMIT_WINDOW = 60
RATE_LIMIT_THRESHOLD = 10
ip_request_log = {}

def is_rate_limited(ip):
    now = time.time()
    ip_request_log.setdefault(ip, [])
    ip_request_log[ip] = [t for t in ip_request_log[ip] if now - t < RATE_LIMIT_WINDOW]

    if len(ip_request_log[ip]) >= RATE_LIMIT_THRESHOLD:
        return True

    ip_request_log[ip].append(now)
    return False


def inspect_request(req):
    payload = (
        str(req.url)
        + str(req.args)
        + str(req.headers)
        + str(req.get_data(as_text=True))
    )

    for attack, pattern in ATTACK_SIGNATURES.items():
        if pattern.search(payload):
            return attack
    return None


@app.before_request
def track_requests():
    REQUEST_COUNT[request.path] += 1

@app.after_request
def log_requests(response):
    logging.info(
        "%s %s %s %s",
        request.remote_addr,
        request.method,
        request.path,
        response.status_code,
    )
    return response


@app.route("/", methods=["GET", "POST"])
def sentinel_shield():
    client_ip = request.remote_addr

    # ===============================
    # Check Ban
    # ===============================
    if is_ip_banned(client_ip):
        logging.warning(
            f"IP: {client_ip} | Status: BLOCKED | Reason: IP temporarily banned"
        )
        return jsonify({
            "status": "blocked",
            "reason": "IP temporarily banned"
        }), 403

    # ===============================
    # Rate Limit
    # ===============================
    if is_rate_limited(client_ip):
        ip_hits[client_ip] += 1
        severity_data = calculate_severity("Brute Force", ip_hits[client_ip])

        signal = Signal(
            ip=client_ip,
            attack_type="Brute Force",
            severity=severity_data["severity"],
            confidence=severity_data["confidence"],
            reason=severity_data["reason"],
            endpoint=request.path,
            payload=str(request.args)
        )

        attack_events.append(signal.to_dict())

        logging.warning(
            f"IP: {client_ip} | Attack: Brute Force | "
            f"Severity: {severity_data['severity']} | "
            f"Confidence: {severity_data['confidence']} | "
            f"Status: BLOCKED (Rate Limit)"
        )

        return jsonify({
            "status": "blocked",
            "reason": "Rate limit exceeded",
            "severity": severity_data["severity"]
        }), 429

    # ===============================
    # Signature Detection
    # ===============================
    attack = inspect_request(request)

    if attack:
        ip_hits[client_ip] += 1
        severity_data = calculate_severity(attack, ip_hits[client_ip])

        if severity_data["severity"] in ["HIGH", "CRITICAL"]:
            ip_high_alert_counter[client_ip] += 1

            if ip_high_alert_counter[client_ip] >= MAX_HIGH_ALERTS:
                banned_ips[client_ip] = time.time() + BAN_DURATION_SECONDS
                logging.critical(
                    f"IP: {client_ip} | Status: BANNED | Duration: {BAN_DURATION_SECONDS}s"
                )

        signal = Signal(
            ip=client_ip,
            attack_type=attack,
            severity=severity_data["severity"],
            confidence=severity_data["confidence"],
            reason=severity_data["reason"],
            endpoint=request.path,
            payload=str(request.args)
        )

        attack_events.append(signal.to_dict())

        logging.warning(
            f"IP: {client_ip} | Attack: {attack} | "
            f"Severity: {severity_data['severity']} | "
            f"Confidence: {severity_data['confidence']} | "
            f"Status: BLOCKED"
        )

        return jsonify({
            "status": "blocked",
            "reason": f"Detected {attack}",
            "severity": severity_data["severity"],
            "confidence": severity_data["confidence"]
        }), 403

    # ===============================
    # Allowed Request
    # ===============================
    logging.info(
        f"IP: {client_ip} | Status: ALLOWED"
    )

    return jsonify({"status": "allowed", "message": "Request processed"}), 200

@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "UP",
        "service": "SentinelShield",
        "timestamp": datetime.now(UTC).isoformat()
    }), 200


@app.route("/metrics", methods=["GET"])
def metrics():
    uptime = int(time.time() - START_TIME)

    attack_distribution = {}
    severity_summary = {}
    flagged_ips = {}

    for event in attack_events:
        attack = event["attack"]
        severity = event["severity"]
        ip = event["ip"]

        attack_distribution[attack] = attack_distribution.get(attack, 0) + 1
        severity_summary[severity] = severity_summary.get(severity, 0) + 1
        flagged_ips[ip] = flagged_ips.get(ip, 0) + 1

    return jsonify({
        "service": "SentinelShield",
        "uptime_seconds": uptime,
        "total_attacks": len(attack_events),
        "attack_distribution": attack_distribution,
        "severity_summary": severity_summary,
        "flagged_ips": flagged_ips,
        "banned_ips": {
            ip: int(expiry - time.time())
            for ip, expiry in banned_ips.items()
            if expiry > time.time()
        },
        "request_count": dict(REQUEST_COUNT)
    })


@app.route("/dashboard", methods=["GET"])
def dashboard():
    return jsonify({
        "total_attacks": len(attack_events),
        "active_bans": list(banned_ips.keys()),
        "events": attack_events[-20:]
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
        use_reloader=False,
    )
