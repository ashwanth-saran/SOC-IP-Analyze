import os, time, math
from flask import Flask, render_template, request
import requests

# -------- CONFIG ----------
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY") or "427ba41d8bfa734610625037238ce92fa88b0eea7fa88d17b7da68b8fba1fa7ce1caf702b3c89d49"
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY") or "f23c1895281dcee34b78d2f110e5f1860b82f2c8094253fb90f90ac6fd460905"
CACHE_TTL = 60 * 5   # 5 minutes
# --------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, template_folder=os.path.join(BASE_DIR, 'templates'))

_cache = {}  # simple in-memory cache { ip: (ts, data) }

def get_cached(ip):
    item = _cache.get(ip)
    if not item: return None
    ts, data = item
    if time.time() - ts > CACHE_TTL:
        _cache.pop(ip, None)
        return None
    return data

def set_cache(ip, data):
    _cache[ip] = (time.time(), data)

def safe_get(url, headers=None, params=None, timeout=8):
    try:
        r = requests.get(url, headers=headers, params=params, timeout=timeout)
        return r
    except Exception:
        return None

def compute_score(abuse, vt_attrs):
    breakdown = {}
    score = 0.0

    # VirusTotal malicious ratio
    vt_malicious_ratio = 0.0
    vt_score = 0.0
    if vt_attrs and isinstance(vt_attrs, dict) and 'last_analysis_stats' in vt_attrs:
        las = vt_attrs.get("last_analysis_stats", {})
        total = sum(las.values()) if las else 0
        malicious = las.get('malicious', 0)
        if total > 0:
            vt_malicious_ratio = malicious / total
            vt_score = vt_malicious_ratio * 100
    breakdown['vt_malicious_ratio'] = round(vt_malicious_ratio, 3)
    breakdown['vt_score'] = round(vt_score, 2)
    score += 0.45 * vt_score

    # AbuseIPDB
    abuse_conf = 0
    total_reports = 0
    last_reported = None
    usage_type = ""
    usage_suspicious = 0
    if abuse and isinstance(abuse, dict):
        abuse_conf = abuse.get("abuseConfidenceScore", 0) or 0
        total_reports = abuse.get("totalReports", 0) or 0
        last_reported = abuse.get("lastReportedAt")
        usage_type = abuse.get("usageType") or ""
        suspicious_usages = {"hosting", "vpn", "proxy", "botnet", "malicious", "dynamic", "fraud"}
        if any(s in (usage_type or "").lower() for s in suspicious_usages):
            usage_suspicious = 1
    breakdown['abuse_confidence'] = abuse_conf
    score += 0.30 * abuse_conf

    # Reports log scale
    rep_score = 0
    if total_reports > 0:
        rep_score = min(100, math.log10(total_reports + 1) / 2 * 100)
    breakdown['reports_score'] = round(rep_score, 2)
    score += 0.15 * rep_score

    # usage heuristic
    usage_score = 100 if usage_suspicious else 0
    breakdown['usage_suspicious'] = bool(usage_suspicious)
    score += 0.10 * usage_score

    final_score = round(score, 2)
    if final_score >= 70:
        verdict = "Malicious"
        color = "danger"
    elif final_score >= 40:
        verdict = "Suspicious"
        color = "warning"
    elif final_score >= 10:
        verdict = "Low Risk"
        color = "info"
    else:
        verdict = "Clean"
        color = "success"

    breakdown.update({
        "final_score": final_score,
        "verdict": verdict,
        "color": color,
        "total_reports": total_reports,
        "last_reported": last_reported,
        "usage_type": usage_type
    })
    return final_score, breakdown

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/lookup', methods=['POST'])
def lookup():
    ip = request.form.get('ip', '').strip()
    if not ip:
        return render_template('index.html', error="Please enter a valid IP address.")

    cached = get_cached(ip)
    if cached:
        cached['cached'] = True
        return render_template('result.html', **cached)

    result = {"ip": ip, "cached": False}

    # ip-api
    ip_api_url = f"http://ip-api.com/json/{ip}"
    r = safe_get(ip_api_url, timeout=5)
    ip_api = r.json() if r and r.ok else {"error": "ip-api failed or timed out"}
    result['ip_api'] = ip_api

    # AbuseIPDB
    abuse_data = {}
    if ABUSEIPDB_API_KEY and "PASTE_YOUR" not in ABUSEIPDB_API_KEY:
        abuse_url = "https://api.abuseipdb.com/api/v2/check"
        headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
        params = {'ipAddress': ip, 'maxAgeInDays': 365}
        r = safe_get(abuse_url, headers=headers, params=params, timeout=8)
        if r and r.ok:
            data = r.json().get('data', {})
            # Try to get report timeline (AbuseIPDB doesn't provide full timeline in /check,
            # but we can simulate or leave for future extension)
            result['abuse_reports_timeline'] = []  # Placeholder — could be extended later
            abuse_data = data
        else:
            abuse_data = {"error": "abuseipdb failed or timed out"}
    else:
        abuse_data = {"error": "No AbuseIPDB key configured"}
    result['abuse'] = abuse_data

    # VirusTotal
    vt_attrs = {}
    if VIRUSTOTAL_API_KEY and "PASTE_YOUR" not in VIRUSTOTAL_API_KEY:
        vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}
        r = safe_get(vt_url, headers=headers, timeout=10)
        if r and r.ok:
            try:
                vt_attrs = r.json().get('data', {}).get('attributes', {})
            except Exception:
                vt_attrs = {"error": "vt parse error"}
        else:
            vt_attrs = {"error": "virustotal failed or timed out"}
    else:
        vt_attrs = {"error": "No VirusTotal key configured"}
    result['vt'] = vt_attrs

    score, breakdown = compute_score(abuse_data if isinstance(abuse_data, dict) else {}, vt_attrs if isinstance(vt_attrs, dict) else {})
    result.update({"score": score, "breakdown": breakdown})

    set_cache(ip, result)
    return render_template('result.html', **result)

if __name__ == '__main__':
    app.run(debug=True)