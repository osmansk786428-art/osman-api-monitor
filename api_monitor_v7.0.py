#!/usr/bin/env python3
"""
OSMAN CYBER LAB - API MONITOR V7.1 ULTRA
Educational API monitoring and diagnostics.
"""

import os
import re
import sys
import json
import time
import getpass
import statistics
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

try:
    import requests
except ImportError:
    print("Missing dependency. Install using: pip install requests")
    sys.exit(1)


APP = "OSMAN CYBER LAB"
VERSION = "API MONITOR V7.1 ULTRA"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORT_DIR = os.path.join(BASE_DIR, "reports")
HISTORY_FILE = os.path.join(REPORT_DIR, "history.json")
SUMMARY_FILE = os.path.join(REPORT_DIR, "summary.json")

TIMEOUT_SECONDS = 15
MAX_HISTORY = 500

os.makedirs(REPORT_DIR, exist_ok=True)


def now():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def load_history():
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def save_json(path, data):
    temp = path + ".tmp"
    with open(temp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(temp, path)


def save_history(history):
    save_json(HISTORY_FILE, history[-MAX_HISTORY:])


def mask_text(value):
    """Mask phone-like sequences and common secret values."""
    value = str(value)
    value = re.sub(
        r'(?<!\d)(?:\+?\d[\d\s().-]{7,}\d)(?!\d)',
        '[REDACTED_PHONE]',
        value
    )
    value = re.sub(
        r'(?i)(api[_-]?key|authorization|token|secret)'
        r'(\s*["\']?\s*[:=]\s*["\']?)[^,"\'}\s]+',
        r'\1\2[REDACTED]',
        value
    )
    return value[:1200]


def safe_url(url):
    """Return a display/storage URL with sensitive query values masked."""
    try:
        p = urlsplit(url)
        sensitive = {
            "phone", "number", "mobile", "msisdn",
            "token", "key", "apikey", "api_key",
            "secret", "password", "authorization"
        }
        query = []
        for k, v in parse_qsl(p.query, keep_blank_values=True):
            if k.lower() in sensitive:
                v = "[REDACTED]"
            else:
                v = mask_text(v)
            query.append((k, v))

        # Never retain URL username/password.
        netloc = p.hostname or ""
        if p.port:
            netloc += ":" + str(p.port)

        return urlunsplit((
            p.scheme, netloc, p.path, urlencode(query), ""
        ))
    except Exception:
        return "[URL REDACTED]"


def valid_url(url):
    try:
        p = urlsplit(url.strip())
        return (
            p.scheme.lower() == "https"
            and bool(p.hostname)
            and not p.username
            and not p.password
        )
    except Exception:
        return False


def diagnose(status, body, error=None):
    """Classify API health using HTTP status and response body."""

    if error:
        low = str(error).lower()

        if "timeout" in low or "timed out" in low:
            return "TIMEOUT", "Request timed out"

        if any(x in low for x in ("ssl", "tls", "certificate")):
            return "TLS_ERROR", "HTTPS certificate or TLS problem"

        return "CONNECTION_ERROR", "Could not connect to endpoint"

    try:
        status = int(status) if status is not None else 0
    except (TypeError, ValueError):
        status = 0

    text = str(body or "").lower()

    maintenance_terms = (
        "api under maintenance",
        "under maintenance",
        "temporarily unavailable",
        "scheduled maintenance",
    )

    if any(term in text for term in maintenance_terms):
        return "MAINTENANCE", "Response body reports maintenance"

    if status == 429:
        return "RATE_LIMITED", "Rate limit reached; wait before retrying"

    if status in (401, 403):
        return "ACCESS_DENIED", "Authentication or permission may be required"

    if status == 404:
        return "ENDPOINT_ERROR", "Endpoint or resource not found"

    if status == 408:
        return "TIMEOUT", "Server reported request timeout"

    if status in (500, 502, 503, 504):
        return "SERVER_ERROR", "Server or upstream service error"

    if 300 <= status < 400:
        return "REDIRECT", "Server returned a redirect"

    if status in (200, 201, 202, 204):
        failure_terms = (
            '"success": false',
            '"success":false',
            '"status": "error"',
            '"status":"error"',
            "invalid api key",
            "invalid token",
            "subscription required",
            "access denied",
            "authentication required",
        )

        if any(term in text for term in failure_terms):
            return "API_ERROR", "HTTP succeeded but response suggests an API-level error"

        return "SUCCESS", "HTTP success status; verify response data"

    if status >= 500:
        return "SERVER_ERROR", "Server-side error"

    if status >= 400:
        return "HTTP_ERROR", "HTTP request was rejected or failed"

    return "UNKNOWN", "Unable to determine API status"




def test_endpoint(url, method="GET", api_host="", api_key="",
                  body="", custom_headers=None):
    url = url.strip()
    method = method.upper().strip()

    if not valid_url(url):
        return {
            "time": now(),
            "url": safe_url(url),
            "method": method,
            "status_code": None,
            "response_ms": None,
            "diagnosis": "INVALID_URL",
            "message": "Use a valid HTTPS URL without embedded credentials",
            "body_preview": "",
        }

    if method not in ("GET", "POST", "HEAD"):
        method = "GET"

    headers = {"User-Agent": "OsmanCyberLab-APIMonitor/5.5"}
    if api_host.strip():
        headers["X-RapidAPI-Host"] = api_host.strip()
    if api_key.strip():
        headers["X-RapidAPI-Key"] = api_key.strip()

    if custom_headers:
        for key, value in custom_headers.items():
            # Do not allow overwriting sensitive transport headers here.
            if key.lower() not in (
                "host", "content-length", "connection"
            ):
                headers[key] = value

    payload = None
    if method == "POST" and body.strip():
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            return {
                "time": now(),
                "url": safe_url(url),
                "method": method,
                "status_code": None,
                "response_ms": None,
                "diagnosis": "INVALID_JSON",
                "message": "POST body must be valid JSON",
                "body_preview": "",
            }

    started = time.perf_counter()
    status = None
    preview = ""
    error = None

    try:
        response = requests.request(
            method,
            url,
            headers=headers,
            json=payload,
            timeout=TIMEOUT_SECONDS,
            allow_redirects=False,
            verify=True,
        )
        status = response.status_code
        preview = mask_text(response.text[:1200])
        response.close()
    except requests.RequestException as exc:
        error = type(exc).__name__ + ": " + str(exc)
        preview = ""

    elapsed = round((time.perf_counter() - started) * 1000, 2)
    diagnosis, message = diagnose(status, preview, error)

    return {
        "time": now(),
        "url": safe_url(url),
        "method": method,
        "status_code": status,
        "response_ms": elapsed,
        "diagnosis": diagnosis,
        "message": message,
        "body_preview": preview,
    }


def save_test(result, history):
    result["id"] = len(history) + 1
    previous = history[-1] if history else None

    result["status_changed"] = bool(
        previous
        and previous.get("diagnosis") != result.get("diagnosis")
    )
    result["previous_diagnosis"] = (
        previous.get("diagnosis") if previous else None
    )

    history.append(result)
    save_history(history)

    filename = "test_" + datetime.now().strftime("%Y%m%d_%H%M%S_%f") + ".json"
    save_json(os.path.join(REPORT_DIR, filename), result)
    return result



def show_result(result):
    print()
    print(rainbow("═" * 52))
    print(rainbow("⚔️ API DIAGNOSTIC RESULT ⚔️".center(52)))
    print(rainbow("═" * 52))

    fields = [
        ("Time       ", result.get("time"), AQUA),
        ("Method     ", result.get("method"), PURPLE),
        ("URL        ", result.get("url"), CYAN),
    ]

    for label, value, colour in fields:
        print(rainbow(label) + " : " + colour + str(value) + RESET)

    code = result.get("status_code")
    code_colour = GREEN if isinstance(code, int) and 200 <= code < 300 else (
        YELLOW if isinstance(code, int) and code < 400 else RED
    )
    print(rainbow("HTTP Status") + " : " + code_colour + str(code) + RESET)

    ms = result.get("response_ms")
    print(rainbow("Response ms") + " : " + AQUA + str(ms) + RESET)

    print(rainbow("Diagnosis  ") + " : " + colour_status(result.get("diagnosis")))
    print(rainbow("Message    ") + " : " + YELLOW + str(result.get("message")) + RESET)

    if result.get("status_changed"):
        print(rainbow("────── STATUS CHANGE ──────"))
        print(rainbow("Previous   ") + " : " +
              colour_status(result.get("previous_diagnosis")))
        print(rainbow("Current    ") + " : " +
              colour_status(result.get("diagnosis")))

    body = result.get("body_preview")
    if body:
        print(rainbow("────── RESPONSE BODY ──────"))
        print(rainbow_json(str(body)[:500]))

    print(rainbow("═" * 52))

def ask_endpoint():
    url = input(rainbow("🌐 HTTPS API URL: ") + BOLD).strip()
    method = input(rainbow("⚙️ Method [GET/POST/HEAD, default GET]: ") + BOLD).strip().upper()
    if method not in ("GET", "POST", "HEAD"):
        method = "GET"

    host = input(rainbow("🔗 RapidAPI host (Enter if not needed): ") + BOLD).strip()
    key = getpass.getpass(rainbow("🔐 API key (hidden; Enter if not needed): ") + BOLD).strip()

    body = ""
    if method == "POST":
        print("POST JSON body (one line; Enter for empty):")
        body = input("> ").strip()

    return url, method, host, key, body


def run_one(history):
    url, method, host, key, body = ask_endpoint()
    print("\n" + CYAN + BOLD + "🌐 Testing endpoint..." + RESET)
    result = test_endpoint(url, method, host, key, body)
    result = save_test(result, history)
    show_result(result)
    print(GREEN + BOLD + "✔ Saved to reports/" + RESET)


def run_multiple(history):
    try:
        count = int(input(rainbow("🔗 Number of endpoints to test (1-10): ") + BOLD))
    except ValueError:
        print(RED + "Enter a number." + RESET)
        return

    if not 1 <= count <= 10:
        print(YELLOW + "Choose a number between 1 and 10." + RESET)
        return

    for i in range(count):
        print(f"\n--- Endpoint {i + 1}/{count} ---")
        url = input(rainbow("🌐 HTTPS API URL: ") + BOLD).strip()
        method = input(rainbow("⚙️ Method [GET/POST/HEAD, default GET]: ") + BOLD).strip().upper()
        if method not in ("GET", "POST", "HEAD"):
            method = "GET"
        host = input(rainbow("🔗 RapidAPI host (Enter if not needed): ") + BOLD).strip()
        key = getpass.getpass(rainbow("🔐 API key (hidden; Enter if not needed): ") + BOLD).strip()
        body = input("POST JSON body (Enter if not needed): ").strip() if method == "POST" else ""

        result = test_endpoint(url, method, host, key, body)
        result = save_test(result, history)
        show_result(result)



# COLOURFUL_DASHBOARD_PATCH

def advanced_analytics(history):
    """Display colorful analytics from saved API test history."""
    print()
    print(rainbow("=" * 58))
    print(rainbow("🐺 OSMAN CYBER LAB — ADVANCED ANALYTICS V7.1".center(58)))
    print(rainbow("=" * 58))

    if not history:
        print(YELLOW + BOLD + "  No saved tests available for analysis." + RESET)
        print(rainbow("=" * 58))
        return

    total = len(history)
    counts = {}
    for item in history:
        diagnosis = str(item.get("diagnosis", "UNKNOWN")).upper()
        counts[diagnosis] = counts.get(diagnosis, 0) + 1

    successful = counts.get("SUCCESS", 0) + counts.get("HEALTHY", 0)
    success_rate = successful / total * 100

    times = [
        float(item["response_ms"])
        for item in history
        if isinstance(item.get("response_ms"), (int, float))
        and not isinstance(item.get("response_ms"), bool)
        and item["response_ms"] >= 0
    ]

    print(rainbow("\n  ✦ [1] TEST SUMMARY"))
    print(f"  {CYAN}Total tests       : {BOLD}{total}{RESET}")
    print(f"  {GREEN}Successful tests  : {BOLD}{successful}{RESET}")
    print(f"  {RED}Non-success tests : {BOLD}{total - successful}{RESET}")
    rate_colour = GREEN if success_rate >= 80 else YELLOW if success_rate >= 50 else RED
    print(f"  {MAGENTA}Success rate      : {rate_colour}{BOLD}{success_rate:.2f}%{RESET}")

    if times:
        ordered = sorted(times)
        median = statistics.median(ordered)
        p95_index = max(0, int(0.95 * len(ordered) + 0.999999) - 1)
        p95 = ordered[p95_index]

        print(rainbow("\n  ✦ [2] RESPONSE-TIME ANALYSIS"))
        print(f"  {GREEN}Fastest           : {BOLD}{min(ordered):.2f} ms{RESET}")
        print(f"  {CYAN}Median            : {BOLD}{median:.2f} ms{RESET}")
        print(f"  {BLUE}Average           : {BOLD}{statistics.mean(ordered):.2f} ms{RESET}")
        print(f"  {MAGENTA}95th percentile   : {BOLD}{p95:.2f} ms{RESET}")
        print(f"  {YELLOW}Slowest           : {BOLD}{max(ordered):.2f} ms{RESET}")

    print(rainbow("\n  ✦ [3] DIAGNOSIS BREAKDOWN"))
    for diagnosis, amount in sorted(
        counts.items(), key=lambda pair: (-pair[1], pair[0])
    ):
        percentage = amount / total * 100
        label = colour_status(diagnosis)
        bar_length = max(1, round(percentage / 5))
        bar = "█" * bar_length
        print(f"  {label:<29} {CYAN}{amount:>4}{RESET}  "
              f"{MAGENTA}({percentage:5.1f}%){RESET}  {rainbow(bar)}")

    print(rainbow("\n  ✦ [4] HEALTH CLASSIFICATION"))

    healthy_names = {"SUCCESS", "HEALTHY"}
    degraded_names = {"REDIRECT", "RATE_LIMITED", "MAINTENANCE"}
    unhealthy_names = {
        "API_ERROR", "ACCESS_DENIED", "ENDPOINT_ERROR", "HTTP_ERROR",
        "SERVER_ERROR", "TLS_ERROR", "TIMEOUT", "CONNECTION_ERROR",
        "INVALID_URL", "INVALID_JSON",
    }

    latest = history[-1]
    latest_status = str(latest.get("diagnosis", "UNKNOWN")).upper()

    if latest_status in healthy_names:
        health, health_colour = "HEALTHY", GREEN
    elif latest_status in degraded_names:
        health, health_colour = "DEGRADED", YELLOW
    elif latest_status in unhealthy_names:
        health, health_colour = "UNHEALTHY", RED
    else:
        health, health_colour = "UNKNOWN", CYAN

    print(
        MAGENTA + BOLD + "  Latest diagnosis  : " + RESET
        + colour_status(latest_status)
    )
    print(
        MAGENTA + BOLD + "  Latest health     : " + RESET
        + health_colour + BOLD + health + RESET
    )
    print(
        DIM + CYAN
        + "  This classifies the latest saved test;"
        + RESET
    )
    print(
        DIM + CYAN
        + "  it does not guarantee live uptime."
        + RESET
    )

    print(rainbow("\n  ✦ [5] RECENT PERFORMANCE TREND"))
    recent = [
        item for item in history[-10:]
        if isinstance(item.get("response_ms"), (int, float))
        and not isinstance(item.get("response_ms"), bool)
        and item["response_ms"] >= 0
    ]

    if len(recent) >= 2:
        first = float(recent[0]["response_ms"])
        last = float(recent[-1]["response_ms"])
        difference = last - first

        if difference < 0:
            trend, trend_colour = "FASTER", GREEN
        elif difference > 0:
            trend, trend_colour = "SLOWER", YELLOW
        else:
            trend, trend_colour = "UNCHANGED", CYAN

        print(f"  {CYAN}First recent test : {BOLD}{first:.2f} ms{RESET}")
        print(f"  {CYAN}Latest test       : {BOLD}{last:.2f} ms{RESET}")
        print(f"  {MAGENTA}Difference        : {BOLD}{difference:+.2f} ms{RESET}")
        print("  Trend             : " + trend_colour + BOLD + trend + RESET)
    else:
        print(YELLOW + "  Not enough response-time samples for a trend." + RESET)

    print(rainbow("=" * 58))

def export_advanced_analytics(history):
    """Export an additional analytics report without replacing the summary."""
    if not history:
        print(YELLOW + "No saved tests to export." + RESET)
        return

    counts = {}
    times = []

    for item in history:
        diagnosis = str(item.get("diagnosis", "UNKNOWN")).upper()
        counts[diagnosis] = counts.get(diagnosis, 0) + 1

        value = item.get("response_ms")
        if (isinstance(value, (int, float))
                and not isinstance(value, bool)
                and value >= 0):
            times.append(float(value))

    ordered = sorted(times)
    p95 = None
    if ordered:
        index = max(0, int(0.95 * len(ordered) + 0.999999) - 1)
        p95 = round(ordered[index], 2)

    report = {
        "application": APP,
        "version": "API MONITOR V7.1 ULTRA",
        "generated_at": now(),
        "total_tests": len(history),
        "successful_tests": counts.get("SUCCESS", 0) + counts.get("HEALTHY", 0),
        "success_rate_percent": round(
            (counts.get("SUCCESS", 0) + counts.get("HEALTHY", 0))
            / len(history) * 100, 2
        ),
        "diagnosis_counts": counts,
        "response_time_ms": {
            "sample_count": len(ordered),
            "minimum": round(min(ordered), 2) if ordered else None,
            "median": round(statistics.median(ordered), 2) if ordered else None,
            "average": round(statistics.mean(ordered), 2) if ordered else None,
            "p95_nearest_rank": p95,
            "maximum": round(max(ordered), 2) if ordered else None,
        },
        "latest_test": history[-1],
    }

    filename = os.path.join(REPORT_DIR, "advanced_analytics_v7.json")
    save_json(filename, report)

    print(GREEN + BOLD + "\nAdvanced analytics report saved:" + RESET)
    print(filename)


def dashboard(history):
    print()
    print(rainbow("=" * 54))
    print(rainbow("🐺 OSMAN CYBER LAB — DASHBOARD V7.1 ULTRA ⚔️".center(54)))
    print(rainbow("ADVANCED API ANALYTICS".center(54)))
    print(rainbow("=" * 54))

    if not history:
        print(YELLOW + BOLD + "  No tests saved yet." + RESET)
        print(rainbow("=" * 54))
        return

    total = len(history)
    counts = {}

    for item in history:
        diagnosis = item.get("diagnosis", "UNKNOWN")
        counts[diagnosis] = counts.get(diagnosis, 0) + 1

    successful = sum(
        1 for item in history
        if item.get("diagnosis") in ("SUCCESS", "HEALTHY")
    )
    failed = total - successful
    success_rate = successful / total * 100

    times = [
        item.get("response_ms")
        for item in history
        if isinstance(item.get("response_ms"), (int, float))
        and item.get("response_ms") >= 0
    ]

    print(CYAN + BOLD + "\n  📊 OVERVIEW" + RESET)
    print(PURPLE + "  Total tests       : " + WHITE + BOLD + str(total) + RESET)
    print(GREEN + "  Successful        : " + str(successful) + RESET)
    print(RED + "  Non-success       : " + str(failed) + RESET)

    rate_colour = GREEN if success_rate >= 80 else YELLOW if success_rate >= 50 else RED
    filled = round(success_rate / 5)
    bar = "█" * filled + "░" * (20 - filled)
    print(rainbow("\n  ─────── SUCCESS RATE ───────"))
    print("  " + rate_colour + BOLD + f"[{bar}] {success_rate:.1f}%" + RESET)
    print(DIM + "  Based on saved test diagnoses, not guaranteed uptime." + RESET)

    print(rainbow("\n  ───── RESPONSE PERFORMANCE ─────"))
    if times:
        avg = statistics.mean(times)
        print(GREEN + f"  Fastest  : {min(times):.2f} ms" + RESET)
        print(AQUA + f"  Average  : {avg:.2f} ms" + RESET)
        print(YELLOW + f"  Slowest  : {max(times):.2f} ms" + RESET)

        if avg < 500:
            rating, colour = "FAST", GREEN
        elif avg < 1500:
            rating, colour = "NORMAL", YELLOW
        else:
            rating, colour = "SLOW", RED
        print("  Performance rating: " + colour + BOLD + rating + RESET)
    else:
        print(DIM + "  No response-time data." + RESET)

    print(rainbow("\n  ───── DIAGNOSIS BREAKDOWN ─────"))
    for diagnosis, amount in sorted(counts.items(), key=lambda x: (-x[1], x[0])):
        pct = amount / total * 100
        bar = "█" * min(round(pct / 5), 20)
        print(
            "  " + colour_status(diagnosis)
            + f" {amount:>4} ({pct:5.1f}%) "
            + GREEN + bar + RESET
        )

    print(rainbow("\n  ───── RECENT HEALTH TREND ─────"))
    recent = history[-10:]
    for item in recent:
        diagnosis = str(item.get("diagnosis", "UNKNOWN"))
        colour = colour_status(diagnosis)
        symbol = "✓" if diagnosis in ("SUCCESS", "HEALTHY") else "●"
        stamp = str(item.get("time", "N/A"))
        stamp = stamp.replace("T", " ")
        if len(stamp) > 19:
            stamp = stamp[:19]
        ansi_codes = re.findall(r"\x1b\[[0-9;]*m", colour)
        colour_prefix = "".join(
            code for code in ansi_codes
            if code != RESET
        )
        print(
            "  " + colour_prefix + symbol + RESET
            + " " + AQUA + stamp + RESET
            + " │ " + colour_prefix + diagnosis + RESET
        )

    latest = history[-1]
    print(rainbow("\n  ───────── LATEST TEST ─────────"))
    print(rainbow("  Time      : ") + AQUA + str(latest.get("time", "N/A")) + RESET)
    print(rainbow("  Diagnosis : ") + colour_status(latest.get("diagnosis", "UNKNOWN")))

    code = latest.get("status_code")
    if isinstance(code, int) and 200 <= code < 300:
        code_colour = GREEN
    elif isinstance(code, int) and 300 <= code < 400:
        code_colour = YELLOW
    else:
        code_colour = RED
    print(rainbow("  HTTP      : ") + code_colour + str(code if code is not None else "N/A") + RESET)

    response = latest.get("response_ms")
    response_text = f"{response:.2f} ms" if isinstance(response, (int, float)) else "N/A"
    print(rainbow("  Response  : ") + AQUA + response_text + RESET)

    changes = [item for item in history if item.get("status_changed")]
    print(rainbow("  Status changes : ") + MAGENTA + BOLD + str(len(changes)) + RESET)
    if changes:
        last = changes[-1]
        print(
            rainbow("  Last change    : ")
            + YELLOW + str(last.get("previous_diagnosis", "UNKNOWN"))
            + RESET + rainbow(" → ")
            + colour_status(last.get("diagnosis", "UNKNOWN"))
        )

    print(rainbow("=" * 54))




def show_history(history):
    if not history:
        print(YELLOW + BOLD + "No history available." + RESET)
        return

    print()
    print(rainbow("═" * 100))
    print(rainbow("📜 OSMAN CYBER LAB — SAVED API HISTORY".center(100)))
    print(rainbow("═" * 100))
    print(
        rainbow("ID | TIME | STATUS | HTTP | MS | URL")
    )
    print(rainbow("─" * 100))

    for item in history[-30:]:
        diagnosis = colour_status(item.get("diagnosis", "UNKNOWN"))
        code = item.get("status_code", "-")
        code_colour = GREEN if isinstance(code, int) and 200 <= code < 300 else (
            YELLOW if isinstance(code, int) and code < 400 else RED
        )
        ms = item.get("response_ms", "-")
        print(
            AQUA + str(item.get("id", "?")) + RESET + " | " +
            CYAN + str(item.get("time", "")) + RESET + " | " +
            diagnosis + " | " +
            code_colour + str(code) + RESET + " | " +
            PURPLE + str(ms) + RESET + " | " +
            WHITE + str(item.get("url", ""))[:55] + RESET
        )

    print(rainbow("─" * 100))
    print(GREEN + "Showing latest 30 tests maximum." + RESET)


def compare_history(history):
    if len(history) < 2:
        print(YELLOW + "At least two tests are required for comparison." + RESET)
        return

    print()
    print(rainbow("═" * 72))
    print(rainbow("⚡ RECENT API COMPARISON ⚡".center(72)))
    print(rainbow("═" * 72))

    for item in history[-10:]:
        print(
            CYAN + str(item.get("time")) + RESET + " | " +
            colour_status(item.get("diagnosis")) + " | " +
            AQUA + str(item.get("response_ms")) + " ms" + RESET + " | " +
            WHITE + str(item.get("url", ""))[:45] + RESET
        )

    first, last = history[-2], history[-1]
    print(rainbow("────── LAST TWO TESTS ──────"))
    print(rainbow("Previous") + " : " + colour_status(first.get("diagnosis")) +
          " | " + AQUA + str(first.get("response_ms")) + " ms" + RESET)
    print(rainbow("Current ") + " : " + colour_status(last.get("diagnosis")) +
          " | " + AQUA + str(last.get("response_ms")) + " ms" + RESET)

    a, b = first.get("response_ms"), last.get("response_ms")
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        difference = round(b - a, 2)
        diff_colour = GREEN if difference < 0 else YELLOW if difference == 0 else RED
        print(rainbow("Time difference") + " : " + diff_colour +
              f"{difference:+.2f} ms" + RESET)

    changed = first.get("diagnosis") != last.get("diagnosis")
    print(rainbow("Diagnosis changed") + " : " +
          (YELLOW + "YES" if changed else GREEN + "NO") + RESET)
    print(rainbow("═" * 72))


def export_summary(history):
    counts = {}
    times = []

    for item in history:
        d = item.get("diagnosis", "UNKNOWN")
        counts[d] = counts.get(d, 0) + 1
        t = item.get("response_ms")
        if isinstance(t, (int, float)):
            times.append(t)

    summary = {
        "application": APP,
        "version": VERSION,
        "generated_at": now(),
        "total_tests": len(history),
        "diagnosis_counts": counts,
        "average_response_ms": round(statistics.mean(times), 2) if times else None,
        "fastest_response_ms": min(times) if times else None,
        "slowest_response_ms": max(times) if times else None,
        "latest_test": history[-1] if history else None,
    }

    save_json(SUMMARY_FILE, summary)
    print()
    print(rainbow("═" * 56))
    print(rainbow("📤 SUMMARY REPORT EXPORTED".center(56)))
    print(rainbow("═" * 56))
    print(rainbow("File       ") + " : " + GREEN + SUMMARY_FILE + RESET)
    print(rainbow("Total tests") + " : " + AQUA + str(len(history)) + RESET)

    for diagnosis, amount in sorted(counts.items()):
        print("  " + colour_status(diagnosis) + " : " +
              PURPLE + str(amount) + RESET)

    print(GREEN + BOLD + "✔ Report saved successfully." + RESET)
    print(rainbow("═" * 56))

def clear_history(history):
    confirm = input(ORANGE + BOLD + "⚠️ Type CLEAR to delete saved history: " + RESET).strip()
    if confirm == "CLEAR":
        save_history([])
        history.clear()
        print("History cleared. Individual report files were not deleted.")
    else:
        print("Cancelled.")



# FULL_RGB_COLOUR_PATCH
import os as _colour_os

RESET = "\033[0m"
AQUA = "\033[96m"
ORANGE = "\033[38;5;208m"
PURPLE = "\033[95m"
BOLD = "\033[1m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
DIM = "\033[2m"

def rgb(r, g, b):
    return f"\033[38;2;{r};{g};{b}m"

def rainbow(text):
    colours = [
        (255, 40, 120),
        (255, 130, 40),
        (255, 230, 50),
        (60, 255, 130),
        (40, 220, 255),
        (100, 110, 255),
        (220, 80, 255),
    ]
    out = ""
    for i, char in enumerate(str(text)):
        c = colours[i % len(colours)]
        out += rgb(*c) + char
    return out + RESET

def rainbow_json(text):
    """Display JSON/text using a full RGB rainbow."""
    return rainbow(str(text))


def colour_status(status):
    status = str(status).upper()

    if status in ("SUCCESS", "HEALTHY"):
        return GREEN + BOLD + status + RESET

    if status == "API_ERROR":
        return ORANGE + BOLD + status + RESET

    if status in ("MAINTENANCE", "RATE_LIMITED", "REDIRECT"):
        return YELLOW + BOLD + status + RESET

    if status in (
        "ACCESS_DENIED", "HTTP_ERROR", "SERVER_ERROR",
        "ENDPOINT_ERROR", "TLS_ERROR", "INVALID_URL",
        "INVALID_JSON",
    ):
        return RED + BOLD + status + RESET

    if status in ("TIMEOUT", "CONNECTION_ERROR"):
        return MAGENTA + BOLD + status + RESET

    return CYAN + BOLD + status + RESET



def _colour_banner():
    print()
    print(rainbow("═" * 46))
    print(rainbow("🐺 ⚔️ OSMAN CYBER LAB V7.1 ULTRA ⚔️ 🐺".center(46)))
    print(rainbow("API MONITOR V7.1 DASHBOARD".center(46)))
    print(CYAN + BOLD + "     FULL RGB RAINBOW EDITION" + RESET)
    print(rainbow("═" * 46))


def menu():
    history = load_history()

    while True:
        print("\n")
        _colour_banner()
        print("  " + GREEN + BOLD + "⚔️  1 " + RESET + "│ " + CYAN + BOLD + "📊 Dashboard / Statistics" + RESET)
        print("  " + GREEN + BOLD + "⚔️  2 " + RESET + "│ " + GREEN + "🌐 Test one API endpoint" + RESET)
        print("  " + GREEN + BOLD + "⚔️  3 " + RESET + "│ " + AQUA + "🔗 Test multiple endpoints" + RESET)
        print("  " + GREEN + BOLD + "⚔️  4 " + RESET + "│ " + BLUE + "📜 View saved history" + RESET)
        print("  " + GREEN + BOLD + "⚔️  5 " + RESET + "│ " + MAGENTA + "⚡ Compare recent results" + RESET)
        print("  " + GREEN + BOLD + "⚔️  6 " + RESET + "│ " + YELLOW + "📤 Export summary report" + RESET)
        print("  " + RED + BOLD + "⚔️  7 " + RESET + "│ " + ORANGE + "🧹 Clear history" + RESET + DIM + " (confirmation required)" + RESET)
        print("  " + RED + BOLD + "⚔️  8 " + RESET + "│ " + WHITE + "🚪 Exit" + RESET)
        print("  " + GREEN + BOLD + "⚔️  9 " + RESET + "│ " + CYAN + "📈 Advanced Analytics V7.1" + RESET)
        print("  " + GREEN + BOLD + "⚔️ 10 " + RESET + "│ " + YELLOW + "📤 Export Advanced Analytics" + RESET)
        print(rainbow("─" * 48))

        choice = input("\n" + rainbow("🌈 Select option [1-10]: ") + BOLD).strip()

        if choice == "1":
            dashboard(history)
        elif choice == "2":
            run_one(history)
            history = load_history()
        elif choice == "3":
            run_multiple(history)
            history = load_history()
        elif choice == "4":
            show_history(history)
        elif choice == "5":
            compare_history(history)
        elif choice == "6":
            export_summary(history)
        elif choice == "7":
            clear_history(history)
            history = load_history()
        elif choice == "9":
            advanced_analytics(history)
        elif choice == "10":
            export_advanced_analytics(history)
        elif choice == "8":
            print("\n" + rainbow("⚔️ OSMAN CYBER LAB V7.1 ⚔️") + "\n" + rainbow("🐺 GOODBYE, OSMAN! SEE YOU AGAIN! 🐺") + "\n")
            break
        else:
            print(RED + BOLD + "❌ Invalid option. " + YELLOW + "Choose 1-8." + RESET)

        input("\n" + rainbow("⚔️ Press Enter to continue..."))


if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        print("\nStopped safely.")
