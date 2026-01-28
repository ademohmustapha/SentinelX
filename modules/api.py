import requests
from urllib.parse import urlparse
from core.ui import banner, section, info, good, warn, bad
from core.finding import Finding
from core.findings import FindingsManager

# ---------------------------
# Normalize URL
# ---------------------------
def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url

# ---------------------------
# Scan API
# ---------------------------
def api_scan():
    banner()
    url = input("Enter API URL: ").strip()
    url = normalize_url(url)
    parsed = urlparse(url)

    if not parsed.netloc:
        bad("Invalid URL")
        return FindingsManager()

    info(f"Target API: {url}")
    findings = FindingsManager()

    headers = {
        "User-Agent": "SentinelX Scanner"
    }

    # ---------------------------
    # OPTIONS request check
    # ---------------------------
    section("OPTIONS Request & CORS Check")
    try:
        r = requests.options(url, headers=headers, timeout=(10, 30), allow_redirects=True)
        good(f"Status Code: {r.status_code}")

        cors_headers = r.headers.get("Access-Control-Allow-Headers", "")
        if "Authorization" not in cors_headers:
            findings.add(Finding(
                "Weak Auth / CORS Misconfig",
                "High",
                "Authorization header not restricted by CORS",
                "Restrict Authorization header in CORS policy"
            ))
        else:
            good("Authorization header properly restricted")

    except requests.exceptions.ConnectTimeout:
        warn("Connection timeout")
    except requests.exceptions.ReadTimeout:
        warn("Server took too long to respond")
    except requests.exceptions.SSLError:
        warn("SSL certificate issue")
    except requests.exceptions.ConnectionError:
        bad("Could not connect to API")
    except requests.exceptions.RequestException as e:
        bad(f"Request failed: {e}")
    except Exception as e:
        bad(f"Unexpected error: {e}")

    # ---------------------------
    # GET request check (basic info)
    # ---------------------------
    section("Basic GET Request Check")
    try:
        r = requests.get(url, headers=headers, timeout=10)
        good(f"Status Code: {r.status_code}")
        server = r.headers.get("Server", "Unknown")
        good(f"Server Info: {server}")

        # Detect common sensitive endpoints
        sensitive_paths = ["/admin", "/debug", "/config", "/.git"]
        info("Checking common API paths...")
        for path in sensitive_paths:
            try:
                res = requests.get(url + path, headers=headers, timeout=5)
                if res.status_code == 200:
                    findings.add(Finding(
                        f"Exposed API Path: {path}",
                        "Medium",
                        f"{url}{path} is publicly accessible",
                        "Restrict access or remove unnecessary endpoints"
                    ))
            except:
                continue

    except Exception as e:
        warn(f"GET request check failed: {e}")

    # ---------------------------
    # Summary
    # ---------------------------
    section("SUMMARY OF FINDINGS")
    summary = findings.summary()
    for sev, count in summary.items():
        print(f"{sev}: {count}")

    return findings

