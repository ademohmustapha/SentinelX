import requests
from urllib.parse import urlparse
from core.ui import banner, section, info, good, warn, bad
from core.finding import Finding
from core.findings import FindingsManager

def api_scan(url=None):
    banner()
    if not url:
        url = input("Enter API URL: ").strip()

    if not url.startswith(("http://","https://")):
        url = "https://" + url
    parsed = urlparse(url)
    if not parsed.netloc:
        bad("Invalid URL")
        return []

    info(f"Target API: {url}")
    findings = FindingsManager()
    headers = {"User-Agent": "Kryphorix Scanner"}

    # OPTIONS request & CORS
    section("OPTIONS Request & CORS Check")
    try:
        r = requests.options(url, headers=headers, timeout=(10,30))
        good(f"Status Code: {r.status_code}")
        cors_headers = r.headers.get("Access-Control-Allow-Headers","")
        if "Authorization" not in cors_headers:
            findings.add(Finding(
                "Weak Auth / CORS Misconfig",
                "High",
                "Authorization header not restricted by CORS",
                "Restrict Authorization header in CORS policy"
            ))
        else:
            good("Authorization header properly restricted")
    except Exception as e:
        warn(f"CORS/OPTIONS check failed: {e}")

    # GET request check
    section("Basic GET Request Check")
    try:
        r = requests.get(url, headers=headers, timeout=10)
        good(f"Status Code: {r.status_code}")
        server = r.headers.get("Server", "Unknown")
        good(f"Server Info: {server}")

        sensitive_paths = ["/admin","/debug","/config","/.git"]
        for path in sensitive_paths:
            try:
                res = requests.get(url+path, headers=headers, timeout=5)
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

    # Summary
    section("SUMMARY OF FINDINGS")
    for sev,count in findings.summary().items():
        print(f"{sev}: {count}")

    return findings.findings

