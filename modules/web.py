import requests
from urllib.parse import urlparse
from core.ui import banner, section, info, good, warn, bad
from core.finding import Finding
from core.findings import FindingsManager
import ssl, socket

COMMON_PATHS = ["/admin", "/backup", "/.git", "/login", "/config"]

def web_scan(url=None):
    banner()
    if not url:
        url = input("Enter Web URL: ").strip()

    url = url if url.startswith(("http://","https://")) else "https://" + url
    parsed = urlparse(url)
    if not parsed.netloc:
        bad("Invalid URL")
        return []

    info(f"Target: {url}")
    findings = FindingsManager()
    headers = {"User-Agent": "Mozilla/5.0"}

    # HTTP Headers & Cookies
    section("HTTP HEADERS & SERVER INFO")
    try:
        r = requests.get(url, headers=headers, timeout=10)
        good(f"Status Code: {r.status_code}")
        good(f"Server: {r.headers.get('Server','Unknown')}")

        for h in ["Content-Security-Policy","Strict-Transport-Security",
                  "X-Content-Type-Options","X-Frame-Options","Referrer-Policy"]:
            if h not in r.headers:
                findings.add(Finding(
                    f"Missing {h}",
                    "Medium",
                    f"{h} header is not present",
                    f"Configure {h} header properly"
                ))

        for c in r.cookies:
            if not c.secure or not c.has_nonstandard_attr("HttpOnly"):
                findings.add(Finding(
                    f"Cookie {c.name} missing security flags",
                    "Medium",
                    "Cookie lacks HttpOnly or Secure flags",
                    "Set Secure and HttpOnly flags for cookies"
                ))
    except requests.exceptions.RequestException as e:
        bad(f"Request failed: {e}")
        return []

    # TLS check
    section("TLS CHECK")
    hostname = parsed.hostname
    port = parsed.port or 443
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                version = ssock.version()
                good(f"TLS version: {version}")
                if version in ["SSLv2","SSLv3","TLSv1"]:
                    findings.add(Finding(
                        "Weak TLS Version",
                        "High",
                        f"Server supports insecure TLS version: {version}",
                        "Upgrade server to TLS 1.2+"
                    ))
    except Exception as e:
        warn(f"TLS check failed: {e}")

    # Common paths
    section("COMMON PATHS")
    info("Scanning common paths...")
    for path in COMMON_PATHS:
        try:
            r = requests.get(url+path, timeout=5, allow_redirects=True)
            if r.status_code == 200:
                findings.add(Finding(
                    f"Exposed path: {path}",
                    "Medium",
                    f"{url}{path} is publicly accessible",
                    "Restrict access or remove unnecessary directories"
                ))
        except:
            continue

    # Summary
    section("SUMMARY OF FINDINGS")
    summary = findings.summary()
    for k,v in summary.items():
        print(f"{k}: {v}")

    return findings.findings


