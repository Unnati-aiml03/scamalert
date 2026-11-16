import re
from urllib.parse import urlparse
import tldextract
from rapidfuzz import fuzz

URL_RE = re.compile(r"(https?://[^\s<>\"']+|\b[a-z0-9\-]+(?:\.[a-z0-9\-]+)*\.(?:com|in|xyz|top|click|tk|ml|ga|cf|info|site|online|link|co\.in)(?:/[^\s]*)?)", re.I)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly", "rb.gy", "is.gd"}
BAD_TLDS = {"xyz", "top", "click", "tk", "ml", "ga", "cf", "site", "online", "link"}
KEYWORDS = ["login", "verify", "kyc", "update", "secure", "account", "reward", "refund"]
# brand -> official registered domains
BRANDS = {
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "sbi.bank.in"},
    "hdfcbank": {"hdfcbank.com"}, "icicibank": {"icicibank.com"},
    "paytm": {"paytm.com"}, "phonepe": {"phonepe.com"},
    "irctc": {"irctc.co.in"}, "incometax": {"incometax.gov.in"},
    "aadhaar": {"uidai.gov.in"}, "indiapost": {"indiapost.gov.in"},
}

# Optional: load Phishing.Database list (one domain per line) into data/phishing.txt
try:
    with open("data/phishing.txt") as f:
        PHISH_DB = {l.strip().lower() for l in f if l.strip()}
except FileNotFoundError:
    PHISH_DB = {"sbi-kyc-update.xyz", "paytm-reward-claim.top"}  # demo entries


def extract_urls(text: str):
    return list(dict.fromkeys(m.group(0).rstrip(".,)") for m in URL_RE.finditer(text or "")))


def analyze_url(url: str):
    """Returns (score 0-100, reasons[], in_phish_db)"""
    full = url if url.startswith("http") else "http://" + url
    p = urlparse(full)
    host = (p.hostname or "").lower()
    ext = tldextract.extract(full)
    reg = ext.registered_domain.lower()
    score, reasons, in_db = 0, [], False

    if reg in PHISH_DB or host in PHISH_DB:
        return 100, ["This link is in a known phishing database"], True

    for brand, official in BRANDS.items():
        if reg in official:
            return 0, [], False  # allowlisted official domain

    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        score += 25; reasons.append("Link uses a raw IP address instead of a website name")
    if "@" in full:
        score += 20; reasons.append("Link contains '@' to hide the real destination")
    if "xn--" in host:
        score += 25; reasons.append("Link uses look-alike special characters")
    if len(ext.subdomain.split(".")) >= 4:
        score += 10; reasons.append("Link has too many sub-domains")
    if ext.suffix.split(".")[-1] in BAD_TLDS:
        score += 10; reasons.append(f"Link ends in '.{ext.suffix}', often used by scammers")
    if reg in SHORTENERS:
        score += 10; reasons.append("Shortened link hides the real website")
    if len(full) > 75:
        score += 5; reasons.append("Unusually long link")
    if p.scheme != "https":
        score += 5; reasons.append("Link is not secure (no HTTPS)")
    if any(k in host for k in KEYWORDS):
        score += 10; reasons.append("Domain contains words like login/verify/KYC")

    # lookalike / typosquatting
    cleaned = ext.domain.lower().replace("0", "o").replace("1", "l").replace("rn", "m")
    for brand in BRANDS:
        if brand in cleaned or 80 <= fuzz.ratio(cleaned, brand) < 100:
            score += 35; reasons.append(f"This link imitates '{brand.upper()}' but is NOT the official website")
            break
    return min(score, 100), reasons, False
