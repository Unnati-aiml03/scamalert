from .url_analyzer import extract_urls, analyze_url
from .text_analyzer import analyze_text


def verdict(score):
    return "Safe" if score <= 30 else "Suspicious" if score <= 65 else "Dangerous"

ADVICE = {
    "Safe": "No major risk found. Still, never share OTP or PIN with anyone.",
    "Suspicious": "Be careful. Do not click links or share details. Verify with the official source.",
    "Dangerous": "Do NOT click, reply or pay. Report this on cybercrime.gov.in or call 1930.",
}


def evaluate(text: str, spoofed=None):
    spoofed = spoofed or []
    urls = extract_urls(text)
    url_results = [analyze_url(u) for u in urls]
    url_score = max([r[0] for r in url_results], default=0)
    in_db = any(r[2] for r in url_results)
    reasons = [x for r in url_results for x in r[1]]

    text_score, t_reasons, flags = analyze_text(text)
    reasons += t_reasons + spoofed

    final = 0.5 * url_score + 0.5 * (text_score / 40 * 100)
    final = max(final, url_score * 0.8)  # a very bad link shouldn't be diluted
    # override rules
    if in_db: final = max(final, 90)
    if spoofed: final = max(final, 75)
    if flags["asks_credentials"]: final = max(final, 70)
    if flags["digital_arrest"]: final = max(final, 80)
    final = int(min(final, 100))

    v = verdict(final)
    return {"score": final, "verdict": v, "reasons": reasons or ["No suspicious signs found"],
            "advice": ADVICE[v], "urls_found": urls}
