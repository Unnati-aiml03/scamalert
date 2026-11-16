import re

PATTERNS = {
    "Urgency": [r"within \d+ ?(hours?|hrs|minutes)", r"will be (blocked|suspended|closed|deactivated)", r"immediately", r"urgent", r"turant", r"abhi", r"aaj hi", r"जल्दी", r"तुरंत"],
    "Authority impersonation": [r"\b(cbi|police|rbi|customs|narcotics|trai|cyber ?cell)\b", r"digital arrest", r"arrest warrant", r"पुलिस"],
    "Credential request": [r"\botp\b", r"\bpin\b", r"\bcvv\b", r"update (your )?kyc", r"aadhaar.*(verify|link)", r"pan.*(update|verify)", r"share.*(password|otp)"],
    "Reward bait": [r"you (have )?won", r"lottery", r"cashback", r"free gift", r"prize", r"congratulations"],
    "Payment pressure": [r"pay (a )?fine", r"upi (collect|request)", r"send (rs|₹)", r"processing fee", r"transfer .* (safe|rbi) account"],
    "Fear / threat": [r"legal action", r"sim .*(block|deactivat)", r"account .*(freeze|frozen|block)", r"जेल"],
}


def analyze_text(text: str):
    """Returns (score 0-40, reasons[], flags{})"""
    hits = []
    for cat, pats in PATTERNS.items():
        if any(re.search(p, text or "", re.I) for p in pats):
            hits.append(cat)
    reasons = [f"Message uses a scam tactic: {h}" for h in hits]
    flags = {"asks_credentials": "Credential request" in hits, "digital_arrest": bool(re.search(r"digital arrest", text or "", re.I))}
    return min(len(hits) * 12, 40), reasons, flags
