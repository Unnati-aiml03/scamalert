from app.scoring import evaluate
from app.text_analyzer import analyze_text
from app.url_analyzer import analyze_url, extract_urls


def test_known_phishing_domain_is_dangerous():
    r = evaluate("Claim your cashback: paytm-reward-claim.top")
    assert r["verdict"] == "Dangerous" and r["score"] >= 90


def test_official_bank_link_is_safe():
    r = evaluate("Hi, lunch at 2pm? Form is at https://www.sbi.co.in")
    assert r["verdict"] == "Safe" and r["score"] <= 30


def test_lookalike_bank_link_is_flagged():
    score, reasons, _ = analyze_url("http://sbi-kyc-verify.xyz/login")
    assert score >= 50
    assert any("imitates" in x for x in reasons)


def test_ip_address_link_is_flagged():
    _, reasons, _ = analyze_url("http://192.168.4.5/login")
    assert any("IP address" in x for x in reasons)


def test_url_shortener_is_flagged():
    _, reasons, _ = analyze_url("http://bit.ly/abc123")
    assert any("Shortened" in x for x in reasons)


def test_digital_arrest_is_dangerous():
    r = evaluate("You are under digital arrest. Pay a fine now.")
    assert r["verdict"] == "Dangerous" and r["score"] >= 80


def test_otp_request_is_dangerous():
    r = evaluate("Please share your OTP to continue.")
    assert r["verdict"] == "Dangerous" and r["score"] >= 70


def test_hinglish_scam_with_short_link_is_not_safe():
    r = evaluate("Aapka SIM aaj hi block ho jayega. Turant verify karein: http://bit.ly/sim-verify-now")
    assert r["verdict"] != "Safe"


def test_normal_text_is_safe_with_clear_message():
    r = evaluate("Your account was credited with Rs 2,000.")
    assert r["verdict"] == "Safe"
    assert r["reasons"] == ["No suspicious signs found"]


def test_extract_urls_removes_duplicates_and_trailing_punctuation():
    assert extract_urls("see http://a.com/x, and http://a.com/x.") == ["http://a.com/x"]


def test_text_score_counts_categories_not_words():
    score, reasons, _ = analyze_text("CBI officer says pay a fine immediately")
    assert score == 36 and len(reasons) == 3


def test_every_verdict_has_advice():
    for text in ["hello", "pay a fine to CBI immediately", "share OTP http://sbi-kyc-verify.xyz"]:
        assert evaluate(text)["advice"]
