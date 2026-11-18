import pytest
from fastapi.testclient import TestClient

from app import main

client = TestClient(main.app)
SCAM = "Your SBI account will be blocked in 24 hours. Update KYC at http://sbi-kyc-verify.xyz/login and share OTP"


@pytest.fixture(autouse=True)
def fresh_limiter():
    main._hits.clear()
    yield
    main._hits.clear()


def test_health():
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["ok"] is True


def test_home_message():
    assert "ScamShield" in client.get("/").json()["message"]


def test_scam_text_is_dangerous():
    r = client.post("/analyze", data={"text": SCAM})
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "Dangerous" and body["reasons"] and body["advice"]


def test_safe_text_is_safe():
    r = client.post("/analyze", data={"text": "See you at 5pm. Form: https://www.sbi.co.in"})
    assert r.json()["verdict"] == "Safe"


def test_empty_input_is_rejected():
    assert client.post("/analyze", data={"text": "   "}).status_code == 400


def test_too_long_text_is_rejected():
    r = client.post("/analyze", data={"text": "a" * (main.MAX_TEXT_CHARS + 1)})
    assert r.status_code == 413


def test_unsupported_file_type_is_rejected():
    r = client.post("/analyze", files={"file": ("x.exe", b"MZ", "application/octet-stream")})
    assert r.status_code == 400


def test_fake_pdf_is_rejected():
    r = client.post("/analyze", files={"file": ("x.pdf", b"not a pdf", "application/pdf")})
    assert r.status_code == 400


def test_oversized_file_is_rejected(monkeypatch):
    monkeypatch.setattr(main, "MAX_UPLOAD_BYTES", 10)
    r = client.post("/analyze", files={"file": ("x.pdf", b"%PDF-" + b"0" * 50, "application/pdf")})
    assert r.status_code == 413


def test_security_headers_present():
    h = client.get("/health").headers
    assert h["x-content-type-options"] == "nosniff"
    assert h["x-frame-options"] == "DENY"
    assert h["cache-control"] == "no-store"


def test_report_returns_reference():
    assert client.post("/report").json()["ref"].startswith("DEMO-")


def test_rate_limit_blocks_rapid_requests(monkeypatch):
    monkeypatch.setattr(main, "RATE_LIMIT", 2)
    codes = [client.post("/analyze", data={"text": "hello"}).status_code for _ in range(3)]
    assert codes == [200, 200, 429]


def test_pdf_with_spoofed_link_is_dangerous():
    fitz = pytest.importorskip("fitz")
    doc = fitz.open()
    page = doc.new_page()
    rect = fitz.Rect(72, 72, 300, 100)
    page.insert_textbox(rect, "www.sbi.co.in", fontsize=12)
    page.insert_link({"kind": fitz.LINK_URI, "from": rect, "uri": "http://evil-login.xyz"})
    r = client.post("/analyze", files={"file": ("bank.pdf", doc.tobytes(), "application/pdf")})
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "Dangerous"
    assert any("really opens" in x for x in body["reasons"])
