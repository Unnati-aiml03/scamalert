"""ScamShield API: privacy-first scam and phishing checker."""
import hashlib
import logging
import os
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from . import extractors
from .scoring import evaluate

log = logging.getLogger("scamshield")

MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_MB", "5")) * 1024 * 1024
MAX_TEXT_CHARS = 5000
RATE_LIMIT = int(os.getenv("RATE_LIMIT_PER_MIN", "60"))  # checks per minute per visitor
ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "*").split(",") if o.strip()]

app = FastAPI(title="ScamShield API", version="1.1.0")


class AnalyzeResponse(BaseModel):
    score: int
    verdict: str
    reasons: list[str]
    advice: str
    urls_found: list[str]


# Rate limiting. Visitors are held only as a short hash in memory for 60 seconds and never stored.
_hits: dict[str, deque] = defaultdict(deque)


@app.middleware("http")
async def guard(request: Request, call_next):
    limited = False
    if request.method == "POST" and request.url.path in ("/analyze", "/report"):
        ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or (
            request.client.host if request.client else "unknown")
        key = hashlib.sha256(ip.encode()).hexdigest()[:16]
        now, window = time.monotonic(), _hits[key]
        while window and now - window[0] > 60:
            window.popleft()
        if len(window) >= RATE_LIMIT:
            limited = True
        else:
            window.append(now)
        if len(_hits) > 10000:
            _hits.clear()
    if limited:
        response = JSONResponse({"detail": "Too many checks. Please wait a minute and try again."}, status_code=429)
    else:
        response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


# Added after the guard so CORS headers also appear on 429 responses.
app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_methods=["GET", "POST"], allow_headers=["*"])

# MongoDB with a 24h TTL. Only anonymous verdicts are stored: no user id, no IP, no raw file.
col = None
try:
    from pymongo import MongoClient
    _client = MongoClient(os.getenv("MONGO_URL", "mongodb://localhost:27017"), serverSelectionTimeoutMS=1500)
    _client.admin.command("ping")
    col = _client.scamshield.results
    col.create_index("created_at", expireAfterSeconds=86400)
except Exception:
    log.warning("MongoDB not available - running without storage")


def _file_kind(content_type: str | None) -> str | None:
    ct = (content_type or "").lower()
    if ct == "application/pdf":
        return "pdf"
    if ct in {"image/png", "image/jpeg", "image/webp", "image/bmp"}:
        return "image"
    if ct.startswith("audio/"):
        return "audio"
    return None


@app.get("/")
def home():
    return {"message": "ScamShield API is running. Open /docs to try it."}


@app.get("/health")
def health():
    return {"ok": True, "storage": col is not None}


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(text: str = Form(""), file: UploadFile | None = File(None)):
    if len(text) > MAX_TEXT_CHARS:
        raise HTTPException(413, f"Text is too long. Please keep it under {MAX_TEXT_CHARS} characters.")
    spoofed: list[str] = []
    if file and file.filename:
        kind = _file_kind(file.content_type)
        if kind is None:
            raise HTTPException(400, "Unsupported file type. Please upload a PDF, image or audio file.")
        data = await file.read(MAX_UPLOAD_BYTES + 1)  # memory only, never saved
        if len(data) > MAX_UPLOAD_BYTES:
            raise HTTPException(413, f"File is too large. The limit is {MAX_UPLOAD_BYTES // (1024 * 1024)} MB.")
        if kind == "pdf" and not data.startswith(b"%PDF-"):
            raise HTTPException(400, "This file does not look like a real PDF.")
        try:
            if kind == "pdf":
                extracted, spoofed = extractors.from_pdf(data)
            elif kind == "image":
                extracted = extractors.from_image(data)
            else:
                extracted = extractors.from_audio(data)
        except ImportError:
            raise HTTPException(501, "This file type is not enabled on this server.")
        except Exception:
            log.exception("file processing failed")  # details stay in server logs only
            raise HTTPException(422, "We could not read this file. Try another one or paste the text instead.")
        text += "\n" + extracted
    if not text.strip():
        raise HTTPException(400, "Nothing to analyze. Paste a message or upload a file.")

    result = evaluate(text, spoofed)
    if col is not None:
        try:
            col.insert_one({"score": result["score"], "verdict": result["verdict"],
                            "created_at": datetime.now(timezone.utc)})
        except Exception:
            log.warning("could not store result")
    return result


@app.post("/report")
async def report():
    # Mock of the law-enforcement sync. Replace with a real I4C/cybercrime integration later.
    return {"status": "reported", "ref": "DEMO-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")}
