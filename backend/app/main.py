import os
from datetime import datetime
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from .scoring import evaluate
from . import extractors

app = FastAPI(title="ScamShield API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# MongoDB with 24h TTL. Only anonymous verdicts are stored (no user id, no IP, no raw file).
col = None
try:
    from pymongo import MongoClient
    client = MongoClient(os.getenv("MONGO_URL", "mongodb://localhost:27017"), serverSelectionTimeoutMS=1500)
    client.admin.command("ping")
    col = client.scamshield.results
    col.create_index("created_at", expireAfterSeconds=86400)
except Exception:
    print("MongoDB not available - running without storage")


@app.get("/health")
def health():
    return {"ok": True, "storage": col is not None}


@app.post("/analyze")
async def analyze(text: str = Form(""), file: UploadFile = File(None)):
    spoofed = []
    if file:
        data = await file.read()  # memory only
        ct = file.content_type or ""
        try:
            if ct == "application/pdf":
                t, spoofed = extractors.from_pdf(data); text += "\n" + t
            elif ct.startswith("image/"):
                text += "\n" + extractors.from_image(data)
            elif ct.startswith("audio/"):
                text += "\n" + extractors.from_audio(data)
            else:
                raise HTTPException(400, "Unsupported file type")
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(500, f"Could not read file: {e}")
    if not text.strip():
        raise HTTPException(400, "Nothing to analyze")

    result = evaluate(text, spoofed)
    if col is not None:
        col.insert_one({"score": result["score"], "verdict": result["verdict"], "created_at": datetime.utcnow()})
    return result


@app.post("/report")
async def report(text: str = Form("")):
    # Mock of the law-enforcement sync. Replace with a real I4C/cybercrime integration later.
    return {"status": "reported", "ref": "DEMO-" + datetime.utcnow().strftime("%Y%m%d%H%M%S")}
