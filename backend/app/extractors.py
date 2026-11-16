"""Turn any file into (text, urls, extra_signals). Raw files are processed in memory only."""
import io
from .url_analyzer import extract_urls


def from_pdf(data: bytes):
    import fitz
    doc = fitz.open(stream=data, filetype="pdf")
    text, spoofed = "", []
    for page in doc:
        text += page.get_text() + "\n"
        for link in page.get_links():
            real = link.get("uri")
            shown = page.get_textbox(link["from"]).strip() if link.get("from") else ""
            if real and shown:
                from urllib.parse import urlparse
                import tldextract
                rd = tldextract.extract(real).registered_domain
                sd = tldextract.extract(shown).registered_domain
                if sd and rd and sd != rd:
                    spoofed.append(f"Link text shows '{shown}' but really opens '{real}'")
            if real:
                text += f" {real} "
    return text, spoofed


def from_image(data: bytes):
    from PIL import Image
    import pytesseract, numpy as np, cv2
    img = Image.open(io.BytesIO(data)).convert("RGB")
    text = pytesseract.image_to_string(img)
    qr, _, _ = cv2.QRCodeDetector().detectAndDecode(np.array(img))
    if qr:
        text += f"\nQR code contains: {qr}"
    return text


_whisper = None
def from_audio(data: bytes):
    global _whisper
    import tempfile, os
    from faster_whisper import WhisperModel
    if _whisper is None:
        _whisper = WhisperModel("small", compute_type="int8")
    with tempfile.NamedTemporaryFile(delete=False, suffix=".audio") as f:
        f.write(data); path = f.name
    try:  # temp file removed immediately after transcription
        segs, _ = _whisper.transcribe(path)
        return " ".join(s.text for s in segs)
    finally:
        os.remove(path)
