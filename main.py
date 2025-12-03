# main.py
import os
import requests
import base64
import re
import time
from dotenv import load_dotenv
from newspaper import Article
from urllib.parse import quote
from fastapi import FastAPI, File, UploadFile, Form
from fastapi.responses import JSONResponse
from typing import Optional

# Optional OCR imports
OCR_AVAILABLE = False
try:
    from PIL import Image
    import pytesseract
    OCR_AVAILABLE = True
except Exception:
    OCR_AVAILABLE = False

# Load env
load_dotenv()
FACTCHECK_API_KEY = os.getenv("FACTCHECK_API_KEY")
SAFEBROWSING_API_KEY = os.getenv("SAFEBROWSING_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GNEWS_API_KEY = os.getenv("GNEWS_API_KEY")
NEWSDATA_API_KEY = os.getenv("NEWS_DATA_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
HUGGINGFACE_API_KEY = os.getenv("HUGGINGFACE_API_KEY")

GEMINI_ENDPOINT = f"https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateContent?key={GEMINI_API_KEY}"

app = FastAPI(title="Unified Fake News Analyzer", version="0.1.0")
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],            # change "*" to your frontend origin for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -----------------------
# Helpers
# -----------------------
def detect_category(title: str, text: str, url: str) -> str:
    combined = " ".join(filter(None, [title, (text or "")[:2000], url])).lower()
    categories = {
        "Cricket": ["cricket", "kohli", "ipl", "bcci", "odi", "t20", "test", "world cup"],
        "Sports": ["football", "fifa", "nba", "olympic", "athlete", "sports", "match", "tennis"],
        "Politics": ["prime minister", "minister", "election", "mp", "parliament", "bjp", "congress", "government"],
        "Entertainment": ["film", "movie", "bollywood", "actor", "music", "celebrity", "tv", "song"],
        "Technology": ["tech", "ai", "startup", "gadgets", "software", "google", "amazon"],
        "Business": ["market", "stocks", "finance", "economy", "company", "business"],
        "Health": ["health", "vaccine", "disease", "hospital"],
        "Science": ["research", "nasa", "space", "study"],
        "World": ["international", "united nations", "diplomacy", "global"],
        "Viral": ["viral", "rumour", "rumor", "hoax", "fake", "fact check", "fact-check"],
    }
    for cat, kws in categories.items():
        for kw in kws:
            if kw in combined:
                return cat
    return "General"


def check_url_safety(url: str):
    details = []
    dangerous = False
    # Safe Browsing
    try:
        if SAFEBROWSING_API_KEY:
            sb_endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFEBROWSING_API_KEY}"
            payload = {
                "client": {"clientId": "factcheck-app", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            }
            r = requests.post(sb_endpoint, json=payload, timeout=8)
            j = r.json() if r.status_code == 200 else {}
            if j.get("matches"):
                dangerous = True
                types = [m.get("threatType") for m in j.get("matches", [])]
                details.append(f"⚠️ Google Safe Browsing: {', '.join(types)}")
            else:
                details.append("✅ Google Safe Browsing: Clean")
        else:
            details.append("⚠️ Safe Browsing API key not configured")
    except Exception as e:
        details.append(f"⚠️ Safe Browsing error: {e}")

    # VirusTotal
    try:
        if VIRUSTOTAL_API_KEY:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            vt_endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            headers = {"x-apikey": VIRUSTOTAL_API_KEY}
            r = requests.get(vt_endpoint, headers=headers, timeout=8)
            if r.status_code == 200:
                stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                mal = stats.get("malicious", 0)
                susp = stats.get("suspicious", 0)
                if mal > 0 or susp > 0:
                    dangerous = True
                    details.append(f"⚠️ VirusTotal: {mal} malicious, {susp} suspicious")
                else:
                    details.append("✅ VirusTotal: Clean")
            else:
                details.append("⏳ VirusTotal: No quick report (first-time or rate-limited)")
        else:
            details.append("⚠️ VirusTotal API key not configured")
    except Exception as e:
        details.append(f"⚠️ VirusTotal error: {e}")

    return dangerous, "\n".join(details)


def extract_content_from_url(url: str):
    try:
        article = Article(url)
        article.download()
        article.parse()
        text = article.text or ""
        title = article.title or ""
        meta = {
            "title": title,
            "authors": article.authors or [],
            "publish_date": str(article.publish_date) if article.publish_date else None,
            "top_image": article.top_image or None,
        }
        meta["category"] = detect_category(title, text, url)
        media = []
        if article.top_image:
            media.append({"type": "image", "url": article.top_image})
        return text[:5000], meta, media
    except Exception as e:
        return None, {"error": str(e)}, []


def get_factcheck_results(claim: str, lang: str = "en"):
    try:
        q = quote(claim)
        url = f"https://factchecktools.googleapis.com/v1alpha1/claims:search?query={q}&languageCode={lang}&key={FACTCHECK_API_KEY}"
        r = requests.get(url, timeout=12)
        return r.json().get("claims", [])
    except Exception:
        return []


def get_gnews(query: str):
    try:
        q = quote(query)
        url = f"https://gnews.io/api/v4/search?q={q}&lang=en&max=8&token={GNEWS_API_KEY}"
        r = requests.get(url, timeout=12)
        return r.json().get("articles", [])
    except Exception:
        return []


def get_newsdata(query: str):
    try:
        q = quote(query)
        url = f"https://newsdata.io/api/1/news?apikey={NEWSDATA_API_KEY}&q={q}&language=en"
        r = requests.get(url, timeout=12)
        j = r.json()
        results = j.get("results", []) if isinstance(j, dict) else []
        normalized = []
        for item in results:
            normalized.append({
                "title": item.get("title"),
                "source": {"name": item.get("source_id") or item.get("source")},
                "url": item.get("link") or item.get("url")
            })
        return normalized
    except Exception:
        return []


def gather_news_evidence(query: str, factchecks: list):
    news = []
    g = get_gnews(query)
    if g:
        for it in g:
            news.append({
                "title": it.get("title"),
                "source": {"name": it.get("source", {}).get("name") if isinstance(it.get("source"), dict) else it.get("source")},
                "url": it.get("url")
            })

    nd = get_newsdata(query)
    if nd:
        news.extend(nd)

    # If still empty, use fact-check review URLs as trustworthy evidence fallback
    if not news and factchecks:
        for fc in factchecks[:6]:
            for rev in fc.get("claimReview", [])[:2]:
                url = rev.get("url")
                pub = rev.get("publisher", {}).get("name", "Fact-checker")
                text = fc.get("text", "")
                if url:
                    news.append({"title": text, "source": {"name": pub}, "url": url})

    # dedupe by url
    normalized = []
    seen = set()
    for item in news:
        u = (item.get("url") or "").strip()
        if not u or u in seen:
            continue
        seen.add(u)
        src = item.get("source", {})
        src_name = src.get("name") if isinstance(src, dict) else src or "Unknown"
        normalized.append({"title": item.get("title", "N/A"), "source": {"name": src_name}, "url": u})
    return normalized


def compute_verdict_from_factchecks(factchecks: list):
    if not factchecks:
        return "UNVERIFIED"
    verdicts = []
    for fc in factchecks:
        for r in fc.get("claimReview", []):
            rating = (r.get("textualRating") or "").upper()
            if "FALSE" in rating:
                verdicts.append("FALSE")
            elif "TRUE" in rating:
                verdicts.append("TRUE")
            elif "MISLEADING" in rating:
                verdicts.append("MISLEADING")
            elif "PARTLY" in rating:
                verdicts.append("PARTLY TRUE")
    if "FALSE" in verdicts:
        return "FALSE"
    if "TRUE" in verdicts:
        return "TRUE"
    if "MISLEADING" in verdicts:
        return "MISLEADING"
    if "PARTLY TRUE" in verdicts:
        return "PARTLY TRUE"
    return "UNVERIFIED"


def gemini_generate_explanation(claim_short: str, factchecks: list, news: list, image_text: Optional[str] = None):
    # Build short evidence
    fact_lines = []
    for i, fc in enumerate(factchecks[:5], 1):
        text = fc.get("text", "")
        rev = fc.get("claimReview", [])
        if rev:
            r0 = rev[0]
            fact_lines.append(f"{i}. {text} — {r0.get('publisher', {}).get('name','Unknown')}: {r0.get('textualRating','N/A')}")
        else:
            fact_lines.append(f"{i}. {text}")

    news_lines = []
    for i, n in enumerate(news[:5], 1):
        news_lines.append(f"{i}. {n.get('title','N/A')} ({n.get('source',{}).get('name','Unknown')})")

    prompt = (
        "You are a concise fact-check assistant. Use only the evidence provided.\n\n"
        f"CLAIM: {claim_short}\n\n"
        "FACTCHECK_EVIDENCE:\n" + ("\n".join(fact_lines) if fact_lines else "None") + "\n\n"
        "NEWS_EVIDENCE:\n" + ("\n".join(news_lines) if news_lines else "None") + "\n\n"
    )
    if image_text:
        prompt += f"IMAGE_OCR_TEXT:\n{image_text}\n\n"

    prompt += ("Write a short explanation (2-4 sentences) whether the claim appears TRUE, FALSE, or UNVERIFIED based on the evidence. "
               "Cite the fact-check or news item names when possible. Do not invent facts.")

    # Call Gemini (best-effort; may fail or return unexpected structure)
    if not GEMINI_API_KEY:
        return None

    payload = {
        "contents": [{"parts": [{"text": prompt[:6000]}]}],
        "generationConfig": {"temperature": 0.1, "maxOutputTokens": 300}
    }
    try:
        r = requests.post(GEMINI_ENDPOINT, json=payload, timeout=20)
        j = r.json()
        if isinstance(j, dict) and "candidates" in j and len(j["candidates"]) > 0:
            cand = j["candidates"][0]
            if "content" in cand and "parts" in cand["content"]:
                return cand["content"]["parts"][0].get("text", "").strip()
            if "text" in cand:
                return cand.get("text", "").strip()
        return None
    except Exception:
        return None


def ocr_extract_text_from_file(upload_file: UploadFile):
    """Return OCR text or None. Only runs if pytesseract & PIL available."""
    if not OCR_AVAILABLE:
        return None, "OCR libs not installed"
    try:
        contents = upload_file.file.read()
        upload_file.file.seek(0)
        img = Image.open(upload_file.file).convert("RGB")
        text = pytesseract.image_to_string(img)
        return text.strip(), None
    except Exception as e:
        return None, str(e)


# -----------------------
# Routes
# -----------------------
@app.get("/")
def home():
    return {"message": "VerifyX backend is running!"}


@app.post("/analyze")
async def analyze(text: Optional[str] = Form(None), image: Optional[UploadFile] = File(None)):
    """
    Unified endpoint:
     - text: either a short claim OR a URL
     - image: optional upload (will attempt OCR)
    """
    # Basic input check
    if not text and not image:
        return JSONResponse({"error": "No text/URL or image provided"}, status_code=400)

    is_url = False
    claim_for_search = text or ""
    article_meta = None
    image_ocr_text = None
    image_ocr_error = None

    # If it's a URL (starts with http)
    if claim_for_search and (claim_for_search.startswith("http://") or claim_for_search.startswith("https://")):
        is_url = True
        unsafe, safety_details = check_url_safety(claim_for_search)
        if unsafe:
            return JSONResponse({"error": "URL flagged as dangerous", "details": safety_details}, status_code=400)

        text_extracted, meta, media = extract_content_from_url(claim_for_search)
        if not text_extracted:
            return JSONResponse({"error": "Could not extract article content", "details": meta.get("error")}, status_code=500)
        article_meta = meta
        # use title as compact claim for queries
        claim_for_search = meta.get("title") or (text_extracted[:250])

    # If image present, do OCR (best-effort)
    if image:
        ocr_text, ocr_err = ocr_extract_text_from_file(image)
        if ocr_text:
            image_ocr_text = ocr_text
            # If user didn't provide text, we'll also use OCR text as part of query
            if not claim_for_search:
                claim_for_search = (ocr_text[:280])
        else:
            image_ocr_error = ocr_err

    # Use a compact claim string for searches (title or short input)
    query_for_search = claim_for_search or (article_meta.get("title") if article_meta else None) or ""

    # 1) Fact-check DB
    factchecks = get_factcheck_results(query_for_search) if query_for_search else []

    # 2) News evidence
    news_evidence = gather_news_evidence(query_for_search, factchecks)

    # 3) Compute verdict (primary: fact-checks)
    verdict = compute_verdict_from_factchecks(factchecks)

    # 4) Gemini explanation (best-effort) — pass OCR text if available
    gemini_text = gemini_generate_explanation(query_for_search, factchecks, news_evidence, image_ocr_text)

    if not gemini_text:
        # Build a short fallback explanation from first fact-checks
        if factchecks:
            fallback_parts = []
            for fc in factchecks[:3]:
                revs = fc.get("claimReview", [])
                if revs:
                    r = revs[0]
                    fallback_parts.append(f"{r.get('publisher', {}).get('name','Unknown')} classifies the claim as {r.get('textualRating','N/A')}.")
            gemini_text = " ".join(fallback_parts) + " Based on these fact-checks, treat the claim accordingly." if fallback_parts else "No good explanation could be generated."
        else:
            gemini_text = "No fact-checks or news evidence available and Gemini did not return an explanation."

    # Build final response: required format per your requests
    response_payload = {
        "verdict": verdict,
        "original_input": text if text else (image.filename if image else None),
        "article_metadata": article_meta,
        "fact_checks": [],
        "news_evidence": [],
        "image_ocr_text": image_ocr_text,
        "image_ocr_error": image_ocr_error,
        "explanation": gemini_text
    }

    # Add 3-5 fact-checks in requested friendly format
    for i, fc in enumerate(factchecks[:5], 1):
        rev = fc.get("claimReview", [])
        if rev:
            r0 = rev[0]
            response_payload["fact_checks"].append({
                "index": i,
                "text": fc.get("text", "N/A"),
                "rating": r0.get("textualRating", "N/A"),
                "publisher": r0.get("publisher", {}).get("name", "Unknown"),
                "url": r0.get("url", "N/A")
            })
        else:
            response_payload["fact_checks"].append({
                "index": i,
                "text": fc.get("text", "N/A"),
                "rating": "N/A",
                "publisher": "Unknown",
                "url": "N/A"
            })

    # Add news items + urls
    for i, n in enumerate(news_evidence[:8], 1):
        response_payload["news_evidence"].append({
            "index": i,
            "title": n.get("title", "N/A"),
            "source": n.get("source", {}).get("name", "Unknown") if isinstance(n.get("source"), dict) else (n.get("source") or "Unknown"),
            "url": n.get("url", "N/A")
        })

    # Return valid JSONResponse (content required)
    return JSONResponse(content=response_payload, status_code=200)
