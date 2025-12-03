import os
import requests
import base64
import re
import time
from dotenv import load_dotenv
from newspaper import Article
from urllib.parse import quote

# Load API keys from .env
load_dotenv()
FACTCHECK_API_KEY = os.getenv("FACTCHECK_API_KEY")
SAFEBROWSING_API_KEY = os.getenv("SAFEBROWSING_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GNEWS_API_KEY = os.getenv("GNEWS_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
HUGGINGFACE_API_KEY = os.getenv("HUGGINGFACE_API_KEY")  # optional (deepfake)

# -------------------------
# Utility: Clean claim text
# -------------------------
def clean_claim(c):
    if not c:
        return ""
    c = c.lower()
    fillers = [
        "from next week", "next week", "pm", "prime minister", "minister",
        "says", "claims", "viral", "video", "message", "circulating",
        "in india", "india", "reportedly", "according to", "allegedly",
        "breaking", "urgent", "shocking", "must watch", "exclusive",
        "watch", "see", "check out", "click here"
    ]
    for f in fillers:
        c = re.sub(r'\b' + re.escape(f) + r'\b', '', c)
    words = re.findall(r"[a-zA-Z]{3,}", c)
    # preserve order, unique
    seen = set()
    uniq = []
    for w in words:
        if w not in seen:
            seen.add(w)
            uniq.append(w)
    return " ".join(uniq)

# -------------------------
# URL Safety (SafeBrowsing + VirusTotal)
# -------------------------
def check_url_safety(url):
    details = []
    is_dangerous = False

    # Google Safe Browsing
    try:
        sb_endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFEBROWSING_API_KEY}"
        payload = {
            "client": {"clientId": "factcheck-app", "clientVersion": "2.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        resp = requests.post(sb_endpoint, json=payload, timeout=10)
        data = resp.json()
        if data.get("matches"):
            is_dangerous = True
            types = [m.get("threatType") for m in data.get("matches", [])]
            details.append(f"⚠️ Google Safe Browsing: {', '.join(types)}")
        else:
            details.append("✅ Google Safe Browsing: Clean")
    except Exception as e:
        details.append(f"⚠️ Safe Browsing error: {e}")

    # VirusTotal
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        vt_endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        resp = requests.get(vt_endpoint, headers=headers, timeout=10)
        if resp.status_code == 200:
            stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            mal = stats.get("malicious", 0)
            susp = stats.get("suspicious", 0)
            if mal > 0 or susp > 0:
                is_dangerous = True
                details.append(f"⚠️ VirusTotal: {mal} malicious, {susp} suspicious")
            else:
                details.append("✅ VirusTotal: Clean")
        elif resp.status_code == 404:
            # submit for scanning (best-effort)
            try:
                submit_url = "https://www.virustotal.com/api/v3/urls"
                requests.post(submit_url, headers=headers, data={"url": url}, timeout=10)
                details.append("⏳ VirusTotal: URL submitted for scanning")
            except Exception as inner_e:
                details.append(f"⚠️ VirusTotal submit failed: {inner_e}")
    except Exception as e:
        details.append(f"⚠️ VirusTotal error: {e}")

    return is_dangerous, "\n".join(details)

# -------------------------
# Article extraction (newspaper3k)
# -------------------------
def extract_content_from_url(url):
    try:
        article = Article(url)
        article.download()
        article.parse()

        metadata = {
            "title": article.title,
            "authors": article.authors or [],
            "publish_date": str(article.publish_date) if article.publish_date else None,
            "top_image": article.top_image or None,
            "domain": article.source_url or url
        }

        media = []
        if article.top_image:
            media.append({"type": "image", "url": article.top_image})
        # newspaper's movies attr may not always exist; check safely
        movies = getattr(article, "movies", None)
        if movies:
            for mv in movies:
                media.append({"type": "video", "url": mv})

        return article.text[:5000], metadata, media

    except Exception as e:
        return None, {"error": str(e)}, []

# -------------------------
# Deepfake detection via HuggingFace (optional)
# -------------------------
def detect_deepfake(media_url, media_type="image"):
    if not HUGGINGFACE_API_KEY:
        return None, 0.0, "⚠️ HuggingFace API key not configured"

    try:
        r = requests.get(media_url, timeout=15)
        if r.status_code != 200:
            return None, 0.0, "❌ Could not download media"

        data = r.content
        if media_type == "image":
            api_url = "https://api-inference.huggingface.co/models/dima806/deepfake_vs_real_image_detection"
        else:
            api_url = "https://api-inference.huggingface.co/models/abhishek/autotrain-deepfake-detection"

        headers = {"Authorization": f"Bearer {HUGGINGFACE_API_KEY}"}
        resp = requests.post(api_url, headers=headers, data=data, timeout=30)
        if resp.status_code != 200:
            return None, 0.0, f"⚠️ Deepfake model returned {resp.status_code}"

        result = resp.json()
        fake_score = 0.0
        real_score = 0.0

        # handle common shapes
        if isinstance(result, list):
            preds = result[0] if len(result) > 0 else []
            if isinstance(preds, list):
                for p in preds:
                    label = str(p.get("label","")).upper()
                    score = float(p.get("score",0.0))
                    if "FAKE" in label or "DEEPFAKE" in label:
                        fake_score = max(fake_score, score)
                    elif "REAL" in label or "AUTHENTIC" in label:
                        real_score = max(real_score, score)
        elif isinstance(result, dict):
            preds = result.get("predictions") or result.get("labels") or result.get("output")
            if isinstance(preds, list):
                for p in preds:
                    label = str(p.get("label","")).upper()
                    score = float(p.get("score",0.0))
                    if "FAKE" in label or "DEEPFAKE" in label:
                        fake_score = max(fake_score, score)
                    elif "REAL" in label or "AUTHENTIC" in label:
                        real_score = max(real_score, score)

        if max(fake_score, real_score) == 0.0:
            return None, 0.0, "⚠️ Deepfake model returned no usable scores"

        is_deepfake = fake_score > real_score
        confidence = max(fake_score, real_score)
        details = (f"🚨 DEEPFAKE DETECTED (Confidence: {confidence*100:.1f}%)"
                   if is_deepfake else f"✅ APPEARS AUTHENTIC (Confidence: {confidence*100:.1f}%)")
        return is_deepfake, confidence, details

    except Exception as e:
        return None, 0.0, f"❌ Deepfake detection failed: {e}"

# -------------------------
# FactCheck API (basic)
# -------------------------
def get_factcheck_results(claim, lang="en"):
    try:
        q = quote(claim)
        fc_url = f"https://factchecktools.googleapis.com/v1alpha1/claims:search?query={q}&languageCode={lang}&key={FACTCHECK_API_KEY}"
        resp = requests.get(fc_url, timeout=10)
        return resp.json().get("claims", [])
    except Exception:
        return []

# -------------------------
# GNews query (basic)
# -------------------------
def get_news_evidence(claim, lang="en", country="in"):
    try:
        q = quote(claim)
        url = f"https://gnews.io/api/v4/search?q={q}&lang={lang}&country={country}&max=10&token={GNEWS_API_KEY}"
        resp = requests.get(url, timeout=10)
        return resp.json().get("articles", [])
    except Exception:
        return []

# -------------------------
# Compute verdict from fact-checks (primary source of truth)
# -------------------------
def compute_verdict_from_factchecks(fact_data):
    """
    Return one of: FALSE, TRUE, MISLEADING, PARTLY TRUE, UNVERIFIED, None (if no info)
    Priority: FALSE > TRUE > MISLEADING > PARTLY TRUE
    """
    if not fact_data:
        return None

    verdicts = []
    for fc in fact_data:
        for review in fc.get("claimReview", []):
            rating = str(review.get("textualRating", "")).upper()
            if "FALSE" in rating or "NO" in rating and "EVIDENCE" in rating:
                verdicts.append("FALSE")
            elif "TRUE" in rating:
                verdicts.append("TRUE")
            elif "MISLEADING" in rating or "MIXED" in rating:
                verdicts.append("MISLEADING")
            elif "PARTLY" in rating or "HALF" in rating:
                verdicts.append("PARTLY TRUE")

    if not verdicts:
        return None

    if "FALSE" in verdicts:
        return "FALSE"
    if "TRUE" in verdicts:
        return "TRUE"
    if "MISLEADING" in verdicts:
        return "MISLEADING"
    if "PARTLY TRUE" in verdicts:
        return "PARTLY TRUE"
    return None

# -------------------------
# Gemini-pro explanation (attempt; fallback provided)
# -------------------------
def generate_explanation_with_gemini(claim, fact_data, news_data, deepfake_summary=None):
    """
    Returns explanation string (may include verdict line), or fallback explanation.
    Gemini is only used for the textual explanation — we do NOT rely on it for the final verdict.
    """
    # Build short evidence
    fact_summary = ""
    if fact_data:
        fact_summary += "\nFACT-CHECKS:\n"
        for i, fc in enumerate(fact_data[:6], 1):
            fact_summary += f"{i}. {fc.get('text','N/A')}\n"
            for r in fc.get("claimReview", [])[:2]:
                fact_summary += f"   - {r.get('publisher', {}).get('name','Unknown')}: {r.get('textualRating','N/A')}\n"
    else:
        fact_summary += "\nNo fact-check entries found.\n"

    news_summary = ""
    if news_data:
        news_summary += "\nNEWS:\n"
        for i, a in enumerate(news_data[:6], 1):
            news_summary += f"{i}. {a.get('title','N/A')} ({a.get('source',{}).get('name','Unknown')})\n"
    else:
        news_summary += "\nNo news evidence found.\n"

    deepfake_text = ""
    if deepfake_summary:
        deepfake_text = f"\nMEDIA ANALYSIS:\n{deepfake_summary}\n"

    prompt = f"""You are a concise fact-check assistant. Do NOT invent facts.

CLAIM:
\"\"\"{claim}\"\"\"\n
EVIDENCE:
{fact_summary}
{news_summary}
{deepfake_text}

INSTRUCTIONS:
- Use the evidence above to write a short explanation (2 paragraphs) about whether the claim appears true or false.
- DO NOT output a new verdict line that overrides external logic. Provide reasoning and cite sources from the evidence block.
- If evidence is contradictory, explain that and say the claim is partly true/misleading/uncertain.
"""

    url = f"https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateContent?key={GEMINI_API_KEY}"
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.1, "maxOutputTokens": 800}
    }

    try:
        resp = requests.post(url, json=payload, timeout=30)
        resp_json = resp.json()
        # attempt to extract text-based output
        if "candidates" in resp_json and len(resp_json["candidates"]) > 0:
            cand = resp_json["candidates"][0]
            if "content" in cand and "parts" in cand["content"]:
                return cand["content"]["parts"][0]["text"]
            if "text" in cand:
                return cand["text"]
        # fallback if structure unexpected
        return None
    except Exception:
        return None

# -------------------------
# Fallback explanation builder (when Gemini fails)
# -------------------------
def build_fallback_explanation(claim, fact_data, news_data, deepfake_summary=None):
    parts = []
    if fact_data:
        parts.append("Fact-checks found the following (summary):")
        for fc in fact_data[:5]:
            parts.append(f"- {fc.get('text','N/A')}")
            for r in fc.get("claimReview", [])[:1]:
                parts.append(f"   • {r.get('publisher', {}).get('name','Unknown')}: {r.get('textualRating','N/A')}")
    else:
        parts.append("No fact-check entries were found for this claim.")

    if news_data:
        parts.append("\nRelevant news headlines (summary):")
        for a in news_data[:5]:
            parts.append(f"- {a.get('title','N/A')} ({a.get('source',{}).get('name','Unknown')})")
    else:
        parts.append("\nNo relevant news articles were found.")

    if deepfake_summary:
        parts.append("\nMedia authenticity checks:")
        parts.append(deepfake_summary)

    parts.append("\nConclusion: Based on the fact-checks and news evidence above, draw a verdict. If fact-checkers declare the claim FALSE, it should be treated as FALSE.")
    return "\n".join(parts)

# -------------------------
# Final display: big bold verdict box (style A)
# -------------------------
def verdict_box(verdict_label):
    # verdict_label expected: TRUE / FALSE / MISLEADING / PARTLY TRUE / UNVERIFIED
    # show with emojis
    emoji = {
        "TRUE": "✅",
        "FALSE": "❌",
        "MISLEADING": "⚠️",
        "PARTLY TRUE": "⚠️",
        "UNVERIFIED": "ℹ️",
        "UNDETERMINED": "ℹ️"
    }.get(verdict_label, "ℹ️")

    box = "\n" + "="*70 + "\n"
    box += f"        {emoji}  FINAL VERDICT: **{verdict_label}**\n"
    box += "="*70 + "\n"
    return box

# -------------------------
# MAIN PROCESS
# -------------------------
def process_input(user_input):
    # header
    header = "\n" + "="*70 + "\n" + "🛡️  FAKE NEWS DETECTION SYSTEM v2.0" + "\n" + "="*70 + "\n"
    print(header)

    claim_text = user_input
    metadata = None
    deepfake_summary = None
    media_checks = []

    # If URL: safety + extract
    if claim_text.startswith("http://") or claim_text.startswith("https://"):
        print("🔗 URL detected — checking safety and extracting article...")
        unsafe, safety_details = check_url_safety(claim_text)
        print(safety_details)
        if unsafe:
            return header + "\n❌ URL flagged as dangerous. Analysis stopped.\n" + safety_details

        text, metadata, media = extract_content_from_url(claim_text)
        if not text:
            return header + "\n❌ Could not extract article content.\n"

        claim_text = text  # use article text as claim/topic

        # Deepfake checks (if media found)
        if media:
            df_parts = []
            for m in media[:3]:
                is_fake, conf, details = detect_deepfake(m["url"], m["type"])
                df_parts.append(details)
                media_checks.append(details)
            deepfake_summary = "\n".join(df_parts) if df_parts else None

    else:
        print("📝 Text claim detected.")

    # Step: get fact-checks & news
    print("\n🔍 Searching fact-check database...")
    fact_data = get_factcheck_results(claim_text)

    print("\n📰 Searching news evidence (GNews)...")
    news_data = get_news_evidence(claim_text)

    # Compute verdict from fact-checkers first (primary)
    fc_verdict = compute_verdict_from_factchecks(fact_data)

    # If no fact-check derived verdict, derive fallback via news presence
    if not fc_verdict:
        if news_data:
            fc_verdict = "UNVERIFIED"
        else:
            fc_verdict = "UNVERIFIED"

    # Now attempt Gemini-only-for-explanation (do not override fc_verdict)
    print("\n🤖 Asking Gemini (for explanation text only)...")
    gemini_text = generate_explanation_with_gemini(claim_text, fact_data, news_data, deepfake_summary)

    if not gemini_text:
        print("⚠️ Gemini failed or returned no usable text. Using fallback explanation.")
        explanation = build_fallback_explanation(claim_text, fact_data, news_data, deepfake_summary)
    else:
        explanation = gemini_text

    # Build final output
    out = ""
    # BIG VERDICT BOX (style A)
    out += verdict_box(fc_verdict)

    # Then original input and cleaned claim
    out += f"\n📌 ORIGINAL INPUT:\n{user_input}\n"
    if metadata:
        out += "\n📰 ARTICLE METADATA:\n"
        for k, v in metadata.items():
            out += f"   • {k}: {v}\n"
    out += f"\n🧹 CLEANED CLAIM:\n{clean_claim(claim_text)}\n\n"

    # Media check summary
    if media_checks:
        out += "\n🎭 MEDIA AUTHENTICITY CHECKS:\n"
        for m in media_checks:
            out += f" - {m}\n"
        out += "\n"

    # Fact-checks summary
    out += "\n" + "-"*70 + "\n🔍 FACT-CHECK DATABASE RESULTS\n" + "-"*70 + "\n"
    if not fact_data:
        out += "No fact-checks found.\n"
    else:
        for i, fc in enumerate(fact_data[:8], 1):
            out += f"{i}. {fc.get('text','N/A')}\n"
            for r in fc.get("claimReview", [])[:2]:
                out += f"   • {r.get('publisher',{}).get('name','Unknown')}: {r.get('textualRating','N/A')}\n"
            out += f"      URL: {r.get('url','N/A') if fc.get('claimReview') else 'N/A'}\n"

    # News evidence
    out += "\n" + "-"*70 + "\n📰 NEWS EVIDENCE\n" + "-"*70 + "\n"
    if not news_data:
        out += "No relevant news found.\n"
    else:
        for i, a in enumerate(news_data[:8], 1):
            title = a.get('title','N/A')
            src = a.get('source',{}).get('name','Unknown')
            url = a.get('url','N/A')
            out += f"{i}. {title}\n   • {src}\n   • {url}\n"

    # Explanation (Gemini or fallback)
    out += "\n" + "-"*70 + "\n🤖 AI EXPLANATION\n" + "-"*70 + "\n"
    out += explanation + "\n"

    out += "\n" + "="*70 + "\n" + "✅ ANALYSIS COMPLETE\n" + "="*70 + "\n"
    return out

# -------------------------
# CLI
# -------------------------
def main():
    print("\n" + "="*70)
    print("            🛡️  FAKE NEWS DETECTION SYSTEM v2.0")
    print("="*70 + "\n")
    inp = input("Enter claim or URL: ").strip()
    if not inp:
        print("❌ No input provided. Exiting.")
        return
    result = process_input(inp)
    print(result)

if __name__ == "__main__":
    main()
