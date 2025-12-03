# all_test2_fixed.py
import os
import requests
import base64
import re
from dotenv import load_dotenv
from newspaper import Article
from urllib.parse import quote

# Load API keys
load_dotenv()
FACTCHECK_API_KEY = os.getenv("FACTCHECK_API_KEY")
SAFEBROWSING_API_KEY = os.getenv("SAFEBROWSING_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GNEWS_API_KEY = os.getenv("GNEWS_API_KEY")
NEWSDATA_API_KEY = os.getenv("NEWS_DATA_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
HUGGINGFACE_API_KEY = os.getenv("HUGGINGFACE_API_KEY")

GEMINI_ENDPOINT = f"https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateContent?key={GEMINI_API_KEY}"


# -------------------------------
# CATEGORY DETECTION (improved)
# -------------------------------
def detect_category(title: str, text: str, url: str) -> str:
    """Detect category by searching the title + text + url for many keywords."""
    combined = " ".join(filter(None, [title, text[:2000], url])).lower()

    categories = {
        "Cricket": ["cricket", "kohli", "virat", "ipl", "bcci", "odi", "t20", "test", "world cup", "wc"],
        "Sports": ["football", "fifa", "nba", "olympic", "athlete", "match", "sports", "rugby", "tennis"],
        "Politics": ["prime minister", "minister", "election", "mp", "parliament", "bjp", "congress", "government"],
        "Entertainment": ["film", "movie", "bollywood", "actor", "music", "celebrity", "tv", "song"],
        "Technology": ["tech", "ai", "artificial intelligence", "startup", "gadgets", "software", "amazon", "google"],
        "Business": ["market", "stocks", "finance", "economy", "company", "business", "revenue"],
        "Health": ["health", "covid", "vaccine", "disease", "hospital"],
        "Science": ["science", "research", "nasa", "space", "study"],
        "World": ["international", "world", "global", "united nations", "diplomacy"],
        "Viral": ["viral", "rumour", "rumor", "hoax", "fake", "fact check", "fact-check"],
    }

    for cat, keywords in categories.items():
        for kw in keywords:
            if kw in combined:
                return cat
    return "General"


# -------------------------------
# URL SAFETY CHECK (unchanged)
# -------------------------------
def check_url_safety(url: str):
    details = []
    dangerous = False
    # Safe Browsing
    try:
        sb_endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFEBROWSING_API_KEY}"
        payload = {
            "client": {"clientId": "factcheck-app", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        r = requests.post(sb_endpoint, json=payload, timeout=10)
        j = r.json() if r.status_code == 200 else {}
        if j.get("matches"):
            dangerous = True
            types = [m.get("threatType") for m in j.get("matches", [])]
            details.append(f"⚠️ Google Safe Browsing: {', '.join(types)}")
        else:
            details.append("✅ Google Safe Browsing: Clean")
    except Exception as e:
        details.append(f"⚠️ Safe Browsing error: {e}")

    # VirusTotal
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        vt_endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY} if VIRUSTOTAL_API_KEY else {}
        r = requests.get(vt_endpoint, headers=headers, timeout=10)
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
            details.append("⏳ VirusTotal: No report / first-time URL")
    except Exception as e:
        details.append(f"⚠️ VirusTotal error: {e}")

    return dangerous, "\n".join(details)


# -------------------------------
# ARTICLE EXTRACTION (newspaper3k)
# -------------------------------
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
        category = detect_category(title, text, url)
        meta["category"] = category

        # media list simplified
        media = []
        if article.top_image:
            media.append({"type": "image", "url": article.top_image})

        return text[:5000], meta, media
    except Exception as e:
        return None, {"error": str(e)}, []


# -------------------------------
# FACTCHECK API (Google FactCheck)
# -------------------------------
def get_factcheck_results(claim: str, lang: str = "en"):
    try:
        q = quote(claim)
        url = f"https://factchecktools.googleapis.com/v1alpha1/claims:search?query={q}&languageCode={lang}&key={FACTCHECK_API_KEY}"
        r = requests.get(url, timeout=12)
        return r.json().get("claims", [])
    except Exception:
        return []


# -------------------------------
# GNEWS + NEWSDATA (news evidence)
# -------------------------------
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
        # newsdata returns 'results' list
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
    # Try GNews first
    news = []
    g = get_gnews(query)
    if g:
        news.extend(g)

    # Try NewsData as fallback/extra
    nd = get_newsdata(query)
    if nd:
        news.extend(nd)

    # If still empty, add fact-check review URLs (these are trustworthy evidence about the claim)
    if not news and factchecks:
        for fc in factchecks[:6]:
            reviews = fc.get("claimReview", [])
            for rev in reviews[:2]:
                url = rev.get("url")
                pub = rev.get("publisher", {}).get("name", "Fact-checker")
                text = fc.get("text", "")
                if url:
                    news.append({"title": text, "source": {"name": pub}, "url": url})

    # Normalize & dedupe by URL
    normalized = []
    seen = set()
    for item in news:
        url = item.get("url") or item.get("link") or ""
        if not url:
            continue
        if url in seen:
            continue
        seen.add(url)
        src = item.get("source", {})
        src_name = src.get("name") if isinstance(src, dict) else src or "Unknown"
        normalized.append({"title": item.get("title", "N/A"), "source": {"name": src_name}, "url": url})
    return normalized


# -------------------------------
# GEMINI wrapper + fallback
# -------------------------------
def gemini_generate_explanation(claim_short: str, factchecks: list, news: list):
    # Build short evidence strings
    fact_summary_lines = []
    for i, fc in enumerate(factchecks[:5], 1):
        text = fc.get("text", "")
        rev = fc.get("claimReview", [])
        if rev:
            r0 = rev[0]
            fact_summary_lines.append(f"{i}. {text} — {r0.get('publisher', {}).get('name','Unknown')}: {r0.get('textualRating','N/A')}")
        else:
            fact_summary_lines.append(f"{i}. {text}")

    news_summary_lines = []
    for i, n in enumerate(news[:5], 1):
        news_summary_lines.append(f"{i}. {n.get('title','N/A')} ({n.get('source',{}).get('name','Unknown')})")

    prompt = (
        "You are a concise fact-check assistant. Use only the evidence provided.\n\n"
        f"CLAIM: {claim_short}\n\n"
        "FACTCHECK_EVIDENCE:\n" + ("\n".join(fact_summary_lines) if fact_summary_lines else "None") + "\n\n"
        "NEWS_EVIDENCE:\n" + ("\n".join(news_summary_lines) if news_summary_lines else "None") + "\n\n"
        "Write a short explanation (2-4 sentences) whether the claim appears TRUE, FALSE, or UNVERIFIED based on the evidence. Cite the fact-check or news item names when possible."
    )

    try:
        payload = {
            "contents": [{"parts": [{"text": prompt[:6000]}]}],
            "generationConfig": {"temperature": 0.1, "maxOutputTokens": 300}
        }
        r = requests.post(GEMINI_ENDPOINT, json=payload, timeout=20)
        j = r.json()
        # Try several possible response shapes
        if isinstance(j, dict) and "candidates" in j and len(j["candidates"]) > 0:
            cand = j["candidates"][0]
            if "content" in cand and "parts" in cand["content"]:
                return cand["content"]["parts"][0].get("text", "").strip()
            if "text" in cand:
                return cand.get("text", "").strip()
        return None
    except Exception:
        return None


# Fallback explanation builder (if Gemini fails)
def fallback_explanation_from_factchecks(factchecks):
    if not factchecks:
        return "No fact-checks or news evidence available and Gemini did not return an explanation."
    # Use the first fact-checks to build a short explanation
    parts = []
    # prefer explicit rated reviews
    for fc in factchecks[:3]:
        text = fc.get("text", "")
        revs = fc.get("claimReview", [])
        if revs:
            r = revs[0]
            publisher = r.get("publisher", {}).get("name", "Unknown")
            rating = r.get("textualRating", "N/A")
            parts.append(f"{publisher} classifies the claim as {rating}.")
    if parts:
        return " ".join(parts) + " Based on these fact-checks, the claim appears to be false or unverified."
    else:
        return "Fact-check entries were found but no clear rating could be parsed. Please inspect the listed fact-check URLs."


# -------------------------------
# DECIDE VERDICT from fact-checks (primary)
# -------------------------------
def compute_verdict_from_factchecks(factchecks):
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


# -------------------------------
# MAIN pipeline
# -------------------------------
def process_input(user_input: str):
    print("\n" + "=" * 56)
    print("🛡️  FAKE NEWS DETECTION SYSTEM v2.0")
    print("=" * 56 + "\n")

    is_url = user_input.startswith("http://") or user_input.startswith("https://")
    article_meta = None
    claim_for_search = user_input

    if is_url:
        print("🔗 URL detected — checking safety & extracting article...")
        unsafe, safety_details = check_url_safety(user_input)
        print(safety_details)
        if unsafe:
            return "\n❌ DANGEROUS URL detected. Analysis stopped.\n"

        text, meta, media = extract_content_from_url(user_input)
        if not text:
            return "\n❌ Could not extract article content.\n"
        article_meta = meta
        # Use the title as the claim search text (short)
        claim_for_search = meta.get("title") or text[:250]

    print("\n🔍 STEP 1 — Searching Google FactCheck database...")
    factchecks = get_factcheck_results(claim_for_search)

    print("\n📰 STEP 2 — Gathering news evidence (GNews -> NewsData -> fact-check URLs fallback)...")
    news_evidence = gather_news_evidence(claim_for_search, factchecks)

    print("\n🔎 STEP 3 — Determine verdict from fact-checks...")
    verdict = compute_verdict_from_factchecks(factchecks)

    print("\n🤖 STEP 4 — Asking Gemini for a concise explanation...")
    gemini_text = gemini_generate_explanation = None
    try:
        gemini_text = gemini_generate_explanation(claim_for_search, factchecks, news_evidence)
    except Exception:
        gemini_text = None

    if not gemini_text:
        # fallback
        gemini_text = fallback_explanation_from_factchecks(factchecks)

    # -------------------------
    # Build Output
    # -------------------------
    out = "\n" + "=" * 56 + "\n"
    if verdict == "FALSE":
        out += f"❌ FINAL VERDICT: {verdict}\n"
    else:
        out += f"ℹ️ FINAL VERDICT: {verdict}\n"
    out += "=" * 56 + "\n\n"

    # Article metadata (title, category, publish_date)
    if article_meta:
        out += "📰 ARTICLE METADATA:\n"
        out += f"• title: {article_meta.get('title','N/A')}\n"
        out += f"• category: {article_meta.get('category','N/A')}\n"
        out += f"• publish_date: {article_meta.get('publish_date','N/A')}\n\n"

    # Fact-checks (3-5) printed in the format you requested
    out += "-" * 50 + "\n🔍 FACT CHECK RESULTS\n" + "-" * 50 + "\n"
    if not factchecks:
        out += "No fact-check results found.\n\n"
    else:
        for i, fc in enumerate(factchecks[:5], 1):
            text = fc.get("text", "N/A")
            rev = fc.get("claimReview", [])
            if rev:
                r0 = rev[0]
                rating = r0.get("textualRating", "N/A")
                publisher = r0.get("publisher", {}).get("name", "Unknown")
                url = r0.get("url", "N/A")
            else:
                rating = "N/A"
                publisher = "Unknown"
                url = "N/A"
            out += f"{i}. Text: {text}\n"
            out += f"   Rating: {rating}\n"
            out += f"   Publisher: {publisher}\n"
            out += f"   URL: {url}\n\n"

    # News evidence
    out += "-" * 50 + "\n📰 NEWS EVIDENCE\n" + "-" * 50 + "\n"
    if not news_evidence:
        out += "No relevant news found.\n\n"
    else:
        for i, a in enumerate(news_evidence[:8], 1):
            title = a.get("title", "N/A")
            src = a.get("source", {}).get("name", "Unknown") if isinstance(a.get("source"), dict) else a.get("source") or "Unknown"
            url = a.get("url", a.get("link", "N/A"))
            out += f"{i}. {title}\n"
            out += f"   • {src}\n"
            out += f"   • {url}\n\n"

    # AI explanation
    out += "-" * 50 + "\n🤖 AI EXPLANATION\n" + "-" * 50 + "\n"
    out += gemini_text + "\n\n"

    out += "=" * 56 + "\n✅ ANALYSIS COMPLETE\n" + "=" * 56 + "\n"
    return out


# -------------------------------
# CLI
# -------------------------------
def main():
    ui = input("\nEnter claim or URL: ").strip()
    if not ui:
        print("No input provided.")
        return
    print(process_input(ui))


if __name__ == "__main__":
    main()
