import os
import requests
from dotenv import load_dotenv
import base64

# Load API keys from .env
load_dotenv()
FACTCHECK_API_KEY = os.getenv("FACTCHECK_API_KEY")
SAFEBROWSING_API_KEY = os.getenv("SAFEBROWSING_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
HUGGINGFACE_API_KEY = os.getenv("HUGGINGFACE_API_KEY")

# ----------- User Input ----------- #
query = input("Enter a claim or topic to fact-check: ")
show_top = input("Do you want to see only the top 3 most relevant fact-checks? (yes/no): ").lower()
check_url = input("Enter a URL to check for malware/phishing (or leave blank to skip): ").strip()

# ----------- Language Selection with Shorthand ----------- #
print("\nChoose languages (comma-separated). Examples:")
print("en = English, hi = Hindi, fr = French, sp = Spanish, ge = German, it = Italian, ja = Japanese")
lang_choice = input("Enter preferred languages (e.g., en,sp,fr): ").lower().replace(" ", "")

# Map shorthand to actual ISO codes
lang_map = {
    "en": "en",
    "hi": "hi",
    "fr": "fr",
    "sp": "es",
    "ge": "de",
    "it": "it",
    "ja": "ja",
    "po": "pt",
    "ru": "ru",
    "ch": "zh",
}

# Convert shorthand input into valid codes
language_list = []
for code in lang_choice.split(","):
    if code in lang_map:
        language_list.append(lang_map[code])
    else:
        print(f"⚠️ Unknown language shorthand: {code}")

# ----------- FactCheck API ----------- #
for lang in language_list:
    print(f"\n===== FactCheck Results (Language: {lang}) =====\n")
    fc_url = f"https://factchecktools.googleapis.com/v1alpha1/claims:search?query={query}&languageCode={lang}&key={FACTCHECK_API_KEY}"
    response = requests.get(fc_url)
    data = response.json()
    claims = data.get("claims", [])
    if show_top == "yes":
        claims = claims[:3]

    if not claims:
        print("No fact-checks found for this language.")
        continue

    for claim in claims:
        print("🔹 Claim:", claim.get("text", "No text found"))
        for review in claim.get("claimReview", []):
            rating = review.get("textualRating", None)
            if not rating or str(rating).isdigit():
                rating = "No rating available"
            print("   ✅ Source:", review.get("publisher", {}).get("name", "Unknown"))
            print("   📝 Rating:", rating)
            print("   🔗 URL:", review.get("url", "No URL"))
        print("-" * 50)

# ----------- URL Safety Check (Google Safe Browsing + VirusTotal) ----------- #
if check_url:
    print("\n===== URL Safety Check =====\n")
    is_dangerous = False

    # --- Google Safe Browsing --- #
    try:
        sb_endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFEBROWSING_API_KEY}"
        payload = {
            "client": {"clientId": "myapp", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": check_url}]
            }
        }
        sb_response = requests.post(sb_endpoint, json=payload)
        sb_data = sb_response.json()
        if sb_data.get("matches"):
            is_dangerous = True
    except Exception as e:
        print(f"Safe Browsing error: {e}")

    # --- VirusTotal --- #
    try:
        url_id = base64.urlsafe_b64encode(check_url.encode()).decode().strip("=")
        vt_endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        vt_response = requests.get(vt_endpoint, headers=headers)

        if vt_response.status_code == 200:
            vt_data = vt_response.json()
            stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

            # --- Display detailed stats ---
            print("--- VirusTotal Analysis Stats ---")
            for key, value in stats.items():
                print(f"{key.capitalize()}: {value}")

            if stats.get("malicious", 0) > 0 or stats.get("suspicious", 0) > 0:
                is_dangerous = True
        else:
            print("VirusTotal: No data found for this URL or URL needs to be submitted for scanning.")
    except Exception as e:
        print(f"VirusTotal error: {e}")

    # --- Final Safety Output --- #
    if is_dangerous:
        print(f"\n⚠️ Warning: The URL {check_url} is potentially dangerous!")
    else:
        print(f"\n✅ The URL {check_url} appears safe.")

# ----------- Hugging Face Deepfake Analysis (placeholder) ----------- #
# if media_file:
#     print("\n===== Hugging Face Deepfake Check =====\n")
#     hf_model = "your-chosen-model"
#     hf_endpoint = f"https://api-inference.huggingface.co/models/{hf_model}"
#     headers = {"Authorization": f"Bearer {HUGGINGFACE_API_KEY}"}
#     with open(media_file, "rb") as f:
#         hf_response = requests.post(hf_endpoint, headers=headers, data=f.read())
#     hf_data = hf_response.json()
#     print(hf_data)
