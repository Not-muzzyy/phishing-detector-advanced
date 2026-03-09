# FastAPI wrapper for Intelligent Phishing Detection System

# Built by Mohammed Muzamil C

# Exposes all 5 detection layers as REST API endpoints

from **future** import annotations

import http.client
import json
import os
import re
import socket
import time
import urllib.parse
from html.parser import HTMLParser
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ── App Setup ────────────────────────────────────────────────────────────────

app = FastAPI(
title=“Intelligent Phishing Detection API”,
description=“5-layer ML-powered phishing detection. Built by Mohammed Muzamil C.”,
version=“1.0.0”,
)

app.add_middleware(
CORSMiddleware,
allow_origins=[”*”],
allow_methods=[”*”],
allow_headers=[”*”],
)

# ── Request Models ────────────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
message: Optional[str] = “”
url: Optional[str] = “”
include_ai: Optional[bool] = False

class TextRequest(BaseModel):
message: str

class URLRequest(BaseModel):
url: str

class HTMLRequest(BaseModel):
html: str

class SMTPRequest(BaseModel):
headers: str

# ── Detection Constants ───────────────────────────────────────────────────────

PHISHING_KEYWORDS = [
“verify”, “urgent”, “account”, “suspended”, “click here”, “login”,
“confirm”, “password”, “bank”, “update”, “blocked”, “security alert”,
“immediate action”, “limited time”, “winner”, “congratulations”,
“free”, “prize”, “claim”, “risk”, “unauthorized”, “locked”,
“paise”, “paisa”, “rupee”, “rupees”, “khata”, “band”, “block”,
“turant”, “abhi”, “jaldi”, “verify karo”, “login karo”, “click karo”,
“inaam”, “inam”, “jeeta”, “jeet”, “free mein”, “reward”,
“otp”, “pin”, “card number”, “atm”, “upi”, “gpay”, “phonepe”,
“ban karwa”, “police”, “arrest”, “legal action”, “court”,
“warna”, “nahi to”, “varna”, “dhamki”,
]

SUSPICIOUS_TLDS = [”.xyz”, “.top”, “.click”, “.loan”, “.win”, “.gq”, “.cf”, “.tk”]
LEGIT_DOMAINS = [“google.com”, “microsoft.com”, “apple.com”, “amazon.com”, “paypal.com”]
CRITICAL_KEYWORDS = [“paytm”, “sbi”, “hdfc”, “icici”, “verify”, “secure”, “login”, “account”]

VALID_URL_PATTERN = re.compile(
r”^(https?://)?((\d{1,3}.){3}\d{1,3}|[\w-]+(.[\w-]+)+)(/.*)?$”,
re.IGNORECASE,
)

# ── Detection Functions ───────────────────────────────────────────────────────

def analyze_text(text):
if not text.strip():
return {“score”: 0.0, “signals”: [], “keyword_hits”: []}
text_lower = text.lower()
hits = [kw for kw in PHISHING_KEYWORDS if kw in text_lower]
keyword_score = min(len(hits) / 5.0, 1.0)
urgency = any(w in text_lower for w in [
“urgent”, “immediately”, “now”, “asap”, “limited”,
“turant”, “abhi”, “jaldi”, “abhi karo”,
])
threat = any(w in text_lower for w in [
“blocked”, “suspended”, “locked”, “banned”, “ban karwa”,
“police”, “arrest”, “court”, “legal action”, “warna”, “nahi to”, “varna”,
])
reward = any(w in text_lower for w in [
“winner”, “free”, “prize”, “congratulations”, “claim”,
“inaam”, “inam”, “jeeta”, “free mein”,
])
signals = []
score = keyword_score * 0.6
if urgency:
signals.append(“Urgency language detected”)
score += 0.15
if threat:
signals.append(“Account threat language detected”)
score += 0.15
if reward:
signals.append(“Reward/prize bait language detected”)
score += 0.10
return {“score”: min(score, 1.0), “signals”: signals, “keyword_hits”: hits}

def check_domain_reachable(domain):
try:
socket.setdefaulttimeout(3)
socket.getaddrinfo(domain, None)
return True, “”
except socket.gaierror:
return False, “Domain does not resolve (DNS failure) - likely fake or taken down”
except Exception:
return False, “Could not verify domain reachability”

def analyze_url(url):
if not url.strip():
return {“score”: 0.0, “signals”: [], “domain”: “”, “reachable”: None}
if not VALID_URL_PATTERN.match(url.strip()):
return {“score”: 0.0, “signals”: [“Not a valid URL format - skipped”], “domain”: “”, “reachable”: None}
signals = []
score = 0.0
reachable = None
domain = “”
try:
parsed = urllib.parse.urlparse(url if “://” in url else “http://” + url)
domain = parsed.netloc.lower().replace(“www.”, “”)
path = parsed.path.lower()
ip_pattern = re.compile(r”^\d{1,3}(.\d{1,3}){3}$”)

```
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            signals.append("Suspicious TLD detected: " + tld)
            score += 0.30

    if ip_pattern.match(domain):
        signals.append("IP address used instead of domain name - major red flag")
        score += 0.40

    for legit in LEGIT_DOMAINS:
        base = legit.split(".")[0]
        if base in domain and legit not in domain:
            signals.append("Lookalike domain - impersonating " + legit)
            score += 0.35

    hyphen_count = domain.count("-")
    if hyphen_count >= 2:
        signals.append(str(hyphen_count) + " hyphens in domain (common phishing pattern)")
        score += 0.15

    kw_hits = [kw for kw in CRITICAL_KEYWORDS if kw in domain + path]
    if kw_hits:
        signals.append("Sensitive keywords in URL: " + ", ".join(kw_hits))
        score += 0.20

    if len(url) > 100:
        signals.append("Very long URL (" + str(len(url)) + " chars)")
        score += 0.10

    if parsed.scheme == "http":
        signals.append("No HTTPS - connection is unencrypted")
        score += 0.10

    subdomain_parts = domain.split(".")
    if len(subdomain_parts) > 4:
        signals.append("Deep subdomain nesting - evasion technique")
        score += 0.15

    special_chars = sum(url.count(c) for c in ["%20", "%3D", "%2F", "//", "\\"])
    if special_chars > 3:
        signals.append("Unusual encoding in URL - obfuscation attempt")
        score += 0.15

    if domain and not ip_pattern.match(domain):
        reachable, dns_msg = check_domain_reachable(domain)
        if not reachable:
            signals.append("UNREACHABLE: " + dns_msg)
            score += 0.35

    if len(subdomain_parts) >= 3:
        possible_impersonation = [
            legit for legit in LEGIT_DOMAINS
            if legit.split(".")[0] in ".".join(subdomain_parts[:-2])
        ]
        if possible_impersonation:
            signals.append("Brand name buried in subdomain - spoofing: " + domain)
            score += 0.40

except Exception:
    signals.append("Could not fully parse URL")
    score = max(score, 0.3)

return {"score": min(score, 1.0), "signals": signals, "domain": domain, "reachable": reachable}
```

class HTMLLinkParser(HTMLParser):
def **init**(self):
super().**init**()
self.links = []
self.has_forms = False
self.external_resources = []

```
def handle_starttag(self, tag, attrs):
    attrs_dict = dict(attrs)
    if tag == "a" and "href" in attrs_dict:
        self.links.append(attrs_dict["href"])
    if tag == "form":
        self.has_forms = True
    if tag in ("img", "script", "link") and any(k in attrs_dict for k in ("src", "href")):
        src = attrs_dict.get("src") or attrs_dict.get("href", "")
        if src.startswith("http"):
            self.external_resources.append(src)
```

def analyze_html_email(html_content):
if not html_content.strip():
return {“score”: 0.0, “signals”: [], “links”: [], “has_forms”: False, “link_count”: 0, “suspicious_links”: []}
signals = []
score = 0.0
parser = HTMLLinkParser()
try:
parser.feed(html_content)
except Exception:
pass
links = parser.links
mismatch_pattern = re.findall(r’href=[”']([^"']+)[”'][^>]*>([^<]+)<’, html_content, re.IGNORECASE)
mismatches = []
for href, text in mismatch_pattern:
text_clean = text.strip().lower()
if text_clean.startswith(“http”) and text_clean not in href.lower():
mismatches.append(text.strip()[:40] + “ -> “ + href[:40])
if mismatches:
signals.append(“Link text does not match href (” + str(len(mismatches)) + “ found)”)
score += 0.40
if parser.has_forms:
signals.append(“HTML form detected - possible credential harvesting”)
score += 0.35
suspicious_ext = [r for r in parser.external_resources if any(tld in r for tld in SUSPICIOUS_TLDS)]
if suspicious_ext:
signals.append(“External resources from suspicious domains”)
score += 0.25
hidden_count = html_content.lower().count(“display:none”) + html_content.lower().count(“visibility:hidden”)
if hidden_count > 2:
signals.append(str(hidden_count) + “ hidden elements - obfuscation attempt”)
score += 0.20
encoded = html_content.count(”&#”) + html_content.count(”%3C”)
if encoded > 10:
signals.append(“Heavy HTML encoding detected - evasion technique”)
score += 0.15
url_results = []
for link in links[:5]:
if link.startswith(“http”):
result = analyze_url(link)
if result[“score”] > 0.3:
url_results.append({“url”: link, “score”: result[“score”]})
if url_results:
signals.append(str(len(url_results)) + “ suspicious links found in HTML”)
score += 0.20
return {
“score”: min(score, 1.0),
“signals”: signals,
“links”: links[:10],
“has_forms”: parser.has_forms,
“link_count”: len(links),
“suspicious_links”: url_results,
}

def analyze_smtp_headers(raw_headers):
if not raw_headers.strip():
return {“score”: 0.0, “signals”: [], “dkim”: “Not found”, “spf”: “Not found”, “from_domain”: “”}
signals = []
score = 0.0
headers_lower = raw_headers.lower()
spf_status = “Not found”
if “spf=pass” in headers_lower:
spf_status = “PASS”
elif “spf=fail” in headers_lower:
spf_status = “FAIL”
signals.append(“SPF FAIL - sender not authorized for this domain”)
score += 0.35
elif “spf=softfail” in headers_lower:
spf_status = “SOFTFAIL”
signals.append(“SPF SoftFail - suspicious sender”)
score += 0.20
elif “spf=neutral” in headers_lower:
spf_status = “NEUTRAL”
dkim_status = “Not found”
if “dkim=pass” in headers_lower:
dkim_status = “PASS”
elif “dkim=fail” in headers_lower:
dkim_status = “FAIL”
signals.append(“DKIM FAIL - email signature invalid”)
score += 0.40
elif “dkim=none” in headers_lower:
dkim_status = “NONE”
signals.append(“No DKIM signature - unverified sender”)
score += 0.15
if “dmarc=fail” in headers_lower:
signals.append(“DMARC FAIL - domain alignment failed”)
score += 0.30
from_match = re.search(r”from:\s*.*?<?([\w.-]+@[\w.-]+)>?”, raw_headers, re.IGNORECASE)
reply_match = re.search(r”reply-to:\s*.*?<?([\w.-]+@[\w.-]+)>?”, raw_headers, re.IGNORECASE)
from_domain = “”
if from_match and reply_match:
from_email = from_match.group(1).lower()
reply_email = reply_match.group(1).lower()
from_domain = from_email.split(”@”)[-1] if “@” in from_email else from_email
reply_domain = reply_email.split(”@”)[-1] if “@” in reply_email else reply_email
if from_domain != reply_domain:
signals.append(“From domain does not match Reply-To domain - spoofing indicator”)
score += 0.40
elif from_match:
from_domain = from_match.group(1).split(”@”)[-1].lower()
received_count = headers_lower.count(“received:”)
if received_count > 6:
signals.append(“Unusual number of mail hops (” + str(received_count) + “) - possible relay abuse”)
score += 0.15
for mailer in [“phpmailer”, “mass mailer”, “bulk”]:
if mailer in headers_lower:
signals.append(“Suspicious mailer tool: “ + mailer)
score += 0.20
return {
“score”: min(score, 1.0),
“signals”: signals,
“dkim”: dkim_status,
“spf”: spf_status,
“from_domain”: from_domain,
}

def meta_model(text_score, url_score, html_score, smtp_score):
weights = {“text”: 0.25, “url”: 0.30, “html”: 0.25, “smtp”: 0.20}
active_scores = []
active_weights = []
if text_score > 0:
active_scores.append(text_score)
active_weights.append(weights[“text”])
if url_score > 0:
active_scores.append(url_score)
active_weights.append(weights[“url”])
if html_score > 0:
active_scores.append(html_score)
active_weights.append(weights[“html”])
if smtp_score > 0:
active_scores.append(smtp_score)
active_weights.append(weights[“smtp”])
if not active_scores:
return 0.0
total_weight = sum(active_weights)
weighted = sum(s * w for s, w in zip(active_scores, active_weights))
return weighted / total_weight

def run_groq_analysis(message_text, url, rule_score, signals):
api_key = os.getenv(“GROQ_API_KEY”)
if not api_key:
return {“error”: “GROQ_API_KEY not set”}
signals_text = “, “.join(signals) if signals else “No signals found”
prompt = (
“You are a cybersecurity expert. Analyze this potential phishing attempt. “
“Respond ONLY with valid JSON, no markdown, no extra text. “
“Message: “ + str(message_text or “Not provided”) + “. “
“URL: “ + str(url or “Not provided”) + “. “
“Rule score: “ + str(round(rule_score, 2)) + “ out of 1.0. “
“Signals: “ + signals_text + “. “
“Return exactly: {"threat_level": "HIGH", "attack_type": "phrase", “
“"confidence": 0.9, "explanation": "explanation", “
“"target": "who", "recommended_action": "what to do"}”
)
try:
body = json.dumps({
“model”: “llama-3.1-8b-instant”,
“messages”: [{“role”: “user”, “content”: prompt}],
“temperature”: 0.1,
“max_tokens”: 400,
})
conn = http.client.HTTPSConnection(“api.groq.com”, timeout=20)
conn.request(
“POST”,
“/openai/v1/chat/completions”,
body=body,
headers={
“Content-Type”: “application/json”,
“Authorization”: “Bearer “ + api_key,
}
)
response = conn.getresponse()
raw = response.read().decode(“utf-8”)
conn.close()
if response.status != 200:
return {“error”: “HTTP “ + str(response.status)}
data = json.loads(raw)
content = data[“choices”][0][“message”][“content”]
content = re.sub(r”`json|`”, “”, content).strip()
start = content.find(”{”)
end = content.rfind(”}”) + 1
if start != -1 and end > start:
content = content[start:end]
return json.loads(content)
except Exception as e:
return {“error”: str(e)}

# ── API Endpoints ─────────────────────────────────────────────────────────────

@app.get(”/”)
def health_check():
return {
“status”: “online”,
“service”: “Intelligent Phishing Detection API”,
“version”: “1.0.0”,
“built_by”: “Mohammed Muzamil C”,
“endpoints”: [
“POST /analyze”,
“POST /analyze/text”,
“POST /analyze/url”,
“POST /analyze/html”,
“POST /analyze/smtp”,
],
}

@app.post(”/analyze”)
def analyze(req: AnalyzeRequest):
if not req.message and not req.url:
raise HTTPException(status_code=400, detail=“Provide at least message or url”)

```
text_result = analyze_text(req.message or "")
url_result = analyze_url(req.url or "")
final_score = meta_model(text_result["score"], url_result["score"], 0.0, 0.0)
verdict = "PHISHING" if final_score >= 0.45 else "SAFE"
all_signals = text_result["signals"] + url_result["signals"]

response = {
    "verdict": verdict,
    "confidence": round(final_score, 4),
    "text_score": round(text_result["score"], 4),
    "url_score": round(url_result["score"], 4),
    "signals": all_signals,
    "keyword_hits": text_result["keyword_hits"],
    "domain": url_result.get("domain", ""),
    "domain_reachable": url_result.get("reachable"),
    "ai_assessment": None,
}

if req.include_ai:
    response["ai_assessment"] = run_groq_analysis(
        req.message, req.url, final_score, all_signals
    )

return response
```

@app.post(”/analyze/text”)
def analyze_text_only(req: TextRequest):
if not req.message.strip():
raise HTTPException(status_code=400, detail=“Message cannot be empty”)
result = analyze_text(req.message)
return {
“verdict”: “PHISHING” if result[“score”] >= 0.45 else “SAFE”,
“score”: round(result[“score”], 4),
“signals”: result[“signals”],
“keyword_hits”: result[“keyword_hits”],
}

@app.post(”/analyze/url”)
def analyze_url_only(req: URLRequest):
if not req.url.strip():
raise HTTPException(status_code=400, detail=“URL cannot be empty”)
result = analyze_url(req.url)
return {
“verdict”: “PHISHING” if result[“score”] >= 0.45 else “SAFE”,
“score”: round(result[“score”], 4),
“domain”: result[“domain”],
“reachable”: result[“reachable”],
“signals”: result[“signals”],
}

@app.post(”/analyze/html”)
def analyze_html(req: HTMLRequest):
if not req.html.strip():
raise HTTPException(status_code=400, detail=“HTML content cannot be empty”)
result = analyze_html_email(req.html)
return {
“verdict”: “SUSPICIOUS” if result[“score”] >= 0.40 else “CLEAN”,
“score”: round(result[“score”], 4),
“has_forms”: result[“has_forms”],
“link_count”: result[“link_count”],
“suspicious_links”: result[“suspicious_links”],
“signals”: result[“signals”],
}

@app.post(”/analyze/smtp”)
def analyze_smtp(req: SMTPRequest):
if not req.headers.strip():
raise HTTPException(status_code=400, detail=“Headers cannot be empty”)
result = analyze_smtp_headers(req.headers)
return {
“verdict”: “SPOOFED” if result[“score”] >= 0.35 else “LEGITIMATE”,
“score”: round(result[“score”], 4),
“spf”: result[“spf”],
“dkim”: result[“dkim”],
“from_domain”: result[“from_domain”],
“signals”: result[“signals”],
}
