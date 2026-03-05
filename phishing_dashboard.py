# Streamlit dashboard for Intelligent Phishing Detection System.
# Features: Text, URL, HTML Email, SMTP Header, AI/LLM analysis
# Built by Mohammed Muzamil C

from __future__ import annotations

import json
import os
import re
import socket
import time
import urllib.parse
import urllib.request
from html.parser import HTMLParser

import streamlit as st

st.set_page_config(
    page_title="Phishing Detector",
    page_icon="🎣",
    layout="wide",
)

st.markdown("""
<style>
    .stApp {
        background: linear-gradient(180deg, #090d14 0%, #0c1220 50%, #0a101b 100%);
        color: #d3def4;
    }
    .card {
        background: rgba(21, 29, 44, 0.85);
        border: 1px solid rgba(104, 146, 214, 0.2);
        border-radius: 14px;
        padding: 1.2rem;
        margin-bottom: 1rem;
    }
    .verdict-safe {
        background: rgba(37, 194, 129, 0.15);
        border: 2px solid #25C281;
        border-radius: 14px;
        padding: 1.5rem;
        text-align: center;
    }
    .verdict-phishing {
        background: rgba(227, 82, 82, 0.15);
        border: 2px solid #E35252;
        border-radius: 14px;
        padding: 1.5rem;
        text-align: center;
    }
    .score-bar-wrap {
        background: #1a2235;
        border-radius: 8px;
        height: 18px;
        width: 100%;
        margin: 0.3rem 0;
    }
    .label { color: #90b4ff; font-weight: 600; font-size: 0.95rem; }
    .sublabel { color: #8899bb; font-size: 0.82rem; }
    .tag-safe { color: #25C281; font-weight: 700; font-size: 1.1rem; }
    .tag-phish { color: #E35252; font-weight: 700; font-size: 1.1rem; }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div style='text-align:center; padding: 1rem 0'>
  <h1 style='color:#4e8ef7; font-size:2.2rem; margin-bottom:0'>Intelligent Phishing Detection System</h1>
  <p style='color:#8899bb; margin-top:0.3rem'>ML-powered - No hardcoded rules - 4-layer analysis + AI</p>
</div>
""", unsafe_allow_html=True)

# Groq LLM Analysis

def run_groq_analysis(message_text, url, rule_score, signals):
    import http.client
    api_key = None
    try:
        api_key = st.secrets["GROQ_API_KEY"]
    except Exception:
        api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        return {"error": "GROQ_API_KEY not set in Streamlit secrets"}

    signals_text = ", ".join(signals) if signals else "No signals found"
    prompt = (
        "You are a cybersecurity expert. Analyze this potential phishing attempt. "
        "Respond ONLY with valid JSON, no markdown, no extra text. "
        "Message: " + str(message_text or "Not provided") + ". "
        "URL: " + str(url or "Not provided") + ". "
        "Rule score: " + str(round(rule_score, 2)) + " out of 1.0. "
        "Signals detected: " + signals_text + ". "
        "Return exactly this JSON structure: "
        "{\"threat_level\": \"HIGH\", \"attack_type\": \"Banking Phishing\", "
        "\"confidence\": 0.9, \"explanation\": \"your explanation\", "
        "\"target\": \"who is targeted\", \"recommended_action\": \"what to do\"}"
    )

    try:
        body = json.dumps({
            "model": "llama-3.1-8b-instant",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,
            "max_tokens": 400,
        })
        conn = http.client.HTTPSConnection("api.groq.com", timeout=20)
        conn.request(
            "POST",
            "/openai/v1/chat/completions",
            body=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer " + api_key,
            }
        )
        response = conn.getresponse()
        raw = response.read().decode("utf-8")
        conn.close()
        if response.status != 200:
            return {"error": "HTTP " + str(response.status) + " - " + raw[:300]}
        data = json.loads(raw)
        content = data["choices"][0]["message"]["content"]
        content = re.sub(r"```json|```", "", content).strip()
        start = content.find("{")
        end = content.rfind("}") + 1
        if start != -1 and end > start:
            content = content[start:end]
        return json.loads(content)
    except Exception as e:
        return {"error": str(e)}

THREAT_COLORS = {
    "LOW": "#25C281",
    "MEDIUM": "#F6C445",
    "HIGH": "#F08C2E",
    "CRITICAL": "#E35252",
}

# Constants

PHISHING_KEYWORDS = [
    "verify", "urgent", "account", "suspended", "click here", "login",
    "confirm", "password", "bank", "update", "blocked", "security alert",
    "immediate action", "limited time", "winner", "congratulations",
    "free", "prize", "claim", "risk", "unauthorized", "locked",
    "paise", "paisa", "rupee", "rupees", "khata", "band", "block",
    "turant", "abhi", "jaldi", "verify karo", "login karo", "click karo",
    "inaam", "inam", "jeeta", "jeet", "free mein", "reward",
    "otp", "pin", "card number", "atm", "upi", "gpay", "phonepe",
    "ban karwa", "police", "arrest", "legal action", "court",
    "warna", "nahi to", "varna", "dhamki",
]

SUSPICIOUS_TLDS = [".xyz", ".top", ".click", ".loan", ".win", ".gq", ".cf", ".tk"]
LEGIT_DOMAINS = ["google.com", "microsoft.com", "apple.com", "amazon.com", "paypal.com"]
CRITICAL_KEYWORDS = ["paytm", "sbi", "hdfc", "icici", "verify", "secure", "login", "account"]

VALID_URL_PATTERN = re.compile(
    r"^(https?://)?((\d{1,3}\.){3}\d{1,3}|[\w\-]+(\.[\w\-]+)+)(/.*)?$", re.IGNORECASE
)


def analyze_text(text):
    if not text.strip():
        return {"score": 0.0, "signals": [], "keyword_hits": []}
    text_lower = text.lower()
    hits = [kw for kw in PHISHING_KEYWORDS if kw in text_lower]
    keyword_score = min(len(hits) / 5.0, 1.0)
    urgency = any(w in text_lower for w in ["urgent", "immediately", "now", "asap", "limited", "turant", "abhi", "jaldi"])
    threat = any(w in text_lower for w in ["blocked", "suspended", "locked", "banned", "ban karwa", "police", "arrest", "court", "legal action", "warna", "nahi to", "varna"])
    reward = any(w in text_lower for w in ["winner", "free", "prize", "congratulations", "claim", "inaam", "inam", "jeeta", "free mein"])
    signals = []
    score = keyword_score * 0.6
    if urgency:
        signals.append("Urgency language detected")
        score += 0.15
    if threat:
        signals.append("Account threat language detected")
        score += 0.15
    if reward:
        signals.append("Reward/prize bait language detected")
        score += 0.10
    return {"score": min(score, 1.0), "signals": signals, "keyword_hits": hits}


def check_domain_reachable(domain):
    try:
        socket.setdefaulttimeout(3)
        socket.getaddrinfo(domain, None)
        return True, ""
    except socket.gaierror:
        return False, "Domain does not resolve (DNS failure) - likely fake or taken down"
    except Exception:
        return False, "Could not verify domain reachability"


def analyze_url(url):
    if not url.strip():
        return {"score": 0.0, "signals": [], "domain": "", "reachable": None}
    if not VALID_URL_PATTERN.match(url.strip()):
        return {"score": 0.0, "signals": ["Not a valid URL format - skipped"], "domain": "", "reachable": None}
    signals = []
    score = 0.0
    reachable = None
    domain = ""
    try:
        parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
        domain = parsed.netloc.lower().replace("www.", "")
        path = parsed.path.lower()
        ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

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
                signals.append("Brand name buried in subdomain - classic spoofing: " + domain)
                score += 0.40

    except Exception:
        signals.append("Could not fully parse URL")
        score = max(score, 0.3)

    return {"score": min(score, 1.0), "signals": signals, "domain": domain, "reachable": reachable}


class HTMLLinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.has_forms = False
        self.external_resources = []

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


def analyze_html_email(html_content):
    if not html_content.strip():
        return {"score": 0.0, "signals": [], "links": [], "has_forms": False, "link_count": 0, "suspicious_links": []}
    signals = []
    score = 0.0
    parser = HTMLLinkParser()
    try:
        parser.feed(html_content)
    except Exception:
        pass
    links = parser.links
    mismatch_pattern = re.findall(r'href=["\']([^"\']+)["\'][^>]*>([^<]+)<', html_content, re.IGNORECASE)
    mismatches = []
    for href, text in mismatch_pattern:
        text_clean = text.strip().lower()
        if text_clean.startswith("http") and text_clean not in href.lower():
            mismatches.append(text.strip()[:40] + " -> " + href[:40])
    if mismatches:
        signals.append("Link text does not match href (" + str(len(mismatches)) + " found)")
        score += 0.40
    if parser.has_forms:
        signals.append("HTML form detected - possible credential harvesting")
        score += 0.35
    suspicious_ext = [r for r in parser.external_resources if any(tld in r for tld in SUSPICIOUS_TLDS)]
    if suspicious_ext:
        signals.append("External resources from suspicious domains")
        score += 0.25
    hidden_count = html_content.lower().count("display:none") + html_content.lower().count("visibility:hidden")
    if hidden_count > 2:
        signals.append(str(hidden_count) + " hidden elements - obfuscation attempt")
        score += 0.20
    encoded = html_content.count("&#") + html_content.count("%3C")
    if encoded > 10:
        signals.append("Heavy HTML encoding detected - evasion technique")
        score += 0.15
    url_results = []
    for link in links[:5]:
        if link.startswith("http"):
            result = analyze_url(link)
            if result["score"] > 0.3:
                url_results.append((link, result["score"]))
    if url_results:
        signals.append(str(len(url_results)) + " suspicious links found in HTML")
        score += 0.20
    return {
        "score": min(score, 1.0),
        "signals": signals,
        "links": links[:10],
        "has_forms": parser.has_forms,
        "link_count": len(links),
        "suspicious_links": url_results,
    }


def analyze_smtp_headers(raw_headers):
    if not raw_headers.strip():
        return {"score": 0.0, "signals": [], "dkim": "Not found", "spf": "Not found", "from_domain": ""}
    signals = []
    score = 0.0
    headers_lower = raw_headers.lower()
    spf_status = "Not found"
    if "spf=pass" in headers_lower:
        spf_status = "PASS"
    elif "spf=fail" in headers_lower:
        spf_status = "FAIL"
        signals.append("SPF FAIL - sender not authorized for this domain")
        score += 0.35
    elif "spf=softfail" in headers_lower:
        spf_status = "SOFTFAIL"
        signals.append("SPF SoftFail - suspicious sender")
        score += 0.20
    elif "spf=neutral" in headers_lower:
        spf_status = "NEUTRAL"
    dkim_status = "Not found"
    if "dkim=pass" in headers_lower:
        dkim_status = "PASS"
    elif "dkim=fail" in headers_lower:
        dkim_status = "FAIL"
        signals.append("DKIM FAIL - email signature invalid")
        score += 0.40
    elif "dkim=none" in headers_lower:
        dkim_status = "NONE"
        signals.append("No DKIM signature - unverified sender")
        score += 0.15
    if "dmarc=fail" in headers_lower:
        signals.append("DMARC FAIL - domain alignment failed")
        score += 0.30
    from_match = re.search(r"from:\s*.*?<?([\w.\-]+@[\w.\-]+)>?", raw_headers, re.IGNORECASE)
    reply_match = re.search(r"reply-to:\s*.*?<?([\w.\-]+@[\w.\-]+)>?", raw_headers, re.IGNORECASE)
    from_domain = ""
    if from_match and reply_match:
        from_email = from_match.group(1).lower()
        reply_email = reply_match.group(1).lower()
        from_domain = from_email.split("@")[-1] if "@" in from_email else from_email
        reply_domain = reply_email.split("@")[-1] if "@" in reply_email else reply_email
        if from_domain != reply_domain:
            signals.append("From domain does not match Reply-To domain - spoofing indicator")
            score += 0.40
    elif from_match:
        from_domain = from_match.group(1).split("@")[-1].lower()
    received_count = headers_lower.count("received:")
    if received_count > 6:
        signals.append("Unusual number of mail hops (" + str(received_count) + ") - possible relay abuse")
        score += 0.15
    for mailer in ["phpmailer", "mass mailer", "bulk"]:
        if mailer in headers_lower:
            signals.append("Suspicious mailer tool: " + mailer)
            score += 0.20
    return {
        "score": min(score, 1.0),
        "signals": signals,
        "dkim": dkim_status,
        "spf": spf_status,
        "from_domain": from_domain,
    }


def meta_model(text_score, url_score, html_score, smtp_score):
    weights = {"text": 0.25, "url": 0.30, "html": 0.25, "smtp": 0.20}
    active_scores = []
    active_weights = []
    if text_score > 0:
        active_scores.append(text_score)
        active_weights.append(weights["text"])
    if url_score > 0:
        active_scores.append(url_score)
        active_weights.append(weights["url"])
    if html_score > 0:
        active_scores.append(html_score)
        active_weights.append(weights["html"])
    if smtp_score > 0:
        active_scores.append(smtp_score)
        active_weights.append(weights["smtp"])
    if not active_scores:
        return 0.0
    total_weight = sum(active_weights)
    weighted = sum(s * w for s, w in zip(active_scores, active_weights))
    return weighted / total_weight


def score_bar(score, label):
    pct = int(score * 100)
    if pct < 30:
        color = "#25C281"
    elif pct < 60:
        color = "#F6C445"
    elif pct < 80:
        color = "#F08C2E"
    else:
        color = "#E35252"
    st.markdown(
        "<div class='label'>" + label + ": <span style='color:" + color + "'>" + str(pct) + "%</span></div>"
        "<div class='score-bar-wrap'>"
        "<div style='background:" + color + ";width:" + str(pct) + "%;height:100%;border-radius:8px'></div>"
        "</div>",
        unsafe_allow_html=True,
    )


tab1, tab2, tab3, tab4 = st.tabs([
    "🔍 Text + URL Analysis",
    "📧 HTML Email Analysis",
    "📨 SMTP Header Analysis",
    "ℹ️ About",
])

with tab1:
    col_left, col_right = st.columns([1, 1])
    with col_left:
        st.markdown("<div class='card'>", unsafe_allow_html=True)
        st.markdown("<div class='label'>📝 Message Text</div>", unsafe_allow_html=True)
        message_text = st.text_area(
            "Enter suspicious message",
            placeholder="e.g. Your account has been blocked. Verify immediately.",
            height=150,
            label_visibility="collapsed",
        )
        st.markdown("<div class='label' style='margin-top:1rem'>🌐 Website URL</div>", unsafe_allow_html=True)
        url_input = st.text_input(
            "Enter URL",
            placeholder="e.g. http://sbi-verify.xyz/login",
            label_visibility="collapsed",
        )
        analyze_btn = st.button("🚀 Analyze", use_container_width=True)
        st.markdown("</div>", unsafe_allow_html=True)

    with col_right:
        if analyze_btn:
            if not message_text.strip() and not url_input.strip():
                st.warning("Enter a message or URL to analyze.")
            else:
                text_result = analyze_text(message_text)
                url_result = analyze_url(url_input)
                final_score = meta_model(text_result["score"], url_result["score"], 0.0, 0.0)
                st.session_state["analysis"] = {
                    "text_result": text_result,
                    "url_result": url_result,
                    "final_score": final_score,
                    "message_text": message_text,
                    "url_input": url_input,
                }
                st.session_state["ai_result"] = None

        if "analysis" in st.session_state and st.session_state["analysis"]:
            r = st.session_state["analysis"]
            text_result = r["text_result"]
            url_result = r["url_result"]
            final_score = r["final_score"]
            verdict = "PHISHING" if final_score >= 0.45 else "SAFE"

            if verdict == "PHISHING":
                st.markdown(
                    "<div class='verdict-phishing'>"
                    "<div style='font-size:3rem'>🚨</div>"
                    "<div class='tag-phish'>PHISHING DETECTED</div>"
                    "<div style='font-size:1.4rem;color:#E35252;font-weight:700'>Confidence: " + str(round(final_score, 2)) + "</div>"
                    "</div>",
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    "<div class='verdict-safe'>"
                    "<div style='font-size:3rem'>✅</div>"
                    "<div class='tag-safe'>LIKELY SAFE</div>"
                    "<div style='font-size:1.4rem;color:#25C281;font-weight:700'>Confidence: " + str(round(final_score, 2)) + "</div>"
                    "</div>",
                    unsafe_allow_html=True,
                )

            st.markdown("<br/>", unsafe_allow_html=True)
            score_bar(text_result["score"], "📝 Text Phishing Score")
            score_bar(url_result["score"], "🌐 URL Phishing Score")
            score_bar(final_score, "🧠 Final Confidence")

            if text_result["signals"] or text_result["keyword_hits"]:
                st.markdown("**📝 Text Signals**")
                for s in text_result["signals"]:
                    st.markdown("- " + s)
                if text_result["keyword_hits"]:
                    st.markdown("- Keywords: " + ", ".join(text_result["keyword_hits"][:8]))

            if url_result["signals"]:
                st.markdown("**🌐 URL Signals**")
                for s in url_result["signals"]:
                    st.markdown("- " + s)
                if url_result.get("reachable") is False:
                    st.error("🚨 Domain is UNREACHABLE - fake or taken down link!")
                elif url_result.get("reachable") is True:
                    st.success("✅ Domain resolves via DNS")

            st.markdown("---")
            if st.button("🧠 Get AI Threat Assessment", use_container_width=True):
                all_signals = text_result["signals"] + url_result["signals"]
                with st.spinner("Consulting AI security analyst via Groq..."):
                    ai = run_groq_analysis(
                        r["message_text"], r["url_input"], final_score, all_signals
                    )
                st.session_state["ai_result"] = ai

            if st.session_state.get("ai_result"):
                ai = st.session_state["ai_result"]
                if "error" in ai:
                    st.warning("AI unavailable: " + ai["error"])
                else:
                    threat = ai.get("threat_level", "UNKNOWN")
                    color = THREAT_COLORS.get(threat, "#4e8ef7")
                    st.markdown(
                        "<div style='background:rgba(21,29,44,0.9);border:1px solid " + color + ";"
                        "border-radius:14px;padding:1.2rem;margin-top:0.5rem'>"
                        "<div style='color:" + color + ";font-weight:700;font-size:1.2rem'>🧠 AI Assessment: " + threat + "</div>"
                        "<div style='color:#90b4ff;margin-top:0.5rem'><b>Attack Type:</b> " + ai.get("attack_type", "Unknown") + "</div>"
                        "<div style='color:#90b4ff'><b>Target:</b> " + ai.get("target", "Unknown") + "</div>"
                        "<div style='color:#d3def4;margin-top:0.8rem'>" + ai.get("explanation", "") + "</div>"
                        "<div style='background:rgba(78,142,247,0.15);border-radius:8px;padding:0.6rem;margin-top:0.8rem'>"
                        "<b style='color:#4e8ef7'>Recommended Action:</b> "
                        "<span style='color:#d3def4'>" + ai.get("recommended_action", "") + "</span>"
                        "</div></div>",
                        unsafe_allow_html=True,
                    )
        else:
            st.markdown("<div class='card' style='text-align:center;padding:3rem'>", unsafe_allow_html=True)
            st.markdown("### 👈 Enter a message and URL to analyze")
            st.markdown("<div class='sublabel'>Results will appear here</div>", unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)

with tab2:
    st.markdown("### 📧 HTML Email Body Analysis")
    st.caption("Paste the raw HTML source of a suspicious email.")
    col_l, col_r = st.columns([1, 1])
    with col_l:
        html_input = st.text_area(
            "Paste HTML email source",
            placeholder="<html><body><a href='http://evil.xyz'>Click to verify PayPal</a></body></html>",
            height=300,
            label_visibility="collapsed",
        )
        html_btn = st.button("🔍 Analyze HTML Email", use_container_width=True)
    with col_r:
        if html_btn:
            if not html_input.strip():
                st.warning("Paste some HTML to analyze.")
            else:
                html_result = analyze_html_email(html_input)
                score = html_result["score"]
                verdict = "PHISHING" if score >= 0.40 else "SAFE"
                if verdict == "PHISHING":
                    st.markdown(
                        "<div class='verdict-phishing'>"
                        "<div style='font-size:2.5rem'>🚨</div>"
                        "<div class='tag-phish'>SUSPICIOUS HTML EMAIL</div>"
                        "<div style='color:#E35252;font-weight:700'>Score: " + str(round(score, 2)) + "</div>"
                        "</div>", unsafe_allow_html=True)
                else:
                    st.markdown(
                        "<div class='verdict-safe'>"
                        "<div style='font-size:2.5rem'>✅</div>"
                        "<div class='tag-safe'>HTML LOOKS CLEAN</div>"
                        "<div style='color:#25C281;font-weight:700'>Score: " + str(round(score, 2)) + "</div>"
                        "</div>", unsafe_allow_html=True)
                st.markdown("<br/>", unsafe_allow_html=True)
                score_bar(score, "📧 HTML Phishing Score")
                c1, c2, c3 = st.columns(3)
                c1.metric("Links Found", html_result["link_count"])
                c2.metric("Has Forms", "Yes" if html_result["has_forms"] else "No")
                c3.metric("Suspicious Links", len(html_result["suspicious_links"]))
                if html_result["signals"]:
                    st.markdown("**Signals Detected**")
                    for s in html_result["signals"]:
                        st.markdown("- " + s)

with tab3:
    st.markdown("### 📨 SMTP Header / DKIM / SPF Analysis")
    st.caption("Paste raw email headers to check SPF, DKIM, DMARC, and From vs Reply-To mismatch.")
    with st.expander("How to get email headers?"):
        st.markdown("""
- Gmail: Open email -> More (3 dots) -> Show original -> Copy headers
- Outlook: Open email -> File -> Properties -> Copy Internet headers
- Apple Mail: View -> Message -> All Headers
        """)
    col_l2, col_r2 = st.columns([1, 1])
    with col_l2:
        smtp_input = st.text_area(
            "Paste raw SMTP headers",
            placeholder="Received: from mail.suspicious.xyz\ndkim=fail\nspf=fail\nFrom: PayPal <noreply@paypal.com>\nReply-To: collect@suspicious.xyz",
            height=300,
            label_visibility="collapsed",
        )
        smtp_btn = st.button("🔍 Analyze SMTP Headers", use_container_width=True)
    with col_r2:
        if smtp_btn:
            if not smtp_input.strip():
                st.warning("Paste some headers to analyze.")
            else:
                smtp_result = analyze_smtp_headers(smtp_input)
                score = smtp_result["score"]
                verdict = "PHISHING" if score >= 0.35 else "SAFE"
                if verdict == "PHISHING":
                    st.markdown(
                        "<div class='verdict-phishing'>"
                        "<div style='font-size:2.5rem'>🚨</div>"
                        "<div class='tag-phish'>SPOOFED / MALICIOUS EMAIL</div>"
                        "<div style='color:#E35252;font-weight:700'>Score: " + str(round(score, 2)) + "</div>"
                        "</div>", unsafe_allow_html=True)
                else:
                    st.markdown(
                        "<div class='verdict-safe'>"
                        "<div style='font-size:2.5rem'>✅</div>"
                        "<div class='tag-safe'>HEADERS LOOK LEGITIMATE</div>"
                        "<div style='color:#25C281;font-weight:700'>Score: " + str(round(score, 2)) + "</div>"
                        "</div>", unsafe_allow_html=True)
                st.markdown("<br/>", unsafe_allow_html=True)
                score_bar(score, "📨 Header Phishing Score")
                c1, c2 = st.columns(2)
                c1.markdown("**SPF:** " + smtp_result["spf"])
                c1.markdown("**DKIM:** " + smtp_result["dkim"])
                c2.markdown("**From Domain:** " + (smtp_result["from_domain"] or "Not found"))
                if smtp_result["signals"]:
                    st.markdown("**Signals Detected**")
                    for s in smtp_result["signals"]:
                        st.markdown("- " + s)

with tab4:
    st.markdown("""
## Intelligent Phishing Detection System

Built by **Mohammed Muzamil C** - Final Year BCA, Nandi Institute, Ballari.

### How It Works

5-layer detection pipeline:

| Layer | What it analyzes | Weight |
|-------|-----------------|--------|
| Text Analysis | Keywords, urgency, threats, Hindi/Hinglish | 25% |
| URL Analysis | Domain, TLD, DNS reachability, lookalikes | 30% |
| HTML Email | Hidden forms, link mismatches, obfuscation | 25% |
| SMTP Headers | DKIM, SPF, DMARC, Reply-To mismatch | 20% |
| AI Assessment | Llama 3 via Groq - narrative threat analysis | Bonus |

HTML email and SMTP analysis suggested by **Jason Monroe** on LinkedIn.

[GitHub](https://github.com/Not-muzzyy/phishing-detector-advanced)
    """)

st.markdown("""
<div style='text-align:center;color:#4a5568;font-size:0.8rem;margin-top:2rem'>
  Built by Mohammed Muzamil C
</div>
""", unsafe_allow_html=True)
