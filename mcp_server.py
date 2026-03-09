# MCP Server for Intelligent Phishing Detection System
# Built by Mohammed Muzamil C
# Allows AI agents like Tines to call phishing detection as a tool

from __future__ import annotations

import http.client
import json
import os
import re
import socket
import urllib.parse
from html.parser import HTMLParser

# ── MCP SDK ───────────────────────────────────────────────────────────────────

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent
import asyncio

# ── App ───────────────────────────────────────────────────────────────────────

app = Server("phishing-detector")

# ── Constants ─────────────────────────────────────────────────────────────────

PHISHING_KEYWORDS = [
    "verify", "urgent", "account", "suspended", "click here", "login",
    "confirm", "password", "bank", "update", "blocked", "security alert",
    "immediate action", "limited time", "winner", "congratulations",
    "free", "prize", "claim", "risk", "unauthorized", "locked",
    "paise", "paisa", "rupee", "rupees", "khata", "band", "block",
    "turant", "abhi", "jaldi", "verify karo", "login karo",
    "inaam", "inam", "jeeta", "jeet", "free mein", "reward",
    "otp", "pin", "card number", "atm", "upi", "gpay", "phonepe",
    "ban karwa", "police", "arrest", "legal action", "court",
    "warna", "nahi to", "varna", "dhamki",
]

SUSPICIOUS_TLDS = [".xyz", ".top", ".click", ".loan", ".win", ".gq", ".cf", ".tk"]
LEGIT_DOMAINS = ["google.com", "microsoft.com", "apple.com", "amazon.com", "paypal.com"]
CRITICAL_KEYWORDS = ["paytm", "sbi", "hdfc", "icici", "verify", "secure", "login", "account"]

VALID_URL_PATTERN = re.compile(
    r"^(https?://)?((\d{1,3}\.){3}\d{1,3}|[\w\-]+(\.[\w\-]+)+)(/.*)?$",
    re.IGNORECASE,
)

# ── Detection Functions ───────────────────────────────────────────────────────

def analyze_text(text):
    if not text.strip():
        return {"score": 0.0, "signals": [], "keyword_hits": []}
    text_lower = text.lower()
    hits = [kw for kw in PHISHING_KEYWORDS if kw in text_lower]
    keyword_score = min(len(hits) / 5.0, 1.0)
    urgency = any(w in text_lower for w in [
        "urgent", "immediately", "now", "asap", "limited", "turant", "abhi", "jaldi",
    ])
    threat = any(w in text_lower for w in [
        "blocked", "suspended", "locked", "banned", "ban karwa",
        "police", "arrest", "court", "legal action", "warna", "nahi to", "varna",
    ])
    reward = any(w in text_lower for w in [
        "winner", "free", "prize", "congratulations", "claim",
        "inaam", "inam", "jeeta", "free mein",
    ])
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
        return False, "Domain does not resolve - likely fake or taken down"
    except Exception:
        return False, "Could not verify domain reachability"


def analyze_url(url):
    if not url.strip():
        return {"score": 0.0, "signals": [], "domain": "", "reachable": None}
    if not VALID_URL_PATTERN.match(url.strip()):
        return {"score": 0.0, "signals": ["Not a valid URL format"], "domain": "", "reachable": None}
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
                signals.append("Suspicious TLD: " + tld)
                score += 0.30
        if ip_pattern.match(domain):
            signals.append("IP address used instead of domain")
            score += 0.40
        for legit in LEGIT_DOMAINS:
            base = legit.split(".")[0]
            if base in domain and legit not in domain:
                signals.append("Lookalike domain impersonating " + legit)
                score += 0.35
        if domain.count("-") >= 2:
            signals.append("Multiple hyphens in domain")
            score += 0.15
        kw_hits = [kw for kw in CRITICAL_KEYWORDS if kw in domain + path]
        if kw_hits:
            signals.append("Sensitive keywords in URL: " + ", ".join(kw_hits))
            score += 0.20
        if parsed.scheme == "http":
            signals.append("No HTTPS")
            score += 0.10
        if domain and not ip_pattern.match(domain):
            reachable, dns_msg = check_domain_reachable(domain)
            if not reachable:
                signals.append("Domain UNREACHABLE: " + dns_msg)
                score += 0.35
        subdomain_parts = domain.split(".")
        if len(subdomain_parts) >= 3:
            impersonation = [
                l for l in LEGIT_DOMAINS
                if l.split(".")[0] in ".".join(subdomain_parts[:-2])
            ]
            if impersonation:
                signals.append("Brand in subdomain - spoofing: " + domain)
                score += 0.40
    except Exception:
        signals.append("Could not parse URL")
        score = max(score, 0.3)
    return {"score": min(score, 1.0), "signals": signals, "domain": domain, "reachable": reachable}


def analyze_smtp_headers(raw_headers):
    if not raw_headers.strip():
        return {"score": 0.0, "signals": [], "dkim": "Not found", "spf": "Not found", "from_domain": ""}
    signals = []
    score = 0.0
    h = raw_headers.lower()
    spf = "Not found"
    if "spf=pass" in h:
        spf = "PASS"
    elif "spf=fail" in h:
        spf = "FAIL"
        signals.append("SPF FAIL")
        score += 0.35
    elif "spf=softfail" in h:
        spf = "SOFTFAIL"
        signals.append("SPF SoftFail")
        score += 0.20
    dkim = "Not found"
    if "dkim=pass" in h:
        dkim = "PASS"
    elif "dkim=fail" in h:
        dkim = "FAIL"
        signals.append("DKIM FAIL")
        score += 0.40
    elif "dkim=none" in h:
        dkim = "NONE"
        signals.append("No DKIM signature")
        score += 0.15
    if "dmarc=fail" in h:
        signals.append("DMARC FAIL")
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
            signals.append("From/Reply-To domain mismatch - spoofing")
            score += 0.40
    elif from_match:
        from_domain = from_match.group(1).split("@")[-1].lower()
    if h.count("received:") > 6:
        signals.append("Unusual mail hops")
        score += 0.15
    for mailer in ["phpmailer", "mass mailer", "bulk"]:
        if mailer in h:
            signals.append("Suspicious mailer: " + mailer)
            score += 0.20
    return {
        "score": min(score, 1.0),
        "signals": signals,
        "dkim": dkim,
        "spf": spf,
        "from_domain": from_domain,
    }


def meta_model(text_score, url_score, html_score=0.0, smtp_score=0.0):
    weights = {"text": 0.25, "url": 0.30, "html": 0.25, "smtp": 0.20}
    active_scores, active_weights = [], []
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
    return sum(s * w for s, w in zip(active_scores, active_weights)) / sum(active_weights)


# ── MCP Tool Definitions ──────────────────────────────────────────────────────

@app.list_tools()
async def list_tools():
    return [
        Tool(
            name="analyze_phishing",
            description=(
                "Analyze a message and/or URL for phishing indicators. "
                "Supports English, Hindi and Hinglish. "
                "Returns verdict (PHISHING/SAFE), confidence score, and detailed signals."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "description": "The suspicious message text to analyze",
                    },
                    "url": {
                        "type": "string",
                        "description": "The suspicious URL to analyze",
                    },
                },
                "anyOf": [
                    {"required": ["message"]},
                    {"required": ["url"]},
                ],
            },
        ),
        Tool(
            name="analyze_smtp_headers",
            description=(
                "Analyze raw SMTP email headers for spoofing indicators. "
                "Checks DKIM, SPF, DMARC and From/Reply-To mismatch."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "headers": {
                        "type": "string",
                        "description": "Raw SMTP headers from the suspicious email",
                    },
                },
                "required": ["headers"],
            },
        ),
        Tool(
            name="check_url",
            description=(
                "Check a single URL for phishing signals. "
                "Performs live DNS reachability check, TLD reputation, "
                "lookalike domain detection and subdomain spoofing analysis."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "The URL to check",
                    },
                },
                "required": ["url"],
            },
        ),
    ]


# ── MCP Tool Handlers ─────────────────────────────────────────────────────────

@app.call_tool()
async def call_tool(name: str, arguments: dict):

    if name == "analyze_phishing":
        message = arguments.get("message", "")
        url = arguments.get("url", "")

        text_result = analyze_text(message)
        url_result = analyze_url(url)
        final_score = meta_model(text_result["score"], url_result["score"])
        verdict = "PHISHING" if final_score >= 0.45 else "SAFE"
        all_signals = text_result["signals"] + url_result["signals"]

        result = {
            "verdict": verdict,
            "confidence": round(final_score, 4),
            "text_score": round(text_result["score"], 4),
            "url_score": round(url_result["score"], 4),
            "signals": all_signals,
            "keyword_hits": text_result["keyword_hits"],
            "domain": url_result.get("domain", ""),
            "domain_reachable": url_result.get("reachable"),
        }

        return [TextContent(type="text", text=json.dumps(result, indent=2))]

    elif name == "analyze_smtp_headers":
        headers = arguments.get("headers", "")
        result = analyze_smtp_headers(headers)
        verdict = "SPOOFED" if result["score"] >= 0.35 else "LEGITIMATE"
        return [TextContent(type="text", text=json.dumps({
            "verdict": verdict,
            "score": round(result["score"], 4),
            "spf": result["spf"],
            "dkim": result["dkim"],
            "from_domain": result["from_domain"],
            "signals": result["signals"],
        }, indent=2))]

    elif name == "check_url":
        url = arguments.get("url", "")
        result = analyze_url(url)
        verdict = "PHISHING" if result["score"] >= 0.45 else "SAFE"
        return [TextContent(type="text", text=json.dumps({
            "verdict": verdict,
            "score": round(result["score"], 4),
            "domain": result["domain"],
            "reachable": result["reachable"],
            "signals": result["signals"],
        }, indent=2))]

    else:
        return [TextContent(type="text", text=json.dumps({"error": "Unknown tool: " + name}))]


# ── Entry Point ───────────────────────────────────────────────────────────────

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
