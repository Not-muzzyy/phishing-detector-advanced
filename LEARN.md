# Learn

## What this project does

Phishing Detector Advanced is a multi-layer phishing analysis system for English, Hindi, and Hinglish text, URLs, email HTML, and SMTP headers.

It combines:
- machine learning
- heuristic signals
- DNS and URL checks
- email header validation
- AI-generated threat explanations

## Detection layers

### 1. Text analysis

This layer scans message content for phishing intent.

Common signals:
- urgency
- threats
- OTP theft
- UPI scams
- banking impersonation
- reward bait
- fake support claims

Examples:
- "Aapka account block ho gaya hai"
- "OTP share karo"
- "Verify now or your account will be suspended"

### 2. URL analysis

This layer checks whether a link looks deceptive or unsafe.

Common signals:
- lookalike domains
- excessive subdomains
- IP-based URLs
- suspicious TLDs
- DNS failures
- HTTPS misuse
- long or noisy query strings

Example:
- `paypal.com.verify-login.xyz`

### 3. HTML email analysis

This layer inspects raw email HTML for phishing behavior.

Common signals:
- hidden forms
- obfuscated content
- mismatched links
- fake login pages
- external resource abuse

### 4. SMTP header analysis

This layer checks email authenticity using mail-security signals.

Common signals:
- SPF failure
- DKIM failure
- DMARC issues
- Reply-To mismatch
- spoofed sender patterns

### 5. AI threat assessment

This layer uses Llama 3 via Groq to generate a readable security summary.

It helps explain:
- attack type
- likely target
- risk level
- recommended action

## Why Hindi and Hinglish support matters

Many phishing tools miss Indian scam language.

This project looks for patterns such as:
- "OTP bhejo"
- "UPI verify karo"
- "Aapka SBI account block ho gaya"
- "Immediate action required"

## Datasets and training

The project uses phishing and benign samples for training and testing.

Main data areas:
- text analysis datasets
- website and URL features
- meta-analysis signals

## Limitations

No detector is perfect.

False positives often happen with:
- shortened links
- uncommon domains
- aggressive redirects
- tracking URLs

False negatives often happen with:
- new phishing domains
- heavily obfuscated pages
- fast-changing scam kits

## Safe use

This repository is for:
- cybersecurity education
- awareness
- defensive research
- safe testing

Do not use it for:
- phishing campaigns
- credential theft
- evasion work
- abuse or fraud

## Future work

Possible upgrades:
- WhatsApp phishing analysis
- browser extension
- IMAP email integration
- more regional languages
- better reputation scoring
- richer threat explanations
