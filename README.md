<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=28&duration=3000&pause=1000&color=E35252&center=true&vCenter=true&width=700&lines=🎣+Intelligent+Phishing+Detection;No+hardcoded+rules.+Pure+ML+%2B+AI.;English+%2B+Hindi+%2B+Hinglish+support." alt="Typing SVG" />

<br/>

[![Live Demo](https://img.shields.io/badge/🚀_LIVE_DEMO-Try_It_Now-E35252?style=for-the-badge)](https://phishing-detector-advanced-xjjp5jahskwob5pwjbjxq6.streamlit.app/)
[![GitHub](https://img.shields.io/badge/GitHub-Not--muzzyy-181717?style=for-the-badge&logo=github)](https://github.com/Not-muzzyy/phishing-detector-advanced)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Muzzammil_C-0A66C2?style=for-the-badge&logo=linkedin)](https://www.linkedin.com/in/muzzammil-c-63b803290/)

</div>

-----

## 🧠 What Is This?

A **5-layer phishing detection system** that catches attacks in English, Hindi, and Hinglish — no hardcoded rules, everything is signal-based. Built for the Indian threat landscape where most detectors fail.

**The problem:** Phishing detectors are English-only. Scammers in India don’t care.

```
"Mere paise wapas karo warna police bulaunga"     ← caught ✅
"Aapka SBI OTP hai. Abhi UPI se payment karo"    ← caught ✅
"Your HDFC account is blocked. Verify now."       ← caught ✅
"http://paypal.com.verify-account.tk/secure"      ← caught ✅
```

-----

## 🔬 Detection Pipeline

|Layer              |What It Analyzes                                                 |Weight|
|-------------------|-----------------------------------------------------------------|------|
|📝 **Text Analysis**|Keywords, urgency, threats — English + Hindi + Hinglish          |25%   |
|🌐 **URL Analysis** |TLD reputation, DNS reachability, lookalike domains, IP detection|30%   |
|📧 **HTML Email**   |Hidden forms, link mismatches, obfuscation, external resources   |25%   |
|📨 **SMTP Headers** |DKIM, SPF, DMARC validation, From vs Reply-To mismatch           |20%   |
|🧠 **AI Assessment**|Llama 3 via Groq — explains WHY it’s phishing in plain English   |Bonus |

-----

## ✨ Key Features

- **🇮🇳 Hindi + Hinglish Support** — detects OTP scams, UPI fraud, legal threats in local language
- **🌐 Live DNS Check** — unreachable domains flagged as suspicious (dead fake sites caught instantly)
- **🎭 Lookalike Detection** — catches `paypal.com.steal.xyz` style subdomain spoofing
- **📧 HTML Email Parser** — finds credential harvesting forms, hidden elements, mismatched links
- **🔐 SMTP Validation** — DKIM/SPF/DMARC header analysis like a real mail security system
- **🧠 AI Threat Report** — Llama 3 generates attack type, target, explanation and recommended action
- **⚡ Real-time** — all analysis runs instantly in browser via Streamlit

-----

## 🚀 Live Demo

👉 **[Try it here](https://phishing-detector-advanced-xjjp5jahskwob5pwjbjxq6.streamlit.app/)**

### Test Cases to Try

**Tab 1 — Paste this message + URL:**

```
Message: Your SBI account has been blocked. Verify immediately or it will be permanently suspended.
URL: http://sbi-secure-verify.xyz/login
```

**Tab 3 — Paste these SMTP headers:**

```
dkim=fail header.i=@paypal.com
spf=fail
From: PayPal Security <noreply@paypal.com>
Reply-To: harvest@evil-collector.xyz
```

-----

## 🛠️ Tech Stack

![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?style=flat-square&logo=streamlit&logoColor=white)
![Groq](https://img.shields.io/badge/Groq-LLaMA_3-orange?style=flat-square)
![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-F7931E?style=flat-square&logo=scikit-learn&logoColor=white)

- **Backend:** Python — `re`, `socket`, `http.client`, `html.parser`
- **Frontend:** Streamlit with custom dark CSS
- **AI Layer:** Llama 3.1 via Groq API (free tier)
- **No external ML dependencies** for core analysis — pure Python signal detection

-----

## 📁 Project Structure

```
phishing-detector-advanced/
├── phishing_dashboard.py      ← Main Streamlit app (all 5 layers)
├── final_predict.py           ← Original CLI prediction script
├── requirements.txt           ← Dependencies
├── data/                      ← Training datasets
├── models/                    ← Trained ML models
├── text_analysis/             ← Text model training
├── website_analysis/          ← URL feature analysis
└── meta_analysis/             ← Meta-model decision layer
```

-----

## ⚙️ Run Locally

```bash
git clone https://github.com/Not-muzzyy/phishing-detector-advanced
cd phishing-detector-advanced
pip install -r requirements.txt
streamlit run phishing_dashboard.py
```

Add your Groq API key (free at [console.groq.com](https://console.groq.com)):

```bash
# Create .streamlit/secrets.toml
GROQ_API_KEY = "your_key_here"
```

-----

## 📊 Model Performance

|Metric   |Score   |
|---------|--------|
|Accuracy |**0.97**|
|Precision|**0.96**|
|Recall   |**0.97**|
|F1 Score |**0.97**|

-----

## 💡 Roadmap

- [ ] WhatsApp message analysis
- [ ] Browser extension version
- [ ] Real email integration (IMAP)
- [ ] Regional language expansion (Tamil, Telugu, Kannada)
- [ ] API endpoint for third-party integration

-----

-----

<div align="center">

**Built by Mohammed Muzamil C**
Final Year BCA · Nandi Institute of Management & Science · Ballari, Karnataka 🇮🇳

*“Runs on the internet.”* 🌐

[![LinkedIn](https://img.shields.io/badge/Connect-LinkedIn-0A66C2?style=for-the-badge&logo=linkedin)](https://www.linkedin.com/in/muzzammilc7/)
[![GitHub](https://img.shields.io/badge/Follow-GitHub-181717?style=for-the-badge&logo=github)](https://github.com/Not-muzzyy)

</div>
