# 🛡️ Intelligent Phishing Detection System

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/Machine%20Learning-Scikit--Learn-orange?style=for-the-badge&logo=scikit-learn&logoColor=white"/>
  <img src="https://img.shields.io/badge/Domain-Cybersecurity-red?style=for-the-badge&logo=shield&logoColor=white"/>
  <img src="https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge"/>
</p>

<p align="center">
  A cybersecurity project that detects phishing attacks using machine learning — no hardcoded rules, fully data-driven.
</p>

-----

## 🔍 What is This?

Phishing is one of the most common cyberattacks today. This system uses **Machine Learning** to intelligently detect whether a message or website URL is a phishing attempt — with high confidence scores.

> ✅ **Final Confidence Score achieved: 0.97** on test samples

-----

## ⚙️ How It Works

The system uses a **3-layer detection pipeline:**

```
User Input (Text + URL)
        │
        ├──► 📝 Text Analysis Model     → Text Phishing Score
        │
        ├──► 🌐 Website Analysis Model  → Website Phishing Score
        │
        └──► 🤖 Meta Model              → Final Confidence + Verdict
```

Each layer is independently trained and combined by a **meta-model** that makes the final PHISHING / SAFE decision.

-----

## 🚀 Features

- 🔎 **Text-based phishing detection** — analyzes message content
- 🌐 **Website URL feature analysis** — checks URL patterns & characteristics
- 🧠 **Meta-model decision system** — combines both scores intelligently
- 📊 **Confidence scoring** — shows how confident the model is
- ⚡ **No hardcoded rules** — purely data-driven ML approach

-----

## 📸 Sample Output

```
=== Intelligent Phishing Detection System ===

Enter message text: verify karo arna account block
Enter website URL: https://paytmkaro.com

--- Analysis Result ---
Text Phishing Score   : 0.94
Website Phishing Score: 0.01
Final Confidence      : 0.97
Verdict               : 🚨 PHISHING
```

```
=== Intelligent Phishing Detection System ===

Enter message text: thanks for the recent purchase you made check your invoice here
Enter website URL: https://applepurchases.com

--- Analysis Result ---
Text Phishing Score   : 0.15
Website Phishing Score: 0.82
Final Confidence      : 0.11
Verdict               : ✅ SAFE
```

-----

## 🗂️ Project Structure

```
phishing-detector-advanced/
│
├── data/                   → Training & test datasets
├── models/                 → Trained ML model files (.pkl)
├── text_analysis/          → Text model training scripts
├── website_analysis/       → Website/URL model training scripts
├── meta_analysis/          → Meta-model combining both scores
├── final_predict.py        → Unified prediction script (run this)
├── requirements.txt        → Project dependencies
└── README.md
```

-----

## 🛠️ Tech Stack

|Technology      |Purpose                   |
|----------------|--------------------------|
|Python 3.8+     |Core language             |
|Scikit-learn    |ML model training         |
|Pandas / NumPy  |Data processing           |
|NLP techniques  |Text feature extraction   |
|URL parsing libs|Website feature extraction|

-----

## 📦 Installation & Usage

```bash
# 1. Clone the repository
git clone https://github.com/Not-muzzyy/phishing-detector-advanced.git
cd phishing-detector-advanced

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the detector
python final_predict.py
```

-----

## 🎯 Results & Performance

|Metric                            |Score                   |
|----------------------------------|------------------------|
|Final Confidence (Phishing sample)|0.97                    |
|Detection Type                    |Binary (PHISHING / SAFE)|
|Approach                          |Ensemble Meta-Model     |

-----

## 👨‍💻 About the Author

**Mohammed Muzamil C**
Final Year BCA Student | Cybersecurity & Machine Learning Enthusiast
Nandi Institute of Management & Science College, Ballari
Vijayanagara Sri Krishnadevaraya University

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=flat&logo=linkedin)](https://linkedin.com/in/muzammilc7)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-black?style=flat&logo=github)](https://github.com/Not-muzzyy)

-----

## 📄 License

This project is open source and available under the [MIT License](LICENSE).

-----

<p align="center">
  ⭐ If you found this useful, please star the repository!
</p>
