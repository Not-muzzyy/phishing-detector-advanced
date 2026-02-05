import joblib
import pandas as pd
from urllib.parse import urlparse

# ---------- Load all models ----------
text_model = joblib.load("models/text_model.pkl")
vectorizer = joblib.load("models/text_vectorizer.pkl")
website_model = joblib.load("models/website_model.pkl")
meta_model = joblib.load("models/meta_model.pkl")


# ---------- URL feature extractor ----------
def extract_url_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc

    return pd.DataFrame([{
        "url_length": len(url),
        "domain_length": len(domain),
        "hyphen_count": domain.count("-"),
        "dot_count": domain.count("."),
        "subdomain_count": domain.count(".") - 1,
        "digit_count": sum(c.isdigit() for c in domain),
    }])


# ---------- Final prediction function ----------
def predict_phishing(text, url):
    # Text score
    text_vec = vectorizer.transform([text])
    text_score = text_model.predict_proba(text_vec)[0][1]

    # Website score
    url_features = extract_url_features(url)
    website_score = website_model.predict_proba(url_features)[0][1]

    # Meta decision
    final_input = pd.DataFrame([{
        "text_score": text_score,
        "website_score": website_score
    }])

    final_pred = meta_model.predict(final_input)[0]
    final_prob = meta_model.predict_proba(final_input)[0][1]

    return text_score, website_score, final_pred, final_prob


# ---------- CLI Demo ----------
if __name__ == "__main__":
    print("=== Intelligent Phishing Detection System ===\n")

    text = input("Enter message text:\n")
    url = input("\nEnter website URL:\n")

    text_score, website_score, verdict, confidence = predict_phishing(text, url)

    print("\n--- Analysis Result ---")
    print(f"Text Phishing Score     : {text_score:.2f}")
    print(f"Website Phishing Score  : {website_score:.2f}")
    print(f"Final Confidence        : {confidence:.2f}")

    if verdict == 1:
        print("Verdict                : 🚨 PHISHING")
    else:
        print("Verdict                : ✅ SAFE")
