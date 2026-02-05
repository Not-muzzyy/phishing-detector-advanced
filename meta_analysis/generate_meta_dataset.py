import pandas as pd
import joblib
from urllib.parse import urlparse

# Load trained models
text_model = joblib.load("models/text_model.pkl")
vectorizer = joblib.load("models/text_vectorizer.pkl")
website_model = joblib.load("models/website_model.pkl")

def extract_url_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    return {
        "url_length": len(url),
        "domain_length": len(domain),
        "hyphen_count": domain.count("-"),
        "dot_count": domain.count("."),
        "subdomain_count": domain.count(".") - 1,
        "digit_count": sum(c.isdigit() for c in domain),
    }

text_df = pd.read_csv("data/phishing_texts.csv")
web_df = pd.read_csv("data/website_dataset.csv")

size = min(len(text_df), len(web_df))
text_df = text_df.sample(size, random_state=42).reset_index(drop=True)
web_df = web_df.sample(size, random_state=42).reset_index(drop=True)

meta_data = []

for i in range(size):
    text = text_df.loc[i, "text"]
    label = text_df.loc[i, "label"]
    url = web_df.loc[i, "url"]

    text_vec = vectorizer.transform([text])
    text_score = text_model.predict_proba(text_vec)[0][1]

    url_feat = pd.DataFrame([extract_url_features(url)])
    website_score = website_model.predict_proba(url_feat)[0][1]

    meta_data.append({
        "text_score": text_score,
        "website_score": website_score,
        "label": label
    })

meta_df = pd.DataFrame(meta_data)
meta_df.to_csv("data/meta_dataset.csv", index=False)

print("Meta dataset created successfully.")
