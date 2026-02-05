import pandas as pd
import joblib
from urllib.parse import urlparse

from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score


# ---------- Feature Extraction ----------
def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc

    features = {
        "url_length": len(url),
        "domain_length": len(domain),
        "hyphen_count": domain.count("-"),
        "dot_count": domain.count("."),
        "subdomain_count": domain.count(".") - 1,
        "digit_count": sum(char.isdigit() for char in domain),
    }
    return features


# ---------- Load Dataset ----------
df = pd.read_csv("data/website_dataset.csv")

X = df["url"].apply(extract_features)
X = pd.DataFrame(X.tolist())
y = df["label"]

# ---------- Train-Test Split ----------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# ---------- Train Model ----------
model = LogisticRegression(max_iter=1000)
model.fit(X_train, y_train)

# ---------- Evaluate ----------
y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]

print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))

# ---------- Save Model ----------
joblib.dump(model, "models/website_model.pkl")

print("Website model trained and saved.")
