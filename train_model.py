
from pathlib import Path
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

ROOT = Path(__file__).resolve().parent
DATASET = ROOT / "Dataset" / "phishing_emails.csv"
MODEL_DIR = ROOT / "Models"
MODEL_DIR.mkdir(exist_ok=True)

df = pd.read_csv(DATASET).fillna("")

df["text"] = (
    df["subject"].astype(str) + " " +
    df["body"].astype(str)
)

df["label"] = df["label"].str.strip().str.lower()

df = df[df["label"].isin(["phishing", "legitimate"])]

if len(df) < 10 or df["label"].nunique() < 2:
    raise ValueError("Need at least 10 labelled emails from both classes.")

model = Pipeline([
    ("tfidf", TfidfVectorizer(ngram_range=(1, 2))),
    ("classifier", LogisticRegression(max_iter=1000))
])

X = df["text"]
y = df["label"]

model.fit(X, y)

joblib.dump(model, MODEL_DIR / "email_model.pkl")

print("Model training completed!")
print("Total emails:", len(df))
print("Classes:", list(y.unique()))
print("Saved at:", MODEL_DIR / "email_model.pkl")
