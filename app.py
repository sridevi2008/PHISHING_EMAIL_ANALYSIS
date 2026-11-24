from pathlib import Path
from functools import wraps
import os
import subprocess
import sys

import pandas as pd
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory

ROOT = Path(__file__).resolve().parent
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-demo-secret-key")

# Demo credentials. Set APP_USERNAME and APP_PASSWORD environment variables before deployment.
APP_USERNAME = os.environ.get("APP_USERNAME", "admin")
APP_PASSWORD = os.environ.get("APP_PASSWORD", "Admin@123")

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

def load_dashboard_data():
    report_dir = ROOT / "Reports"
    cleaned_file = report_dir / "cleaned_email_dataset.csv"
    dataset_file = ROOT / "Dataset" / "phishing_emails.csv"
    sample_file = ROOT / "Dataset" / "sample_phishing_emails.csv"

    # Generate the analysis outputs the first time the dashboard is opened.
    if not cleaned_file.exists():
        if not dataset_file.exists() and sample_file.exists():
            # Sample data is used only as a demonstration until the user adds a real dataset.
            import shutil
            shutil.copy2(sample_file, dataset_file)
        if dataset_file.exists():
            subprocess.run([sys.executable, str(ROOT / "main.py")], cwd=ROOT, check=False)

    if cleaned_file.exists():
        df = pd.read_csv(cleaned_file).fillna("")
    elif dataset_file.exists():
        df = pd.read_csv(dataset_file).fillna("")
    elif sample_file.exists():
        df = pd.read_csv(sample_file).fillna("")
    else:
        df = pd.DataFrame()

    label_col = "label" if "label" in df.columns else "label_original"
    if label_col in df.columns:
        labels = df[label_col].astype(str).str.lower()
        phishing = int(labels.str.contains("phish|spam|fraud|malicious|^1$", regex=True).sum())
        legitimate = int(labels.str.contains("legit|ham|safe|benign|^0$", regex=True).sum())
    else:
        phishing, legitimate = 0, 0

    total = len(df)
    url_count = int(pd.to_numeric(df.get("url_count", pd.Series([0]*total)), errors="coerce").fillna(0).sum()) if total else 0
    suspicious_count = int(pd.to_numeric(df.get("suspicious_keyword_count", pd.Series([0]*total)), errors="coerce").fillna(0).gt(0).sum()) if total else 0

    domains = []
    domain_file = report_dir / "sender_domain_analysis.csv"
    if domain_file.exists():
        try:
            domain_df = pd.read_csv(domain_file).sort_values("total", ascending=False).head(6)
            domains = [{"domain": row.iloc[0], "count": int(row["total"])} for _, row in domain_df.iterrows()]
        except Exception:
            domains = []

    charts = [
        ("01_phishing_vs_legitimate.png", "Phishing vs Legitimate"),
        ("02_email_category_pie.png", "Email category distribution"),
        ("03_top10_suspicious_keywords.png", "Top suspicious keywords"),
        ("04_email_length_distribution.png", "Email length distribution"),
        ("05_sender_domain_frequency.png", "Sender domain frequency"),
        ("06_url_count_per_email.png", "URL count per email"),
        ("07_phishing_keyword_comparison.png", "Keyword comparison"),
        ("08_phishing_pattern_heatmap.png", "Phishing pattern heatmap"),
    ]
    available_charts = [
        {"file": filename, "title": title}
        for filename, title in charts if (ROOT / "Graphs" / filename).exists()
    ]

    recent = []
    if not df.empty:
        for _, row in df.head(8).iterrows():
            recent.append({
                "sender": str(row.get("sender", ""))[:48] or "Not available",
                "subject": str(row.get("subject", ""))[:72] or "No subject",
                "label": str(row.get(label_col, "Unknown")).title(),
                "urls": int(row.get("url_count", 0) or 0)
            })

    return {
        "total": total, "phishing": phishing, "legitimate": legitimate,
        "urls": url_count, "suspicious": suspicious_count,
        "domains": domains, "charts": available_charts, "recent": recent
    }

@app.route("/", methods=["GET"])
def home():
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if username == APP_USERNAME and password == APP_PASSWORD:
            session.clear()
            session["logged_in"] = True
            session["username"] = username
            return redirect(url_for("dashboard"))
        flash("Incorrect username or password. Please try again.", "error")
    return render_template("login.html")

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", data=load_dashboard_data(),
                           username=session.get("username", "User"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )