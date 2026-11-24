
from pathlib import Path
from functools import wraps
import os
import subprocess
import sys
import csv
import io
import shutil

import pandas as pd
import joblib

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    send_from_directory,
    Response
)

ROOT = Path(__file__).resolve().parent

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "change-this-demo-secret-key"
)

APP_USERNAME = os.environ.get("APP_USERNAME", "admin")
APP_PASSWORD = os.environ.get("APP_PASSWORD", "Admin@123")


# ==========================================
# LOGIN REQUIRED
# ==========================================

def login_required(view):

    @wraps(view)
    def wrapped(*args, **kwargs):

        if not session.get("logged_in"):
            return redirect(url_for("login"))

        return view(*args, **kwargs)

    return wrapped


# ==========================================
# LOAD DASHBOARD DATA
# ==========================================

def load_dashboard_data():

    report_dir = ROOT / "Reports"
    cleaned_file = report_dir / "cleaned_email_dataset.csv"
    dataset_file = ROOT / "Dataset" / "phishing_emails.csv"
    sample_file = ROOT / "Dataset" / "sample_phishing_emails.csv"

    report_dir.mkdir(exist_ok=True)

    if not dataset_file.exists() and sample_file.exists():
        shutil.copy2(sample_file, dataset_file)

    needs_analysis = (
        dataset_file.exists()
        and (
            not cleaned_file.exists()
            or dataset_file.stat().st_mtime > cleaned_file.stat().st_mtime
        )
    )

    if needs_analysis:

        try:
            subprocess.run(
                [sys.executable, str(ROOT / "main.py")],
                cwd=ROOT,
                check=False
            )

        except Exception as error:
            print("Analysis warning:", error)

    if cleaned_file.exists():
        df = pd.read_csv(cleaned_file).fillna("")

    elif dataset_file.exists():
        df = pd.read_csv(dataset_file).fillna("")

    elif sample_file.exists():
        df = pd.read_csv(sample_file).fillna("")

    else:
        df = pd.DataFrame()

    label_col = (
        "label" if "label" in df.columns
        else "label_original"
    )

    if label_col in df.columns:

        labels = df[label_col].astype(str).str.lower()

        phishing = int(
            labels.str.contains(
                "phish|spam|fraud|malicious|^1$",
                regex=True
            ).sum()
        )

        legitimate = int(
            labels.str.contains(
                "legit|ham|safe|benign|^0$",
                regex=True
            ).sum()
        )

    else:
        phishing = 0
        legitimate = 0

    total = len(df)

    url_count = (
        int(
            pd.to_numeric(
                df.get("url_count", pd.Series([0] * total)),
                errors="coerce"
            ).fillna(0).sum()
        )
        if total else 0
    )

    suspicious_count = (
        int(
            pd.to_numeric(
                df.get(
                    "suspicious_keyword_count",
                    pd.Series([0] * total)
                ),
                errors="coerce"
            ).fillna(0).gt(0).sum()
        )
        if total else 0
    )

    # Sender domain analysis
    domains = []

    domain_file = report_dir / "sender_domain_analysis.csv"

    if domain_file.exists():

        try:
            domain_df = pd.read_csv(domain_file)

            if "total" in domain_df.columns:

                domain_df = domain_df.sort_values(
                    "total",
                    ascending=False
                ).head(6)

                domains = [
                    {
                        "domain": row.iloc[0],
                        "count": int(row["total"])
                    }
                    for _, row in domain_df.iterrows()
                ]

        except Exception as error:
            print("Domain analysis warning:", error)
            domains = []

    # Chart details
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
        {
            "file": filename,
            "title": title
        }
        for filename, title in charts
        if (ROOT / "Graphs" / filename).exists()
    ]

    # Recent email records
    recent = []

    if not df.empty:

        for _, row in df.head(8).iterrows():

            try:
                urls = int(row.get("url_count", 0) or 0)

            except (ValueError, TypeError):
                urls = 0

            recent.append({
                "sender": str(
                    row.get("sender", "")
                )[:48] or "Not available",

                "subject": str(
                    row.get("subject", "")
                )[:72] or "No subject",

                "label": str(
                    row.get(label_col, "Unknown")
                ).title(),

                "urls": urls
            })

    return {
        "total": total,
        "phishing": phishing,
        "legitimate": legitimate,
        "urls": url_count,
        "suspicious": suspicious_count,
        "domains": domains,
        "charts": available_charts,
        "recent": recent
    }


# ==========================================
# HOME PAGE
# ==========================================

@app.route("/")
def home():

    if session.get("logged_in"):
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


# ==========================================
# LOGIN
# ==========================================

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

        flash(
            "Incorrect username or password. Please try again.",
            "error"
        )

    return render_template("login.html")


# ==========================================
# DASHBOARD
# ==========================================

@app.route("/dashboard")
@login_required
def dashboard():

    return render_template(
        "dashboard.html",
        data=load_dashboard_data(),
        username=session.get("username", "User")
    )


# ==========================================
# ABOUT PROJECT
# ==========================================

@app.route("/about")
@login_required
def about():

    return render_template(
        "about.html",
        username=session.get("username", "User"),
        project_name="SecureSight",
        total_features=6
    )


# ==========================================
# GET EMAIL RECORDS
# ==========================================

def get_email_records():

    report_file = ROOT / "Reports" / "cleaned_email_dataset.csv"
    dataset_file = ROOT / "Dataset" / "phishing_emails.csv"

    file_path = (
        report_file
        if report_file.exists()
        else dataset_file
    )

    if not file_path.exists():
        return []

    try:

        df = pd.read_csv(file_path).fillna("")

        return df.head(500).to_dict(orient="records")

    except Exception as error:
        print("Email records error:", error)
        return []


# ==========================================
# VISUAL ANALYTICS
# ==========================================

@app.route("/visual-analytics")
@login_required
def visual_analytics():

    data = load_dashboard_data()

    return render_template(
        "visual_analytics.html",
        data=data,
        charts=data["charts"],
        username=session.get("username", "User")
    )


# ==========================================
# SENDER DOMAINS
# ==========================================

@app.route("/sender-domains")
@login_required
def sender_domains():

    data = load_dashboard_data()

    return render_template(
        "sender_domains.html",
        domains=data["domains"],
        username=session.get("username", "User")
    )


# ==========================================
# EMAIL RECORDS
# ==========================================

@app.route("/email-records")
@login_required
def email_records():

    return render_template(
        "email_records.html",
        records=get_email_records(),
        username=session.get("username", "User")
    )


# ==========================================
# DOWNLOAD REPORTS - DIRECT CSV DOWNLOAD
# ==========================================

@app.route("/download-reports")
@login_required
def download_reports():

    records = get_email_records()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "S.No",
        "Sender",
        "Subject",
        "Label",
        "URL Count"
    ])

    for index, email in enumerate(records, start=1):

        writer.writerow([
            index,
            email.get("sender", "N/A"),
            email.get("subject", "No Subject"),
            email.get(
                "label",
                email.get("label_original", "Unknown")
            ),
            email.get("url_count", 0)
        ])

    csv_content = "\ufeff" + output.getvalue()

    response = Response(
        csv_content,
        mimetype="text/csv; charset=utf-8"
    )

    response.headers["Content-Disposition"] = (
        "attachment; filename=SecureSight_Email_Reports.csv"
    )

    return response


# ==========================================
# EMAIL PREDICTION
# ==========================================

@app.route("/predict", methods=["GET", "POST"])
@login_required
def predict_email():

    result = None
    email_subject = ""
    email_body = ""

    if request.method == "POST":

        email_subject = request.form.get(
            "subject", ""
        ).strip()

        email_body = request.form.get(
            "body", ""
        ).strip()

        if not email_subject and not email_body:

            flash("Please enter email content.", "error")

        else:

            model_path = ROOT / "Models" / "email_model.pkl"

            try:

                if not model_path.exists():

                    flash(
                        "Email prediction model was not found.",
                        "error"
                    )

                else:

                    model = joblib.load(model_path)

                    email_text = email_subject + " " + email_body

                    prediction = model.predict([email_text])[0]

                    result = str(prediction).upper()

            except Exception as error:

                flash(
                    f"Prediction error: {error}",
                    "error"
                )

    return render_template(
        "email_prediction.html",
        result=result,
        subject=email_subject,
        body=email_body
    )


# ==========================================
# LOGOUT
# ==========================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


# ==========================================
# GRAPH IMAGES
# ==========================================

@app.route("/graphs/<path:filename>")
def graph_file(filename):

    return send_from_directory(
        ROOT / "Graphs",
        filename
    )


# ==========================================
# RUN APPLICATION
# ==========================================

if __name__ == "__main__":

    app.run(debug=True)
