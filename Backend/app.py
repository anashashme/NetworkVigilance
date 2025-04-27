import urllib

from flask import Flask, render_template, request, jsonify, redirect, session, flash
from flow_processing.custom_extractor import extract_custom_features
from prediction_engine.predict import predict_from_csv
from firewall_control.block_unblock import block_ip, unblock_ip_by_id
from collections import defaultdict
from psycopg2.extras import RealDictCursor
import matplotlib.pyplot as plt
import uuid
import pdfkit
from datetime import datetime, timedelta
from flask import send_file
from flask import render_template, make_response

from database.db import (
    get_db_connection,
    log_prediction_session,
    log_malicious_flow,
    log_blocked_ip,
    get_all_blocked_ips,
    get_all_prediction_logs,
    get_all_malicious_flows,
    delete_prediction_log_by_id,
    get_flows_by_session_id
)
import asyncio
import os
import subprocess
import random

app = Flask(__name__)
app.secret_key = 'supersecretkey123'
# Make sessions permanent (optional)
app.permanent_session_lifetime = timedelta(minutes=30)

PCAP_PATH = "data/live_capture.pcap"
CSV_PATH = "data/Latest-Flow.csv"
THRESHOLD = -999

def unblock_firewall_rule(ip):
    rule_name = f"Block_{ip}"
    subprocess.run(
        ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
        shell=True
    )

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        first_name = request.form.get("first_name")
        last_name = request.form.get("last_name")
        email = request.form.get("email")
        password = request.form.get("password")

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO users (first_name, last_name, email, password)
            VALUES (%s, %s, %s, %s)
            """, (first_name, last_name, email, password)
        )
        conn.commit()
        cur.close()
        conn.close()

        flash('Account created! Please log in.', 'success')
        return redirect("/login")

    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT id FROM users WHERE email = %s AND password = %s",
            (email, password)
        )
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user:
            session.permanent = True
            session["user_id"] = user[0]
            session["user_email"] = email
            flash('Logged in successfully.', 'success')
            return redirect("/")
        else:
            flash('Invalid credentials. Please try again.', 'danger')

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect("/login")

# Protected routes
@app.route("/")
def home():
    if "user_id" not in session:
        flash('Please login to access the dashboard.', 'warning')
        return redirect("/login")

    logs = get_all_prediction_logs()
    blocked = get_all_blocked_ips()

    sorted_logs = sorted(logs, key=lambda l: l["timestamp"], reverse=True)[:5]
    prediction_summary = [
        {
            "timestamp": l["timestamp"].strftime("%b %d, %I:%M%p"),
            "total_flows": l["total_flows"],
            "malicious_flows": l["malicious_flows"]
        }
        for l in sorted_logs
    ]

    return render_template(
        "index.html",
        prediction_summary=prediction_summary,
        blocked_count=len(blocked),
        unblocked_count=max(0, len(logs) - len(blocked))
    )

@app.route("/run_capture", methods=["POST"])
def capture():
    if "user_id" not in session:
        return jsonify({"error": "Not authorized"}), 401

    os.system(f'dumpcap -i "Wi-Fi 2" -a duration:30 -w {PCAP_PATH} > NUL 2>&1')
    return jsonify({"status": "✅ Traffic capture completed!"})

@app.route("/extract_features", methods=["POST"])
def extract():
    if "user_id" not in session:
        return jsonify({"error": "Not authorized"}), 401

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        extract_custom_features(pcap_path=PCAP_PATH, csv_output_path=CSV_PATH)
        return jsonify({"status": "✅ Feature extraction completed."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

import uuid

@app.route("/predict", methods=["POST"])
def predict():
    if "user_id" not in session:
        return jsonify({"error": "Not authorized"}), 401

    y_rf_pred, y_iso_pred, src_ips = predict_from_csv(CSV_PATH, threshold=THRESHOLD)
    if not len(y_iso_pred):
        return jsonify({"status": "⚠️ No predictions to display."})

    total_flows = len(y_iso_pred)
    malicious_ips = list({ip for pred, ip in zip(y_iso_pred, src_ips) if pred == 1})

    for ip in malicious_ips:
        block_ip(ip)

    # Generate a unique session ID
    session_id = str(uuid.uuid4())

    log_prediction_session(datetime.datetime.now(), total_flows, len(malicious_ips))

    for ip, pred in zip(src_ips, y_iso_pred):
        if pred == 1:
            model_score = round(random.uniform(0.7, 1.0), 2)
            log_malicious_flow(
                ip,
                datetime.datetime.now(),
                "Combined Models",
                model_score,
                True,
                session_id  # <-- NEW
            )

    if malicious_ips:
        return jsonify({
            "status": "🚫 Malicious traffic detected and blocked.",
            "blocked_ips": malicious_ips
        })
    else:
        return jsonify({"status": "✅ All traffic is benign."})


@app.route("/unblock/<int:ip_id>", methods=["POST"])
def unblock_individual(ip_id):
    if "user_id" not in session:
        return jsonify({"error": "Not authorized"}), 401

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT src_ip FROM blocked_ips WHERE id = %s;", (ip_id,))
    row = cur.fetchone()

    if row:
        ip = row[0]
        unblock_firewall_rule(ip)
        cur.execute("DELETE FROM blocked_ips WHERE id = %s;", (ip_id,))
        conn.commit()

    cur.close()
    conn.close()
    return jsonify({"status": "✅ Unblocked", "id": ip_id})

@app.route("/blocked_ips")
def blocked_ips():
    if "user_id" not in session:
        flash('Please login to view blocked IPs.', 'warning')
        return redirect("/login")
    ips = get_all_blocked_ips()
    return render_template("blocked_ips.html", blocked_ips=ips)

@app.route("/prediction_logs")
def prediction_logs():
    if "user_id" not in session:
        flash('Please login to view logs.', 'warning')
        return redirect("/login")

    logs = get_all_prediction_logs()
    sorted_logs = sorted(logs, key=lambda l: l["timestamp"], reverse=True)
    recent_logs = sorted_logs[:10]

    logs_data = {
        "labels": [log["timestamp"].strftime("%b %d, %I:%M%p") for log in recent_logs],
        "total_flows": [log["total_flows"] for log in recent_logs],
        "malicious_flows": [log["malicious_flows"] for log in recent_logs]
    }

    return render_template("prediction_logs.html", prediction_logs=logs, logs_data=logs_data)

@app.route("/get_logs_data")
def get_logs_data():
    if "user_id" not in session:
        return jsonify({"error": "Not authorized"}), 401

    logs = get_all_prediction_logs()
    sorted_logs = sorted(logs, key=lambda l: l["timestamp"], reverse=True)
    recent_logs = sorted_logs[:10]

    logs_data = {
        "labels": [log["timestamp"].strftime("%b %d, %I:%M%p") for log in recent_logs],
        "total_flows": [log["total_flows"] for log in recent_logs],
        "malicious_flows": [log["malicious_flows"] for log in recent_logs]
    }
    return jsonify(logs_data)

@app.route("/delete_log/<int:log_id>", methods=["POST"])
def delete_log(log_id):
    if "user_id" not in session:
        return jsonify({"error": "Not authorized"}), 401
    delete_prediction_log_by_id(log_id)
    return jsonify({"status":"✅ Deleted", "id": log_id})


@app.route("/malicious_flows")
def malicious_flows():
    if "user_id" not in session:
        flash('Please login to view malicious flows.', 'warning')
        return redirect("/login")

    session_id = request.args.get("session_id")

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    if session_id:
        cur.execute("""
            SELECT id, src_ip, timestamp, predicted_by, model_score, was_blocked, session_id
            FROM malicious_flows
            WHERE session_id = %s
            ORDER BY timestamp DESC
        """, (session_id,))
    else:
        cur.execute("""
            SELECT id, src_ip, timestamp, predicted_by, model_score, was_blocked, session_id
            FROM malicious_flows
            ORDER BY timestamp DESC
        """)

    flows = cur.fetchall()
    cur.close()
    conn.close()

    last5 = flows[-5:] if flows else []
    flows_chart_data = {
        "labels": [f["timestamp"].strftime("%Y-%m-%dT%H:%M:%S") for f in last5],
        "scores": [f["model_score"] for f in last5],
        "blocked": [1 if f["was_blocked"] else 0 for f in last5]
    }

    return render_template(
        "malicious_flows.html",
        malicious_flows=flows,
        malicious_chart_data=flows_chart_data
    )


@app.route("/get_malicious_chart_data")
def get_malicious_chart_data():
    if "user_id" not in session:
        return jsonify({"error": "Not authorized"}), 401

    flows = get_all_malicious_flows()
    grouped = defaultdict(int)
    for f in flows:
        key = f["timestamp"].strftime("%Y-%m-%dT%H:%M:%S")
        grouped[key] += 1

    sorted_grouped = sorted(grouped.items(), key=lambda x: x[0], reverse=True)[:10]
    sorted_grouped.reverse()

    chart_data = {
        "labels": [ts for ts, count in sorted_grouped],
        "counts": [count for ts, count in sorted_grouped]
    }
    return jsonify(chart_data)

@app.route("/profile", methods=["GET", "POST"])
def profile():
    if "user_id" not in session:
        return redirect("/login")

    conn = get_db_connection()
    cur = conn.cursor()

    if request.method == "POST":
        first_name = request.form.get("first_name")
        last_name = request.form.get("last_name")
        password = request.form.get("password")

        cur.execute(
            """
            UPDATE users
            SET first_name = %s, last_name = %s, password = %s
            WHERE id = %s
            """, (first_name, last_name, password, session["user_id"])
        )
        conn.commit()

    cur.execute("SELECT first_name, last_name, email, password FROM users WHERE id = %s", (session["user_id"],))
    user = cur.fetchone()
    cur.close()
    conn.close()

    return render_template("profile.html", user=user)

@app.route("/get_block_counts")
def get_block_counts():
    blocked = get_all_blocked_ips()
    logs = get_all_prediction_logs()
    blocked_count = len(blocked)
    unblocked_count = max(0, len(logs) - blocked_count)
    return jsonify({
        "blocked_count": blocked_count,
        "unblocked_count": unblocked_count
    })

@app.route("/session/<uuid:session_id>")
def session_view(session_id):
    if "user_id" not in session:
        flash('Please login to view session flows.', 'warning')
        return redirect("/login")

    all_flows = get_all_malicious_flows()
    session_flows = [f for f in all_flows if str(f["session_id"]) == str(session_id)]

    if not session_flows:
        flash("No flows found for this session.", "info")
        return redirect("/malicious_flows")

    total_flows = len(session_flows)
    blocked_count = sum(1 for f in session_flows if f["was_blocked"])
    block_percentage = round((blocked_count / total_flows) * 100, 2)
    predicted_by = session_flows[0]["predicted_by"]
    session_time = session_flows[0]["timestamp"].strftime("%I:%M %p")

    chart_labels = [f["timestamp"].strftime("%I:%M %p") for f in session_flows]
    chart_scores = [f["model_score"] for f in session_flows]

    return render_template(
        "session_view.html",
        session_id=session_id,
        session_flows=session_flows,
        total_flows=total_flows,
        blocked_count=blocked_count,
        block_percentage=block_percentage,
        predicted_by=predicted_by,
        session_time=session_time,
        chart_labels=chart_labels,  # <== THIS
        chart_scores=chart_scores
    )

config = pdfkit.configuration(
    wkhtmltopdf=r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe'
)

@app.route("/generate_report/<int:flow_id>")
def generate_report(flow_id):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute("SELECT * FROM malicious_flows WHERE id = %s", (flow_id,))
    flow = cur.fetchone()
    cur.close()
    conn.close()

    # Determine risk level
    score = flow["model_score"]
    if score >= 0.9:
        risk_label = "Critical"
        risk_color = "Red"
    elif score >= 0.8:
        risk_label = "High Risk"
        risk_color = "Orange"
    elif score >= 0.7:
        risk_label = "Moderate Risk"
        risk_color = "Yellow"
    else:
        risk_label = "Low Risk"
        risk_color = "Green"

    # Use full URL path for logo
    logo_url = request.url_root.rstrip('/') + '/static/NetworkVigilance_logo.png'

    rendered = render_template(
        "report_template.html",
        flow=flow,
        logo_path=logo_url,
        now=datetime.now(),
        risk_label=risk_label,
        risk_color=risk_color
    )

    # wkhtmltopdf options to allow loading external logo
    options = {
        'enable-local-file-access': None
    }

    config = pdfkit.configuration(wkhtmltopdf=r"C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe")
    pdf = pdfkit.from_string(rendered, False, configuration=config, options=options)

    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=report_{flow['src_ip']}.pdf'
    return response

if __name__ == "__main__":
    app.run(debug=True)
