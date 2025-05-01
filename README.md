🛡️ Network Vigilance: AI-Powered Multi-Layered APT Protection

[![Python](https://img.shields.io/badge/Python-3.10-blue?style=flat-square\&logo=python)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-WebApp-lightgrey?style=flat-square\&logo=flask)](https://flask.palletsprojects.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Database-blue?style=flat-square\&logo=postgresql)](https://www.postgresql.org/)
[![MIT License](https://img.shields.io/badge/License-MIT-success?style=flat-square)](LICENSE)

> **Network Vigilance** is an AI-powered real-time network monitoring and intrusion detection system. Built with a custom dataset and intelligent flow-based feature extraction, it detects Advanced Persistent Threat (APT) behaviors and automatically responds to malicious activity on network.

---

 📚 Table of Contents

* [About the Project](about-the-project)
* [System Features](system-features)
* [Tech Stack](tech-stack)
* [Custom Dataset Generation](custom-dataset-generation)
* [Feature Extraction and Dataset Construction](feature-extraction-and-dataset-construction)
* [Installation & Setup](installation--setup)
* [Usage Guide](usage-guide)
* [Model Overview](model-overview)
* [PDF Reporting](pdf-reporting)
* [Limitations & Future Work](limitations--future-work)
* [Contributors](contributors)
* [License](license)

---

 📖 About the Project

**Network Vigilance** is a research-grade, enterprise-oriented system for real-time detection and mitigation of cyber threats on network environments. It goes beyond traditional IDS/IPS systems by integrating both supervised and unsupervised ML models trained on a **custom dataset**, collected from a realistic, virtualized lab simulating APT behaviors.

Key innovations include:

* Passive capture of all network traffic (not just host traffic)
* Real-time feature extraction and prediction process
* Combined model strategy to reduce false negatives
* A fully interactive, professional dashboard for monitoring and control

---

 ✨ System Features

* Modern, responsive frontend built with Flask, Bootstrap, and modular HTML templates
* User authentication via login/signup/profile management pages
* Real-time capture on network interface using dumpcap
* Feature extraction with a custom CICFlowMeter-like script
* Combined ML model prediction (Random Forest + Isolation Forest)
* Immediate firewall-level blocking of malicious IPs
* PostgreSQL for persistent storage of flows and sessions
* Session grouping and analysis via dashboard
* Admin dashboard (Flask + Bootstrap) for logs, reports, and actions
* PDF reporting with branding and interpretability

---

 👨‍💻 Tech Stack

* **Python 3.10**
* **Flask** (web server & dashboard)
* **PostgreSQL** (flow/session storage)
* **dumpcap/Wireshark** (live traffic capture)
* **Matplotlib** (analytics charting)
* **PDFKit + wkhtmltopdf** (PDF reports)
* **Bootstrap + Chart.js** (frontend)

---

 📀 Custom Dataset Generation

To generate a realistic dataset capturing Advanced Persistent Threat (APT) behaviors, a complete test environment was built using VMware virtualization. It included one Ubuntu-based victim VM and three Kali Linux attacker VMs, all connected to a common isolated network. Each attacker VM was responsible for executing a specific stage of an APT, such as reconnaissance, exploitation, brute force, or denial of service.

**APT Attack Scenarios Simulated:**

* **Stealth Scans (Reconnaissance):** Using advanced Nmap options (e.g., T1, -sS, -sU, -sV) to perform stealthy TCP and UDP scans.
* **Port Scanning:** Standard Nmap scans to enumerate open services.
* **Brute Force Attacks:** SSH and RDP targeted via Hydra.
* **Denial of Service (DoS):** SYN/ICMP floods to overload the system.
* **Man-in-the-Middle (MITM):** ARP spoofing to intercept internal traffic.
* **File Transfer via Netcat:** Simulating C2 communication or exfiltration.
* **Slowloris Attack:** Slow HTTP headers to exhaust web server connections.
* **RDP Exploits:** Simulated brute-force and exploit-based access attempts.

---

 🧪 Feature Extraction and Dataset Construction

Raw `.pcap` files were transformed into flow-based feature vectors using **CICFlowMeter 4.0**, producing 84 statistical metrics per flow. Each flow is defined by a 5-tuple and includes features like:

* Flow duration
* Byte volume (fwd/bwd)
* Packet count, length, IAT
* TCP flags, window sizes
* Packet rates, errors, and retransmissions

 Labeling:

* Manual inspection via Wireshark
* IP-based filtering (victim ↔ attacker)
* Cross-referenced with execution logs and time windows

SMOTE was applied to handle class imbalance. The dataset was normalized and split into training/testing subsets.

---

 🛠️ Installation & Setup

This module prepares your environment for running Network Vigilance both locally and on deployment servers. It involves setting up the backend Python application, PostgreSQL database, required libraries, and configuration files to enable seamless operation of the detection pipeline.

 Prerequisites

* Python 3.10+
* PostgreSQL 13+
* `wkhtmltopdf` installed and added to system PATH

 Clone and Setup

```bash
git clone https://github.com/yourusername/network-vigilance.git
cd network-vigilance
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

 Configure Database

* Create a DB named `network_vigilance`
* Edit `config.py` with your DB credentials

```bash
psql -U your_user -d network_vigilance -f schema/init.sql
```

 Run the Application

```bash
python app.py
```

Visit: [http://localhost:5000](http://localhost:5000)

---

 📋 Usage Guide

This module handles the system's end-to-end operation during deployment. It runs as a long-lived background process that periodically captures packets, extracts flow-based features, classifies flows, and updates the system state in real-time. The user interface is constructed with multiple modular HTML components for each feature page.

* **Live Traffic Capture:** Triggered every 30 seconds using dumpcap, optimized for lightweight background packet capture.
* **Feature Extraction:** In-memory with CICFlowMeter-like parser. All packets are converted into flow records with statistical summaries, mimicking offline feature generation.
* **Flow Classification:** Both supervised (Random Forest) and unsupervised (Isolation Forest) models are applied on each new flow to predict its nature.
* **Firewall Block:** Detected malicious flows result in immediate IP blocking via `netsh advfirewall`. The blocked IP and flow metadata are logged into PostgreSQL.
* **Dashboard Features:**

  * **User Authentication Pages:** Includes `login.html`, `logout.html`, `signup.html`, and `profile.html` templates — each designed for secure admin access and session management.Login, signup, and profile sections secured for admin access only.\*\* Triggered every 30 seconds
  * **Feature Extraction:** In-memory with CICFlowMeter-like parser
  * **Flow Classification:** Both models applied in real-time
  * **Firewall Block:** Detected malicious IPs are blocked via `netsh advfirewall`
  * **Blocked IPs (`blocked_ips.html`):** Lets admins unblock IPs or view blocked history.
  * **Prediction Logs (`prediction_logs.html`):** Shows a timeline of past alerts and classification results.
  * **Malicious Flows (`malicious_flows.html`):** Detailed breakdown of suspicious activity.
  * **Session View (`session_view.html`):** Visualizes flow groups by detection session.
  * **Report Viewer (`report_template.html`):** Rendered HTML used to export professional PDFs.
  
* **Dashboard Features:**

  * User login/signup/profile access
  * IP blocking/unblocking
  * Prediction history log
  * Session view with flow breakdown
  * Manual report generation
  
---

 📊 Model Overview

This module is responsible for performing machine learning-based flow classification. It encapsulates model training, loading, and prediction logic for both supervised and anomaly-based detection.

 🎯 Supervised Model: Random Forest

* Trained with labeled flows
* Captures known malicious patterns
* Achieving **94% accuracy**

 🔍 Unsupervised Model: Isolation Forest

* Trained only on benign flows
* Flags anomalous and unknown behavior

 🔗 Combined Strategy:

* A flow is flagged as malicious only if **both** models independently classify it as malicious. This conservative approach reduces false positives and increases confidence in detection.

 🔑 Key Features Used:

* `Flow Duration`, `Total Fwd Packet`, `Total Bwd packets`
* `Flow Bytes/s`, `Flow Packets/s`
* `Fwd/Bwd Packet Length Mean`, `IAT Mean`
* `Average Packet Size`, `Packet Length Std`
* `Subflow Bwd Bytes`, `FWD Init Win Bytes`

---

 🧾 PDF Reporting

The PDF reporting module generates detailed forensic-grade reports for any detected malicious flow. Reports are designed for use by network administrators, security analysts, or auditors. They summarize model predictions, timestamps, flow features, and risk context with clean formatting and branding.

Additionally, the system supports **automated threat report generation**, which compiles the flow metadata and classification results into a formatted PDF file and stores or emails it to designated stakeholders or security teams.

* Downloadable PDF for each malicious flow

* Includes:

  * IP info, timestamps, feature summary
  * Model decision and confidence
  * Session ID and contextual theory
  * Branded layout with charts and annotations

* Powered by **wkhtmltopdf + PDFKit**. Reports are designed for use by network administrators, security analysts, or auditors. They summarize model predictions, timestamps, flow features, and risk context with clean formatting and branding.

* Downloadable PDF for each malicious flow

* Includes:

  * IP info, timestamps, feature summary
  * Model decision and confidence
  * Session ID and contextual theory
  * Branded layout with charts and annotations

* Powered by **wkhtmltopdf + PDFKit**

---

 ⚠️ Limitations & Future Work

 Current Limitations:

* The model may not generalize perfectly to all types of enterprise network environments due to differences in topology, device behavior, and traffic volume.
* No live retraining or web-based ML interface

 Planned Enhancements:

* 🔁 Transfer Learning / Incremental Learning support for adaptable models — allowing the system to continuously learn from new environments without requiring complete retraining. This enables seamless adaptation to changing network patterns, device behavior, or evolving APT strategies over time.

---

 👥 Contributors

* **Anas Hashmi**
* **Yasir**
* **Kabir Ahmed**

---

 📄 License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.
