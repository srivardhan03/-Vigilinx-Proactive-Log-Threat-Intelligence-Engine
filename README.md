# Vigilinx: Proactive Log Threat Intelligence Engine

![image](https://github.com/user-attachments/assets/22fe5d63-bfce-4134-9bb1-38256b937669)

---

## Table of Contents

- [Project Overview](#project-overview)  
- [Features](#features)  
- [Technology Stack](#technology-stack)  
- [Installation](#installation)  
- [Usage](#usage)  
- [Configuration](#configuration)  
- [How It Works](#how-it-works)  
  - [Log Parsing](#log-parsing)  
  - [Suspicious Activity Detection](#suspicious-activity-detection)  
  - [Anomaly Detection](#anomaly-detection)  
  - [Brute Force Detection](#brute-force-detection)  
- [Screenshots](#screenshots)  
- [File Format](#file-format)  
- [Logging](#logging)  
- [Contact](#contact)  

---

## Project Overview

**Vigilinx** is an advanced security log analyzer designed to proactively identify suspicious activities, anomalies, and brute force attack attempts in Apache-style web server logs. Using a combination of heuristic rules and machine learning models, Vigilinx empowers security analysts and system administrators to gain actionable threat intelligence from large volumes of log data with ease.

This tool is built with **Streamlit** for an interactive and user-friendly web interface, making security log analysis accessible even for those with limited experience in log parsing or machine learning.

---

## Features

- Upload Apache-style `.log` or `.txt` files or paste live log lines for immediate analysis.
- Parse logs to extract key attributes such as IP address, timestamp, HTTP method, URL, status code, user agent, and more.
- Identify bot traffic by detecting known bot keywords in User-Agent strings.
- Flag suspicious HTTP methods outside the common set (GET, POST, etc.).
- Detect anomalies in log entries using an Isolation Forest model for unsupervised outlier detection.
- Detect potential brute force attacks using a Random Forest classifier trained on request frequency features.
- Interactive tabs presenting:
  - Log summary statistics and visualizations.
  - Tables of bot and suspicious method activity.
  - Anomaly detection results with visualization of anomalous requests.
  - Brute force attack detection details including requests per minute distribution.
- Sidebar configuration controls for tuning detection sensitivity and time windows.
- Logging of all application events and errors to a log file for audit and debugging.

---

## Technology Stack

- **Python 3.8+**  
- **Streamlit** — for the interactive web UI  
- **Pandas** and **NumPy** — for data processing  
- **scikit-learn** — for machine learning models (Isolation Forest and Random Forest)  
- **Regex** — for efficient log line parsing  
- **Logging module** — for app event logging  

---

## Installation

1. Clone the repository:

git clone https://github.com/srivardhan03/Vigilinx-Proactive-Log-Threat-Intelligence-Engine.git
cd vigilinx-Proactive-Log-Threat-Intelligence-Engine

**Create a Python virtual environment (recommended):**
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

**Install dependencies from the provided requirements.txt:**
pip install -r requirements.txt

## Usage
Run the Streamlit app with:
streamlit run app.py

This will launch Vigilinx in your default browser. You can then:
Upload an Apache-style log file (.log or .txt).
Or paste real-time log lines in the text box.

Configure detection thresholds using the sidebar sliders.

Explore the analysis results across four tabs: Summary, Suspicious Activity, Anomaly Detection, and Brute Force Detection.

## Configuration
In the sidebar, you can customize:

**Anomaly Contamination:** Controls sensitivity of Isolation Forest anomaly detection (default 0.05). Lower values result in fewer anomalies detected.

**Brute Force Threshold:** Number of requests per minute from a single IP to flag as a brute force attempt (default 20).

**Detection Time Window:** Sliding window in minutes for brute force detection (default 1).

Adjusting these parameters helps tune Vigilinx for different server loads and security policies.

## How It Works
**Log Parsing**
Uses a robust regex pattern to parse Apache-style log lines extracting fields: IP, datetime, HTTP method, URL, status, response size, referrer, and user agent.

Converts datetime string into Python datetime object for temporal analysis.

Extracts derived features such as URL length and converts user agent to lowercase for consistent bot detection.

**Suspicious Activity Detection**
Detects bot traffic by matching User-Agent strings against a list of common bot-related keywords (bot, spider, crawler, etc.).

Flags HTTP methods outside of the usual allowed set (GET, POST, HEAD, etc.) as suspicious.

**Anomaly Detection**
Applies an Isolation Forest model on encoded and numerical features extracted from log data.

Flags log entries as anomalies if they significantly deviate from typical request patterns.

**Brute Force Detection**
Computes requests per IP per sliding time window (e.g., requests per minute).

Labels entries exceeding the threshold as brute force attempts.

Trains a Random Forest classifier on historical labeled data to predict brute force behavior.

Predicts brute force attempts on new log data.

## Screenshots
![image](https://github.com/user-attachments/assets/7103dd81-bfb1-4d69-a8bf-3d30d5a727ff)


![image](https://github.com/user-attachments/assets/23252ad9-ffab-4bad-b371-fbe10810fc12)


![image](https://github.com/user-attachments/assets/8b1d1a43-61de-40f3-b52f-b56d1cd64c9f)


![image](https://github.com/user-attachments/assets/474f8272-c427-4965-aeaa-0aaa9baf1ae0)


![image](https://github.com/user-attachments/assets/3bf46b30-2404-4382-a3f7-6cdf0badfb80)


## File Format
Vigilinx expects Apache-style log entries in this format (combined log format):

127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] "GET /apache_pb.gif HTTP/1.0" 200 2326 "-" "Mozilla/4.08 [en] (Win98; I ;Nav)"

## Each log line should include:

Client IP address

Timestamp with timezone offset

HTTP method and requested URL

Response status code and size

Referrer URL

User-Agent string

**Logging**
The application logs info, warnings, and errors to both the console and a log file named vigilinx_log_analyzer.log.

This facilitates troubleshooting and audit trail of analysis runs.


## Contact
Developed and maintained by Your Name.

**Email:** srivarthansugumar2005@gmail.com

**GitHub:** srivardhan03

Thank you for using Vigilinx — proactive security through intelligent log analysis!

