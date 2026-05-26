# CyberEye: Cybersecurity Threat Log Analytics

CyberEye is a complete, production-ready Cybersecurity Threat Log Analytics system built using Python, SQLite, and Streamlit. It automates the ingestion, preprocessing, analysis, and visualization of security logs, utilizing both traditional rule-based checks and machine learning (Isolation Forest) to detect anomalies, brute-force attacks, port scans, and suspicious user behavior.

---

##  Project Overview

Modern security teams are overwhelmed with log data. CyberEye solves this by providing a unified data ingestion pipeline and interactive threat response dashboard. The system processes raw CSV security logs, enriches them with threat parameters and severity grades, stores them in an SQLite database for fast analytical querying, and renders them in a dark-themed cybersecurity command center UI.

### Key Features
1. **Automated Data Ingestion**: Automatically cleans, normalizes, and validates IP formats and datetimes in raw CSV log files.
2. **Rule-Based Threat Detection**:
   - **Brute-Force Detection**: Tracks rolling failed login counts in a 10-minute sliding window per IP.
   - **Suspicious Actions**: Automatically flags port scans, privilege escalations, and unapproved file transfers.
   - **Context Indicators**: Tags unusual login times (11:00 PM – 5:00 AM) and administrative events.
3. **Machine Learning Anomaly Detection**: Trains an **Isolation Forest** model to detect multivariate outliers that static rules miss.
4. **Relational SQLite Database Storage**: Saves enriched logs to an optimized schema containing custom indexes on Timestamp, Severity, IP Address, and Anomalies.
5. **Cyberpunk Command Center Dashboard**:
   - KPIs: Ingestion volume, failed login rates, high-severity threat counts, and ML outliers.
   - Interactive Filters: Time window, severity multi-select, ML status, origin country, action type, and access device.
   - Rich Data Visualizations: Time-series area charts, severity donut charts, authentication outcomes, top attacking IPs, and a global geo-distribution map.
   - Live Incident Feed: Simulated command terminal showing the latest threat alerts.
   - Export Reports: Dynamic download of filtered logs as CSV reports.

---

## Tech Stack & Dependencies

- **Frontend / Interface**: Streamlit
- **Visualization**: Plotly, Seaborn, Matplotlib
- **Data Preprocessing & Analytics**: Pandas, NumPy
- **Machine Learning**: Scikit-Learn (Isolation Forest, LabelEncoder)
- **Database**: SQLite3
- **Language**: Python 3.8+

---

##  Repository Structure

```text
cybersecurity/
├── dataset/
│   ├── sample_logs.csv         # Generated raw log dataset
│   └── security_logs.db        # SQLite database file containing logs
├── scripts/
│   ├── generate_logs.py        # Realistic security log generator
│   ├── data_cleaning.py        # Logs preprocessing & sanitization
│   ├── log_analysis.py         # Rolling window & rule-based engine
│   ├── anomaly_detection.py    # Isolation Forest ML classification
│   └── database.py             # SQLite interface & query repository
├── dashboard/
│   └── dashboard.py            # Streamlit interactive application
├── reports/
│   ├── cleaned_logs_preview.csv # Cleaned preview CSV
│   └── threat_report.csv       # Exported security reports
├── screenshots/
│   └── dashboard_preview.png   # Dashboard dashboard preview
├── requirements.txt            # Python package dependencies
├── run.py                      # Main entrypoint runner
└── README.md                   # Project documentation (this file)
```

---

##  SQL Schema

The SQLite schema is structured for quick aggregation and searching. An index is applied to the most heavily queried columns:

```sql
CREATE TABLE security_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL,
    ip_address TEXT NOT NULL,
    username TEXT NOT NULL,
    login_status TEXT NOT NULL,
    country TEXT NOT NULL,
    event_type TEXT NOT NULL,
    device TEXT NOT NULL,
    severity TEXT NOT NULL,
    is_anomaly INTEGER NOT NULL,
    threat_description TEXT,
    hour INTEGER,
    recent_failures INTEGER
);

-- Optimization Indexes
CREATE INDEX idx_timestamp ON security_logs (timestamp);
CREATE INDEX idx_ip ON security_logs (ip_address);
CREATE INDEX idx_severity ON security_logs (severity);
CREATE INDEX idx_anomaly ON security_logs (is_anomaly);
```

---

##  Installation & Setup

Follow these steps to run the project on your local machine.

### 1. Clone & Navigate to Workspace


### 2. Install Dependencies
Install all required Python libraries:
```bash
pip install -r requirements.txt
```

### 3. Run the System
The project includes a single entrypoint script (`run.py`) which generates the sample data, runs the cleaning/analysis/ML pipeline, populates the SQLite database, and automatically launches the Streamlit dashboard:

```bash
python run.py
```

*Alternative CLI arguments:*
* Run the pipeline without launching the dashboard:
  ```bash
  python run.py --pipeline-only
  ```
* Force regeneration of raw sample logs (e.g. to start with fresh timestamps):
  ```bash
  python run.py --generate
  ```
* Start the dashboard manually if database is already populated:
  ```bash
  streamlit run dashboard/dashboard.py
  ```

---

##  Dataset Sample

Below is an illustration of the cleaned and enriched schema:

| Timestamp | IP Address | Username | Login Status | Country | Event Type | Device | Severity | Is_Anomaly | Threat Description |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 2026-05-24 14:02:10 | 185.220.12.94 | admin | Failed | Russia | Login | Linux | High | 1 | Brute Force Attack: 6 failed logins in 10m from IP 185.220.12.94 |
| 2026-05-24 14:02:15 | 185.220.12.94 | admin | Success | Russia | Login | Linux | High | 1 | Critical: Successful Privilege Escalation by user 'admin' |
| 2026-05-25 03:15:00 | 200.140.85.12 | db_admin | Success | Brazil | Data Export | MacOS | High | 1 | Critical: Bulk Data Export at unusual hour (3:00) by 'db_admin' |
| 2026-05-25 09:30:12 | 192.168.1.45 | jdoe | Success | United States | File Access | Windows | Low | 0 | Normal event |

---

##  Future Improvements
- **SIEM Ingestion Integration**: Support streaming ingest from syslog-ng, Logstash, or AWS CloudWatch.
- **Geolocation Lookup**: Integrate MaxMind GeoIP API for live country and city lookup of dynamic IPs.
- **Deep Anomaly Explanations**: Integrate SHAP (SHapley Additive exPlanations) to show why the Isolation Forest flagged a specific log as anomalous.
- **Real-Time SMS/Email Alerts**: Hook webhook notifications using Twilio or Slack APIs to notify security analysts when High-severity alerts are triggered.
