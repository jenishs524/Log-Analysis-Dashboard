# Log-Analysis-Dashboard

🎯 Objective

To build a centralised log analysis platform that:

    Aggregates logs from multiple sources (e.g., /var/log/syslog, Apache/Nginx access logs, application logs).

    Parses structured and unstructured log entries to extract key fields (timestamp, source IP, user, event type, status code, message).

    Identifies suspicious patterns, anomalies, and known attack signatures (SQL injection attempts, brute‑force login failures, error spikes).

    Visualises data through a real‑time dashboard showing metrics, alerts, and historical trends.

    Generates automated reports for compliance and incident response.

This tool is designed to bridge the gap between simple grep‑based log checking and full‑fledged SIEM systems like Splunk or Elastic Stack, providing immediate value without the overhead of complex infrastructure.
🧠 How It Works – Technical Overview

The Log Analysis Dashboard combines three core components:
1. Log Ingestion & Parsing

    File Tailing: Continuously tails (tail -f) specified log files in real time using subprocess and Python generators.

    Multiformat Support: Parses common log formats (Apache Combined Log Format, Syslog RFC 3164/5424, JSON logs, custom application logs).

    Regex Extraction: Uses robust regular expressions to extract key fields: timestamp, source IP, username, event type, HTTP method, URI, status code, response size, and error messages.

2. Analysis & Correlation Engine

    Rule‑Based Detection: Applies a library of configurable rules to flag suspicious events (e.g., more than 10 failed logins from a single IP in 60 seconds, SQL injection patterns in query strings, 404 error spikes).

    Statistical Anomaly Detection: Computes baselines (average request rate, error percentage) and flags deviations beyond standard thresholds.

    Attack Signature Matching: Leverages a curated list of regex patterns for SQLi, XSS, command injection, path traversal, and known exploit attempts.

3. Dashboard & Reporting

    Live Metrics: Displays real‑time counters (requests/sec, error rate, top IPs, top URLs, status code distribution) updated at configurable intervals.

    Alert Feed: Shows a scrolling feed of triggered alerts with severity levels (INFO, WARN, HIGH, CRITICAL).

    Historical Graphs: Tracks trends over time (hourly, daily, weekly) to identify patterns, such as a gradual increase in error rates or recurring attack spikes at specific times.

    Exportable Reports: Generates JSON/HTML reports summarizing key findings for a given time period (e.g., "Top 10 attackers", "Most targeted endpoints", "Suspicious events count").

✨ Advanced Features (Real‑World Upgrade)
Feature	Implementation
Real‑Time Log Tailing	Continuously streams logs and processes events with sub‑second latency, ensuring immediate alerting.
Multi‑Log Source Support	Simultaneously consumes logs from multiple files (syslog, web server, auth logs, application logs) and correlates them.
Custom Rule Engine	Users can define custom rules via JSON configuration (e.g., {"pattern":"Failed password.*from (\\d+\.\\d+\.\\d+\.\\d+)", "action":"alert", "severity":"HIGH"}).
Statistical Baselines	Automatically calculates normal behaviour patterns and triggers alerts when thresholds are exceeded (e.g., 200% increase in 404 errors).
Geolocation Enrichment	Resolves source IPs to country/city (using a local GeoIP database) to identify traffic from high‑risk regions.
Dashboard Visualisations	Generates live charts (bar charts, line graphs, pie charts) using lightweight JavaScript libraries (e.g., Chart.js) for an intuitive view.
Alert Deduplication	Suppresses repeated alerts for the same event within a configurable time window to prevent alert fatigue.
Historical Storage & Indexing	Stores parsed logs in a SQLite/MySQL database for fast historical querying and trend analysis.
Incident Playbook Links	Provides direct links to incident response playbooks when specific alerts are triggered (e.g., "SSH brute‑force" → "Block IP via firewall").
🛠️ Tools & Technologies

    Python 3 – core engine for parsing, analysis, and API logic.

    tail (subprocess) – efficient, low‑overhead log streaming.

    Regular Expressions (regex) – flexible and fast parsing of varied log formats.

    SQLite / MySQL – optional lightweight storage for historical analysis.

    Flask / FastAPI – lightweight web framework for the dashboard interface.

    Chart.js / D3.js – frontend visualisation libraries (if a web UI is included).

    dateutil / datetime – temporal parsing and calculations.

🔬 Testing & Typical Use Case

Scenario:
A SOC analyst is responsible for monitoring a medium‑sized e‑commerce web application. They deploy the Log Analysis Dashboard to centrally collect logs from the web server (/var/log/nginx/access.log), SSH service (/var/log/auth.log), and application error log.

Process:

    Configure the dashboard to tail all three log files.

    Set up rules:

        Alert if 502 Bad Gateway errors exceed 5 per minute (potential application failure).

        Alert if an IP attempts more than 10 failed SSH logins in 5 minutes.

        Alert if any request contains union select or drop table (SQL injection attempt).

    Observe real‑time dashboard:

        Metrics panel: Shows 150 requests/min, 0.5% error rate, top IP 192.168.1.100.

        Alert feed: [HIGH] 192.168.1.100 attempted SQL injection on /login (triggered at 14:32:15).

        Traffic graph: Shows a spike in requests at 14:30, correlating with the attack.

Outcome:

    The analyst blocks the attacking IP using the firewall command provided in the alert.

    The dashboard continues monitoring and detects that the attack has stopped.

    At the end of the shift, the analyst generates a daily report listing all triggered alerts, top offending IPs, and an overall risk summary.

This scenario demonstrates how the tool empowers a single analyst to effectively monitor and respond to threats without investing in a full‑scale SIEM infrastructure.
📁 Report Output Example (Dashboard Export)

A typical report (JSON or HTML) contains:

    Time Period – Start and end of the monitoring window.

    Total Log Entries Processed – Overall count.

    Alert Summary – Number of alerts by severity (HIGH, MEDIUM, LOW).

    Top Attackers – List of IPs with the most suspicious events.

    Top Targeted Resources – Most frequently attacked URLs or endpoints.

    Error Rate Trends – Daily/hourly breakdown of error status codes (4xx, 5xx).

    Recommendations – Actionable security steps based on findings (e.g., "Increase rate limiting on /login").

📝 Conclusion

The Log Analysis Dashboard is a versatile and powerful tool that bridges the gap between manual log inspection and enterprise‑grade SIEM solutions. It provides real‑time visibility into system and application health, enables rapid detection of attacks and operational issues, and offers structured reporting for compliance. Its flexible rule engine and multi‑source log support make it adaptable to a wide range of environments. During testing, it successfully detected SSH brute‑force attempts, SQL injection probes, and application errors, demonstrating its effectiveness as a central monitoring and alerting platform. It is an essential component of any SOC analyst’s toolkit and serves as a strong foundation for developing custom security monitoring solutions.
