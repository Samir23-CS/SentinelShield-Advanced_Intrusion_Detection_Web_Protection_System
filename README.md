#SentinelShield: AdvancedIntrusion Detection Web Protection System

SentinelShield is a Python-based, real-time web security application designed to detect, analyze, and block common web attacks before they compromise your system. Built using Flask with advanced pattern matching, rate-limiting, and automated IP blocking, this project demonstrates a full-stack approach to modern cybersecurity for web applications.

🚀 Key Features

Real-Time Threat Detection: Monitors incoming requests and identifies attacks such as SQL Injection, XSS, Command Injection, Directory Traversal, and LFI/RFI using configurable regex-based signatures.

Adaptive Severity Engine: Automatically calculates confidence levels and severity scores (LOW → CRITICAL) based on attack frequency and type.

Rate Limiting & Brute Force Protection: Detects rapid repeated requests and automatically flags or blocks abusive IPs.

IP Ban Mechanism: High-risk IPs are temporarily banned after multiple critical attacks, ensuring proactive threat containment.

Structured Security Logging: Logs every request with attack type, severity, confidence, endpoint, payload, and IP address, providing actionable insights for monitoring and auditing.

Metrics & Dashboard Endpoints: Track attack distribution, flagged IPs, banned IPs, uptime, and request counts through /metrics and /dashboard endpoints.

Extensible Architecture: Easily add new attack signatures, customize severity rules, or integrate with SIEM tools for enterprise deployment.

📌 Technical Highlights

Python 3.14+ & Flask – Lightweight and fast web framework for API handling.

Regex-Based Attack Signatures – Flexible detection for multiple attack vectors.

UTC-Timestamped Security Events – Ensures accurate audit logs for compliance.

Rate-Limited & Configurable Ban Duration – Prevents brute-force attacks while avoiding false positives.

Logging – Logs to both console and file, with warning and critical levels for actionable alerting.

🎯 Use Cases

Security monitoring for internal tools or public-facing web applications.

Portfolio showcase for cybersecurity engineers or ethical hackers.

Learning and experimentation with web attack detection, rate limiting, and automated mitigation.

📂 Project Structure

app.py – Main Flask application managing requests, detection, and blocking logic.

signal_model.py – Security event model defining attack metadata (IP, attack type, severity, confidence, payload, etc.).

sentinelshield.log – Runtime log of all security events and request activity.

💡 Why SentinelShield Stands Out

Proactive & Real-Time: Detects attacks before damage occurs.

Professional Logging: Security events are structured for easy ingestion into SIEM tools.

Flexible & Extensible: Add new signatures or thresholds with minimal effort.

Enterprise-Ready Concepts: Combines rate limiting, attack classification, severity scoring, and IP banning — all key for real-world web defense.

🖥️ Demo
# Run the application
python app.py

# Access the service
http://127.0.0.1:5000

# View metrics
http://127.0.0.1:5000/metrics

# View recent attack events
http://127.0.0.1:5000/dashboard

SentinelShield isn’t just a project — it’s a showcase of real-world cybersecurity skills, combining Python development, web security, and proactive monitoring.
