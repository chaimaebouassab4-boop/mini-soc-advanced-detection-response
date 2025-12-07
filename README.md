# mini-soc-advanced-detection-response
A fully local Mini-SOC implementing real log detection, hybrid analysis (heuristics + local LLM via LM Studio), and automated response (IP blocking, alerts, webhooks). Designed for cybersecurity hands-on training.

🔭 Overview

Traditional SOCs rely on static rules or expensive cloud SIEMs. This project bridges the gap by running a Local Large Language Model (Mistral 7B) via LM Studio to analyze system logs contextually.

The system monitors Linux server logs, detects anomalies (like SSH Brute-force or Network Scanning), and autonomously configures the firewall (UFW) to block attackers.

Why Local AI?

Privacy: Sensitive logs never leave your server.

Cost: Zero API fees (runs on consumer hardware).

Control: Full sovereignty over the detection logic.


🏗 Architecture

The system is built as a pipeline of 4 independent Python agents communicating via REST APIs:

👁️ Log Tailer: Watches system logs (auth.log, ufw.log, nginx/access.log) in real-time.

📨 Collector: Aggregates and normalizes raw log lines into JSON events.

🧠 Analyzer (The Brain): A Hybrid Engine combining:

Fast Heuristics: For high-volume attacks (e.g., threshold detection).

Local AI: For contextual analysis of ambiguous threats.

🛡️ Responder: Executes the defense action (e.g., sudo ufw deny from <IP>).



