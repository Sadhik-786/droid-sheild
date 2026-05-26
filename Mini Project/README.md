# Android Malicious App Detection System - Hybrid Security Dashboard

Welcome to the **Android Malicious App Detection System using Hybrid Malware Analysis** web application. 

This client-side Single Page Application (SPA) brings the entire product requirements (PRD), technical design (TRD), and high-level client-server architecture to life. It features a premium, responsive, cybersecurity-themed dashboard built with custom HTML5, CSS3, and modern JavaScript.

---

## 🚀 Key Modules & Capabilities

1. **Executive Dashboard**:
   - Displays real-time aggregate telemetry: total scans conducted, malware items flagged, average device threat risk rating, and active rule definitions.
   - Charts distribution metrics dynamically using **Chart.js**.
   - Pulls and categorizes active warnings inside the "Recent Threat Alerts" feed.

2. **App Scanner**:
   - Includes **7 preset app profiles** to test immediately, ranging from safe communication tools (WhatsApp) to highly malicious payloads (ransomware, SMS Trojans).
   - Features a **Dynamic Android Manifest XML Parser**—paste any raw `AndroidManifest.xml` layout to parse `<uses-permission>` nodes on-the-fly.
   - Triggers simulated scanning animations showing step-by-step diagnostic milestones.

3. **Permission Analyzer**:
   - Indexes a detailed catalog of Android API permissions.
   - Provides a searchable directory categorizing permissions into **Dangerous** vs **Normal**, with technical write-ups explaining how malware exploits them.

4. **Machine Learning Model Visualizer**:
   - Explains the **Random Forest Classifier** ensemble algorithm.
   - Renders interactive node-based tree structures for the 3 decision classifiers: *SMS & Overlay Tree*, *Spyware & Data Leak Tree*, and *Location & Admin Tree*.
   - **Highlights traversed node paths in real-time** according to the scanned app's active permission feature vectors.
   - Plots feature importance weights using a horizontal chart.

5. **Simulated SQLite Database (malware_detector.db)**:
   - Emulates tables `scan_history` and `malware_rules` backed by local storage persistence.
   - Features an **Interactive SQL Console Prompt** where you can write custom queries (e.g. `SELECT * FROM scan_history WHERE risk_score > 50`) and render results in a formatted output table.

6. **Malware Rules Registry**:
   - Displays active static rule parameters parsed by the intersection checker.
   - Lets you create, edit, or delete custom rules using a modal checkbox form. Changes instantly update the detection engine!

7. **Client-Server API Monitor**:
   - Inspects the client-server boundary.
   - Logs simulated HTTP communications (`POST /predict` and `GET /history`), network status codes, latency, payload JSON contents, and SQL transactions.

---

## 🛠️ How to Run & Verify the Web Application

1. Open your web browser (Chrome, Edge, Firefox, or Safari).
2. Use **Ctrl+O** (or Command+O on macOS) and select the [index.html](file:///c:/Mini%20Project/index.html) file located in this directory.
3. Click on the sidebar items to navigate between tabs.
4. Go to **App Scanner**, select **Android System Update Helper** (or paste your own manifest), and click **Run Malware Analysis** to see the hybrid scan in action!
