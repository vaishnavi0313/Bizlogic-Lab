# 🧠 Business Logic & Workflow Exploitation Lab (CLI Tool)

Business Logic & Workflow Exploitation Lab is a **command-line based cybersecurity tool** designed to identify logical flaws in web applications.

Unlike traditional scanners, this tool focuses on **how applications behave**, helping users detect vulnerabilities by simulating real-world attack scenarios such as workflow manipulation, parameter tampering, and race conditions.

---

## 🚨 Problem Statement

Most security tools focus on technical vulnerabilities (SQLi, XSS, etc.), but **business logic vulnerabilities** are often missed.

Attackers exploit flaws in application workflows such as:

* Bypassing payment systems
* Reusing coupons
* Manipulating order processes
* Accessing unauthorized data

These issues are difficult to detect automatically and require **attacker mindset + workflow understanding**.

This project provides a tool to simulate such attacks and detect logic flaws.

---

## ⚙️ How It Works

### 1. User Input

The user enters a target URL in the terminal.

---

### 2. Attack Selection

The tool provides multiple attack levels:

* Basic
* Semi-Advanced
* Advanced

---

### 3. Attack Execution

The system simulates attacks such as:

* Parameter tampering (price, quantity, user_id)
* Workflow manipulation (skip steps, repeat actions)
* Coupon abuse testing
* Privilege escalation attempts
* Race condition testing using parallel requests

---

### 4. Analysis

The tool evaluates server responses to detect:

* Unexpected success responses
* Price inconsistencies
* Unauthorized access
* Workflow bypass issues

---

### 5. Result Classification

```text
[✓] Safe → No issues detected  
[⚠️] Suspicious → Potential logic flaw  
[🚨] Vulnerable → High-risk business logic issue
```

---

### 6. Report Generation

After execution, the tool generates:

* `report.txt` → Raw findings
* `report.pdf` → Structured vulnerability report

---

## 🧰 Technology Stack

### Core

* Python 3

### Libraries

* requests
* threading
* reportlab (PDF generation)

---

## ✨ Key Features

* CLI-based tool (runs in PowerShell / CMD)
* Multi-level attack simulation
* Payload mutation engine
* Workflow-based testing approach
* Race condition detection
* Automated report generation
* Real-world bug bounty oriented logic

---

## ⚔️ Attack Modules

### 🔹 Basic

* Price tampering
* Quantity manipulation
* Coupon reuse
* IDOR (user_id manipulation)

---

### 🔸 Semi-Advanced

* Workflow skipping (direct checkout)
* Repeated actions (coupon abuse)
* Privilege escalation simulation

---

### 🔥 Advanced

* Race condition testing (parallel requests)
* Replay attacks
* Combined logic bypass
* Server behavior analysis

---

## ▶️ Usage

Run the tool in terminal:

```bash
python logic_lab.py
```

---

### CLI Flow

```text
Enter target URL: http://localhost:3000

Select Attack Mode:
1. Basic
2. Semi-Advanced
3. Advanced
4. Exit
```

---

## ⚠️ Disclaimer

This tool is intended for **educational purposes and authorized security testing only**.

Do NOT use this tool on:

* Production systems
* Websites without permission

---

## 🎯 Learning Objectives

* Understand business logic vulnerabilities
* Develop attacker mindset
* Practice bug bounty techniques
* Learn workflow-based exploitation

---

## 🔮 Future Improvements

* Selenium-based workflow recording
* Proxy integration (mitmproxy)
* AI-based anomaly detection
* Browser extension support

---

## 👨‍💻 Author

Vaishnavi
Cybersecurity Student

---
