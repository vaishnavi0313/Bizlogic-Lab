#!/usr/bin/env python3
"""
=============================================================
  Business Logic & Workflow Exploitation Lab
  Author  : Cybersecurity Student Project
  Purpose : Simulate business logic attacks for VAPT testing
  Usage   : python biz_logic_lab.py
  WARNING : For authorized testing ONLY. Never run against
            systems you do not have explicit permission to test.
=============================================================
"""

import requests
import threading
import time
import datetime
import os
import sys
import json
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

# ─────────────────────────────────────────────
#  ANSI COLOR CODES (work in most terminals)
# ─────────────────────────────────────────────
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
MAGENTA = "\033[95m"
BOLD    = "\033[1m"
RESET   = "\033[0m"

# ─────────────────────────────────────────────
#  GLOBAL FINDINGS COLLECTOR
#  Every attack appends results here so the
#  report generator can consume them later.
# ─────────────────────────────────────────────
findings = []          # list of finding dicts
raw_log  = []          # plain-text log lines (for TXT report)

def log(msg, tag="INFO"):
    """Print to terminal and store in raw_log for reports."""
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    line = f"[{timestamp}] [{tag}] {msg}"
    raw_log.append(line)
    print(line)

def banner():
    print(f"""
{CYAN}{BOLD}
╔══════════════════════════════════════════════════════════════╗
║      Business Logic & Workflow Exploitation Lab v1.0         ║
║      For authorized penetration testing only                 ║
╚══════════════════════════════════════════════════════════════╝
{RESET}""")

def warn_disclaimer():
    print(f"{YELLOW}⚠  DISCLAIMER: This tool simulates attacks for educational and")
    print(f"   authorized VAPT purposes only. Unauthorized use is illegal.{RESET}\n")

# ─────────────────────────────────────────────────────────────
#  SECTION 1 — PAYLOAD MUTATION ENGINE
#  Automatically generates variations of a base payload.
#  Real attackers mutate payloads to bypass filters; this
#  engine models that behaviour for testing purposes.
# ─────────────────────────────────────────────────────────────

def mutate_payload(base: dict) -> list:
    """
    Given a base payload dict, produce a list of mutated copies.
    Mutations include: negative values, zero, very large numbers,
    type-confusion strings, boundary values, and combined extremes.
    """
    mutations = []

    # Original
    mutations.append(("original", dict(base)))

    for key, val in base.items():
        if isinstance(val, (int, float)):
            mutations.append((f"{key}=0",          {**base, key: 0}))
            mutations.append((f"{key}=-1",         {**base, key: -1}))
            mutations.append((f"{key}=999999",     {**base, key: 999999}))
            mutations.append((f"{key}=0.001",      {**base, key: 0.001}))
            mutations.append((f"{key}=string",     {**base, key: "abc"}))
        elif isinstance(val, str):
            mutations.append((f"{key}=empty",      {**base, key: ""}))
            mutations.append((f"{key}=null",       {**base, key: "null"}))
            mutations.append((f"{key}=admin",      {**base, key: "admin"}))
            mutations.append((f"{key}=../etc",     {**base, key: "../etc/passwd"}))

    return mutations


# ─────────────────────────────────────────────────────────────
#  SECTION 2 — HTTP HELPER
#  Thin wrapper around requests so every call is logged and
#  we never crash the tool on connection errors.
# ─────────────────────────────────────────────────────────────

def safe_request(method, url, **kwargs):
    """
    Send an HTTP request; return (response, error_string).
    Timeout is 10 s by default to keep tests snappy.
    """
    try:
        kwargs.setdefault("timeout", 10)
        resp = requests.request(method, url, **kwargs)
        return resp, None
    except requests.exceptions.ConnectionError:
        return None, "Connection refused / host unreachable"
    except requests.exceptions.Timeout:
        return None, "Request timed out"
    except Exception as e:
        return None, str(e)


def record_finding(vuln_type, detail, severity="MEDIUM", response=None):
    """Store a finding and print it in a coloured format."""
    entry = {
        "type":     vuln_type,
        "detail":   detail,
        "severity": severity,
        "status":   response.status_code if response else "N/A",
        "time":     datetime.datetime.now().isoformat(),
    }
    findings.append(entry)

    colour = RED if severity == "HIGH" else YELLOW if severity == "MEDIUM" else GREEN
    sym    = "[!]" if severity != "SAFE" else "[✓]"
    print(f"  {colour}{BOLD}{sym} {vuln_type}{RESET} — {detail}  (HTTP {entry['status']})")
    raw_log.append(f"  {sym} {vuln_type} — {detail}  (HTTP {entry['status']})")


# ─────────────────────────────────────────────────────────────
#  SECTION 3 — BASIC ATTACKS
#  Goal: test the simplest business-logic flaws that developers
#  often forget because they trust client-supplied values.
# ─────────────────────────────────────────────────────────────

def basic_attack(target_url):
    print(f"\n{CYAN}{BOLD}[ BASIC ATTACK MODULE ]{RESET}")
    log("Starting Basic Attack — parameter tampering, coupon abuse, IDOR")

    # ── 3a. Price Tampering ───────────────────────────────────
    # Why it matters: if price is read from the request body
    # instead of the server-side catalogue, an attacker can
    # buy items for free.
    print(f"\n  {MAGENTA}▶ 3a. Payment / Price Tampering{RESET}")
    log("Running payment bypass test...")

    base_payload = {"item_id": 1, "price": 100, "quantity": 1}
    mutations    = mutate_payload(base_payload)

    for label, payload in mutations[:6]:          # test first 6 mutations
        resp, err = safe_request("POST", f"{target_url}/checkout", json=payload)
        if err:
            log(f"  Price tamper [{label}]: {err}", "WARN")
            continue
        if resp.status_code in (200, 201):
            if payload.get("price", 100) <= 0:
                record_finding(
                    "Price Tampering",
                    f"Server accepted price={payload['price']} → possible free purchase",
                    "HIGH", resp
                )
            else:
                record_finding("Price Test", f"payload={label}", "SAFE", resp)
        else:
            log(f"  Price tamper [{label}]: HTTP {resp.status_code}", "INFO")

    # ── 3b. Quantity Abuse ────────────────────────────────────
    # Why it matters: negative or massive quantities can cause
    # inventory corruption or credit to the attacker's account.
    print(f"\n  {MAGENTA}▶ 3b. Quantity Abuse{RESET}")
    log("Testing quantity abuse...")

    for qty in [0, -1, 999999, -999999]:
        payload = {"item_id": 1, "price": 100, "quantity": qty}
        resp, err = safe_request("POST", f"{target_url}/checkout", json=payload)
        if err:
            log(f"  Quantity [{qty}]: {err}", "WARN")
            continue
        if resp.status_code in (200, 201) and qty < 0:
            record_finding(
                "Negative Quantity",
                f"Server accepted quantity={qty} → may credit attacker",
                "HIGH", resp
            )
        else:
            log(f"  Quantity [{qty}]: HTTP {resp.status_code}", "INFO")

    # ── 3c. Coupon Reuse ──────────────────────────────────────
    # Why it matters: if the server doesn't track coupon usage
    # per user, coupons can be applied unlimited times.
    print(f"\n  {MAGENTA}▶ 3c. Coupon Reuse{RESET}")
    log("Testing coupon abuse...")

    for i in range(3):
        payload = {"coupon": "SAVE50", "order_id": 1001}
        resp, err = safe_request("POST", f"{target_url}/apply-coupon", json=payload)
        if err:
            log(f"  Coupon attempt #{i+1}: {err}", "WARN")
            continue
        if resp.status_code == 200:
            record_finding(
                "Coupon Reuse",
                f"Coupon accepted on attempt #{i+1} — server may not track usage",
                "HIGH", resp
            )
        else:
            log(f"  Coupon attempt #{i+1}: HTTP {resp.status_code}", "INFO")

    # ── 3d. Basic IDOR ────────────────────────────────────────
    # Why it matters: if object IDs are sequential and not
    # validated against session ownership, any authenticated
    # user can read/modify other users' data.
    print(f"\n  {MAGENTA}▶ 3d. IDOR — Insecure Direct Object Reference{RESET}")
    log("Testing basic IDOR on user_id...")

    for uid in [1, 2, 3, 100, 9999]:
        resp, err = safe_request("GET", f"{target_url}/user/{uid}/orders")
        if err:
            log(f"  IDOR user_id={uid}: {err}", "WARN")
            continue
        if resp.status_code == 200:
            record_finding(
                "IDOR",
                f"user_id={uid} returned 200 — no ownership check?",
                "HIGH", resp
            )
        else:
            log(f"  IDOR user_id={uid}: HTTP {resp.status_code}", "INFO")

    log("Basic Attack module complete.")


# ─────────────────────────────────────────────────────────────
#  SECTION 4 — SEMI-ADVANCED ATTACKS
#  Goal: test workflow integrity — can steps be skipped? Can
#  privileges be escalated by modifying request fields?
# ─────────────────────────────────────────────────────────────

def semi_advanced_attack(target_url):
    print(f"\n{CYAN}{BOLD}[ SEMI-ADVANCED ATTACK MODULE ]{RESET}")
    log("Starting Semi-Advanced Attack — workflow manipulation & privilege escalation")

    # ── 4a. Step-Skip (direct checkout) ──────────────────────
    # Why it matters: multi-step workflows (add-to-cart →
    # address → payment → confirm) often only enforce the final
    # step server-side, allowing attackers to skip earlier ones.
    print(f"\n  {MAGENTA}▶ 4a. Workflow Step-Skip — direct checkout{RESET}")
    log("Testing workflow manipulation: skipping to checkout directly...")

    payload = {"item_id": 42, "price": 299, "skip_address": True, "skip_payment": True}
    resp, err = safe_request("POST", f"{target_url}/order/confirm", json=payload)
    if err:
        log(f"  Step-skip: {err}", "WARN")
    elif resp.status_code in (200, 201):
        record_finding(
            "Workflow Step-Skip",
            "Order confirmed without going through payment/address steps",
            "HIGH", resp
        )
    else:
        log(f"  Step-skip: HTTP {resp.status_code}", "INFO")

    # ── 4b. Repeat Coupon via Workflow Replay ─────────────────
    # Why it matters: state machines that don't persist
    # intermediate state on the server can be exploited by
    # replaying earlier workflow steps.
    print(f"\n  {MAGENTA}▶ 4b. Coupon Stacking via Workflow Replay{RESET}")
    log("Testing coupon stacking...")

    for i in range(5):
        resp, err = safe_request(
            "POST", f"{target_url}/cart/coupon",
            json={"coupon_code": "DISCOUNT10", "cart_id": 777}
        )
        if err:
            log(f"  Coupon stack #{i+1}: {err}", "WARN")
            continue
        if resp.status_code == 200:
            record_finding(
                "Coupon Stacking",
                f"Coupon applied {i+1} times successfully",
                "HIGH", resp
            )
        else:
            log(f"  Coupon stack #{i+1}: HTTP {resp.status_code} (expected rejection)", "INFO")
            break

    # ── 4c. Privilege Escalation via Parameter ────────────────
    # Why it matters: if the server trusts a "role" or "is_admin"
    # field sent in the request body, any user can self-promote.
    print(f"\n  {MAGENTA}▶ 4c. Privilege Escalation — role=admin injection{RESET}")
    log("Testing privilege escalation simulation...")

    priv_payloads = [
        {"username": "testuser", "role": "admin"},
        {"username": "testuser", "is_admin": True},
        {"username": "testuser", "user_type": "superuser"},
        {"username": "testuser", "access_level": 9},
    ]
    for payload in priv_payloads:
        resp, err = safe_request("POST", f"{target_url}/profile/update", json=payload)
        if err:
            log(f"  Priv-esc [{list(payload.keys())[-1]}]: {err}", "WARN")
            continue
        if resp.status_code == 200:
            record_finding(
                "Privilege Escalation",
                f"Server accepted {payload} without server-side role validation",
                "HIGH", resp
            )
        else:
            log(f"  Priv-esc [{list(payload.keys())[-1]}]: HTTP {resp.status_code}", "INFO")

    # ── 4d. Response Comparison ───────────────────────────────
    # Why it matters: comparing responses for admin vs normal
    # endpoints reveals whether access controls differ.
    print(f"\n  {MAGENTA}▶ 4d. Response Comparison — normal vs admin endpoints{RESET}")
    log("Running response comparison...")

    endpoints = ["/api/orders", "/api/admin/orders", "/api/users", "/api/admin/users"]
    for ep in endpoints:
        resp, err = safe_request("GET", f"{target_url}{ep}")
        if err:
            log(f"  {ep}: {err}", "WARN")
            continue
        status = resp.status_code
        label = f"{GREEN}[✓] Properly restricted{RESET}" if status in (401, 403) else \
                f"{RED}[!] Unexpectedly accessible{RESET}"
        print(f"    {ep} → HTTP {status} {label}")
        raw_log.append(f"    {ep} → HTTP {status}")
        if status == 200 and "admin" in ep:
            record_finding(
                "Broken Access Control",
                f"Admin endpoint {ep} returned 200 without auth",
                "HIGH", resp
            )

    log("Semi-Advanced Attack module complete.")


# ─────────────────────────────────────────────────────────────
#  SECTION 5 — ADVANCED ATTACKS
#  Goal: race conditions, replay attacks, and combined
#  mutations — the hardest flaws to catch in code review.
# ─────────────────────────────────────────────────────────────

# Thread-safe list for collecting race-condition results
race_results = []
race_lock    = threading.Lock()

def _race_worker(url, payload, thread_id):
    """Worker function executed by each thread in race-condition test."""
    resp, err = safe_request("POST", url, json=payload)
    with race_lock:
        if err:
            race_results.append({"thread": thread_id, "status": "ERROR", "detail": err})
        else:
            race_results.append({"thread": thread_id, "status": resp.status_code,
                                  "body_len": len(resp.text)})

def advanced_attack(target_url):
    print(f"\n{CYAN}{BOLD}[ ADVANCED ATTACK MODULE ]{RESET}")
    log("Starting Advanced Attack — race conditions, replay, combined mutations")

    race_results.clear()

    # ── 5a. Race Condition ────────────────────────────────────
    # Why it matters: when two requests arrive simultaneously,
    # servers without proper locking may process both before
    # either commits to the database (e.g., double-spend).
    print(f"\n  {MAGENTA}▶ 5a. Race Condition — parallel requests{RESET}")
    log("Launching race condition test with 10 parallel threads...")

    payload   = {"coupon": "ONCE_ONLY", "order_id": 5001}
    threads   = []
    thread_count = 10

    for i in range(thread_count):
        t = threading.Thread(
            target=_race_worker,
            args=(f"{target_url}/apply-coupon", payload, i)
        )
        threads.append(t)

    # Fire all threads simultaneously
    start = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = round(time.time() - start, 2)

    successes = [r for r in race_results if r.get("status") == 200]
    log(f"  Race test complete in {elapsed}s — {len(successes)}/{thread_count} threads got 200")

    if len(successes) > 1:
        record_finding(
            "Race Condition",
            f"{len(successes)} parallel requests all succeeded — coupon/action not atomic",
            "HIGH"
        )
    else:
        record_finding("Race Condition", "No race condition detected (only 0-1 success)", "SAFE")

    # Print thread results table
    print(f"  {'Thread':<8} {'Status':<10} {'Body Len'}")
    print(f"  {'──────':<8} {'──────':<10} {'────────'}")
    for r in race_results:
        status_col = f"{GREEN}{r['status']}{RESET}" if r['status'] == 200 else str(r['status'])
        print(f"  {r['thread']:<8} {status_col:<10} {r.get('body_len', r.get('detail', 'N/A'))}")

    # ── 5b. Replay Attack ─────────────────────────────────────
    # Why it matters: if a transaction token is not invalidated
    # after first use, an attacker can replay it to duplicate
    # the action (e.g., get two shipments for one payment).
    print(f"\n  {MAGENTA}▶ 5b. Replay Attack — reusing transaction tokens{RESET}")
    log("Testing replay attack...")

    token   = "txn_sample_abc123"       # sample token that should be single-use
    statuses = []

    for attempt in range(3):
        resp, err = safe_request(
            "POST", f"{target_url}/payment/confirm",
            json={"token": token, "amount": 500}
        )
        if err:
            log(f"  Replay #{attempt+1}: {err}", "WARN")
            continue
        statuses.append(resp.status_code)
        log(f"  Replay attempt #{attempt+1}: HTTP {resp.status_code}")

    if statuses.count(200) > 1:
        record_finding(
            "Replay Attack",
            f"Transaction token accepted {statuses.count(200)} times — not invalidated after use",
            "HIGH"
        )
    else:
        record_finding("Replay Attack", "Token properly invalidated after first use", "SAFE")

    # ── 5c. Combined Mutation Attack ──────────────────────────
    # Why it matters: combining multiple flaws (price tampering +
    # coupon abuse + privilege escalation) often bypasses
    # defences designed to catch each flaw in isolation.
    print(f"\n  {MAGENTA}▶ 5c. Combined Mutation — price + coupon + role{RESET}")
    log("Running combined payload mutations...")

    combined_payloads = [
        {"item_id": 1, "price": 0,    "quantity": 1,    "coupon": "SAVE50", "role": "admin"},
        {"item_id": 1, "price": -1,   "quantity": -1,   "coupon": "FREE",   "is_admin": True},
        {"item_id": 1, "price": 0.01, "quantity": 9999, "coupon": "SAVE50", "user_type": "staff"},
    ]

    for i, payload in enumerate(combined_payloads, 1):
        resp, err = safe_request("POST", f"{target_url}/checkout", json=payload)
        if err:
            log(f"  Combined #{i}: {err}", "WARN")
            continue
        if resp.status_code in (200, 201):
            record_finding(
                "Combined Logic Bypass",
                f"Combined payload #{i} accepted — multiple flaws exploitable together",
                "HIGH", resp
            )
        else:
            log(f"  Combined #{i}: HTTP {resp.status_code}", "INFO")

    # ── 5d. Inconsistency Detection ───────────────────────────
    # Why it matters: servers sometimes return different results
    # for identical requests (caching bugs, race conditions, or
    # A/B deployment mismatches) which attackers can exploit.
    print(f"\n  {MAGENTA}▶ 5d. Server Inconsistency Detection{RESET}")
    log("Checking for inconsistent server behaviour...")

    probe_url = f"{target_url}/cart/total"
    probe_payload = {"cart_id": 9999, "currency": "USD"}
    response_bodies = []

    for _ in range(5):
        resp, err = safe_request("GET", probe_url, params=probe_payload)
        if err:
            break
        response_bodies.append(resp.text)
        time.sleep(0.2)

    if response_bodies:
        unique_responses = set(response_bodies)
        if len(unique_responses) > 1:
            record_finding(
                "Server Inconsistency",
                f"Same request returned {len(unique_responses)} different responses — unstable logic",
                "MEDIUM"
            )
        else:
            record_finding(
                "Server Consistency",
                "Consistent responses across repeated identical requests",
                "SAFE"
            )

    log("Advanced Attack module complete.")


# ─────────────────────────────────────────────────────────────
#  SECTION 6 — ANALYZER / RESULT SUMMARY
# ─────────────────────────────────────────────────────────────

def print_summary():
    print(f"\n{CYAN}{BOLD}{'═'*60}")
    print(f"  ATTACK SUMMARY")
    print(f"{'═'*60}{RESET}")

    high   = [f for f in findings if f["severity"] == "HIGH"]
    medium = [f for f in findings if f["severity"] == "MEDIUM"]
    safe   = [f for f in findings if f["severity"] == "SAFE"]

    print(f"  {RED}HIGH severity  : {len(high)}{RESET}")
    print(f"  {YELLOW}MEDIUM severity: {len(medium)}{RESET}")
    print(f"  {GREEN}SAFE / clean   : {len(safe)}{RESET}")
    print(f"  Total findings : {len(findings)}")
    print()

    for f in findings:
        if f["severity"] == "HIGH":
            print(f"  {RED}[!] {f['type']}: {f['detail']}{RESET}")
        elif f["severity"] == "MEDIUM":
            print(f"  {YELLOW}[~] {f['type']}: {f['detail']}{RESET}")
        else:
            print(f"  {GREEN}[✓] {f['type']}: {f['detail']}{RESET}")

    print(f"\n{CYAN}{BOLD}{'═'*60}{RESET}")


# ─────────────────────────────────────────────────────────────
#  SECTION 7 — REPORT GENERATION
#  Saves a plain-text report and a formatted PDF.
# ─────────────────────────────────────────────────────────────

def save_txt_report(target_url, attack_name, filename):
    """Write the raw log and findings to a .txt file."""
    with open(filename, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("  BUSINESS LOGIC & WORKFLOW EXPLOITATION LAB — REPORT\n")
        f.write("=" * 70 + "\n")
        f.write(f"  Target     : {target_url}\n")
        f.write(f"  Attack     : {attack_name}\n")
        f.write(f"  Generated  : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 70 + "\n\n")

        f.write("── ACTIVITY LOG ──\n")
        for line in raw_log:
            # strip ANSI codes for clean text
            clean = line
            for code in [RED, GREEN, YELLOW, CYAN, MAGENTA, BOLD, RESET]:
                clean = clean.replace(code, "")
            f.write(clean + "\n")

        f.write("\n── FINDINGS ──\n")
        for idx, finding in enumerate(findings, 1):
            f.write(f"\n[{idx}] {finding['type']} ({finding['severity']})\n")
            f.write(f"    Detail  : {finding['detail']}\n")
            f.write(f"    HTTP    : {finding['status']}\n")
            f.write(f"    Time    : {finding['time']}\n")

        high_count = len([f for f in findings if f["severity"] == "HIGH"])
        f.write(f"\n── SUMMARY ──\n")
        f.write(f"  HIGH: {high_count}  |  MEDIUM: {len([f for f in findings if f['severity']=='MEDIUM'])}  |  SAFE: {len([f for f in findings if f['severity']=='SAFE'])}\n")

    print(f"  {GREEN}[✓] TXT report saved → {filename}{RESET}")


def save_pdf_report(target_url, attack_name, filename):
    """Generate a formatted PDF report using reportlab."""
    doc    = SimpleDocTemplate(filename, pagesize=letter,
                               rightMargin=0.75*inch, leftMargin=0.75*inch,
                               topMargin=0.75*inch, bottomMargin=0.75*inch)
    styles = getSampleStyleSheet()
    story  = []

    # Custom styles
    title_style = ParagraphStyle("Title2", parent=styles["Title"],
                                 fontSize=18, textColor=colors.HexColor("#1a1a2e"),
                                 spaceAfter=6)
    h2_style    = ParagraphStyle("H2", parent=styles["Heading2"],
                                 fontSize=13, textColor=colors.HexColor("#16213e"),
                                 spaceBefore=12, spaceAfter=4)
    body_style  = ParagraphStyle("Body", parent=styles["Normal"],
                                 fontSize=10, leading=14)
    code_style  = ParagraphStyle("Code", parent=styles["Normal"],
                                 fontSize=8, fontName="Courier",
                                 backColor=colors.HexColor("#f5f5f5"),
                                 leftIndent=12, leading=12)
    sev_high    = ParagraphStyle("SevHigh", parent=body_style,
                                 textColor=colors.red)
    sev_med     = ParagraphStyle("SevMed",  parent=body_style,
                                 textColor=colors.HexColor("#e67e00"))
    sev_safe    = ParagraphStyle("SevSafe", parent=body_style,
                                 textColor=colors.green)

    # ── Header ───────────────────────────────────────────────
    story.append(Paragraph("Business Logic &amp; Workflow Exploitation Lab", title_style))
    story.append(Paragraph("Penetration Test Report", styles["Heading3"]))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#1a1a2e")))
    story.append(Spacer(1, 10))

    # Meta table
    meta = [
        ["Target URL",  target_url],
        ["Attack Type", attack_name],
        ["Generated",   datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
        ["Tool",        "BizLogic Lab v1.0"],
    ]
    meta_table = Table(meta, colWidths=[1.5*inch, 5*inch])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#1a1a2e")),
        ("TEXTCOLOR",  (0, 0), (0, -1), colors.white),
        ("FONTNAME",   (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE",   (0, 0), (-1, -1), 10),
        ("ROWBACKGROUNDS", (1, 0), (-1, -1), [colors.HexColor("#f0f0f0"), colors.white]),
        ("BOX",        (0, 0), (-1, -1), 0.5, colors.grey),
        ("GRID",       (0, 0), (-1, -1), 0.25, colors.lightgrey),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING",(0, 0), (-1, -1), 8),
        ("RIGHTPADDING",(0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",(0,0),(-1,-1), 5),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 16))

    # ── Summary Box ───────────────────────────────────────────
    story.append(Paragraph("Executive Summary", h2_style))
    high_count   = len([f for f in findings if f["severity"] == "HIGH"])
    medium_count = len([f for f in findings if f["severity"] == "MEDIUM"])
    safe_count   = len([f for f in findings if f["severity"] == "SAFE"])

    summary_data = [
        ["Severity", "Count", "Risk Level"],
        ["HIGH",   str(high_count),   "Critical — immediate remediation required"],
        ["MEDIUM", str(medium_count), "Moderate — should be addressed"],
        ["SAFE",   str(safe_count),   "No issue detected"],
    ]
    summary_table = Table(summary_data, colWidths=[1*inch, 0.8*inch, 4.5*inch])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0),  colors.HexColor("#1a1a2e")),
        ("TEXTCOLOR",  (0, 0), (-1, 0),  colors.white),
        ("FONTNAME",   (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, -1), 10),
        ("BACKGROUND", (0, 1), (-1, 1),  colors.HexColor("#fdecea")),
        ("BACKGROUND", (0, 2), (-1, 2),  colors.HexColor("#fff8e1")),
        ("BACKGROUND", (0, 3), (-1, 3),  colors.HexColor("#e8f5e9")),
        ("BOX",        (0, 0), (-1, -1), 0.5, colors.grey),
        ("GRID",       (0, 0), (-1, -1), 0.25, colors.lightgrey),
        ("LEFTPADDING",(0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",(0,0),(-1,-1), 5),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 16))

    # ── Detailed Findings ─────────────────────────────────────
    story.append(Paragraph("Detailed Findings", h2_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.grey))
    story.append(Spacer(1, 6))

    if not findings:
        story.append(Paragraph("No findings recorded.", body_style))
    else:
        for idx, f in enumerate(findings, 1):
            sev_colour = {"HIGH": colors.red, "MEDIUM": colors.HexColor("#e67e00"),
                          "SAFE": colors.green}.get(f["severity"], colors.black)
            row_header = Table(
                [[f"Finding #{idx}  —  {f['type']}", f["severity"]]],
                colWidths=[5.5*inch, 0.8*inch]
            )
            row_header.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f5f5f5")),
                ("TEXTCOLOR",  (1, 0), (1, 0),   sev_colour),
                ("FONTNAME",   (0, 0), (-1, -1), "Helvetica-Bold"),
                ("FONTSIZE",   (0, 0), (-1, -1), 10),
                ("LEFTPADDING",(0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING",(0,0),(-1,-1), 5),
                ("ALIGN",      (1, 0), (1, 0),   "RIGHT"),
            ]))
            story.append(row_header)

            detail_data = [
                ["Detail",   f["detail"]],
                ["HTTP",     str(f["status"])],
                ["Time",     f["time"]],
            ]
            detail_table = Table(detail_data, colWidths=[0.9*inch, 5.4*inch])
            detail_table.setStyle(TableStyle([
                ("FONTNAME",   (0, 0), (0, -1),  "Helvetica-Bold"),
                ("FONTSIZE",   (0, 0), (-1, -1), 9),
                ("LEFTPADDING",(0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING",(0,0),(-1,-1), 3),
                ("ROWBACKGROUNDS",(0, 0),(-1,-1),[colors.white, colors.HexColor("#fafafa")]),
                ("BOX",        (0, 0), (-1, -1), 0.25, colors.lightgrey),
            ]))
            story.append(detail_table)
            story.append(Spacer(1, 8))

    # ── Activity Log ──────────────────────────────────────────
    story.append(Paragraph("Activity Log", h2_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.grey))
    story.append(Spacer(1, 4))

    for line in raw_log[-60:]:          # cap at last 60 lines to keep PDF lean
        clean = line
        for code in [RED, GREEN, YELLOW, CYAN, MAGENTA, BOLD, RESET]:
            clean = clean.replace(code, "")
        story.append(Paragraph(clean, code_style))

    # ── Disclaimer ────────────────────────────────────────────
    story.append(Spacer(1, 16))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.grey))
    disclaimer = (
        "<b>Disclaimer:</b> This report was generated by an automated tool for "
        "educational and authorised penetration testing purposes only. "
        "Results are indicative and require manual verification. "
        "Unauthorised use against systems you do not own is illegal."
    )
    story.append(Paragraph(disclaimer, ParagraphStyle(
        "Disc", parent=body_style, fontSize=8, textColor=colors.grey, spaceBefore=6
    )))

    doc.build(story)
    print(f"  {GREEN}[✓] PDF report saved → {filename}{RESET}")


def generate_reports(target_url, attack_name):
    """Save both TXT and PDF reports to the current directory."""
    ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"bizlogic_report_{ts}"

    print(f"\n{CYAN}{BOLD}[ GENERATING REPORTS ]{RESET}")
    save_txt_report(target_url, attack_name, f"{base}.txt")
    save_pdf_report(target_url, attack_name, f"{base}.pdf")
    print(f"\n  Reports saved in: {os.getcwd()}")


# ─────────────────────────────────────────────────────────────
#  SECTION 8 — SAMPLE PAYLOAD DEMO
#  Prints sample payloads so a tester can understand what the
#  tool sends before running against a live target.
# ─────────────────────────────────────────────────────────────

def show_sample_payloads():
    print(f"\n{CYAN}{BOLD}[ SAMPLE PAYLOADS REFERENCE ]{RESET}")
    samples = {
        "Price Tampering":        {"item_id": 1, "price": 0,    "quantity": 1},
        "Negative Quantity":      {"item_id": 1, "price": 100,  "quantity": -1},
        "Coupon Reuse":           {"coupon": "SAVE50",           "order_id": 1001},
        "IDOR":                   {"user_id": 99,               "action": "view_orders"},
        "Privilege Escalation":   {"username": "user",          "role": "admin"},
        "Race Condition Trigger": {"coupon": "ONCE_ONLY",       "order_id": 5001},
        "Replay Attack":          {"token": "txn_abc123",       "amount": 500},
        "Combined Bypass":        {"price": 0, "coupon": "FREE","role": "admin", "qty": 9999},
    }
    for name, payload in samples.items():
        print(f"\n  {MAGENTA}{name}{RESET}")
        print(f"  {json.dumps(payload, indent=4)}")


# ─────────────────────────────────────────────────────────────
#  SECTION 9 — MAIN CLI MENU
# ─────────────────────────────────────────────────────────────

def main():
    banner()
    warn_disclaimer()

    # Collect target URL
    target_url = input(f"{BOLD}[?] Enter target URL (e.g. http://localhost:5000): {RESET}").strip()
    if not target_url.startswith("http"):
        target_url = "http://" + target_url
    target_url = target_url.rstrip("/")
    print(f"  Target set → {CYAN}{target_url}{RESET}\n")

    attack_name = "N/A"

    while True:
        print(f"\n{BOLD}{'─'*50}")
        print(f"  MAIN MENU")
        print(f"{'─'*50}{RESET}")
        print(f"  {CYAN}1.{RESET} Basic Attack       (parameter tampering, IDOR, coupon)")
        print(f"  {CYAN}2.{RESET} Semi-Advanced       (workflow skip, priv-esc, comparison)")
        print(f"  {CYAN}3.{RESET} Advanced Attack     (race condition, replay, combined)")
        print(f"  {CYAN}4.{RESET} Show Sample Payloads")
        print(f"  {CYAN}5.{RESET} Generate Report     (saves TXT + PDF for last run)")
        print(f"  {CYAN}6.{RESET} Exit")

        choice = input(f"\n{BOLD}[?] Select option (1-6): {RESET}").strip()

        if choice == "1":
            attack_name = "Basic Attack"
            findings.clear(); raw_log.clear()
            basic_attack(target_url)
            print_summary()

        elif choice == "2":
            attack_name = "Semi-Advanced Attack"
            findings.clear(); raw_log.clear()
            semi_advanced_attack(target_url)
            print_summary()

        elif choice == "3":
            attack_name = "Advanced Attack"
            findings.clear(); raw_log.clear()
            advanced_attack(target_url)
            print_summary()

        elif choice == "4":
            show_sample_payloads()

        elif choice == "5":
            if not findings:
                print(f"  {YELLOW}[!] No attack data — run an attack first.{RESET}")
            else:
                generate_reports(target_url, attack_name)

        elif choice == "6":
            print(f"\n  {GREEN}Exiting. Stay ethical. 🛡{RESET}\n")
            sys.exit(0)

        else:
            print(f"  {RED}Invalid choice. Enter 1-6.{RESET}")


# ─────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    main()


# =============================================================
#  HOW EACH ATTACK WORKS & REAL-WORLD VAPT VALUE
# =============================================================
#
#  1. PRICE / PARAMETER TAMPERING
#     How: Send HTTP requests with modified fields (price=0).
#     Why: Many apps read price from the request body instead
#     of the server-side catalogue, trusting the client.
#     VAPT value: Demonstrates that ALL business-critical values
#     must be validated and sourced server-side.
#
#  2. NEGATIVE QUANTITY ABUSE
#     How: Set quantity to a negative integer.
#     Why: A negative quantity * negative price = credit.
#     Some carts blindly multiply; attacker gets money back.
#     VAPT value: Shows missing numeric validation on order lines.
#
#  3. COUPON REUSE / STACKING
#     How: Apply the same coupon code in a loop.
#     Why: Without server-side usage tracking per user/order,
#     coupons can be applied unlimited times.
#     VAPT value: Demonstrates missing idempotency controls.
#
#  4. IDOR (Insecure Direct Object Reference)
#     How: Change user_id or order_id in the URL/body.
#     Why: If the server doesn't verify the object belongs
#     to the requesting session, any user can access any data.
#     VAPT value: One of OWASP Top 10 — extremely common.
#
#  5. WORKFLOW STEP-SKIP
#     How: POST directly to the final confirmation endpoint,
#     skipping address/payment steps.
#     Why: Multi-step workflows that only enforce the last step
#     allow attackers to bypass fraud checks or payment.
#     VAPT value: Exposes missing state-machine validation.
#
#  6. PRIVILEGE ESCALATION VIA PARAMETER
#     How: Add role=admin or is_admin=true to the request.
#     Why: If the server reads roles from the request body
#     instead of the session/JWT, any user becomes admin.
#     VAPT value: Exposes broken access control design.
#
#  7. RACE CONDITION
#     How: Fire 10 identical requests simultaneously with
#     Python's threading module.
#     Why: Without database-level locking (SELECT FOR UPDATE),
#     two requests can both pass the "coupon not used?" check
#     before either commits, allowing double redemption.
#     VAPT value: Critical for fintech/e-commerce targets.
#
#  8. REPLAY ATTACK
#     How: Reuse a transaction token across multiple requests.
#     Why: One-time tokens that are not invalidated server-side
#     after first use allow attackers to replay payments or
#     actions (e.g., get two shipments for one payment).
#     VAPT value: Common in payment gateway integrations.
#
#  9. COMBINED MUTATION
#     How: Send a single request with price=0, coupon, AND
#     role=admin simultaneously.
#     Why: Defences designed to catch one flaw at a time often
#     fail when multiple flaws are exploited together.
#     VAPT value: Realistic attacker behaviour; catches weak
#     composed defences.
#
# 10. PAYLOAD MUTATION ENGINE
#     How: Automatically generates boundary/edge-case variants
#     of any base payload (zero, negative, huge numbers, etc.).
#     Why: Mirrors what a skilled manual tester does; covers
#     input classes that developers often forget to validate.
#     VAPT value: Increases test coverage without extra effort.
#
# =============================================================
