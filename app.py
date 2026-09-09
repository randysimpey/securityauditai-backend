"""
SecurityAuditAI — MVP scan backend

Accepts a public GitHub repo URL, clones it, runs:
  - Gitleaks  -> hardcoded secrets / leaked credentials (incl. git history)
  - Trivy     -> dependency vulnerabilities (SCA) + IaC misconfigurations

...then emails a summary report to the submitter.

NOT included in this MVP: live API security scanning (requires a running
endpoint, not a static repo — different tool/threat model, see README).
"""

import hashlib
import hmac
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import requests
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, field_validator

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("securityauditai")

app = FastAPI(title="SecurityAuditAI Scan Service")

# In-memory job store — fine for MVP traffic on a single instance.
# NOTE: this resets on redeploy/restart (Render free tier can spin down on
# inactivity), so it's a live-progress cache, not a permanent record. The
# email is the durable copy of every report.
JOBS: dict[str, dict] = {}
JOB_TTL_SECONDS = 3600

FREE_SCANS_PER_MONTH = 1

# Allow your website/form to call this API directly from the browser.
# Tighten this to your actual domain once it's live.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

GITHUB_URL_RE = re.compile(r"^https://github\.com/[\w.-]+/[\w.-]+/?$")

# Safety limits — free tier is rate-limited (see check_free_tier_limit below);
# Pro users (marked via Stripe webhook) bypass the monthly cap entirely.
MAX_REPO_SIZE_MB = int(os.environ.get("MAX_REPO_SIZE_MB", "300"))
CLONE_TIMEOUT_SEC = int(os.environ.get("CLONE_TIMEOUT_SEC", "120"))
SCAN_TIMEOUT_SEC = int(os.environ.get("SCAN_TIMEOUT_SEC", "180"))


# --- Upstash Redis (REST) — stores Pro status + free-tier monthly usage ---
def redis_cmd(*args):
    base = os.environ["UPSTASH_REDIS_REST_URL"].rstrip("/")
    token = os.environ["UPSTASH_REDIS_REST_TOKEN"]
    url = base + "/" + "/".join(quote(str(a), safe="") for a in args)
    resp = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=10)
    resp.raise_for_status()
    return resp.json().get("result")


def is_pro(email: str) -> bool:
    try:
        return redis_cmd("GET", f"pro:{email.lower()}") == "1"
    except Exception:
        log.exception("Redis GET failed — failing open (treat as not-pro, but don't block the request)")
        return False


def mark_pro(email: str) -> None:
    redis_cmd("SET", f"pro:{email.lower()}", "1")


def unmark_pro(email: str) -> None:
    redis_cmd("DEL", f"pro:{email.lower()}")


def check_free_tier_limit(email: str) -> None:
    """Raises HTTPException if a non-Pro email has already used its free
    scan(s) this calendar month. Silently allows the request through if
    Redis itself is unreachable — a scan should never hard-fail because of
    the rate limiter being down."""
    month_key = datetime.now(timezone.utc).strftime("%Y-%m")
    key = f"freeuse:{email.lower()}:{month_key}"
    try:
        count = int(redis_cmd("INCR", key))
        if count == 1:
            redis_cmd("EXPIRE", key, 40 * 86400)
    except HTTPException:
        raise
    except Exception:
        log.exception("Redis INCR failed — failing open, allowing the scan")
        return
    if count > FREE_SCANS_PER_MONTH:
        raise HTTPException(
            status_code=402,
            detail=(
                f"Free tier limit reached ({FREE_SCANS_PER_MONTH} scan/month). "
                f"Upgrade to SecurityAuditAI Pro for unlimited scans."
            ),
        )


class ScanRequest(BaseModel):
    repo_url: str
    email: EmailStr

    @field_validator("repo_url")
    @classmethod
    def validate_github_url(cls, v: str) -> str:
        v = v.strip()
        if not GITHUB_URL_RE.match(v):
            raise ValueError(
                "repo_url must be a public GitHub URL, e.g. "
                "https://github.com/owner/repo"
            )
        return v.rstrip("/")


class SubscribeRequest(BaseModel):
    email: EmailStr


_AUDIENCE_ID_CACHE: str | None = None
AUDIENCE_NAME = "CipherCapital Subscribers"


def get_or_create_audience() -> str:
    """Reuse the Resend Audience if it already exists, else create it once.
    Cached in-process so we don't hit the API on every signup."""
    global _AUDIENCE_ID_CACHE
    if _AUDIENCE_ID_CACHE:
        return _AUDIENCE_ID_CACHE

    api_key = os.environ["RESEND_API_KEY"]
    headers = {"Authorization": f"Bearer {api_key}"}

    resp = requests.get("https://api.resend.com/audiences", headers=headers, timeout=15)
    resp.raise_for_status()
    for aud in resp.json().get("data", []):
        if aud.get("name") == AUDIENCE_NAME:
            _AUDIENCE_ID_CACHE = aud["id"]
            log.info("Reusing existing Resend audience id=%s", aud["id"])
            return _AUDIENCE_ID_CACHE

    create_resp = requests.post(
        "https://api.resend.com/audiences",
        headers=headers,
        json={"name": AUDIENCE_NAME},
        timeout=15,
    )
    create_resp.raise_for_status()
    _AUDIENCE_ID_CACHE = create_resp.json()["id"]
    log.info("Created new Resend audience id=%s", _AUDIENCE_ID_CACHE)
    return _AUDIENCE_ID_CACHE


@app.post("/subscribe")
def subscribe(req: SubscribeRequest):
    api_key = os.environ["RESEND_API_KEY"]
    try:
        audience_id = get_or_create_audience()
        resp = requests.post(
            f"https://api.resend.com/audiences/{audience_id}/contacts",
            headers={"Authorization": f"Bearer {api_key}"},
            json={"email": req.email, "unsubscribed": False},
            timeout=15,
        )
        if resp.status_code == 409 or (resp.status_code == 400 and "already exists" in resp.text.lower()):
            return {"status": "already_subscribed", "message": "You're already on the list."}
        resp.raise_for_status()
        log.info("SUBSCRIBED email=%s", req.email)
        return {"status": "subscribed", "message": "You're on the list."}
    except requests.HTTPError as exc:
        log.error("Subscribe failed email=%s status=%s body=%s", req.email, exc.response.status_code, exc.response.text)
        raise HTTPException(status_code=502, detail="Could not subscribe right now — try again shortly.")


@app.get("/")
def health():
    return {"status": "ok", "service": "SecurityAuditAI scan backend"}


@app.post("/scan")
def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    if not is_pro(req.email):
        check_free_tier_limit(req.email)

    job_id = uuid.uuid4().hex[:12]
    JOBS[job_id] = {
        "status": "queued",
        "stage": "queued",
        "repo_url": req.repo_url,
        "created_at": time.time(),
        "summary": None,
        "error": None,
    }
    background_tasks.add_task(run_scan_and_email, req.repo_url, req.email, job_id)
    return {
        "status": "queued",
        "job_id": job_id,
        "message": f"Scan started for {req.repo_url}. "
        f"Report will be emailed to {req.email} shortly.",
    }


@app.get("/scan/{job_id}")
def get_scan_status(job_id: str):
    job = JOBS.get(job_id)
    if job is None:
        raise HTTPException(
            status_code=404,
            detail="Unknown job_id — it may have expired after a server restart.",
        )
    return job


@app.post("/webhook/stripe")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")
    webhook_secret = os.environ["STRIPE_WEBHOOK_SECRET"]

    verify_stripe_signature(payload, sig_header, webhook_secret)
    event = json.loads(payload)
    event_type = event.get("type")
    log.info("STRIPE WEBHOOK received type=%s id=%s", event_type, event.get("id"))

    if event_type == "checkout.session.completed":
        session = event["data"]["object"]
        email = session.get("customer_details", {}).get("email")
        customer_id = session.get("customer")
        if email:
            mark_pro(email)
            if customer_id:
                redis_cmd("SET", f"customer_email:{customer_id}", email)
            log.info("PRO ACTIVATED email=%s", email)
    elif event_type == "customer.subscription.deleted":
        customer_id = event["data"]["object"].get("customer")
        email = redis_cmd("GET", f"customer_email:{customer_id}") if customer_id else None
        if email:
            unmark_pro(email)
            log.info("PRO DEACTIVATED email=%s", email)
        else:
            log.warning("Could not find email for cancelled customer=%s", customer_id)

    return {"received": True}


def verify_stripe_signature(payload: bytes, sig_header: str, secret: str) -> None:
    try:
        parts = dict(p.split("=", 1) for p in sig_header.split(","))
        timestamp, signature = parts["t"], parts["v1"]
    except Exception:
        raise HTTPException(status_code=400, detail="Malformed Stripe-Signature header")

    signed_payload = f"{timestamp}.".encode() + payload
    expected = hmac.new(secret.encode(), signed_payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise HTTPException(status_code=400, detail="Invalid Stripe webhook signature")


@app.get("/scan-test")
def start_scan_get(repo_url: str, email: str, background_tasks: BackgroundTasks):
    """Convenience GET version so a scan can be triggered by opening a URL
    in a browser, without needing curl or a form. Same validation as /scan."""
    req = ScanRequest(repo_url=repo_url, email=email)

    if not is_pro(req.email):
        check_free_tier_limit(req.email)

    job_id = uuid.uuid4().hex[:12]
    JOBS[job_id] = {
        "status": "queued",
        "stage": "queued",
        "repo_url": req.repo_url,
        "created_at": time.time(),
        "summary": None,
        "error": None,
    }
    background_tasks.add_task(run_scan_and_email, req.repo_url, req.email, job_id)
    return {
        "status": "queued",
        "job_id": job_id,
        "message": f"Scan started for {req.repo_url}. "
        f"Report will be emailed to {req.email} shortly.",
    }


def run_scan_and_email(repo_url: str, email: str, job_id: str) -> None:
    def update(stage: str, **extra):
        if job_id in JOBS:
            JOBS[job_id]["stage"] = stage
            JOBS[job_id].update(extra)

    workdir = Path(tempfile.mkdtemp(prefix="saai_"))
    repo_dir = workdir / "repo"
    log.info("SCAN START repo=%s email=%s job=%s workdir=%s", repo_url, email, job_id, workdir)
    try:
        update("cloning", status="running")
        clone_repo(repo_url, repo_dir)
        log.info("CLONE OK repo=%s", repo_url)

        check_repo_size(repo_dir)
        log.info("SIZE CHECK OK repo=%s", repo_url)

        update("scanning_secrets")
        gitleaks_findings = run_gitleaks(repo_dir, workdir)
        log.info("GITLEAKS OK findings=%d", len(gitleaks_findings))

        update("scanning_dependencies")
        trivy_findings = run_trivy(repo_dir, workdir)
        log.info("TRIVY OK")

        vuln_count = sum(len(r.get("Vulnerabilities") or []) for r in trivy_findings.get("Results", []))
        misconfig_count = sum(len(r.get("Misconfigurations") or []) for r in trivy_findings.get("Results", []))
        summary = {
            "secrets": len(gitleaks_findings),
            "vulnerabilities": vuln_count,
            "misconfigurations": misconfig_count,
        }
        update("emailing", summary=summary)

        report_text = build_report(repo_url, gitleaks_findings, trivy_findings)
        log.info("SENDING EMAIL to=%s", email)
        send_email(email, f"Your security audit for {repo_url}", report_text)
        log.info("EMAIL SENT to=%s", email)

        update("done", status="done")

    except Exception as exc:  # noqa: BLE001 — MVP: report failures by email too
        log.exception("SCAN FAILED repo=%s error=%s", repo_url, exc)
        update("failed", status="failed", error=str(exc)[:300])
        try:
            send_email(
                email,
                f"Security audit failed for {repo_url}",
                f"We couldn't complete the scan.\n\nReason: {exc}\n\n"
                f"If this repo is large or private, that's likely why — "
                f"reply to this email and we'll take a look.",
            )
        except Exception:
            log.exception("FAILURE EMAIL ALSO FAILED for=%s", email)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def clone_repo(repo_url: str, dest: Path) -> None:
    result = subprocess.run(
        ["git", "clone", "--depth", "50", repo_url, str(dest)],
        capture_output=True,
        text=True,
        timeout=CLONE_TIMEOUT_SEC,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git clone failed: {result.stderr.strip()[:300]}")


def check_repo_size(repo_dir: Path) -> None:
    total_bytes = sum(f.stat().st_size for f in repo_dir.rglob("*") if f.is_file())
    size_mb = total_bytes / (1024 * 1024)
    if size_mb > MAX_REPO_SIZE_MB:
        raise RuntimeError(
            f"Repo is {size_mb:.0f} MB, over the {MAX_REPO_SIZE_MB} MB MVP limit."
        )


def run_gitleaks(repo_dir: Path, workdir: Path) -> list[dict]:
    report_path = workdir / "gitleaks.json"
    subprocess.run(
        [
            "./gitleaks", "detect",
            "--source", str(repo_dir),
            "--report-format", "json",
            "--report-path", str(report_path),
            "--exit-code", "0",  # don't treat "leaks found" as a process failure
        ],
        capture_output=True,
        text=True,
        timeout=SCAN_TIMEOUT_SEC,
    )
    if report_path.exists():
        data = json.loads(report_path.read_text() or "[]")
        return data if isinstance(data, list) else []
    return []


def run_trivy(repo_dir: Path, workdir: Path) -> dict:
    report_path = workdir / "trivy.json"
    subprocess.run(
        [
            "./trivy", "fs",
            "--scanners", "vuln,misconfig",
            "--format", "json",
            "--output", str(report_path),
            "--timeout", f"{SCAN_TIMEOUT_SEC}s",
            str(repo_dir),
        ],
        capture_output=True,
        text=True,
        timeout=SCAN_TIMEOUT_SEC + 15,
    )
    if report_path.exists():
        return json.loads(report_path.read_text() or "{}")
    return {}


def build_report(repo_url: str, gitleaks_findings: list[dict], trivy_data: dict) -> str:
    lines = [
        f"SecurityAuditAI — Free Scan Report",
        f"Repository: {repo_url}",
        "=" * 50,
        "",
        "1. SECRETS DETECTION",
        "-" * 30,
    ]

    if gitleaks_findings:
        lines.append(f"⚠ {len(gitleaks_findings)} potential secret(s) found:")
        for f in gitleaks_findings[:15]:
            lines.append(
                f"  - [{f.get('RuleID', 'unknown')}] {f.get('File', '?')}"
                f" (line {f.get('StartLine', '?')})"
            )
        if len(gitleaks_findings) > 15:
            lines.append(f"  ...and {len(gitleaks_findings) - 15} more.")
    else:
        lines.append("✅ No hardcoded secrets detected.")

    lines += ["", "2. DEPENDENCY VULNERABILITIES (SCA)", "-" * 30]
    vuln_count = 0
    for result in trivy_data.get("Results", []):
        vulns = result.get("Vulnerabilities") or []
        vuln_count += len(vulns)
        for v in vulns[:10]:
            lines.append(
                f"  - [{v.get('Severity', '?')}] {v.get('PkgName', '?')} "
                f"{v.get('InstalledVersion', '?')} — {v.get('VulnerabilityID', '?')}"
            )
    if vuln_count == 0:
        lines.append("✅ No known dependency vulnerabilities detected.")
    else:
        lines.append(f"⚠ {vuln_count} known vulnerabilities found across dependencies.")

    lines += ["", "3. INFRASTRUCTURE AS CODE (IaC)", "-" * 30]
    misconfig_count = 0
    for result in trivy_data.get("Results", []):
        misconfigs = result.get("Misconfigurations") or []
        misconfig_count += len(misconfigs)
        for m in misconfigs[:10]:
            lines.append(f"  - [{m.get('Severity', '?')}] {m.get('Title', '?')}")
    if misconfig_count == 0:
        lines.append("✅ No IaC misconfigurations detected.")
    else:
        lines.append(f"⚠ {misconfig_count} misconfiguration(s) found.")

    lines += [
        "",
        "4. API SECURITY",
        "-" * 30,
        "Not included in this free static scan — API security requires testing",
        "a live endpoint, not just the repo. Ask us about a manual API review.",
        "",
        "=" * 50,
        "Want this automatically on every commit? See SecurityAuditAI Pro.",
    ]
    return "\n".join(lines)


def send_email(to_email: str, subject: str, body: str) -> None:
    api_key = os.environ["RESEND_API_KEY"]
    from_email = os.environ.get("FROM_EMAIL", "onboarding@resend.dev")

    log.info("Resend API call to=%s", to_email)

    response = requests.post(
        "https://api.resend.com/emails",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "from": from_email,
            "to": [to_email],
            "subject": subject,
            "text": body,
        },
        timeout=20,
    )
    if not response.ok:
        log.error("Resend error status=%s body=%s", response.status_code, response.text)
    response.raise_for_status()
    log.info("Resend accepted email id=%s", response.json().get("id"))
