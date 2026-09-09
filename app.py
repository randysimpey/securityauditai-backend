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
    """True for both Pro and Business — used for uncapped scanning."""
    return get_tier(email) in ("pro", "business")


def get_tier(email: str) -> str:
    try:
        tier = redis_cmd("GET", f"tier:{email.lower()}")
        return tier if tier in ("pro", "business") else "free"
    except Exception:
        log.exception("Redis GET failed — failing open (treat as free tier)")
        return "free"


def set_tier(email: str, tier: str) -> None:
    redis_cmd("SET", f"tier:{email.lower()}", tier)


def unmark_pro(email: str) -> None:
    redis_cmd("DEL", f"tier:{email.lower()}")


# Maps a Stripe Payment Link ID to the tier it grants.
PAYMENT_LINK_TIERS = {
    # Test mode (Cipher Capital sandbox account)
    "plink_1UDX0uFyLwFaAD3Q772TkRmD": "pro",
    "plink_1UDizpFyLwFaAD3QVbYdvcn5": "business",
    # Live mode (Cipher Capital account)
    "plink_1UDjRqCQ26ATxEcCYbhNkZLn": "pro",
    "plink_1UDjRvCQ26ATxEcCkSsyv0gi": "business",
}

PRO_REPO_LIMIT = 5


def check_repo_limit(email: str, repo_url: str) -> None:
    """Pro is capped at 5 distinct repos (ever). Business is unlimited.
    Free tier never reaches this — it's blocked earlier by check_free_tier_limit."""
    if get_tier(email) == "business":
        return
    key = f"pro_repos:{email.lower()}"
    try:
        existing = redis_cmd("SMEMBERS", key) or []
        if repo_url in existing:
            return  # already-scanned repo, doesn't count against the cap
        if len(existing) >= PRO_REPO_LIMIT:
            raise HTTPException(
                status_code=402,
                detail=(
                    f"Pro is limited to {PRO_REPO_LIMIT} repos. "
                    f"Upgrade to Business for unlimited repos."
                ),
            )
        redis_cmd("SADD", key, repo_url)
    except HTTPException:
        raise
    except Exception:
        log.exception("Redis repo-limit check failed — failing open")


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


class RegisterRepoRequest(BaseModel):
    repo_url: str
    email: EmailStr

    @field_validator("repo_url")
    @classmethod
    def validate_github_url(cls, v: str) -> str:
        v = v.strip()
        if not GITHUB_URL_RE.match(v):
            raise ValueError("repo_url must be a public GitHub URL, e.g. https://github.com/owner/repo")
        return v.rstrip("/")


@app.post("/business/register-repo")
def register_repo(req: RegisterRepoRequest):
    """Business tier only. Links a repo to a Business account so pushes to it
    trigger an automatic scan. Returns a webhook secret the customer adds to
    their GitHub repo's webhook settings."""
    if get_tier(req.email) != "business":
        raise HTTPException(
            status_code=402,
            detail="Auto-scan on commit is a Business-tier feature. Upgrade to enable it.",
        )

    secret = uuid.uuid4().hex + uuid.uuid4().hex  # 64 hex chars
    redis_cmd("SET", f"business_repo:{req.repo_url}", json.dumps({"email": req.email, "secret": secret}))

    owner_repo = req.repo_url.replace("https://github.com/", "")
    webhook_url = f"https://securityauditai-backend.onrender.com/webhook/github/{owner_repo}"

    return {
        "status": "registered",
        "webhook_url": webhook_url,
        "webhook_secret": secret,
        "instructions": (
            f"In your GitHub repo → Settings → Webhooks → Add webhook. "
            f"Payload URL: {webhook_url} — Content type: application/json — "
            f"Secret: (the webhook_secret above) — Events: 'Just the push event'."
        ),
    }


@app.post("/webhook/github/{owner}/{repo}")
async def github_webhook(owner: str, repo: str, request: Request, background_tasks: BackgroundTasks):
    repo_url = f"https://github.com/{owner}/{repo}"
    raw = redis_cmd("GET", f"business_repo:{repo_url}")
    if not raw:
        raise HTTPException(status_code=404, detail="This repo is not registered for auto-scan.")
    registration = json.loads(raw)

    payload = await request.body()
    sig_header = request.headers.get("x-hub-signature-256", "")
    expected = "sha256=" + hmac.new(registration["secret"].encode(), payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig_header):
        raise HTTPException(status_code=401, detail="Invalid webhook signature.")

    event_type = request.headers.get("x-github-event", "")
    if event_type != "push":
        return {"status": "ignored", "reason": f"event type '{event_type}' is not 'push'"}

    email = registration["email"]
    if get_tier(email) != "business":
        return {"status": "ignored", "reason": "account is no longer Business tier"}

    job_id = uuid.uuid4().hex[:12]
    JOBS[job_id] = {
        "status": "queued", "stage": "queued", "repo_url": repo_url,
        "created_at": time.time(), "summary": None, "error": None,
    }
    background_tasks.add_task(run_scan_and_email, repo_url, email, job_id)
    log.info("GITHUB WEBHOOK triggered scan repo=%s email=%s job=%s", repo_url, email, job_id)
    return {"status": "queued", "job_id": job_id}


@app.post("/scan")
def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    if is_pro(req.email):
        check_repo_limit(req.email, req.repo_url)
    else:
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

    # Try both the test-mode and live-mode webhook secrets — whichever
    # matches this payload's signature is the correct one.
    possible_secrets = [
        s for s in [
            os.environ.get("STRIPE_WEBHOOK_SECRET"),
            os.environ.get("STRIPE_WEBHOOK_SECRET_LIVE"),
        ] if s
    ]
    verify_stripe_signature(payload, sig_header, possible_secrets)
    event = json.loads(payload)
    event_type = event.get("type")
    log.info("STRIPE WEBHOOK received type=%s id=%s livemode=%s", event_type, event.get("id"), event.get("livemode"))

    if event_type == "checkout.session.completed":
        session = event["data"]["object"]
        email = session.get("customer_details", {}).get("email")
        customer_id = session.get("customer")
        payment_link = session.get("payment_link")
        tier = PAYMENT_LINK_TIERS.get(payment_link, "pro")  # default to pro if unrecognized
        if email:
            set_tier(email, tier)
            if customer_id:
                redis_cmd("SET", f"customer_email:{customer_id}", email)
            log.info("TIER ACTIVATED email=%s tier=%s", email, tier)
    elif event_type == "customer.subscription.deleted":
        customer_id = event["data"]["object"].get("customer")
        email = redis_cmd("GET", f"customer_email:{customer_id}") if customer_id else None
        if email:
            unmark_pro(email)
            log.info("TIER DEACTIVATED email=%s", email)
        else:
            log.warning("Could not find email for cancelled customer=%s", customer_id)

    return {"received": True}


def verify_stripe_signature(payload: bytes, sig_header: str, secrets: list[str]) -> None:
    try:
        parts = dict(p.split("=", 1) for p in sig_header.split(","))
        timestamp, signature = parts["t"], parts["v1"]
    except Exception:
        raise HTTPException(status_code=400, detail="Malformed Stripe-Signature header")

    signed_payload = f"{timestamp}.".encode() + payload
    for secret in secrets:
        expected = hmac.new(secret.encode(), signed_payload, hashlib.sha256).hexdigest()
        if hmac.compare_digest(expected, signature):
            return
    raise HTTPException(status_code=400, detail="Invalid Stripe webhook signature")


@app.get("/scan-test")
def start_scan_get(repo_url: str, email: str, background_tasks: BackgroundTasks):
    """Convenience GET version so a scan can be triggered by opening a URL
    in a browser, without needing curl or a form. Same validation as /scan."""
    req = ScanRequest(repo_url=repo_url, email=email)

    if is_pro(req.email):
        check_repo_limit(req.email, req.repo_url)
    else:
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

        tier = get_tier(email)
        if tier in ("pro", "business"):
            pdf_bytes = build_pdf_report(repo_url, gitleaks_findings, trivy_findings, tier)
            repo_slug = repo_url.rstrip("/").split("/")[-1]
            log.info("SENDING EMAIL (PDF, tier=%s) to=%s", tier, email)
            send_email(
                email,
                f"Your SecurityAuditAI {tier.capitalize()} report for {repo_url}",
                f"Your security audit for {repo_url} is attached as a PDF, "
                f"including fix suggestions for every finding.\n\n"
                f"Summary: {summary['secrets']} secrets, {summary['vulnerabilities']} "
                f"vulnerabilities, {summary['misconfigurations']} IaC issues.",
                pdf_attachment=pdf_bytes,
                pdf_filename=f"securityauditai-{repo_slug}.pdf",
            )
        else:
            report_text = build_report(repo_url, gitleaks_findings, trivy_findings)
            log.info("SENDING EMAIL (text, tier=free) to=%s", email)
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


SECRET_REMEDIATION = {
    "generic-api-key": "Revoke this key immediately, then move it to an environment variable or secret manager (never commit it, even to a private repo).",
    "aws-access-token": "Rotate this AWS key immediately in the IAM console — treat it as compromised. Use environment variables or AWS Secrets Manager going forward.",
    "private-key": "Revoke and regenerate this key pair. Private keys should never be committed; use a secrets manager or your CI/CD platform's encrypted secrets store.",
    "github-pat": "Revoke this token at github.com/settings/tokens immediately, then use environment variables or GitHub Actions secrets instead.",
    "slack-webhook-url": "Regenerate this webhook URL in Slack's app settings, then store it as an environment variable.",
}
DEFAULT_SECRET_REMEDIATION = (
    "Treat this credential as compromised: revoke/rotate it, then move it to an "
    "environment variable or a secrets manager instead of committing it to the repo."
)


def collect_findings(gitleaks_findings: list[dict], trivy_data: dict) -> dict:
    """Turns raw Gitleaks/Trivy output into a structured, remediation-annotated
    shape used by both the plain-text (free) and PDF (Pro/Business) reports."""
    secrets = []
    for f in gitleaks_findings:
        rule = f.get("RuleID", "unknown")
        secrets.append({
            "rule": rule,
            "file": f.get("File", "?"),
            "line": f.get("StartLine", "?"),
            "remediation": SECRET_REMEDIATION.get(rule, DEFAULT_SECRET_REMEDIATION),
        })

    vulnerabilities = []
    for result in trivy_data.get("Results", []):
        for v in result.get("Vulnerabilities") or []:
            fixed = v.get("FixedVersion")
            remediation = (
                f"Upgrade {v.get('PkgName', 'this package')} to version {fixed} or later."
                if fixed else
                f"No fixed version published yet for {v.get('VulnerabilityID', 'this CVE')} — "
                f"monitor the advisory and consider a temporary mitigation or alternative package."
            )
            vulnerabilities.append({
                "severity": v.get("Severity", "?"),
                "package": v.get("PkgName", "?"),
                "installed": v.get("InstalledVersion", "?"),
                "id": v.get("VulnerabilityID", "?"),
                "remediation": remediation,
            })

    misconfigs = []
    for result in trivy_data.get("Results", []):
        for m in result.get("Misconfigurations") or []:
            misconfigs.append({
                "severity": m.get("Severity", "?"),
                "title": m.get("Title", "?"),
                "id": m.get("ID", "?"),
                "remediation": m.get("Resolution") or "See the linked Trivy check ID for detailed guidance.",
            })

    return {"secrets": secrets, "vulnerabilities": vulnerabilities, "misconfigs": misconfigs}


def build_report(repo_url: str, gitleaks_findings: list[dict], trivy_data: dict) -> str:
    findings = collect_findings(gitleaks_findings, trivy_data)
    lines = [
        f"SecurityAuditAI — Free Scan Report",
        f"Repository: {repo_url}",
        "=" * 50,
        "",
        "1. SECRETS DETECTION",
        "-" * 30,
    ]

    if findings["secrets"]:
        lines.append(f"⚠ {len(findings['secrets'])} potential secret(s) found:")
        for s in findings["secrets"][:15]:
            lines.append(f"  - [{s['rule']}] {s['file']} (line {s['line']})")
        if len(findings["secrets"]) > 15:
            lines.append(f"  ...and {len(findings['secrets']) - 15} more.")
    else:
        lines.append("✅ No hardcoded secrets detected.")

    lines += ["", "2. DEPENDENCY VULNERABILITIES (SCA)", "-" * 30]
    if findings["vulnerabilities"]:
        for v in findings["vulnerabilities"][:10]:
            lines.append(f"  - [{v['severity']}] {v['package']} {v['installed']} — {v['id']}")
        lines.append(f"⚠ {len(findings['vulnerabilities'])} known vulnerabilities found across dependencies.")
    else:
        lines.append("✅ No known dependency vulnerabilities detected.")

    lines += ["", "3. INFRASTRUCTURE AS CODE (IaC)", "-" * 30]
    if findings["misconfigs"]:
        for m in findings["misconfigs"][:10]:
            lines.append(f"  - [{m['severity']}] {m['title']}")
        lines.append(f"⚠ {len(findings['misconfigs'])} misconfiguration(s) found.")
    else:
        lines.append("✅ No IaC misconfigurations detected.")

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


def build_pdf_report(repo_url: str, gitleaks_findings: list[dict], trivy_data: dict, tier: str) -> bytes:
    """Pro/Business report: same findings as the free text report, but with
    remediation snippets for every item, and (Business only) a compliance
    framing section suitable as SOC 2 / GDPR evidence."""
    import io
    from reportlab.lib.colors import HexColor
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer

    findings = collect_findings(gitleaks_findings, trivy_data)

    DARK = HexColor("#282a36")
    PURPLE = HexColor("#7c3aed")
    GREEN = HexColor("#16a34a")
    RED = HexColor("#dc2626")
    MUTED = HexColor("#6b7280")

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("T", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=22, textColor=DARK, spaceAfter=4)
    subtitle_style = ParagraphStyle("S", parent=styles["Normal"], fontSize=11, textColor=MUTED, spaceAfter=18)
    section_style = ParagraphStyle("H2", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=14, textColor=PURPLE, spaceBefore=16, spaceAfter=8)
    body_style = ParagraphStyle("B", parent=styles["Normal"], fontSize=10, textColor=DARK, leading=14)
    finding_style = ParagraphStyle("F", parent=styles["Normal"], fontSize=10, textColor=DARK, leading=14, leftIndent=10, spaceAfter=2)
    remediation_style = ParagraphStyle("R", parent=styles["Normal"], fontSize=9.5, textColor=GREEN, leading=13, leftIndent=10, spaceAfter=10)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, topMargin=0.75*inch, bottomMargin=0.75*inch, leftMargin=0.85*inch, rightMargin=0.85*inch)
    story = []

    report_label = "Compliance Evidence Report" if tier == "business" else "Security Audit Report"
    story.append(Paragraph(f"SecurityAuditAI — {report_label}", title_style))
    story.append(Paragraph(f"Repository: {repo_url} &nbsp;|&nbsp; Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1, color=HexColor("#e5e7eb"), spaceAfter=10))

    if tier == "business":
        story.append(Paragraph("Scope &amp; Methodology", section_style))
        story.append(Paragraph(
            "This report documents an automated static security scan of the repository above, "
            "covering secrets detection (Gitleaks), dependency vulnerability analysis against "
            "public CVE databases (Trivy), and infrastructure-as-code configuration review (Trivy). "
            "Suitable as supporting evidence for SOC 2 and GDPR technical control reviews. "
            "This is an automated static analysis, not a substitute for a full penetration test.",
            body_style,
        ))

    def render_section(heading, color, items, render_item):
        story.append(Paragraph(heading, ParagraphStyle("Hd", parent=section_style, textColor=color)))
        if not items:
            story.append(Paragraph("No issues found.", body_style))
            return
        for item in items:
            render_item(item)

    render_section("1. Secrets Detection", RED, findings["secrets"], lambda s: (
        story.append(Paragraph(f"<b>[{s['rule']}]</b> {s['file']} (line {s['line']})", finding_style)),
        story.append(Paragraph(f"→ Fix: {s['remediation']}", remediation_style)),
    ))
    render_section("2. Dependency Vulnerabilities", PURPLE, findings["vulnerabilities"], lambda v: (
        story.append(Paragraph(f"<b>[{v['severity']}]</b> {v['package']} {v['installed']} — {v['id']}", finding_style)),
        story.append(Paragraph(f"→ Fix: {v['remediation']}", remediation_style)),
    ))
    render_section("3. Infrastructure as Code", GREEN, findings["misconfigs"], lambda m: (
        story.append(Paragraph(f"<b>[{m['severity']}]</b> {m['title']}", finding_style)),
        story.append(Paragraph(f"→ Fix: {m['remediation']}", remediation_style)),
    ))

    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1, color=HexColor("#e5e7eb"), spaceAfter=8))
    story.append(Paragraph("CipherCapital / SecurityAuditAI — automated security audits.", ParagraphStyle("F2", parent=styles["Normal"], fontSize=8.5, textColor=MUTED)))

    doc.build(story)
    return buf.getvalue()


def send_email(to_email: str, subject: str, body: str, pdf_attachment: bytes | None = None, pdf_filename: str = "report.pdf") -> None:
    api_key = os.environ["RESEND_API_KEY"]
    from_email = os.environ.get("FROM_EMAIL", "onboarding@resend.dev")

    log.info("Resend API call to=%s attachment=%s", to_email, bool(pdf_attachment))

    payload = {
        "from": from_email,
        "to": [to_email],
        "subject": subject,
        "text": body,
    }
    if pdf_attachment:
        import base64
        payload["attachments"] = [{
            "filename": pdf_filename,
            "content": base64.b64encode(pdf_attachment).decode("ascii"),
        }]

    response = requests.post(
        "https://api.resend.com/emails",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=20,
    )
    if not response.ok:
        log.error("Resend error status=%s body=%s", response.status_code, response.text)
    response.raise_for_status()
    log.info("Resend accepted email id=%s", response.json().get("id"))
