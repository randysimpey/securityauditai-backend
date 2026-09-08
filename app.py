"""
SecurityAuditAI — MVP scan backend

Accepts a public GitHub repo URL, clones it, runs:
  - Gitleaks  -> hardcoded secrets / leaked credentials (incl. git history)
  - Trivy     -> dependency vulnerabilities (SCA) + IaC misconfigurations

...then emails a summary report to the submitter.

NOT included in this MVP: live API security scanning (requires a running
endpoint, not a static repo — different tool/threat model, see README).
"""

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import requests
from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, field_validator

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("securityauditai")

app = FastAPI(title="SecurityAuditAI Scan Service")

# Allow your website/form to call this API directly from the browser.
# Tighten this to your actual domain once it's live.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

GITHUB_URL_RE = re.compile(r"^https://github\.com/[\w.-]+/[\w.-]+/?$")

# Safety limits — MVP has no auth/payment gate, so keep scans cheap and bounded.
MAX_REPO_SIZE_MB = int(os.environ.get("MAX_REPO_SIZE_MB", "300"))
CLONE_TIMEOUT_SEC = int(os.environ.get("CLONE_TIMEOUT_SEC", "120"))
SCAN_TIMEOUT_SEC = int(os.environ.get("SCAN_TIMEOUT_SEC", "180"))


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


@app.get("/")
def health():
    return {"status": "ok", "service": "SecurityAuditAI scan backend"}


@app.post("/scan")
def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    background_tasks.add_task(run_scan_and_email, req.repo_url, req.email)
    return {
        "status": "queued",
        "message": f"Scan started for {req.repo_url}. "
        f"Report will be emailed to {req.email} shortly.",
    }


@app.get("/scan-test")
def start_scan_get(repo_url: str, email: str, background_tasks: BackgroundTasks):
    """Convenience GET version so a scan can be triggered by opening a URL
    in a browser, without needing curl or a form. Same validation as /scan."""
    req = ScanRequest(repo_url=repo_url, email=email)
    background_tasks.add_task(run_scan_and_email, req.repo_url, req.email)
    return {
        "status": "queued",
        "message": f"Scan started for {req.repo_url}. "
        f"Report will be emailed to {req.email} shortly.",
    }


def run_scan_and_email(repo_url: str, email: str) -> None:
    workdir = Path(tempfile.mkdtemp(prefix="saai_"))
    repo_dir = workdir / "repo"
    log.info("SCAN START repo=%s email=%s workdir=%s", repo_url, email, workdir)
    try:
        clone_repo(repo_url, repo_dir)
        log.info("CLONE OK repo=%s", repo_url)
        check_repo_size(repo_dir)
        log.info("SIZE CHECK OK repo=%s", repo_url)

        gitleaks_findings = run_gitleaks(repo_dir, workdir)
        log.info("GITLEAKS OK findings=%d", len(gitleaks_findings))
        trivy_findings = run_trivy(repo_dir, workdir)
        log.info("TRIVY OK")

        report_text = build_report(repo_url, gitleaks_findings, trivy_findings)
        log.info("SENDING EMAIL to=%s", email)
        send_email(email, f"Your security audit for {repo_url}", report_text)
        log.info("EMAIL SENT to=%s", email)

    except Exception as exc:  # noqa: BLE001 — MVP: report failures by email too
        log.exception("SCAN FAILED repo=%s error=%s", repo_url, exc)
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
    response.raise_for_status()
    log.info("Resend accepted email id=%s", response.json().get("id"))
