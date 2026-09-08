# SecurityAuditAI — MVP Scan Backend

Free, working v1 of the audit tool: scans a public GitHub repo for
**secrets**, **dependency vulnerabilities**, and **IaC misconfigurations**,
then emails a report. Built on two open-source engines (Gitleaks + Trivy) —
no scanning logic had to be written from scratch.

**Not included (documented limitation, not a bug):** API security scanning.
That requires testing a *live* endpoint, not a static repo — a different
tool and threat model (e.g. OWASP ZAP against a running URL). Add this as a
v2 feature once v1 is live and validated.

---

## 1. Deploy the backend (free tier)

1. Push this folder to a new GitHub repo (e.g. `securityauditai-backend`).
2. Go to [render.com](https://render.com) → New → Web Service → connect that repo.
3. Render will detect the `Dockerfile` automatically. Choose the **Free** instance type.
4. Under **Environment**, add these variables:

   | Key | Value |
   |---|---|
   | `SMTP_HOST` | e.g. `smtp.gmail.com` (or your email provider's SMTP host) |
   | `SMTP_PORT` | `587` |
   | `SMTP_USER` | your sending email address |
   | `SMTP_PASS` | your SMTP password / app password |
   | `FROM_EMAIL` | the address reports are sent from |

   Gmail note: you'll need an "App Password" (not your normal password) —
   search "Gmail app password" for the 2-minute setup. Alternatively, use a
   transactional email provider like Resend or Brevo (both have free tiers
   and simpler SMTP setup for this exact use case).

5. Deploy. Render gives you a URL like `https://securityauditai-backend.onrender.com`.
6. **Free tier caveat:** the service spins down after inactivity and takes
   ~30-50 seconds to wake up on the next request. Fine for a low-traffic MVP;
   upgrade to a paid instance later if that becomes a problem.

---

## 2. Connect your website form

Open `scan-form.html`, replace `YOUR-BACKEND-URL` with your real Render URL,
and add the file's contents to your website as a new page or section.

---

## 3. Test it

```bash
curl -X POST https://YOUR-BACKEND-URL.onrender.com/scan \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/octocat/Hello-World", "email": "you@example.com"}'
```

You should get an immediate `{"status": "queued", ...}` response, then an
email with the report within a minute or two.

---

## 4. Known MVP limitations (be upfront about these)

- **Public repos only** — no private repo auth flow yet.
- **No abuse protection** — anyone can submit any public repo. For launch,
  add a CAPTCHA on the form (or a simple honeypot field) before promoting
  this widely. Fine to skip for your first few videos' worth of traffic.
- **Repo size capped at 300MB** and scan timeout at 3 minutes, to keep the
  free-tier server from getting overwhelmed. Adjust via env vars
  (`MAX_REPO_SIZE_MB`, `SCAN_TIMEOUT_SEC`) if needed.
- **No results dashboard** — report is emailed as plain text. A future
  version could show results on a webpage instead.

---

## 5. Roadmap (v2+)

- API security scanning (live endpoint testing)
- CI/CD integration (scan on every push — this is your "Business tier" pitch)
- Web dashboard instead of email-only reports
- PDF export for compliance reports (SOC 2 / GDPR), as described in your
  product overview
