from datetime import datetime

from fastapi import FastAPI, Request, Depends, Form, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select

from app.config import SESSION_COOKIE_NAME, SESSION_MAX_AGE_SECONDS, BASE_DIR
from app.db import init_db, get_session, engine
from app.auth import (
    bootstrap_admin_if_needed, verify_password, hash_password,
    create_session_cookie_value, get_current_username,
)
from app.models import User, Host, Port, Finding, ScanJob, AllowlistEntry
from app.scanner.jobs import submit_scan_job
from app.scanner.scope import get_allowlist, assert_in_scope, ScopeError
from app.scanner.nuclei_scan import update_templates

app = FastAPI(title="NetGuard Dashboard")
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "app" / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "app" / "templates"))

_generated_admin_password: str | None = None


@app.on_event("startup")
def on_startup():
    global _generated_admin_password
    init_db()
    with Session(engine) as session:
        _generated_admin_password = bootstrap_admin_if_needed(session)
    if _generated_admin_password:
        print("=" * 60)
        print(" First run: generated admin credentials")
        print(f"   username: admin")
        print(f"   password: {_generated_admin_password}")
        print(" Change this after first login (Settings > Users).")
        print("=" * 60)


def current_user_or_redirect(request: Request):
    username = get_current_username(request)
    if not username:
        return None
    return username


def require_user(request: Request) -> str:
    username = get_current_username(request)
    if not username:
        raise HTTPException(status_code=401)
    return username


# ---------- auth ----------

@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    if get_current_username(request):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "login.html", {
        "error": None})


@app.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    session: Session = Depends(get_session),
):
    user = session.exec(select(User).where(User.username == username)).first()
    if not user or not verify_password(password, user.password_hash):
        return templates.TemplateResponse(request, "login.html", {
        "error": "Invalid username or password."}, status_code=401
        )
    resp = RedirectResponse("/", status_code=303)
    resp.set_cookie(
        SESSION_COOKIE_NAME, create_session_cookie_value(user.username),
        httponly=True, samesite="lax", max_age=SESSION_MAX_AGE_SECONDS,
    )
    return resp


@app.get("/logout")
def logout():
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE_NAME)
    return resp


# ---------- dashboard ----------

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, session: Session = Depends(get_session)):
    username = current_user_or_redirect(request)
    if not username:
        return RedirectResponse("/login", status_code=303)

    host_count = len(session.exec(select(Host)).all())
    findings = session.exec(select(Finding)).all()
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
    recent_jobs = session.exec(select(ScanJob).order_by(ScanJob.created_at.desc()).limit(5)).all()

    return templates.TemplateResponse(request, "dashboard.html", {
        "username": username, "host_count": host_count,
        "severity_counts": severity_counts, "total_findings": len(findings),
        "recent_jobs": recent_jobs,
    })


# ---------- hosts ----------

@app.get("/hosts", response_class=HTMLResponse)
def hosts_view(request: Request, session: Session = Depends(get_session)):
    username = current_user_or_redirect(request)
    if not username:
        return RedirectResponse("/login", status_code=303)
    hosts = session.exec(select(Host).order_by(Host.ip)).all()
    ports_by_host = {}
    findings_by_host = {}
    for h in hosts:
        ports_by_host[h.id] = session.exec(select(Port).where(Port.host_id == h.id)).all()
        findings_by_host[h.id] = session.exec(select(Finding).where(Finding.host_id == h.id)).all()
    return templates.TemplateResponse(request, "hosts.html", {
        "username": username, "hosts": hosts,
        "ports_by_host": ports_by_host, "findings_by_host": findings_by_host,
    })


# ---------- findings ----------

@app.get("/findings", response_class=HTMLResponse)
def findings_view(request: Request, session: Session = Depends(get_session)):
    username = current_user_or_redirect(request)
    if not username:
        return RedirectResponse("/login", status_code=303)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings = session.exec(select(Finding)).all()
    findings = sorted(findings, key=lambda f: order.get(f.severity, 5))
    hosts = {h.id: h for h in session.exec(select(Host)).all()}
    return templates.TemplateResponse(request, "findings.html", {
        "username": username, "findings": findings, "hosts": hosts,
    })


# ---------- scans ----------

@app.get("/scans", response_class=HTMLResponse)
def scans_view(request: Request, session: Session = Depends(get_session)):
    username = current_user_or_redirect(request)
    if not username:
        return RedirectResponse("/login", status_code=303)
    jobs = session.exec(select(ScanJob).order_by(ScanJob.created_at.desc())).all()
    allowlist = get_allowlist(session)
    return templates.TemplateResponse(request, "scans.html", {
        "username": username, "jobs": jobs, "allowlist": allowlist,
    })


@app.get("/scans/status.json")
def scans_status_json(request: Request, session: Session = Depends(get_session)):
    require_user(request)
    jobs = session.exec(select(ScanJob).order_by(ScanJob.created_at.desc()).limit(20)).all()
    return [
        {
            "id": j.id, "target": j.target, "scan_type": j.scan_type, "status": j.status,
            "hosts_found": j.hosts_found, "findings_found": j.findings_found,
            "error_message": j.error_message,
        }
        for j in jobs
    ]


@app.post("/scans/new")
def scans_new(
    request: Request,
    target: str = Form(...),
    scan_type: str = Form(...),
    confirm_authorized: str | None = Form(None),
    session: Session = Depends(get_session),
):
    username = require_user(request)
    target = target.strip()

    if confirm_authorized != "yes":
        jobs = session.exec(select(ScanJob).order_by(ScanJob.created_at.desc())).all()
        return templates.TemplateResponse(request, "scans.html", {
        "username": username, "jobs": jobs,
            "allowlist": get_allowlist(session),
            "error": "You must confirm you are authorized to scan this target.",
        }, status_code=400)

    try:
        assert_in_scope(session, target)
    except ScopeError as exc:
        jobs = session.exec(select(ScanJob).order_by(ScanJob.created_at.desc())).all()
        return templates.TemplateResponse(request, "scans.html", {
        "username": username, "jobs": jobs,
            "allowlist": get_allowlist(session), "error": str(exc),
        }, status_code=400)

    job = ScanJob(target=target, scan_type=scan_type, created_by=username, status="queued")
    session.add(job)
    session.commit()
    session.refresh(job)
    submit_scan_job(job.id)
    return RedirectResponse("/scans", status_code=303)


# ---------- settings: allowlist + users ----------

@app.get("/settings", response_class=HTMLResponse)
def settings_view(request: Request, session: Session = Depends(get_session)):
    username = current_user_or_redirect(request)
    if not username:
        return RedirectResponse("/login", status_code=303)
    entries = session.exec(select(AllowlistEntry)).all()
    users = session.exec(select(User)).all()
    return templates.TemplateResponse(request, "settings.html", {
        "username": username, "entries": entries, "users": users,
        "update_result": None,
    })


@app.post("/settings/update-templates")
def settings_update_templates(request: Request, session: Session = Depends(get_session)):
    username = require_user(request)
    ok, output = update_templates()
    entries = session.exec(select(AllowlistEntry)).all()
    users = session.exec(select(User)).all()
    return templates.TemplateResponse(request, "settings.html", {
        "username": username, "entries": entries, "users": users,
        "update_result": {"ok": ok, "output": output},
    })


@app.post("/settings/allowlist/add")
def allowlist_add(
    request: Request, cidr: str = Form(...), label: str = Form(""),
    session: Session = Depends(get_session),
):
    require_user(request)
    import ipaddress
    cidr = cidr.strip()
    try:
        ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid CIDR")
    if not session.exec(select(AllowlistEntry).where(AllowlistEntry.cidr == cidr)).first():
        session.add(AllowlistEntry(cidr=cidr, label=label.strip()))
        session.commit()
    return RedirectResponse("/settings", status_code=303)


@app.post("/settings/allowlist/delete/{entry_id}")
def allowlist_delete(request: Request, entry_id: int, session: Session = Depends(get_session)):
    require_user(request)
    entry = session.get(AllowlistEntry, entry_id)
    if entry:
        session.delete(entry)
        session.commit()
    return RedirectResponse("/settings", status_code=303)


@app.post("/settings/users/add")
def user_add(
    request: Request, new_username: str = Form(...), new_password: str = Form(...),
    session: Session = Depends(get_session),
):
    require_user(request)
    new_username = new_username.strip()
    if len(new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if session.exec(select(User).where(User.username == new_username)).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    session.add(User(username=new_username, password_hash=hash_password(new_password), is_admin=True))
    session.commit()
    return RedirectResponse("/settings", status_code=303)


@app.post("/settings/users/delete/{user_id}")
def user_delete(request: Request, user_id: int, session: Session = Depends(get_session)):
    acting_user = require_user(request)
    target = session.get(User, user_id)
    if target and target.username != acting_user:
        session.delete(target)
        session.commit()
    return RedirectResponse("/settings", status_code=303)


@app.get("/healthz")
def healthz():
    return {"status": "ok", "time": datetime.utcnow().isoformat()}
