from __future__ import annotations

import datetime as dt
import json

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.db import ENGINE, db_session
from app.models import Base, Finding, Scan, Target
from app.scanner import PassiveScanner
from app.utils import normalize_http_url, severity_rank


app = FastAPI(title="Web Security Review Workbench")

app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")


def _init_db() -> None:
    Base.metadata.create_all(bind=ENGINE)


@app.on_event("startup")
def startup() -> None:
    _init_db()
    _ensure_demo_data()


def _ensure_demo_data() -> None:
    with db_session() as s:
        count = s.scalar(select(func.count(Target.id)))
        if count and count > 0:
            return
        demo = [
            Target(
                name="Localhost (example)",
                base_url="http://127.0.0.1:8000/",
                owner="demo",
                environment="local",
                notes="Demo target pointing at the workbench itself.",
            ),
            Target(
                name="Example (harmless)",
                base_url="https://example.com/",
                owner="demo",
                environment="public",
                notes="Harmless public example domain.",
            ),
        ]
        s.add_all(demo)


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    with db_session() as s:
        total_targets = s.scalar(select(func.count(Target.id))) or 0
        total_scans = s.scalar(select(func.count(Scan.id))) or 0

        by_sev = dict(
            s.execute(
                select(Finding.severity, func.count(Finding.id)).group_by(Finding.severity)
            ).all()
        )

        missing_headers = dict(
            s.execute(
                select(Finding.title, func.count(Finding.id))
                .where(Finding.category == "headers")
                .where(Finding.title.like("Missing security header:%"))
                .group_by(Finding.title)
                .order_by(func.count(Finding.id).desc())
                .limit(8)
            ).all()
        )

        recent_scans = (
            s.execute(
                select(Scan, Target)
                .join(Target, Target.id == Scan.target_id)
                .order_by(Scan.id.desc())
                .limit(8)
            )
            .all()
        )

        recent_findings = (
            s.execute(
                select(Finding, Scan, Target)
                .join(Scan, Scan.id == Finding.scan_id)
                .join(Target, Target.id == Scan.target_id)
                .order_by(Finding.id.desc())
                .limit(10)
            )
            .all()
        )

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "total_targets": total_targets,
            "total_scans": total_scans,
            "by_sev": {"low": by_sev.get("low", 0), "medium": by_sev.get("medium", 0), "high": by_sev.get("high", 0)},
            "missing_headers": missing_headers,
            "recent_scans": recent_scans,
            "recent_findings": recent_findings,
        },
    )


@app.get("/targets", response_class=HTMLResponse)
def targets_list(request: Request, archived: int = 0):
    with db_session() as s:
        q = select(Target).order_by(Target.updated_at.desc())
        if archived:
            q = q.where(Target.is_archived.is_(True))
        else:
            q = q.where(Target.is_archived.is_(False))
        targets = list(s.scalars(q).all())

    return templates.TemplateResponse(
        "targets.html",
        {"request": request, "targets": targets, "archived": bool(archived)},
    )


@app.get("/targets/new", response_class=HTMLResponse)
def targets_new(request: Request):
    return templates.TemplateResponse(
        "target_form.html",
        {"request": request, "target": None, "error": None},
    )


@app.post("/targets/new")
def targets_create(
    request: Request,
    name: str = Form(...),
    base_url: str = Form(...),
    owner: str = Form(""),
    environment: str = Form(""),
    notes: str = Form(""),
):
    try:
        normalized = normalize_http_url(base_url)
    except ValueError as e:
        return templates.TemplateResponse(
            "target_form.html",
            {
                "request": request,
                "target": {"name": name, "base_url": base_url, "owner": owner, "environment": environment, "notes": notes},
                "error": str(e),
            },
            status_code=400,
        )

    with db_session() as s:
        t = Target(
            name=name.strip() or normalized,
            base_url=normalized,
            owner=owner.strip() or None,
            environment=environment.strip() or None,
            notes=notes.strip() or None,
        )
        s.add(t)
        try:
            s.flush()
        except IntegrityError:
            return templates.TemplateResponse(
                "target_form.html",
                {
                    "request": request,
                    "target": {"name": name, "base_url": base_url, "owner": owner, "environment": environment, "notes": notes},
                    "error": "A target with this base URL already exists.",
                },
                status_code=400,
            )
        except Exception:
            raise HTTPException(status_code=400, detail="Target could not be saved")
        tid = t.id

    return RedirectResponse(url=f"/targets/{tid}", status_code=303)


@app.get("/targets/{target_id}", response_class=HTMLResponse)
def target_detail(request: Request, target_id: int):
    with db_session() as s:
        t = s.get(Target, target_id)
        if not t:
            raise HTTPException(status_code=404, detail="Target not found")
        scans = list(
            s.scalars(select(Scan).where(Scan.target_id == t.id).order_by(Scan.id.desc()).limit(25)).all()
        )

    return templates.TemplateResponse(
        "target_detail.html",
        {"request": request, "target": t, "scans": scans},
    )


@app.post("/targets/{target_id}/archive")
def target_archive(target_id: int):
    with db_session() as s:
        t = s.get(Target, target_id)
        if not t:
            raise HTTPException(status_code=404, detail="Target not found")
        t.is_archived = True
    return RedirectResponse(url="/targets", status_code=303)


@app.post("/targets/{target_id}/unarchive")
def target_unarchive(target_id: int):
    with db_session() as s:
        t = s.get(Target, target_id)
        if not t:
            raise HTTPException(status_code=404, detail="Target not found")
        t.is_archived = False
    return RedirectResponse(url=f"/targets/{target_id}", status_code=303)


@app.post("/targets/{target_id}/scan")
async def run_scan(target_id: int):
    scanner = PassiveScanner()

    with db_session() as s:
        t = s.get(Target, target_id)
        if not t:
            raise HTTPException(status_code=404, detail="Target not found")
        if t.is_archived:
            raise HTTPException(status_code=400, detail="Target is archived")
        scan = Scan(target_id=t.id, started_at=dt.datetime.utcnow())
        s.add(scan)
        s.flush()
        scan_id = scan.id
        base_url = t.base_url

    obs, findings, score, sev, err = await scanner.scan(base_url)

    with db_session() as s:
        scan = s.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=500, detail="Scan record missing")
        scan.finished_at = dt.datetime.utcnow()
        scan.overall_score = score
        scan.overall_severity = sev
        scan.http_status = obs.http_status
        scan.final_url = obs.final_url
        scan.error = err
        scan.observations_json = json.dumps(
            {
                "http_status": obs.http_status,
                "final_url": obs.final_url,
                "server_header": obs.server_header,
                "missing_security_headers": obs.missing_security_headers,
                "security_headers": obs.security_headers,
                "cookies": obs.cookies,
                "forms": obs.forms,
                "options_allow": obs.options_allow,
                "robots_present": obs.robots_present,
                "security_txt_present": obs.security_txt_present,
                "https": obs.https,
                "tls": obs.tls,
            },
            ensure_ascii=False,
            sort_keys=True,
        )

        for f in findings:
            s.add(
                Finding(
                    scan_id=scan.id,
                    severity=f.severity,
                    category=f.category,
                    title=f.title,
                    description=f.description,
                    recommendation=f.recommendation,
                )
            )

    return RedirectResponse(url=f"/scans/{scan_id}", status_code=303)


@app.get("/scans/{scan_id}", response_class=HTMLResponse)
def scan_detail(request: Request, scan_id: int):
    with db_session() as s:
        scan = s.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        target = s.get(Target, scan.target_id)
        findings = list(
            s.scalars(select(Finding).where(Finding.scan_id == scan.id)).all()
        )

    observations = None
    if scan.observations_json:
        try:
            observations = json.loads(scan.observations_json)
        except Exception:
            observations = None

    grouped: dict[str, list[Finding]] = {"high": [], "medium": [], "low": []}
    for f in sorted(findings, key=lambda x: (-severity_rank(x.severity), x.category, x.title)):
        grouped.setdefault(f.severity, []).append(f)

    return templates.TemplateResponse(
        "scan_detail.html",
        {"request": request, "scan": scan, "target": target, "grouped": grouped, "observations": observations},
    )


@app.get("/scans/{scan_id}/report", response_class=HTMLResponse)
def scan_report(request: Request, scan_id: int):
    with db_session() as s:
        scan = s.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        target = s.get(Target, scan.target_id)
        findings = list(s.scalars(select(Finding).where(Finding.scan_id == scan.id)).all())

    observations = None
    if scan.observations_json:
        try:
            observations = json.loads(scan.observations_json)
        except Exception:
            observations = None

    grouped: dict[str, list[Finding]] = {"high": [], "medium": [], "low": []}
    for f in sorted(findings, key=lambda x: (-severity_rank(x.severity), x.category, x.title)):
        grouped.setdefault(f.severity, []).append(f)

    return templates.TemplateResponse(
        "scan_report.html",
        {"request": request, "scan": scan, "target": target, "grouped": grouped, "observations": observations},
    )


@app.exception_handler(HTTPException)
def http_error(request: Request, exc: HTTPException):
    return templates.TemplateResponse(
        "error.html",
        {"request": request, "status_code": exc.status_code, "detail": exc.detail},
        status_code=exc.status_code,
    )
