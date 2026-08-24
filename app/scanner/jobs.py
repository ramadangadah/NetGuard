"""
Lightweight in-process job runner. Deliberately avoids pulling in Celery /
Redis / a message broker -- this app targets a single small container, so
a bounded thread pool with a DB-backed job status row is simpler, lighter,
and fast enough for office-network scan volumes.
"""
import logging
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from sqlmodel import Session, select

from app.config import MAX_CONCURRENT_SCANS
from app.db import engine
from app.models import ScanJob, Host, Port, Finding
from app.scanner.nmap_scan import run_discovery_scan, NmapError
from app.scanner.nuclei_scan import run_vuln_scan, NucleiError, QUICK_TAGS, DEEP_TAGS
from app.scanner.scope import assert_in_scope, ScopeError

log = logging.getLogger("netguard.jobs")

_executor = ThreadPoolExecutor(max_workers=max(1, MAX_CONCURRENT_SCANS))
_lock = threading.Lock()


def _mark_error(job_id: int, message: str) -> None:
    with Session(engine) as session:
        job = session.get(ScanJob, job_id)
        if not job:
            return
        job.status = "error"
        job.error_message = message[:2000]
        job.finished_at = datetime.utcnow()
        session.add(job)
        session.commit()


def submit_scan_job(job_id: int) -> None:
    future = _executor.submit(_run_job, job_id)

    def _on_done(f):
        # ThreadPoolExecutor swallows exceptions raised in the worker unless
        # the future's result is inspected -- without this, a bug in the
        # scan pipeline leaves the job stuck at "running" forever with no
        # trace in the logs. Always surface it and fail the job cleanly.
        exc = f.exception()
        if exc is not None:
            log.error("scan job %s crashed: %s", job_id, exc, exc_info=exc)
            _mark_error(job_id, f"Internal error: {exc}")

    future.add_done_callback(_on_done)


def _run_job(job_id: int) -> None:
    with Session(engine) as session:
        job = session.get(ScanJob, job_id)
        if not job:
            return
        try:
            assert_in_scope(session, job.target)
        except ScopeError as exc:
            job.status = "error"
            job.error_message = str(exc)
            job.finished_at = datetime.utcnow()
            session.add(job)
            session.commit()
            return

        # Capture what we need locally -- attributes on `job` become
        # unavailable for reads once this session block exits and the
        # instance's cached state is expired on commit.
        scan_type = job.scan_type

        job.status = "running"
        job.started_at = datetime.utcnow()
        session.add(job)
        session.commit()

    try:
        if scan_type == "discovery":
            _run_discovery(job_id)
        elif scan_type in ("vuln", "vuln_deep"):
            _run_vuln(job_id, deep=(scan_type == "vuln_deep"))
        else:
            raise ValueError(f"unknown scan_type {scan_type}")
    except (NmapError, NucleiError, ValueError) as exc:
        _mark_error(job_id, str(exc))
        return

    with Session(engine) as session:
        job = session.get(ScanJob, job_id)
        job.status = "done"
        job.finished_at = datetime.utcnow()
        session.add(job)
        session.commit()


def _run_discovery(job_id: int) -> None:
    with Session(engine) as session:
        job = session.get(ScanJob, job_id)
        target = job.target

    results = run_discovery_scan(target)

    with Session(engine) as session:
        job = session.get(ScanJob, job_id)
        for hr in results:
            existing = session.exec(select(Host).where(Host.ip == hr.ip)).first()
            now = datetime.utcnow()
            if existing:
                existing.hostname = hr.hostname or existing.hostname
                existing.mac = hr.mac or existing.mac
                existing.vendor = hr.vendor or existing.vendor
                existing.os_guess = hr.os_guess or existing.os_guess
                existing.last_seen = now
                existing.scan_job_id = job_id
                host_row = existing
            else:
                host_row = Host(
                    ip=hr.ip, hostname=hr.hostname, mac=hr.mac,
                    vendor=hr.vendor, os_guess=hr.os_guess,
                    first_seen=now, last_seen=now, scan_job_id=job_id,
                )
                session.add(host_row)
                session.flush()  # get host_row.id

            session.add(host_row)
            session.flush()

            # Replace port rows for this host with the fresh scan results
            old_ports = session.exec(select(Port).where(Port.host_id == host_row.id)).all()
            for p in old_ports:
                session.delete(p)
            session.flush()

            for pr in hr.ports:
                session.add(Port(
                    host_id=host_row.id, port=pr.port, protocol=pr.protocol,
                    state=pr.state, service=pr.service, product=pr.product,
                    version=pr.version,
                ))

        job.hosts_found = len(results)
        session.add(job)
        session.commit()


def _run_vuln(job_id: int, deep: bool = False) -> None:
    with Session(engine) as session:
        job = session.get(ScanJob, job_id)
        target = job.target
        # Vuln scan targets hosts already known from discovery within scope.
        hosts = session.exec(select(Host)).all()
        import ipaddress
        net = ipaddress.ip_network(target if "/" in target else f"{target}/32", strict=False)
        in_scope_hosts = [h for h in hosts if ipaddress.ip_address(h.ip) in net]

        targets: list[str] = []
        if in_scope_hosts:
            for h in in_scope_hosts:
                ports = session.exec(select(Port).where(Port.host_id == h.id)).all()
                if not ports:
                    # No known open ports yet -- let nuclei probe the bare host.
                    targets.append(h.ip)
                    continue
                for p in ports[:25]:  # cap per host so scan time stays bounded
                    # Pass host:port with no scheme and let nuclei's own
                    # httpx-based prober auto-detect http vs https once per
                    # target. Forcing both schemes ourselves was doubling
                    # every template's timeout budget on non-TLS ports and
                    # made scans take 5-10x longer for no extra coverage.
                    targets.append(f"{h.ip}:{p.port}")
        elif net.num_addresses == 1:
            # A single bare host/IP with nothing discovered yet is still a
            # sensible thing to hand straight to nuclei -- it'll probe the
            # default web ports itself.
            targets = [target]
        else:
            # No hosts discovered in this range yet. Falling back to handing
            # nuclei the raw CIDR here is a real trap: nuclei silently
            # expands a CIDR into every individual address and scans each
            # one on the default web ports only -- for a /24 that's 256
            # blind probes ignoring whatever ports Discovery would have
            # actually found open, and for anything bigger it can turn into
            # tens of thousands of pointless probes that just run until the
            # timeout kills them. Refuse clearly instead of quietly doing
            # something close to useless and reporting "done, 0 findings"
            # as if it were a real result.
            raise NucleiError(
                f"No hosts have been discovered in {target} yet. Run a Discovery scan on "
                "this range first so the vulnerability scan knows which hosts and ports to "
                "actually target, instead of blindly probing every address in the range."
            )

    tags = DEEP_TAGS if deep else QUICK_TAGS
    findings = run_vuln_scan(targets, tags=tags)

    with Session(engine) as session:
        job = session.get(ScanJob, job_id)
        count = 0
        for f in findings:
            host_ip = f.matched_at.split("://")[-1].split("/")[0].split(":")[0]
            host_row = session.exec(select(Host).where(Host.ip == host_ip)).first()
            if not host_row:
                # Finding on a target that wasn't in our host table yet (e.g. raw IP scan)
                host_row = Host(ip=host_ip, first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
                session.add(host_row)
                session.flush()

            session.add(Finding(
                host_id=host_row.id, scan_job_id=job_id, template_id=f.template_id,
                name=f.name, severity=f.severity, description=f.description,
                matched_at=f.matched_at, reference=f.reference, cve_id=f.cve_id,
            ))
            count += 1

        job.findings_found = count
        session.add(job)
        session.commit()
