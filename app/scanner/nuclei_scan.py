"""
CVE / misconfiguration scan engine built on Nuclei (ProjectDiscovery),
using the community-maintained template set. This replaces the
"exploit routers" approach with "check discovered services against a
public, constantly-updated vulnerability template library and report
matches" -- detection, not exploitation.
"""
import json
import subprocess
from dataclasses import dataclass

import os

from app.config import NUCLEI_BIN, NUCLEI_TEMPLATES_DIR


@dataclass
class NucleiFinding:
    template_id: str
    name: str
    severity: str
    matched_at: str
    description: str | None = None
    reference: str | None = None
    cve_id: str | None = None


class NucleiError(RuntimeError):
    pass


# Quick profile (default): focused on what actually matters for routers/IoT/
# office-network gear -- default creds, exposed panels/files, misconfig, and
# known device CVEs. This is a few thousand templates, not the whole corpus,
# which is what keeps a routine scan down to roughly a minute or two per
# host instead of nuclei's full multi-thousand-CVE sweep taking much longer
# for coverage that's mostly irrelevant to network appliances.
QUICK_TAGS = "default-login,router,iot,camera,print,upnp,exposure,misconfig"

# Deep profile (opt-in): adds the full "cve" tag set across all software
# categories nuclei knows about. Much more thorough, much slower -- use for
# a periodic full audit rather than every scan.
DEEP_TAGS = QUICK_TAGS + ",cve"


def run_vuln_scan(
    targets: list[str], timeout_sec: int = 1800, tags: str = QUICK_TAGS
) -> list[NucleiFinding]:
    if not targets:
        return []

    cmd = [
        NUCLEI_BIN,
        "-target", ",".join(targets),
        "-tags", tags,
        "-severity", "low,medium,high,critical",
        "-jsonl",
        "-silent",
        "-no-color",
        "-rate-limit", "150",
        "-timeout", "4",
        "-disable-update-check",
    ]
    if os.path.isdir(NUCLEI_TEMPLATES_DIR):
        # Point explicitly at our baked-in/mounted template set rather than
        # relying on nuclei's own auto-detected default location, so the
        # container behaves the same regardless of $HOME or first-run state.
        cmd += ["-t", NUCLEI_TEMPLATES_DIR]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_sec, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise NucleiError(f"nuclei timed out after {timeout_sec}s") from exc

    # nuclei exits non-zero in some template-warning cases even with valid
    # results, so we key off stdout content rather than the return code.
    findings: list[NucleiFinding] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = obj.get("info", {})
        classification = info.get("classification") or {}
        cve_id = None
        cve_ids = classification.get("cve-id")
        if cve_ids:
            cve_id = cve_ids[0] if isinstance(cve_ids, list) else str(cve_ids)

        findings.append(
            NucleiFinding(
                template_id=obj.get("template-id", "unknown"),
                name=info.get("name", obj.get("template-id", "unknown")),
                severity=info.get("severity", "info"),
                matched_at=obj.get("matched-at", obj.get("host", "")),
                description=info.get("description"),
                reference=(info.get("reference") or [None])[0] if isinstance(info.get("reference"), list) else info.get("reference"),
                cve_id=cve_id,
            )
        )
    return findings


def update_templates(timeout_sec: int = 300) -> tuple[bool, str]:
    """
    Refresh the local nuclei-templates copy. The image bakes in a git clone
    of projectdiscovery/nuclei-templates at build time (see Dockerfile), so
    we refresh with `git pull` here rather than nuclei's own -update-templates,
    which calls Anthropic-external metadata/version-check APIs that some
    networks block -- git pull only needs plain github.com access, which is
    the same access the image build already required.
    """
    git_dir = os.path.join(NUCLEI_TEMPLATES_DIR, ".git")
    if os.path.isdir(git_dir):
        proc = subprocess.run(
            ["git", "-C", NUCLEI_TEMPLATES_DIR, "pull", "--ff-only"],
            capture_output=True, text=True, timeout=timeout_sec, check=False,
        )
        ok = proc.returncode == 0
        return ok, (proc.stdout + proc.stderr).strip()[:2000]

    proc = subprocess.run(
        [NUCLEI_BIN, "-update-templates", "-silent", "-disable-update-check"],
        capture_output=True, text=True, timeout=timeout_sec, check=False,
    )
    return proc.returncode == 0, (proc.stdout + proc.stderr).strip()[:2000]
