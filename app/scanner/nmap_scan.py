"""
Discovery / port-scan engine built on nmap. We ask nmap for XML output
(-oX -) and parse it, rather than screen-scraping text, so results are
reliable across nmap versions.
"""
import os
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from app.config import NMAP_BIN, NMAP_TIMING


@dataclass
class PortResult:
    port: int
    protocol: str
    state: str
    service: str | None = None
    product: str | None = None
    version: str | None = None


@dataclass
class HostResult:
    ip: str
    hostname: str | None = None
    mac: str | None = None
    vendor: str | None = None
    os_guess: str | None = None
    ports: list[PortResult] = field(default_factory=list)


class NmapError(RuntimeError):
    pass


def run_discovery_scan(target: str, top_ports: int = 1000, timeout_sec: int = 900) -> list[HostResult]:
    """
    Host + service discovery: top N TCP ports, service/version detection
    (-sV). The container runs unprivileged by default, so nmap falls back
    to a TCP connect scan automatically -- fine for an office LAN. OS
    fingerprinting (-O) needs raw-socket privileges; we only add it when
    actually running as root (i.e. the operator opted into NET_RAW/NET_ADMIN
    via docker-compose), rather than silently failing on it every scan.
    """
    cmd = [
        NMAP_BIN,
        NMAP_TIMING,
        "-sV",
        "--top-ports", str(top_ports),
        "-oX", "-",
    ]
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        cmd.append("-O")
    cmd.append(target)
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_sec, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise NmapError(f"nmap timed out after {timeout_sec}s scanning {target}") from exc

    if proc.returncode not in (0,) or not proc.stdout.strip():
        raise NmapError(f"nmap failed (code {proc.returncode}): {proc.stderr.strip()[:500]}")

    return _parse_nmap_xml(proc.stdout)


def _parse_nmap_xml(xml_text: str) -> list[HostResult]:
    root = ET.fromstring(xml_text)
    hosts: list[HostResult] = []

    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        if status_el is not None and status_el.get("state") != "up":
            continue

        ip = None
        mac = None
        vendor = None
        for addr_el in host_el.findall("address"):
            addrtype = addr_el.get("addrtype")
            if addrtype in ("ipv4", "ipv6"):
                ip = addr_el.get("addr")
            elif addrtype == "mac":
                mac = addr_el.get("addr")
                vendor = addr_el.get("vendor")
        if not ip:
            continue

        hostname = None
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            hn_el = hostnames_el.find("hostname")
            if hn_el is not None:
                hostname = hn_el.get("name")

        os_guess = None
        os_el = host_el.find("os")
        if os_el is not None:
            match_el = os_el.find("osmatch")
            if match_el is not None:
                os_guess = match_el.get("name")

        result = HostResult(ip=ip, hostname=hostname, mac=mac, vendor=vendor, os_guess=os_guess)

        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                state = state_el.get("state") if state_el is not None else "unknown"
                if state != "open":
                    continue
                service_el = port_el.find("service")
                result.ports.append(
                    PortResult(
                        port=int(port_el.get("portid")),
                        protocol=port_el.get("protocol", "tcp"),
                        state=state,
                        service=service_el.get("name") if service_el is not None else None,
                        product=service_el.get("product") if service_el is not None else None,
                        version=service_el.get("version") if service_el is not None else None,
                    )
                )
        hosts.append(result)

    return hosts
