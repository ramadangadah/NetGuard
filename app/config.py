"""
Central configuration, read from environment variables so the container
can be configured entirely via docker-compose / .env without editing code.
"""
import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("DATA_DIR", BASE_DIR / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_URL = f"sqlite:///{DATA_DIR / 'netguard.db'}"

# Session / cookie signing secret. If not provided, generate one and persist
# it to disk on first run so sessions survive restarts but each install gets
# its own unique key (never ships with a shared default secret).
_secret_file = DATA_DIR / ".secret_key"


def _load_or_create_secret() -> str:
    env_secret = os.environ.get("SECRET_KEY")
    if env_secret:
        return env_secret
    if _secret_file.exists():
        return _secret_file.read_text().strip()
    key = secrets.token_hex(32)
    _secret_file.write_text(key)
    _secret_file.chmod(0o600)
    return key


SECRET_KEY = _load_or_create_secret()

# First-run admin bootstrap credentials. Only used the very first time the
# app starts and no users exist yet.
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")  # if unset, a random one is generated and printed once

# Scan engine tuning
NMAP_BIN = os.environ.get("NMAP_BIN", "nmap")
NUCLEI_BIN = os.environ.get("NUCLEI_BIN", "nuclei")
NUCLEI_TEMPLATES_DIR = os.environ.get("NUCLEI_TEMPLATES_DIR", "/opt/nuclei-templates")
NMAP_TIMING = os.environ.get("NMAP_TIMING", "-T4")  # aggressive-but-safe default timing template
MAX_CONCURRENT_SCANS = int(os.environ.get("MAX_CONCURRENT_SCANS", "1"))
# Skip nmap's ping-based host discovery and probe every address directly
# (-Pn). Default ON: scanning a network over the internet/VPN from a cloud
# VM very commonly has ICMP/discovery probes dropped by a firewall even
# though the real service ports are reachable -- without this, nmap marks
# those hosts "down" and silently skips them, which looks identical to
# "the scan ran and found nothing." Set to "false" if you're scanning a
# LAN directly and know ICMP isn't blocked, for faster scans.
NMAP_SKIP_HOST_DISCOVERY = os.environ.get("NMAP_SKIP_HOST_DISCOVERY", "true").strip().lower() not in (
    "false", "0", "no",
)

# With -Pn active, nmap can't tell "no response yet" apart from "network
# congestion" and throttles itself down defensively when scanning a range
# where most addresses never answer at all -- exactly the case for a /24
# where only a few IPs are actually in use. --min-rate forces a packet-rate
# floor so the scan doesn't crawl to a near-stop on ranges like that.
NMAP_MIN_RATE = int(os.environ.get("NMAP_MIN_RATE", "300"))

# Caps how long nmap will spend on any single unresponsive host, so one
# black-holed address can't eat an unbounded share of the scan budget.
NMAP_HOST_TIMEOUT_SEC = int(os.environ.get("NMAP_HOST_TIMEOUT_SEC", "300"))

# Outer safety-net timeout for the whole nmap subprocess, in seconds per
# address in the target range (on top of a fixed floor and a hard cap) --
# see run_discovery_scan() for how this is applied. This is intentionally
# generous; --min-rate/--host-timeout above are what actually keep real
# scan time well under this ceiling in practice.
NMAP_TIMEOUT_SEC_PER_ADDRESS = int(os.environ.get("NMAP_TIMEOUT_SEC_PER_ADDRESS", "20"))
NMAP_TIMEOUT_FLOOR_SEC = int(os.environ.get("NMAP_TIMEOUT_FLOOR_SEC", "900"))
NMAP_TIMEOUT_CAP_SEC = int(os.environ.get("NMAP_TIMEOUT_CAP_SEC", "10800"))  # 3h

# Reject scans against a range larger than this many addresses outright,
# with a clear error, instead of letting someone submit e.g. a /16 and
# have it silently run for the better part of a day. This app is sized for
# office-network-scale ranges; /20 (4096 addresses) is already generous.
MAX_SCAN_ADDRESSES = int(os.environ.get("MAX_SCAN_ADDRESSES", "4096"))

# Safety guard: scans are only allowed against CIDR ranges the admin has
# explicitly allow-listed. Comma-separated, e.g. "192.168.1.0/24,10.0.0.0/8".
# Empty by default -- admin must configure this before any scan can run.
SCAN_ALLOWLIST = [c.strip() for c in os.environ.get("SCAN_ALLOWLIST", "").split(",") if c.strip()]

SESSION_COOKIE_NAME = "netguard_session"
SESSION_MAX_AGE_SECONDS = 60 * 60 * 12  # 12h
