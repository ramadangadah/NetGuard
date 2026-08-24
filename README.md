# NetGuard Dashboard

A self-hosted network asset & vulnerability dashboard for your own office
network. It wraps two industry-standard, open-source scanners behind a
lightweight web UI with login:

- **Nmap** for host/port/service discovery.
- **Nuclei** (ProjectDiscovery) for CVE, default-credential, and
  misconfiguration detection, using the community-maintained
  `nuclei-templates` set (baked into the image, refreshable from Settings).

It only *detects* — it never attempts to exploit or extract credentials from
anything. Scans are also locked to CIDR ranges you explicitly authorize in
Settings before anything runs, and every scan requires an explicit
"I'm authorized to scan this" confirmation.

## What's inside

- FastAPI + server-rendered HTML (no React/Vue/build step, no CDN
  dependencies) — small image, fast cold start, minimal RAM.
- SQLite for storage — no separate database container.
- Session-cookie auth, bcrypt-hashed passwords.
- A background job runner (in-process thread pool) so scans don't block the
  UI; the Scans page polls status every few seconds.
- Everything runs in one container.

## 1. Deploy on your Oracle Cloud instance

Prerequisites on the VM: Docker Engine + the Compose plugin.

```bash
# Oracle Linux / OL8-OL9
sudo dnf install -y docker
sudo systemctl enable --now docker
sudo dnf install -y docker-compose-plugin   # if not already present

# Ubuntu (if that's what you're running instead)
curl -fsSL https://get.docker.com | sudo sh
sudo systemctl enable --now docker
```

Copy this project to the server (scp/git/whatever you prefer), then:

```bash
cd netguard-dashboard
cp .env.example .env
nano .env        # set ADMIN_PASSWORD to something real before first start

docker compose up -d --build
```

First boot takes a few minutes because the image build clones the
nuclei-templates repository (~14k files). After that, `docker compose up -d`
alone is fast.

Check it came up:

```bash
docker compose logs -f netguard
```

If you left `ADMIN_PASSWORD` unset in `.env`, the generated one-time password
is printed in that log on first boot only — copy it before it scrolls away.

Open `http://<your-oracle-instance-ip>:8080` and log in.

### Oracle Cloud firewall

Oracle Cloud blocks inbound ports by default at two layers — open port 8080
(or whatever `HOST_PORT` you set) at both:

1. The instance's **Security List / Network Security Group** in the OCI
   console (VCN → your subnet → Security Lists → Add Ingress Rule, TCP,
   destination port 8080, source = your office IP range, not `0.0.0.0/0`).
2. The instance's own OS firewall, e.g.:
   ```bash
   sudo firewall-cmd --permanent --add-port=8080/tcp
   sudo firewall-cmd --reload
   ```

**Restrict the source CIDR to your office's public IP**, not the whole
internet — this dashboard controls scanning of your network and shouldn't be
reachable by anyone who finds the port. Consider putting it behind a VPN or
an SSH tunnel instead of exposing it directly if you don't need it reachable
from outside the office at all:

```bash
ssh -L 8080:localhost:8080 you@your-oracle-instance
# then browse http://localhost:8080 from your machine
```

Note: the container's *internal* port is still 8000 (that's what's inside
the box); `HOST_PORT` only controls what it's published as on the host.
If you'd rather use a different host port, just change `HOST_PORT` in
`.env` — no code changes needed.

## 2. First-login setup

1. Log in with the admin account from step 1.
2. Go to **Settings** and add the CIDR range(s) you're authorizing this
   tool to scan — e.g. your office LAN, `192.168.1.0/24`. Scans outside
   these ranges are rejected before anything touches the network.
3. (Optional) Add additional dashboard users under Settings → Dashboard
   users, for other admins/IT staff.

## 3. Running scans

From the **Scans** page:

- **Discovery** — nmap sweep of the target: live hosts, open ports,
  service/version banners. Run this first so the vulnerability scan knows
  what to target.
- **Vulnerability scan — quick** — the default. Runs nuclei against every
  port discovery found, using a focused template set (default credentials,
  exposed files/panels, router/IoT/camera/print CVEs, misconfigurations).
  Expect roughly 1-3 minutes per open port on modest hardware.
- **Vulnerability scan — deep** — adds the *entire* CVE template corpus
  across all software categories nuclei knows about, not just
  network-appliance-relevant ones. Much slower (can be 10-30+ minutes
  depending on how many hosts/ports you're targeting) — use this for a
  periodic thorough audit rather than routine scanning.

Results land on **Assets** (hosts + open ports) and **Findings**
(vulnerabilities, sorted by severity, with CVE IDs and references where
available).

## 4. Keeping vulnerability templates current

The image bakes in a snapshot of `nuclei-templates` at build time. To pull
the latest without rebuilding, click **Update templates now** on the
Settings page, or from the server:

```bash
docker compose exec netguard sh -c "git -C /opt/nuclei-templates pull --ff-only"
```

Rebuilding the image (`docker compose up -d --build`) also refreshes it.

## 5. Resource footprint

Defaults (`docker-compose.yml`) cap the container at 768MB RAM / 1.5 CPUs,
which is comfortable for scanning a typical office LAN (a few dozen to a
few hundred hosts) on a small Oracle Free Tier / Always Free ARM or x86
shape. `MAX_CONCURRENT_SCANS` (in `.env`) keeps only one scan running at a
time by default — bump it if your instance has more headroom and you want
to run discovery and a vuln scan in parallel.

## 6. Scan privileges (SYN scan / OS fingerprinting)

By default the container runs as a non-root user, so nmap automatically
falls back to an unprivileged TCP-connect scan — reliable and sufficient for
finding open services on an office LAN. If you specifically want nmap's
SYN scan and OS fingerprinting (`-O`), uncomment the `cap_add` block in
`docker-compose.yml` (grants `NET_RAW`/`NET_ADMIN`) and redeploy. Only do
this if you're comfortable with the container having raw-socket access.

## 7. Safety notes

- This tool only ever *detects* — it doesn't brute-force logins, exploit
  found vulnerabilities, or extract stored credentials from anything. It's
  built for **visibility and reporting**, the same way a professional
  pentest scanner works, not for gaining access.
- The CIDR allowlist in Settings is the only thing standing between "scan
  my office" and "scan someone else's network by typo." Keep it scoped to
  what you actually own/administer.
- Findings are informational. A "critical" nuclei match means a template
  matched a known signature — always verify manually before acting on it
  (patching, disabling a service, etc.), the same as with any scanner.

## Project layout

```
app/
  main.py              FastAPI routes
  config.py            env-var driven configuration
  auth.py              login/session/password hashing
  models.py             SQLModel tables
  db.py                 SQLite engine/session
  scanner/
    nmap_scan.py        nmap wrapper + XML parsing
    nuclei_scan.py       nuclei wrapper + JSONL parsing
    jobs.py              background job runner
    scope.py             CIDR allowlist enforcement
  templates/            Jinja2 HTML (no JS framework)
  static/style.css       ~4KB, no external assets
Dockerfile
docker-compose.yml
.env.example
```
