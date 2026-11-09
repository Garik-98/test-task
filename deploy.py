#!/usr/bin/env python3
"""
One-click Ghost deployment on a Hetzner Cloud VPS with NO public inbound access.

Architecture
------------
  Visitors ──HTTPS──> Cloudflare ──(Tunnel)──> cloudflared ──> Ghost ──> MySQL
  You      ──SSH────> Cloudflare Access ──(Tunnel)──> cloudflared ──> sshd (127.0.0.1)

  * Hetzner Cloud Firewall with ZERO inbound rules (all inbound traffic dropped)
  * ufw deny-incoming on the host, sshd bound to loopback only
  * Both the blog and SSH are published through a Cloudflare Tunnel (outbound-only)
  * SSH hostname is gated by Cloudflare Access (email one-time-PIN) + your SSH key

Usage
-----
  cp .env.example .env && $EDITOR .env
  python3 deploy.py                # deploy (default)
  python3 deploy.py --dry-run      # print plan + render cloud-init, touch nothing
  python3 deploy.py status
  python3 deploy.py ssh-config     # print ~/.ssh/config snippet
  python3 deploy.py destroy

Python 3.9+, standard library only. Re-running `deploy` resumes a partial run.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

HCLOUD_API = "https://api.hetzner.cloud/v1"
CF_API = "https://api.cloudflare.com/client/v4"
USER_AGENT = "Mozilla/5.0 (compatible; ghost-hetzner-deploy/1.0)"
WORKDIR = Path(".ghost-deploy")
POLICY_NAME = "ghost-deploy admins"


# --------------------------------------------------------------------------- #
# Output helpers
# --------------------------------------------------------------------------- #
def log(msg: str = "") -> None:
    print(msg, flush=True)


def info(msg: str) -> None:
    print(f"   - {msg}", flush=True)


def step(n: int, total: int, msg: str) -> None:
    print(f"\n[{n}/{total}] {msg}", flush=True)


def die(msg: str, code: int = 1) -> "None":
    print(f"\nERROR: {msg}", file=sys.stderr, flush=True)
    sys.exit(code)


# --------------------------------------------------------------------------- #
# HTTP / API clients
# --------------------------------------------------------------------------- #
class ApiError(Exception):
    def __init__(self, status: int, payload: Any, service: str):
        self.status = status
        self.payload = payload
        self.service = service
        super().__init__(f"{service} API error (HTTP {status}): {self.describe()}")

    def describe(self) -> str:
        p = self.payload
        if isinstance(p, dict):
            if p.get("errors"):
                return "; ".join(f"{e.get('code')}: {e.get('message')}" for e in p["errors"])
            if isinstance(p.get("error"), dict):
                return f"{p['error'].get('code')}: {p['error'].get('message')}"
        return json.dumps(p)[:300]

    @property
    def code(self) -> str:
        p = self.payload
        if isinstance(p, dict) and isinstance(p.get("error"), dict):
            return str(p["error"].get("code", ""))
        return ""


class Api:
    def __init__(self, name: str, base: str, token: str):
        self.name, self.base, self.token = name, base, token

    def request(self, method: str, path: str, body: Any = None,
                params: Optional[dict] = None) -> dict:
        url = self.base + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = json.dumps(body).encode() if body is not None else None
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
        }
        for attempt in range(5):
            req = urllib.request.Request(url, data=data, method=method, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    raw = resp.read()
                    return json.loads(raw) if raw else {}
            except urllib.error.HTTPError as e:
                raw = e.read()
                try:
                    payload = json.loads(raw)
                except Exception:
                    payload = {"raw": raw.decode("utf-8", "replace")[:500]}
                if e.code in (429, 500, 502, 503, 504) and attempt < 4:
                    time.sleep(min(2 ** attempt * 2, 30))
                    continue
                raise ApiError(e.code, payload, self.name) from None
            except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
                if attempt < 4:
                    time.sleep(min(2 ** attempt * 2, 30))
                    continue
                raise ApiError(0, {"error": {"code": "network", "message": str(e)}}, self.name) from None
        raise RuntimeError("unreachable")


class Cloudflare(Api):
    def __init__(self, token: str):
        super().__init__("Cloudflare", CF_API, token)

    def call(self, method: str, path: str, body: Any = None, params: Optional[dict] = None) -> Any:
        payload = self.request(method, path, body, params)
        if not payload.get("success", False):
            raise ApiError(200, payload, self.name)
        return payload.get("result")

    def list(self, path: str, params: Optional[dict] = None) -> list:
        out, page = [], 1
        while True:
            q = dict(params or {})
            q.update({"page": page, "per_page": 50})
            payload = self.request("GET", path, params=q)
            if not payload.get("success", False):
                raise ApiError(200, payload, self.name)
            out.extend(payload.get("result") or [])
            total = (payload.get("result_info") or {}).get("total_pages", 1) or 1
            if page >= total:
                return out
            page += 1


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")
NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,30}$")
EMAIL_RE = re.compile(r"^[^@\s,]+@[^@\s,]+\.[^@\s,]+$")


def load_env_file(path: Path) -> None:
    if not path.exists():
        return
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export "):].strip()
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]
        os.environ.setdefault(key, val)  # real environment wins over file


def env(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.environ.get(name)
    return v.strip() if v and v.strip() else default


def env_bool(name: str, default: bool) -> bool:
    return (env(name, "true" if default else "false") or "").lower() in ("1", "true", "yes", "on")


@dataclass
class Config:
    hcloud_token: str
    cf_token: str
    cf_account_id: Optional[str]
    cf_zone_id: Optional[str]
    blog_domain: str
    ssh_domain: Optional[str]
    admin_emails: list = field(default_factory=list)
    access_enabled: bool = True
    server_name: str = "ghost-blog"
    server_type: str = "cx23"
    location: str = "nbg1"
    image: str = "ubuntu-24.04"
    admin_user: str = "deploy"
    ssh_pubkey_path: Path = Path("~/.ssh/id_ed25519.pub")
    backups: bool = False
    ghost_image: str = "ghost:6-alpine"
    mysql_image: str = "mysql:8.4"
    sshd_localhost_only: bool = True
    mail: dict = field(default_factory=dict)


def load_config(dry_run: bool, need_secrets: bool = True) -> Config:
    missing = []
    for k in ("BLOG_DOMAIN",) + (("HCLOUD_TOKEN", "CF_API_TOKEN") if need_secrets and not dry_run else ()):
        if not env(k):
            missing.append(k)
    if missing:
        die("Missing required settings: " + ", ".join(missing) +
            "\nCopy .env.example to .env and fill them in (or export them).")

    blog = (env("BLOG_DOMAIN") or "").lower()
    if not DOMAIN_RE.match(blog):
        die(f"BLOG_DOMAIN '{blog}' is not a valid hostname (e.g. blog.example.com).")
    ssh_domain = (env("SSH_DOMAIN") or "").lower() or None
    if ssh_domain and not DOMAIN_RE.match(ssh_domain):
        die(f"SSH_DOMAIN '{ssh_domain}' is not a valid hostname.")
    if ssh_domain == blog:
        die("SSH_DOMAIN must differ from BLOG_DOMAIN.")

    name = env("SERVER_NAME", "ghost-blog") or "ghost-blog"
    if not NAME_RE.match(name):
        die("SERVER_NAME must be lowercase letters, digits and hyphens.")
    user = env("ADMIN_USER", "deploy") or "deploy"
    if not USER_RE.match(user) or user == "root":
        die("ADMIN_USER must be a valid non-root unix username.")

    access = env_bool("ENABLE_ACCESS", True)
    emails = [e.strip().lower() for e in (env("ADMIN_EMAILS") or env("ADMIN_EMAIL") or "").split(",") if e.strip()]
    if access:
        if not emails:
            die("ADMIN_EMAIL is required (who may open the SSH tunnel via Cloudflare Access).\n"
                "Set ENABLE_ACCESS=false to skip Access (SSH key auth only - not recommended).")
        for e in emails:
            if not EMAIL_RE.match(e):
                die(f"'{e}' is not a valid email address.")

    mail = {}
    if env("MAIL_HOST"):
        mail = {k: env(k, "") or "" for k in ("MAIL_HOST", "MAIL_PORT", "MAIL_USER", "MAIL_PASSWORD", "MAIL_FROM")}
        mail["MAIL_PORT"] = mail["MAIL_PORT"] or "587"
        for k, v in mail.items():
            if "'" in v or "\n" in v:
                die(f"{k} must not contain a single quote or newline.")

    return Config(
        hcloud_token=env("HCLOUD_TOKEN", "dry-run") or "dry-run",
        cf_token=env("CF_API_TOKEN", "dry-run") or "dry-run",
        cf_account_id=env("CF_ACCOUNT_ID"),
        cf_zone_id=env("CF_ZONE_ID"),
        blog_domain=blog,
        ssh_domain=ssh_domain,
        admin_emails=emails,
        access_enabled=access,
        server_name=name,
        server_type=env("SERVER_TYPE", "cx23") or "cx23",
        location=env("LOCATION", "nbg1") or "nbg1",
        image=env("IMAGE", "ubuntu-24.04") or "ubuntu-24.04",
        admin_user=user,
        ssh_pubkey_path=Path(env("SSH_PUBLIC_KEY_PATH", "~/.ssh/id_ed25519.pub") or "").expanduser(),
        backups=env_bool("BACKUPS", False),
        ghost_image=env("GHOST_IMAGE", "ghost:6-alpine") or "ghost:6-alpine",
        mysql_image=env("MYSQL_IMAGE", "mysql:8.4") or "mysql:8.4",
        sshd_localhost_only=env_bool("SSHD_LOCALHOST_ONLY", True),
        mail=mail,
    )


# --------------------------------------------------------------------------- #
# State (so re-runs resume and `destroy` knows what to remove)
# --------------------------------------------------------------------------- #
class State:
    def __init__(self, path: Path):
        self.path = path
        self.data: dict = {}
        if path.exists():
            try:
                self.data = json.loads(path.read_text())
            except Exception:
                die(f"State file {path} is corrupt. Fix or delete it.")

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self.data[key] = value
        self.save()

    def save(self) -> None:
        self.path.write_text(json.dumps(self.data, indent=2))
        os.chmod(self.path, 0o600)


@dataclass
class Ctx:
    cfg: Config
    state: State
    hc: Optional[Api] = None
    cf: Optional[Cloudflare] = None
    account_id: str = ""
    zone_id: str = ""
    zone_name: str = ""
    ssh_domain: Optional[str] = None


# --------------------------------------------------------------------------- #
# Cloud-init payload
# --------------------------------------------------------------------------- #
COMPOSE = r"""name: ghost
services:
  db:
    image: ${MYSQL_IMAGE}
    restart: unless-stopped
    environment:
      MYSQL_ROOT_PASSWORD: ${DB_ROOT_PASSWORD}
      MYSQL_DATABASE: ghost
      MYSQL_USER: ghost
      MYSQL_PASSWORD: ${DB_PASSWORD}
    volumes:
      - db_data:/var/lib/mysql
    healthcheck:
      test: ["CMD-SHELL", "mysqladmin ping -h 127.0.0.1 -uroot -p\"$$MYSQL_ROOT_PASSWORD\" --silent"]
      interval: 10s
      timeout: 5s
      retries: 30
      start_period: 30s

  ghost:
    image: ${GHOST_IMAGE}
    restart: unless-stopped
    depends_on:
      db:
        condition: service_healthy
    ports:
      - "127.0.0.1:2368:2368"   # loopback only; reached by cloudflared (host network)
    environment:
      NODE_ENV: production
      url: https://${BLOG_DOMAIN}
      database__client: mysql
      database__connection__host: db
      database__connection__user: ghost
      database__connection__password: ${DB_PASSWORD}
      database__connection__database: ghost
__MAIL__
    volumes:
      - ./content:/var/lib/ghost/content

  cloudflared:
    image: cloudflare/cloudflared:latest
    restart: unless-stopped
    network_mode: host          # lets it reach ghost on 127.0.0.1:2368 and sshd on 127.0.0.1:22
    command: tunnel --no-autoupdate run
    environment:
      TUNNEL_TOKEN: ${TUNNEL_TOKEN}

volumes:
  db_data:
"""

MAIL_COMPOSE = """      mail__transport: SMTP
      mail__from: ${MAIL_FROM}
      mail__options__host: ${MAIL_HOST}
      mail__options__port: ${MAIL_PORT}
      mail__options__secure: "false"
      mail__options__auth__user: ${MAIL_USER}
      mail__options__auth__pass: ${MAIL_PASSWORD}"""

BACKUP_SH = """#!/usr/bin/env bash
# Daily backup: MySQL dump + Ghost content. Keeps 7 days under /opt/ghost/backups.
set -euo pipefail
cd /opt/ghost
ts=$(date +%F)
mkdir -p backups
docker compose exec -T db sh -c 'mysqldump -uroot -p"$MYSQL_ROOT_PASSWORD" --single-transaction --no-tablespaces ghost' | gzip > "backups/db-$ts.sql.gz"
tar -czf "backups/content-$ts.tar.gz" -C /opt/ghost content
find backups -type f -mtime +7 -delete
"""

CRON = "17 3 * * * root /opt/ghost/backup.sh >> /var/log/ghost-backup.log 2>&1\n"

SOCKET_OVERRIDE = """[Socket]
ListenStream=
ListenStream=127.0.0.1:22
ListenStream=[::1]:22
"""


def sshd_conf(localhost_only: bool) -> str:
    conf = ("PasswordAuthentication no\n"
            "KbdInteractiveAuthentication no\n"
            "PermitRootLogin no\n"
            "X11Forwarding no\n")
    if localhost_only:
        conf += "ListenAddress 127.0.0.1\nListenAddress ::1\n"
    return conf


def render_cloud_init(cfg: Config, creds: dict, tunnel_token: str, pubkey: str) -> str:
    env_lines = [
        f"BLOG_DOMAIN={cfg.blog_domain}",
        f"GHOST_IMAGE={cfg.ghost_image}",
        f"MYSQL_IMAGE={cfg.mysql_image}",
        f"DB_ROOT_PASSWORD={creds['db_root']}",
        f"DB_PASSWORD={creds['db_user']}",
        f"TUNNEL_TOKEN={tunnel_token}",
    ]
    for k, v in cfg.mail.items():
        env_lines.append(f"{k}='{v}'")
    compose = COMPOSE.replace("__MAIL__\n", (MAIL_COMPOSE + "\n") if cfg.mail else "")

    files = [
        ("/opt/ghost/docker-compose.yml", "0644", compose),
        ("/opt/ghost/.env", "0600", "\n".join(env_lines) + "\n"),
        ("/opt/ghost/backup.sh", "0750", BACKUP_SH),
        ("/etc/cron.d/ghost-backup", "0644", CRON),
        ("/etc/ssh/sshd_config.d/10-ghost-deploy.conf", "0644", sshd_conf(cfg.sshd_localhost_only)),
    ]
    if cfg.sshd_localhost_only:
        # Ubuntu 24.04 starts sshd via ssh.socket, which ignores ListenAddress.
        files.append(("/etc/systemd/system/ssh.socket.d/10-localhost.conf", "0644", SOCKET_OVERRIDE))

    runcmd = [
        "systemctl enable --now docker",
        f"usermod -aG docker {cfg.admin_user}",
        "mkdir -p /opt/ghost/content /opt/ghost/backups",
        "chown -R 1000:1000 /opt/ghost/content",
        "chmod 600 /opt/ghost/.env",
        "ufw --force reset",
        "ufw default deny incoming",
        "ufw default allow outgoing",
        "ufw --force enable",
        "for i in 1 2 3 4 5; do (cd /opt/ghost && docker compose pull && docker compose up -d) && break || sleep 20; done",
    ]
    if cfg.sshd_localhost_only:
        runcmd += ["systemctl daemon-reload", "systemctl restart ssh.socket", "systemctl restart ssh"]
    else:
        runcmd += ["systemctl restart ssh"]
    runcmd.append("touch /var/lib/ghost-deploy-ready")

    q = json.dumps  # JSON strings are valid YAML double-quoted scalars
    out = ["#cloud-config",
           f"hostname: {cfg.server_name}",
           "ssh_pwauth: false",
           "disable_root: true",
           "package_update: true",
           "package_upgrade: true",
           "packages:"]
    out += [f"  - {p}" for p in ("docker.io", "docker-compose-v2", "ufw", "unattended-upgrades", "cron", "curl", "ca-certificates")]
    out += ["users:",
            f"  - name: {cfg.admin_user}",
            "    groups: [sudo]",
            "    shell: /bin/bash",
            f"    sudo: {q('ALL=(ALL) NOPASSWD:ALL')}",
            "    lock_passwd: true",
            "    ssh_authorized_keys:",
            f"      - {q(pubkey)}",
            "write_files:"]
    for path, perms, content in files:
        out += [f"  - path: {path}",
                f"    permissions: '{perms}'",
                "    owner: root:root",
                "    encoding: b64",
                f"    content: {base64.b64encode(content.encode()).decode()}"]
    out.append("runcmd:")
    out += [f"  - {q(c)}" for c in runcmd]
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- #
# SSH key handling
# --------------------------------------------------------------------------- #
def load_or_create_pubkey(cfg: Config, dry_run: bool) -> tuple:
    """Returns (public_key_string, private_key_path_or_None)."""
    p = cfg.ssh_pubkey_path
    if p.exists():
        return p.read_text().strip(), Path(str(p)[:-4]) if str(p).endswith(".pub") else None
    if dry_run:
        return "ssh-ed25519 AAAA-DRY-RUN-PLACEHOLDER dry-run", p
    if not shutil.which("ssh-keygen"):
        die(f"No SSH public key at {p} and ssh-keygen is not installed. Set SSH_PUBLIC_KEY_PATH.")
    WORKDIR.mkdir(exist_ok=True, mode=0o700)
    priv = WORKDIR / "id_ed25519"
    if not priv.exists():
        info(f"No key at {p}; generating {priv} (no passphrase - add one with `ssh-keygen -p -f {priv}`)")
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "ghost-deploy", "-f", str(priv)], check=True)
    return (WORKDIR / "id_ed25519.pub").read_text().strip(), priv


def key_material(pub: str) -> str:
    return " ".join(pub.split()[:2])


# --------------------------------------------------------------------------- #
# Deployment steps
# --------------------------------------------------------------------------- #
def preflight(ctx: Ctx) -> None:
    cfg, hc, cf = ctx.cfg, ctx.hc, ctx.cf
    assert hc and cf
    # Hetzner: token + server type
    try:
        r = hc.request("GET", "/server_types", params={"name": cfg.server_type})
    except ApiError as e:
        die(f"Hetzner rejected HCLOUD_TOKEN or the request failed: {e}")
    if not r.get("server_types"):
        allr = hc.request("GET", "/server_types", params={"per_page": 50})
        names = sorted(t["name"] for t in allr.get("server_types", [])
                       if not t.get("deprecated") and not t.get("deprecation"))
        die(f"SERVER_TYPE '{cfg.server_type}' does not exist. Available: {', '.join(names)}")
    if not ctx.state.get("server_id"):
        ex = hc.request("GET", "/servers", params={"name": cfg.server_name}).get("servers", [])
        if ex:
            die(f"A Hetzner server named '{cfg.server_name}' already exists (id {ex[0]['id']}) but isn't in the "
                f"state file. Pick another SERVER_NAME or delete it.")

    # Cloudflare: account + zone
    if not cfg.cf_account_id:
        try:
            accounts = cf.call("GET", "/accounts")
        except ApiError as e:
            die(f"Could not list Cloudflare accounts ({e}). Set CF_ACCOUNT_ID explicitly.")
        if len(accounts) != 1:
            die("Token can see multiple Cloudflare accounts; set CF_ACCOUNT_ID. Found: " +
                ", ".join(f"{a['name']} ({a['id']})" for a in accounts))
        ctx.account_id = accounts[0]["id"]
    else:
        ctx.account_id = cfg.cf_account_id

    try:
        if cfg.cf_zone_id:
            z = cf.call("GET", f"/zones/{cfg.cf_zone_id}")
            ctx.zone_id, ctx.zone_name = z["id"], z["name"]
        else:
            labels = cfg.blog_domain.split(".")
            for i in range(len(labels) - 1):
                cand = ".".join(labels[i:])
                zs = cf.call("GET", "/zones", params={"name": cand})
                if zs:
                    ctx.zone_id, ctx.zone_name = zs[0]["id"], zs[0]["name"]
                    break
    except ApiError as e:
        die(f"Cloudflare zone lookup failed: {e}\nToken needs Zone:Read and DNS:Edit on the zone.")
    if not ctx.zone_id:
        die(f"No Cloudflare zone found for {cfg.blog_domain}. Add the domain to Cloudflare first.")
    if not cfg.blog_domain.endswith(ctx.zone_name):
        die(f"{cfg.blog_domain} is not inside zone {ctx.zone_name}.")

    ctx.ssh_domain = cfg.ssh_domain or f"ssh-{cfg.server_name}.{ctx.zone_name}"
    if not ctx.ssh_domain.endswith(ctx.zone_name):
        die(f"SSH_DOMAIN {ctx.ssh_domain} must be inside zone {ctx.zone_name}.")
    ctx.state.set("blog_domain", cfg.blog_domain)
    ctx.state.set("ssh_domain", ctx.ssh_domain)
    ctx.state.set("account_id", ctx.account_id)
    ctx.state.set("zone_id", ctx.zone_id)
    info(f"Zone: {ctx.zone_name}   Blog: {cfg.blog_domain}   SSH: {ctx.ssh_domain}")


def ensure_firewall(ctx: Ctx) -> None:
    hc, cfg = ctx.hc, ctx.cfg
    assert hc
    if ctx.state.get("firewall_id"):
        info("Firewall already created (state)")
        return
    name = f"{cfg.server_name}-no-inbound"
    ex = hc.request("GET", "/firewalls", params={"name": name}).get("firewalls", [])
    if ex:
        fid = ex[0]["id"]
        if ex[0].get("rules"):
            die(f"Existing firewall '{name}' has inbound rules; refusing to reuse it. Delete or rename it.")
        info(f"Reusing existing empty firewall {fid}")
    else:
        fid = hc.request("POST", "/firewalls", {
            "name": name, "rules": [],
            "labels": {"managed-by": "ghost-deploy", "ghost-deploy": cfg.server_name},
        })["firewall"]["id"]
        info(f"Created firewall '{name}' with zero inbound rules (id {fid})")
    ctx.state.set("firewall_id", fid)


def ensure_tunnel(ctx: Ctx) -> str:
    cf, cfg = ctx.cf, ctx.cfg
    assert cf
    acc = ctx.account_id
    tid = ctx.state.get("tunnel_id")
    if not tid:
        name = f"{cfg.server_name}-tunnel"
        ex = cf.list(f"/accounts/{acc}/cfd_tunnel", {"name": name, "is_deleted": "false"})
        if ex:
            if ex[0].get("config_src") == "local":
                die(f"Existing tunnel '{name}' is locally managed; delete it or change SERVER_NAME.")
            tid = ex[0]["id"]
            info(f"Reusing tunnel {tid}")
        else:
            tid = cf.call("POST", f"/accounts/{acc}/cfd_tunnel", {"name": name, "config_src": "cloudflare"})["id"]
            info(f"Created tunnel '{name}' ({tid})")
        ctx.state.set("tunnel_id", tid)
    ingress = [{"hostname": cfg.blog_domain, "service": "http://localhost:2368"}]
    if ctx.ssh_domain:
        ingress.append({"hostname": ctx.ssh_domain, "service": "ssh://localhost:22"})
    ingress.append({"service": "http_status:404"})
    cf.call("PUT", f"/accounts/{acc}/cfd_tunnel/{tid}/configurations", {"config": {"ingress": ingress}})
    info("Tunnel ingress: blog -> localhost:2368, ssh -> localhost:22")
    token = cf.call("GET", f"/accounts/{acc}/cfd_tunnel/{tid}/token")
    if not isinstance(token, str) or not token:
        die("Cloudflare did not return a tunnel token.")
    return token


def ensure_dns(ctx: Ctx, tunnel_id: str) -> None:
    cf = ctx.cf
    assert cf
    target = f"{tunnel_id}.cfargotunnel.com"
    ids = ctx.state.get("dns_ids", {})
    for host in [ctx.cfg.blog_domain] + ([ctx.ssh_domain] if ctx.ssh_domain else []):
        body = {"type": "CNAME", "name": host, "content": target, "proxied": True, "ttl": 1,
                "comment": "managed by ghost-deploy"}
        recs = cf.call("GET", f"/zones/{ctx.zone_id}/dns_records", params={"name": host})
        if recs:
            r = recs[0]
            if r["type"] != "CNAME":
                die(f"{host} already has a {r['type']} record. Remove it or choose another hostname.")
            if r["content"] != target or not r.get("proxied"):
                cf.call("PUT", f"/zones/{ctx.zone_id}/dns_records/{r['id']}", body)
                info(f"Updated DNS {host} -> tunnel")
            else:
                info(f"DNS {host} already correct")
            ids[host] = r["id"]
        else:
            ids[host] = cf.call("POST", f"/zones/{ctx.zone_id}/dns_records", body)["id"]
            info(f"Created DNS {host} -> tunnel (proxied)")
    ctx.state.set("dns_ids", ids)


def ensure_access(ctx: Ctx) -> None:
    cf, cfg = ctx.cf, ctx.cfg
    assert cf
    if not cfg.access_enabled:
        info("ENABLE_ACCESS=false: SSH hostname is NOT gated by Cloudflare Access")
        return
    acc = ctx.account_id
    try:
        apps = cf.list(f"/accounts/{acc}/access/apps")
        app = next((a for a in apps if a.get("domain") == ctx.ssh_domain), None)
        created = False
        if not app:
            app = cf.call("POST", f"/accounts/{acc}/access/apps", {
                "name": f"{cfg.server_name} SSH", "domain": ctx.ssh_domain, "type": "ssh",
                "session_duration": "8h", "app_launcher_visible": False,
            })
            created = True
            info(f"Created Access app for {ctx.ssh_domain}")
        else:
            info(f"Access app for {ctx.ssh_domain} already exists")
        ctx.state.set("access_app_id", app["id"])
        ctx.state.set("access_app_created", created or ctx.state.get("access_app_created", False))
        pols = cf.call("GET", f"/accounts/{acc}/access/apps/{app['id']}/policies") or []
        if not any(p.get("name") == POLICY_NAME for p in pols):
            cf.call("POST", f"/accounts/{acc}/access/apps/{app['id']}/policies", {
                "name": POLICY_NAME, "decision": "allow", "precedence": 1,
                "include": [{"email": {"email": e}} for e in cfg.admin_emails],
            })
            info(f"Policy: allow {', '.join(cfg.admin_emails)}")
    except ApiError as e:
        die(f"Cloudflare Access setup failed: {e}\n"
            "Zero Trust must be enabled on the account (free plan is fine: https://one.dash.cloudflare.com)\n"
            "and the API token needs 'Access: Apps and Policies: Edit'.")


def ensure_ssh_key(ctx: Ctx, pubkey: str) -> int:
    hc, cfg = ctx.hc, ctx.cfg
    assert hc
    if ctx.state.get("ssh_key_id"):
        return ctx.state.get("ssh_key_id")
    want = key_material(pubkey)
    for k in hc.request("GET", "/ssh_keys", params={"per_page": 50}).get("ssh_keys", []):
        if key_material(k["public_key"]) == want:
            ctx.state.set("ssh_key_id", k["id"])
            ctx.state.set("ssh_key_created", False)
            info(f"Reusing existing Hetzner SSH key '{k['name']}'")
            return k["id"]
    name = f"{cfg.server_name}-deploy"
    for attempt in range(2):
        try:
            kid = hc.request("POST", "/ssh_keys", {"name": name, "public_key": pubkey,
                                                    "labels": {"managed-by": "ghost-deploy"}})["ssh_key"]["id"]
            break
        except ApiError as e:
            if e.code == "uniqueness_error" and attempt == 0:
                name = f"{name}-{secrets.token_hex(3)}"
                continue
            raise
    ctx.state.set("ssh_key_id", kid)
    ctx.state.set("ssh_key_created", True)
    info(f"Uploaded SSH key '{name}'")
    return kid


def create_server(ctx: Ctx, user_data: str, key_id: int) -> None:
    hc, cfg = ctx.hc, ctx.cfg
    assert hc
    if ctx.state.get("server_id"):
        info(f"Server already created (id {ctx.state.get('server_id')}); cloud-init is not re-run on existing servers")
        return
    body = {
        "name": cfg.server_name, "server_type": cfg.server_type, "image": cfg.image,
        "location": cfg.location, "ssh_keys": [key_id], "user_data": user_data,
        "labels": {"managed-by": "ghost-deploy", "ghost-deploy": cfg.server_name},
        "firewalls": [{"firewall": ctx.state.get("firewall_id")}],  # attached at creation: no exposure window
        "public_net": {"enable_ipv4": True, "enable_ipv6": True},
        "start_after_create": True, "automount": False,
    }
    if len(user_data.encode()) > 32 * 1024:
        die("cloud-init user_data exceeds Hetzner's 32 KiB limit.")
    try:
        srv = hc.request("POST", "/servers", body)["server"]
    except ApiError as e:
        if e.code in ("resource_unavailable", "placement_error", "unsupported_error"):
            die(f"Hetzner can't place '{cfg.server_type}' in '{cfg.location}' right now ({e}).\n"
                "Try another LOCATION (nbg1, fsn1, hel1, ash, hil, sin) or SERVER_TYPE.")
        raise
    ctx.state.set("server_id", srv["id"])
    info(f"Created server '{cfg.server_name}' (id {srv['id']})")


def wait_server_running(ctx: Ctx, timeout: int = 300) -> None:
    hc = ctx.hc
    assert hc
    sid = ctx.state.get("server_id")
    end = time.time() + timeout
    while time.time() < end:
        s = hc.request("GET", f"/servers/{sid}")["server"]
        if s["status"] == "running":
            info("Server is running; cloud-init is now installing Docker and starting Ghost")
            return
        time.sleep(5)
    die("Server did not reach 'running' state in time.")


def maybe_enable_backups(ctx: Ctx) -> None:
    if ctx.cfg.backups and not ctx.state.get("backups_enabled"):
        ctx.hc.request("POST", f"/servers/{ctx.state.get('server_id')}/actions/enable_backup", {})  # type: ignore[union-attr]
        ctx.state.set("backups_enabled", True)
        info("Hetzner automated backups enabled (+20% server cost)")


def http_status(url: str) -> Optional[int]:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return None


def wait_for_blog(domain: str, timeout: int) -> bool:
    url = f"https://{domain}/"
    end = time.time() + timeout
    last = None
    while time.time() < end:
        code = http_status(url)
        if code and 200 <= code < 400:
            return True
        if code != last:
            hint = {530: "tunnel not connected yet", 502: "tunnel up, Ghost still starting",
                    None: "no response yet"}.get(code, "waiting")
            info(f"HTTP {code or '-'} ({hint})")
            last = code
        time.sleep(15)
    return False


def ssh_config_snippet(state: dict, cfg: Config, private_key: Optional[str]) -> str:
    lines = [f"Host {cfg.server_name}",
             f"  HostName {state.get('ssh_domain', '<ssh-domain>')}",
             f"  User {cfg.admin_user}"]
    if private_key:
        lines.append(f"  IdentityFile {private_key}")
        lines.append("  IdentitiesOnly yes")
    lines.append("  ProxyCommand cloudflared access ssh --hostname %h")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
def make_ctx(args: argparse.Namespace, need_secrets: bool = True) -> Ctx:
    cfg = load_config(args.dry_run, need_secrets)
    ctx = Ctx(cfg=cfg, state=State(Path(args.state_file)))
    if not args.dry_run:
        ctx.hc = Api("Hetzner", HCLOUD_API, cfg.hcloud_token)
        ctx.cf = Cloudflare(cfg.cf_token)
    return ctx


def cmd_deploy(args: argparse.Namespace) -> None:
    ctx = make_ctx(args)
    cfg = ctx.cfg
    pubkey, priv = load_or_create_pubkey(cfg, args.dry_run)

    if args.dry_run:
        root = ".".join(cfg.blog_domain.split(".")[-2:])
        ssh_domain = cfg.ssh_domain or f"ssh-{cfg.server_name}.{root}"
        log("DRY RUN - nothing will be created. Plan:")
        for line in [
            f"Hetzner firewall '{cfg.server_name}-no-inbound' with ZERO inbound rules",
            f"Cloudflare Tunnel '{cfg.server_name}-tunnel' (remotely managed)",
            f"  {cfg.blog_domain} -> http://localhost:2368   |   {ssh_domain} -> ssh://localhost:22",
            "Proxied CNAMEs for both hostnames",
            (f"Cloudflare Access (ssh) on {ssh_domain}, allow: {', '.join(cfg.admin_emails)}"
             if cfg.access_enabled else "Cloudflare Access: SKIPPED"),
            f"Hetzner server {cfg.server_name} ({cfg.server_type}, {cfg.location}, {cfg.image}), "
            f"firewall attached at creation",
            f"cloud-init: Docker, Ghost ({cfg.ghost_image}), MySQL ({cfg.mysql_image}), cloudflared, ufw, backups cron",
        ]:
            info(line)
        WORKDIR.mkdir(exist_ok=True, mode=0o700)
        out = WORKDIR / "cloud-init.dry-run.yaml"
        out.write_text(render_cloud_init(cfg, {"db_root": "<generated>", "db_user": "<generated>"},
                                         "<tunnel-token>", pubkey))
        log(f"\nRendered cloud-init (secrets are placeholders): {out}")
        return

    total = 8
    log(f"Deploying Ghost to Hetzner ({cfg.server_type} @ {cfg.location}) behind Cloudflare Tunnel")

    step(1, total, "Preflight checks")
    preflight(ctx)
    step(2, total, "Hetzner firewall (no inbound rules)")
    ensure_firewall(ctx)
    step(3, total, "Cloudflare Tunnel")
    token = ensure_tunnel(ctx)
    step(4, total, "DNS records")
    ensure_dns(ctx, ctx.state.get("tunnel_id"))
    step(5, total, "Cloudflare Access for SSH")
    ensure_access(ctx)
    step(6, total, "SSH key")
    key_id = ensure_ssh_key(ctx, pubkey)
    if priv:
        ctx.state.set("private_key", str(priv.resolve()))

    step(7, total, "Hetzner server")
    creds = ctx.state.get("creds") or {"db_root": secrets.token_urlsafe(24), "db_user": secrets.token_urlsafe(24)}
    user_data = render_cloud_init(cfg, creds, token, pubkey)
    create_server(ctx, user_data, key_id)
    wait_server_running(ctx)
    maybe_enable_backups(ctx)

    step(8, total, f"Waiting for https://{cfg.blog_domain} (first boot takes ~3-6 min)")
    ok = wait_for_blog(cfg.blog_domain, args.timeout)

    log("\n" + "=" * 64)
    if ok:
        log("Ghost is live!")
    else:
        log("Server is provisioned, but the blog isn't answering yet. Re-check with: python3 deploy.py status")
    log(f"  Site:        https://{cfg.blog_domain}")
    log(f"  Admin setup: https://{cfg.blog_domain}/ghost   (create your owner account NOW)")
    log("  Public ports: none (Hetzner firewall = zero inbound rules)")
    log("\nSSH (needs `cloudflared` on your machine: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/)")
    log("Add to ~/.ssh/config, then run `ssh " + cfg.server_name + "`:\n")
    log(ssh_config_snippet(ctx.state.data, cfg, ctx.state.get("private_key")))
    log("\nDB passwords live only in /opt/ghost/.env on the server. Backups: /opt/ghost/backups (daily, 7 days).")
    log("=" * 64)


def cmd_status(args: argparse.Namespace) -> None:
    ctx = make_ctx(args)
    s = ctx.state
    if not s.data:
        die("No state file found - nothing deployed from this directory.")
    assert ctx.hc and ctx.cf
    log(f"Blog: https://{s.get('blog_domain')}  -> HTTP {http_status('https://' + s.get('blog_domain') + '/')}")
    if s.get("server_id"):
        try:
            srv = ctx.hc.request("GET", f"/servers/{s.get('server_id')}")["server"]
            log(f"Hetzner server: {srv['name']} status={srv['status']}")
        except ApiError as e:
            log(f"Hetzner server: {e}")
    if s.get("tunnel_id"):
        try:
            t = ctx.cf.call("GET", f"/accounts/{s.get('account_id')}/cfd_tunnel/{s.get('tunnel_id')}")
            log(f"Tunnel: {t.get('name')} status={t.get('status')}")
        except ApiError as e:
            log(f"Tunnel: {e}")


def cmd_ssh_config(args: argparse.Namespace) -> None:
    cfg = load_config(True, need_secrets=False)
    state = State(Path(args.state_file))
    if not state.get("ssh_domain"):
        die("No deployment recorded yet; run `python3 deploy.py` first.")
    log(ssh_config_snippet(state.data, cfg, state.get("private_key")))


def cmd_destroy(args: argparse.Namespace) -> None:
    ctx = make_ctx(args)
    s = ctx.state
    if not s.data:
        die("No state file found - nothing to destroy.")
    assert ctx.hc and ctx.cf
    if not args.yes:
        log("This permanently deletes the server (and the blog database/content on it), firewall,")
        log("tunnel, DNS records and Access app created by this tool.")
        if input("Type the blog domain to confirm: ").strip() != s.get("blog_domain"):
            die("Confirmation did not match; aborting.")

    def attempt(label: str, fn) -> None:
        try:
            fn()
            info(f"Removed {label}")
        except ApiError as e:
            if e.status == 404:
                info(f"{label}: already gone")
            else:
                info(f"{label}: FAILED ({e})")

    acc = s.get("account_id")
    if s.get("server_id"):
        sid = s.get("server_id")
        attempt("server", lambda: ctx.hc.request("DELETE", f"/servers/{sid}"))  # type: ignore[union-attr]
        for _ in range(30):  # wait until the server is really gone so the firewall can be deleted
            try:
                ctx.hc.request("GET", f"/servers/{sid}")
                time.sleep(3)
            except ApiError:
                break
    if s.get("firewall_id"):
        fid = s.get("firewall_id")
        for i in range(10):
            try:
                ctx.hc.request("DELETE", f"/firewalls/{fid}")
                info("Removed firewall")
                break
            except ApiError as e:
                if e.status == 404:
                    break
                if i == 9:
                    info(f"firewall: FAILED ({e})")
                time.sleep(3)
    if s.get("ssh_key_created") and s.get("ssh_key_id"):
        kid = s.get("ssh_key_id")
        attempt("Hetzner SSH key", lambda: ctx.hc.request("DELETE", f"/ssh_keys/{kid}"))  # type: ignore[union-attr]
    zone = s.get("zone_id")
    tid = s.get("tunnel_id")
    target = f"{tid}.cfargotunnel.com"
    for host, rid in (s.get("dns_ids") or {}).items():
        def rm(rid=rid):
            rec = ctx.cf.call("GET", f"/zones/{zone}/dns_records/{rid}")  # type: ignore[union-attr]
            if rec.get("content") == target:
                ctx.cf.call("DELETE", f"/zones/{zone}/dns_records/{rid}")  # type: ignore[union-attr]
        attempt(f"DNS {host}", rm)
    if s.get("access_app_created") and s.get("access_app_id"):
        aid = s.get("access_app_id")
        attempt("Access app", lambda: ctx.cf.call("DELETE", f"/accounts/{acc}/access/apps/{aid}"))  # type: ignore[union-attr]
    if tid:
        def rm_tunnel():
            try:
                ctx.cf.call("DELETE", f"/accounts/{acc}/cfd_tunnel/{tid}/connections")  # type: ignore[union-attr]
            except ApiError:
                pass
            ctx.cf.call("DELETE", f"/accounts/{acc}/cfd_tunnel/{tid}")  # type: ignore[union-attr]
        attempt("tunnel", rm_tunnel)
    Path(args.state_file).unlink(missing_ok=True)
    log("\nDone. (Local key in .ghost-deploy/ was left in place.)")


def main() -> None:
    ap = argparse.ArgumentParser(description="One-click Ghost on Hetzner with no public SSH (Cloudflare Tunnel).")
    ap.add_argument("command", nargs="?", default="deploy",
                    choices=["deploy", "destroy", "status", "ssh-config"])
    ap.add_argument("--env-file", default=".env", help="settings file (default: .env)")
    ap.add_argument("--state-file", default=".ghost-deploy-state.json")
    ap.add_argument("--dry-run", action="store_true", help="plan + render cloud-init only")
    ap.add_argument("-y", "--yes", action="store_true", help="skip destroy confirmation")
    ap.add_argument("--timeout", type=int, default=900, help="seconds to wait for the blog (default 900)")
    args = ap.parse_args()

    load_env_file(Path(args.env_file))
    try:
        {"deploy": cmd_deploy, "destroy": cmd_destroy, "status": cmd_status,
         "ssh-config": cmd_ssh_config}[args.command](args)
    except ApiError as e:
        die(str(e))
    except KeyboardInterrupt:
        die("Interrupted. Re-run to resume; completed steps are recorded in the state file.", 130)


if __name__ == "__main__":
    main()
