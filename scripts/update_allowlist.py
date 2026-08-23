#!/usr/bin/env python3
"""
Generic allowlist maintenance (config-driven).

Daily job: re-resolve every known domain (via public DoH, bypassing the local
blocker), map IPs to ASN/org (RIPE/ARIN RDAP), discover new candidates
(TLS cert SAN clustering + community scrape), classify each domain, regenerate
the list files, and commit+push the repo if anything changed.

All service-specific values (name, trusted/partner suffixes, org tokens, seed
domains, IP blocks, scrape URLs) live in <repo>/config.json, so the same script
powers every allowlist repo (Magenta TV, Twitch, ...).

Design goals (per spec):
  * Idempotent  — no new data => zero changes, no commit.
  * Additive    — never auto-deletes rules; stale domains are only flagged.
  * Verified    — a domain is "verified" if it is service/partner-owned by
                  suffix, or resolves into a trusted ASN. Anything resolving
                  to a non-trusted ASN stays "unverified" for manual review.

Exit 0 on success. Prints a concise human report to stdout (delivered verbatim
by the cron watchdog; empty/no-change runs stay quiet).
"""

import json
import ipaddress
import os
import re
import socket
import ssl
import subprocess
import sys
import urllib.request
import urllib.parse
from datetime import datetime, timezone, timedelta

REPO = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
GIT_CRED = "/opt/data/home/.git-credentials"

DOH = "https://cloudflare-dns.com/dns-query"
DO_H2 = "https://dns.google/resolve"

DOMAIN_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\.(?:de|com|net|tv|at|io|cloud|rocks|live|gg)", re.I)


def load_config():
    with open(os.path.join(REPO, "config.json")) as f:
        return json.load(f)


CFG = load_config()
NAME = CFG["name"]
STATE_FILE = CFG.get("state_file", "allowlist.json")
JSON_PATH = os.path.join(REPO, STATE_FILE)
TRUSTED_SUFFIXES = tuple(CFG.get("trusted_suffixes", []))
PARTNER_SUFFIXES = tuple(CFG.get("partner_suffixes", []))
TRUSTED_ORG_TOKENS = tuple(CFG.get("trusted_org_tokens", []))
IP_ORG_TOKENS = tuple(CFG.get("ip_org_tokens", []))
KNOWN_IP_BLOCKS = set(CFG.get("known_ip_blocks", []))
SEED = [(d, s) for d, s in CFG.get("seed", [])]
SCRAPE_URLS = CFG.get("scrape_urls", [])
_CRIT = CFG.get("criticality", {})
_CRIT_TELEMETRY = set(_CRIT.get("telemetry", []))
_CRIT_ENHANCING = set(_CRIT.get("enhancing", []))


# --- helpers -----------------------------------------------------------------
def http_json(url, timeout=15):
    req = urllib.request.Request(url, headers={"accept": "application/json",
                                               "user-agent": "allowlist-refresh/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def doh(name, rtype="A"):
    """Resolve via public DoH. Returns (status, ips, cnames)."""
    q = urllib.parse.urlencode({"name": name, "type": rtype})
    for sv in (DOH, DO_H2):
        try:
            r = http_json(f"{sv}?{q}", timeout=15)
            ans = r.get("Answer") or []
            ips = [a["data"] for a in ans if a.get("type") == 1]
            cnames = [a["data"].rstrip(".") for a in ans if a.get("type") == 5]
            return r.get("Status", -1), ips, cnames
        except Exception:
            continue
    return -1, [], []


def rdap(ip):
    """Return (netname, netblocks, org) from RIPE then ARIN RDAP."""
    for base in (f"https://rdap.db.ripe.net/ip/{ip}",
                 f"https://rdap.arin.net/registry/ip/{ip}"):
        try:
            r = http_json(base, timeout=15)
            name = r.get("name", "?")
            blocks = [f"{e.get('v4prefix','')}/{e.get('length','')}"
                      for e in r.get("cidr0_cidrs", []) if e.get("v4prefix")]
            org = ""
            for e in r.get("entities", []):
                va = e.get("vcardArray")
                if isinstance(va, list) and len(va) > 1:
                    for it in va[1]:
                        if it[0] == "fn":
                            org = it[3]
                            break
                if org:
                    break
            return name, blocks, org
        except Exception:
            continue
    return "?", [], "?"


def local_blocked(name):
    """True if the local resolver sinkholes this name to 0.0.0.0."""
    try:
        infos = socket.getaddrinfo(name, None)
        return any(i[4][0] in ("0.0.0.0", "::") for i in infos)
    except Exception:
        return False


def cert_sans(host):
    """Extract DNS SAN entries from the host's TLS cert (best-effort)."""
    try:
        out = subprocess.run(
            ["timeout", "10", "openssl", "s_client", "-connect", f"{host}:443",
             "-servername", host],
            input=b"", stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=12,
        ).stdout
        out2 = subprocess.run(
            ["openssl", "x509", "-noout", "-ext", "subjectAltName"],
            input=out, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=12,
        ).stdout.decode(errors="ignore")
        return set(m.group(1) for m in re.finditer(r"DNS:([^,\s]+)", out2))
    except Exception:
        return set()


def scrape_candidates():
    """Best-effort extraction of domain-like tokens from community sources."""
    found = set()
    for url in SCRAPE_URLS:
        try:
            data = http_json(url, timeout=15)
            blob = json.dumps(data)
        except Exception:
            try:
                blob = urllib.request.urlopen(
                    urllib.request.Request(url, headers={"user-agent": "Mozilla/5.0"}),
                    timeout=15).read().decode(errors="ignore")
            except Exception:
                continue
        for m in DOMAIN_RE.findall(blob):
            d = m.lower().rstrip(".")
            if d.endswith(TRUSTED_SUFFIXES) or d.endswith(PARTNER_SUFFIXES):
                found.add(d)
    return found


# --- core --------------------------------------------------------------------
def load_state():
    if os.path.exists(JSON_PATH):
        with open(JSON_PATH) as f:
            return json.load(f)
    return {"version": 1, "domains": {}, "ip_netblocks": sorted(KNOWN_IP_BLOCKS)}


def _has_suffix(domain, suffixes):
    for s in suffixes:
        if domain == s[1:] or domain.endswith(s):  # bare apex or subdomain
            return True
    return False


def criticality(domain):
    """required (breaks function) / enhancing (nice-to-have) / telemetry (block)."""
    if domain in _CRIT_TELEMETRY:
        return "telemetry"
    if domain in _CRIT_ENHANCING:
        return "enhancing"
    return "required"


def classify(domain, status, ips, cnames, org):
    if status == 3:  # NXDOMAIN
        return "rejected"
    if _has_suffix(domain, TRUSTED_SUFFIXES) or _has_suffix(domain, PARTNER_SUFFIXES):
        return "verified"
    if ips or cnames:  # resolves
        if any(t in org.upper() for t in TRUSTED_ORG_TOKENS):
            return "verified"
        return "unverified"
    return "unverified"


def _collapse(blocks):
    """Drop any block that is a subnet of a larger block already kept."""
    kept = []
    nets = sorted((ipaddress.ip_network(b) for b in blocks if "/" in b),
                  key=lambda n: (n.prefixlen, int(n.network_address)))
    for n in nets:
        if not any(n.subnet_of(k) for k in kept):
            kept.append(n)
    return sorted(str(k) for k in kept)


def main():
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    state = load_state()
    domains = state.setdefault("domains", {})
    changed = False
    report = {"new_verified": [], "new_unverified": [], "rejected": [],
              "stale": [], "errors": []}

    # 1) ensure all seed domains exist in state
    for d, src in SEED:
        if d not in domains:
            domains[d] = {
                "hostname": d, "status": "unverified", "first_seen": today,
                "last_seen": None, "session_phase": "unknown",
                "resolved_asn": "", "ips": [], "source": src,
            }
            changed = True

    # 2) discover candidates from cert SAN clustering + community scrape
    new_candidates = scrape_candidates()
    trusted_hosts = [d for d in domains if d.endswith(TRUSTED_SUFFIXES)]
    for host in trusted_hosts[:25]:  # cap to keep the run fast
        for san in cert_sans(host):
            san = san.lstrip("*.").lower().rstrip(".")
            if san.endswith(TRUSTED_SUFFIXES) or san.endswith(PARTNER_SUFFIXES):
                new_candidates.add(san)
    for c in new_candidates:
        if c not in domains:
            domains[c] = {
                "hostname": c, "status": "unverified", "first_seen": today,
                "last_seen": None, "session_phase": "unknown",
                "resolved_asn": "", "ips": [], "source": "discovered",
            }
            changed = True

    # 3) verify every domain
    ip_orgs = {}  # ip -> (netname, netblocks, org)
    for d, rec in domains.items():
        status, ips, cnames = doh(d)
        if status == -1:
            report["errors"].append(d)
            continue
        asn = ""
        if ips:
            for ip in ips:
                if ip not in ip_orgs:
                    name, blocks, org = rdap(ip)
                    ip_orgs[ip] = (name, blocks, org)
            names = ip_orgs[ips[0]]
            asn = f"{names[0]} | {names[2]}"
            rec["ips"] = sorted(set(ips))
        rec["resolved_asn"] = asn or ""
        old_status = rec.get("status")
        new_status = classify(d, status, ips, cnames, asn)
        rec["status"] = new_status
        crit = criticality(d)
        if rec.get("criticality") != crit:
            rec["criticality"] = crit
            changed = True
        if ips or cnames or local_blocked(d):
            rec["last_seen"] = today
        if old_status != new_status:
            changed = True
        if new_status == "rejected" and old_status not in (None, "rejected"):
            report["rejected"].append(d)
        if new_status == "verified" and old_status not in ("verified",):
            report["new_verified"].append(d)
        if new_status == "unverified" and old_status not in ("unverified",):
            report["new_unverified"].append(d)

    # 4) record local-sinkhole status (informational only — a name sinkholed by
    #    THIS box's resolver is NOT proof the client is broken).
    for d, rec in domains.items():
        if rec["status"] == "verified":
            bl = local_blocked(d)
            if bl != rec.get("blocked_locally"):
                rec["blocked_locally"] = bl
                changed = True

    # 5) stale flag (>90 days not seen)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=90)).strftime("%Y-%m-%d")
    for d, rec in domains.items():
        ls = rec.get("last_seen")
        if rec["status"] == "verified" and ls and ls < cutoff:
            report["stale"].append(d)

    # 6) rebuild IP netblocks (trusted orgs only)
    netblocks = set(KNOWN_IP_BLOCKS)
    for ip, (name, blocks, org) in ip_orgs.items():
        if any(t in org.upper() for t in IP_ORG_TOKENS) or any(t in name.upper() for t in IP_ORG_TOKENS):
            netblocks.update(blocks)
    netblocks = _collapse(netblocks)
    if netblocks != state.get("ip_netblocks"):
        state["ip_netblocks"] = netblocks
        changed = True

    # 7) regenerate list files (telemetry domains excluded from the live allowlist)
    verified = sorted(d for d, r in domains.items()
                      if r["status"] == "verified" and r.get("criticality", "required") != "telemetry")
    unverified = sorted(d for d, r in domains.items()
                        if r["status"] == "unverified" and r.get("criticality", "required") != "telemetry")
    telemetry = sorted(d for d, r in domains.items()
                       if r["status"] == "verified" and r.get("criticality", "required") == "telemetry")

    verified_lines = list(verified)
    if unverified:
        verified_lines += [""] + ["# unverified (review before adding)"] + list(unverified)
    domains_txt = "\n".join(verified_lines) + "\n"
    ips_txt = "\n".join(netblocks) + "\n"
    adguard_txt = "\n".join(f"@@||{d}^" for d in verified) + "\n"
    regex_txt = "\n".join(
        r"(\.|^)" + re.escape(d) + r"$" for d in verified
    ) + "\n"
    telemetry_txt = ("# Telemetry / analytics — intentionally kept BLOCKED (not allowlisted):\n"
                     + "".join(f"# {d}\n" for d in telemetry) + "\n")
    # GL.iNet "online text file" format (firmware 4.7+): one filter per line.
    # A bare parent domain matches ALL subdomains, so emit only apex domains
    # (from trusted_suffixes) + CIDRs — NOT deep subdomains/CDN CNAMEs, which
    # GL.iNet's parser rejects as invalid.
    glinet_domains = sorted(s.lstrip(".") for s in TRUSTED_SUFFIXES)
    glinet_txt = "\n".join(glinet_domains + netblocks) + "\n"

    files = {
        "domains.txt": domains_txt,
        "ips.txt": ips_txt,
        "domains-adguard.txt": adguard_txt,
        "domains-regex.txt": regex_txt,
        "telemetry.txt": telemetry_txt,
        "glinet.txt": glinet_txt,
    }
    for fn, content in files.items():
        p = os.path.join(REPO, fn)
        old = open(p).read() if os.path.exists(p) else ""
        if old != content:
            with open(p, "w") as f:
                f.write(content)
            changed = True

    # 8) write JSON only on a real change (keeps tree clean / idempotent)
    if changed:
        state["last_updated"] = datetime.now(timezone.utc).isoformat()
        tmp = JSON_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump(state, f, indent=2, ensure_ascii=False, sort_keys=True)
        os.replace(tmp, JSON_PATH)

    # 9) commit + push if changed
    commit = None
    if changed:
        subprocess.run(["git", "-C", REPO, "add", "-A"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        r = subprocess.run(
            ["git", "-C", REPO,
             "-c", f"credential.helper=store --file={GIT_CRED}",
             "-c", "user.name=Aadhil Musthaq",
             "-c", "user.email=musthaqaadhil@gmail.com",
             "commit", "-m", f"chore: allowlist refresh {today}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if r.returncode == 0:
            pr = subprocess.run(
                ["git", "-C", REPO,
                 "-c", f"credential.helper=store --file={GIT_CRED}",
                 "push", "-q", "origin", "main"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if pr.returncode == 0:
                commit = subprocess.run(
                    ["git", "-C", REPO, "rev-parse", "--short", "HEAD"],
                    stdout=subprocess.PIPE).stdout.decode().strip()
            else:
                report["errors"].append("git push failed")

    # 10) report — silent unless something changed or needs attention
    has_alert = (report["new_unverified"] or report["rejected"] or
                 report["stale"] or report["errors"])
    if not changed and not has_alert:
        return 0

    n_verified = sum(1 for r in domains.values() if r["status"] == "verified")
    n_unver = sum(1 for r in domains.values() if r["status"] == "unverified")
    n_rej = sum(1 for r in domains.values() if r["status"] == "rejected")
    lines = [f"📡 {NAME} allowlist refresh — {today}",
             f"Domains: {len(domains)} total · {n_verified} verified · {n_unver} unverified · {n_rej} rejected"]
    if commit:
        lines.append(f"Updated & pushed ({commit}): {len(verified)} verified domains, {len(netblocks)} IP blocks")
    else:
        lines.append("No changes — allowlist already current")
    if telemetry:
        lines.append("🔇 Telemetry (kept blocked): " + ", ".join(telemetry))
    if report["new_verified"]:
        lines.append("➕ Newly verified: " + ", ".join(report["new_verified"]))
    if report["new_unverified"]:
        lines.append("🟡 Needs review (unverified): " + ", ".join(report["new_unverified"]))
    if report["rejected"]:
        lines.append("🚫 Rejected (NXDOMAIN): " + ", ".join(report["rejected"]))
    if report["stale"]:
        lines.append("⏳ Stale (>90d unseen, review for removal): " + ", ".join(report["stale"]))
    if report["errors"]:
        lines.append("🔴 Lookup errors: " + ", ".join(report["errors"]))
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
