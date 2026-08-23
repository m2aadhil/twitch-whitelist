# Twitch Whitelist 🎮

Domains & IP ranges to **whitelist** so **Twitch** (live streams, VOD, chat, login) keeps working on a **GL.iNet router** running a VPN, AdGuard Home, or any DNS-based blocker.

- ✅ Split-tunnel Twitch **out of the VPN** (video + chat stay smooth)
- ✅ Allow Twitch in **AdGuard Home / ad-block**
- ✅ Keep everything else on your VPN / blocker

---

## Why

Twitch is Amazon-owned and serves content through a mix of **Fastly**, **AWS CloudFront**, and Twitch's own CDN (`jtvnw.net` / `ttvnw.net` / `twitchcdn.net`). DNS blockers and aggressive VPN routing commonly break one of the layers — video doesn't load, chat won't connect, or login loops. This list keeps the whole surface reachable.

> Unlike Magenta TV, Twitch has **no geo-lock** — so this is purely about keeping DNS filtering and VPN routing from breaking playback, not about regional access.

## Files

| File | Format | Use |
|------|--------|-----|
| [`glinet.txt`](glinet.txt) | one filter/line (domains + CIDRs) | **GL.iNet direct import** (VPN Policy / Parental Control) |
| [`domains.txt`](domains.txt) | plain, one per line | AdGuard / ad-block whitelist |
| [`ips.txt`](ips.txt) | CIDR, one per line | firewall / policy routing |
| [`domains-adguard.txt`](domains-adguard.txt) | `@@\|\|domain^` | AdGuard Home custom allowlist rules |
| [`domains-regex.txt`](domains-regex.txt) | Pi-hole regex | Pi-hole allowlist |

---

## GL.iNet — import by URL (firmware v4.7+)

GL.iNet routers (v4.7+) can import rules straight from an online text file. Use the **raw** URL (not the `github.com/.../blob/...` page URL):

```
https://raw.githubusercontent.com/m2aadhil/twitch-whitelist/main/glinet.txt
```

- **VPN → VPN Policy** → "Based on target domain or IP" → import the URL above.
- **Parental Control → Add a New Ruleset** → import the URL above (domain filters only).

`glinet.txt` follows the GL.iNet format: **one filter per line** — `domain` (matches all subdomains), `subdomain`, or `CIDR` — no comments.

> ⚠️ Only `glinet.txt` is GL.iNet-format. Do **not** import `domains-adguard.txt` (`@@||…^`) or `domains-regex.txt` (Pi-hole regex) into GL.iNet — those use a different syntax and every line will be rejected.

## GL.iNet — VPN split-tunnel (recommended)

1. Admin panel → **VPN → VPN Client** → your WireGuard/OpenVPN profile → **Global Options**.
2. Open **VPN Policy** (a.k.a. **Proxy Mode**).
3. Enable **Policy Mode** and select **"Proxy all traffic except the following"**.
4. Add the entries from [`domains.txt`](domains.txt) and [`ips.txt`](ips.txt).
5. Save & apply. Twitch now bypasses the VPN.

> On some firmware versions the rule is labelled **"Based on the target domain or IP"** — add the domains and IPs there.

## GL.iNet — AdGuard Home / ad-block allowlist

- **AdGuard Home** → **Filters → Custom filtering rules** → paste [`domains-adguard.txt`](domains-adguard.txt).
- Built-in **Ad Block** (dnsmasq-based) → whitelist → paste [`domains.txt`](domains.txt).

---

## The lists

### Core domains

```
twitch.tv
twitch.com
jtvnw.net
ttvnw.net
live-video.net
twitchcdn.net
```

### IP ranges

Twitch's own delivery servers live in `99.181.0.0/16` (Twitch Interactive / AS46489); the exact blocks are maintained in [`ips.txt`](ips.txt). Everything else (Fastly, CloudFront) rotates, so whitelist those **by domain only**.

---

## Auto-maintenance (daily job)

This repo self-updates. A scheduled job runs [`scripts/update_allowlist.py`](scripts/update_allowlist.py) daily and:

1. Re-resolves every domain via public **DoH** and maps each IP to its **ASN/org** (RIPE/ARIN RDAP).
2. Discovers new candidates via **TLS cert SAN clustering** (finds sibling `*.ttvnw.net` / `*.jtvnw.net` hosts).
3. Classifies each domain (`verified` / `unverified` / `rejected`).
4. Regenerates the list files and commits+pushes **only on change** (idempotent).

State lives in [`twitch-allowlist.json`](twitch-allowlist.json). The job is **additive** — never auto-deletes; stale domains (>90 days) are only flagged.

## Notes

- Twitch video delivery (`video-weaver.*.hls.ttvnw.net`, ingest `*.live-video.net`) is heavily regional and **rotates subdomains** — that's why the whole `ttvnw.net` / `jtvnw.net` / `live-video.net` parent domains are whitelisted rather than individual hosts.
- Fastly (`151.101.0.0/16`) and CloudFront IPs are shared with thousands of sites — never whitelist those by IP.

## License

[MIT](LICENSE)
