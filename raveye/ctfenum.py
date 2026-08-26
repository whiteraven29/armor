#!/usr/bin/env python3
"""
enum.py — a service-aware enumeration checklist tracker for CTFs / offensive tasks.

The problem it solves: enumeration is a tree, and you lose track of which
branches you've explored. This keeps per-target state on disk, and whenever you
record an open port/service, it surfaces the standard follow-up checks for that
service so you stop missing points.

Everything is stored as JSON under ~/.enumhelper/<target>.json so it survives
across sessions. No scanning is performed automatically — it prints the commands
it suggests so YOU stay in control and learn them.
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

STATE_DIR = Path.home() / ".enumhelper"

# ---------------------------------------------------------------------------
# Service playbooks: for a given service keyword, the checks you should not skip.
# Extend these freely — this file is meant to grow with your own methodology.
# {ip} and {port} get substituted when displayed.
# ---------------------------------------------------------------------------
PLAYBOOKS = {
    "ftp": [
        ("anon-login", "Try anonymous login", "ftp {ip} {port}  # user: anonymous, pass: anything"),
        ("version-cve", "Grab banner, check version for known CVEs", "nmap -sV -p{port} {ip}"),
        ("nmap-scripts", "Run ftp NSE scripts", "nmap --script ftp-anon,ftp-bounce,ftp-syst -p{port} {ip}"),
        ("upload-test", "If writable, test file upload (webroot?)", None),
    ],
    "ssh": [
        ("version-cve", "Check SSH version for known CVEs / user enum", "nmap -sV -p{port} {ip}"),
        ("auth-methods", "Enumerate accepted auth methods", "ssh -v {ip} -p {port}"),
        ("weak-creds", "Try creds found elsewhere / default creds", None),
        ("key-reuse", "Check for reused/leaked private keys on other services", None),
    ],
    "http": [
        ("whatweb", "Fingerprint stack", "whatweb http://{ip}:{port}"),
        ("headers", "Inspect response headers / cookies", "curl -sI http://{ip}:{port}"),
        ("dir-brute", "Directory & file brute force", "feroxbuster -u http://{ip}:{port} -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"),
        ("vhost", "Virtual host / subdomain fuzzing (add host to /etc/hosts first)", "ffuf -u http://{ip}:{port}/ -H 'Host: FUZZ.target.tld' -w subdomains.txt -fs 0"),
        ("robots-sitemap", "Check robots.txt, sitemap.xml, .git, .env, backups", "curl -s http://{ip}:{port}/robots.txt"),
        ("source-comments", "View source for comments, JS endpoints, API keys", None),
        ("nikto", "Baseline web vuln scan", "nikto -h http://{ip}:{port}"),
        ("known-cms", "If CMS (WordPress/Joomla/etc), run targeted scanner", "wpscan --url http://{ip}:{port} --enumerate"),
    ],
    "https": [
        ("cert-info", "Read TLS cert for hostnames / emails / internal names", "openssl s_client -connect {ip}:{port} </dev/null 2>/dev/null | openssl x509 -noout -text"),
        ("same-as-http", "Then run the full http playbook against https://", None),
    ],
    "smb": [
        ("null-session", "Try null/guest session", "smbclient -N -L //{ip}/"),
        ("enum-shares", "Enumerate shares & permissions", "netexec smb {ip} -u '' -p '' --shares"),
        ("version-cve", "OS/version → known CVEs (EternalBlue etc.)", "nmap --script smb-vuln* -p{port} {ip}"),
        ("rid-brute", "RID brute to enumerate users", "netexec smb {ip} -u guest -p '' --rid-brute"),
        ("read-shares", "Recursively pull readable shares", "smbclient //{ip}/SHARE -N  # then recurse; prompt off, mget *"),
    ],
    "rpc": [
        ("null-bind", "Anonymous rpcclient bind", "rpcclient -U '' -N {ip}"),
        ("enum-users", "enumdomusers / querydispinfo", "rpcclient -U '' -N {ip} -c 'enumdomusers'"),
    ],
    "ldap": [
        ("anon-bind", "Anonymous bind + base DN dump", "ldapsearch -x -H ldap://{ip} -s base namingcontexts"),
        ("enum", "Dump users/groups if bind works", "ldapsearch -x -H ldap://{ip} -b 'DC=domain,DC=tld'"),
    ],
    "dns": [
        ("zone-transfer", "Attempt AXFR zone transfer", "dig axfr @{ip} target.tld"),
        ("reverse", "Reverse lookups / hostname discovery", "dig -x {ip} @{ip}"),
    ],
    "mysql": [
        ("weak-creds", "Try root/no-pass and found creds", "mysql -h {ip} -u root"),
        ("version-cve", "Version → CVEs", "nmap -sV -p{port} {ip}"),
    ],
    "mssql": [
        ("login", "Login with found/default creds", "netexec mssql {ip} -u sa -p ''"),
        ("xp-cmdshell", "If admin, check command exec surface", None),
    ],
    "smtp": [
        ("user-enum", "VRFY / RCPT user enumeration", "smtp-user-enum -M VRFY -U users.txt -t {ip}"),
        ("open-relay", "Test for open relay", None),
    ],
    "snmp": [
        ("community", "Brute community strings", "onesixtyone {ip} -c community.txt"),
        ("walk", "Walk the MIB with a valid string", "snmpwalk -v2c -c public {ip}"),
    ],
    "redis": [
        ("unauth", "Test unauthenticated access", "redis-cli -h {ip} -p {port} INFO"),
        ("rce-paths", "Known RCE via config/module load if writable", None),
    ],
    "nfs": [
        ("showmount", "List exports", "showmount -e {ip}"),
        ("mount", "Mount and inspect for creds/keys", "mount -t nfs {ip}:/export /mnt/nfs"),
    ],
    "telnet": [
        ("banner", "Grab banner, note software/version", "telnet {ip} {port}"),
        ("weak-creds", "Try default/found creds", None),
    ],
    "pop3": [
        ("banner", "Grab banner / capabilities", "nc -nv {ip} {port}  # USER x / PASS y"),
        ("read-mail", "Login and read mail for creds/info", "openssl s_client -connect {ip}:{port}  # if TLS"),
    ],
    "imap": [
        ("banner", "Grab banner / capabilities", "nc -nv {ip} {port}  # a LOGIN user pass"),
        ("read-mail", "Login and list/read mailboxes", None),
    ],
    "rdp": [
        ("ntlm-info", "Leak hostname/domain via NLA", "nmap --script rdp-ntlm-info -p{port} {ip}"),
        ("weak-creds", "Spray found/default creds (watch lockouts!)", "netexec rdp {ip} -u users.txt -p passwords.txt"),
        ("bluekeep", "CVE-2019-0708 if old Windows", "nmap --script rdp-vuln-ms12-020 -p{port} {ip}"),
    ],
    "vnc": [
        ("no-auth", "Test for no-auth / bypass", "nmap --script vnc-info,realvnc-auth-bypass -p{port} {ip}"),
        ("connect", "Connect with found password", "vncviewer {ip}:{port}"),
    ],
    "winrm": [
        ("login", "Auth with found creds", "netexec winrm {ip} -u user -p pass"),
        ("evil-winrm", "If creds valid → shell", "evil-winrm -i {ip} -u user -p pass"),
    ],
    "kerberos": [
        ("user-enum", "Enumerate valid users (no creds)", "kerbrute userenum -d domain.tld --dc {ip} users.txt"),
        ("asrep", "AS-REP roast users w/o preauth", "impacket-GetNPUsers domain.tld/ -usersfile users.txt -dc-ip {ip}"),
        ("kerberoast", "With creds, roast SPNs", "impacket-GetUserSPNs domain.tld/user:pass -dc-ip {ip} -request"),
    ],
    "postgresql": [
        ("weak-creds", "Try postgres/no-pass and found creds", "psql -h {ip} -p {port} -U postgres"),
        ("rce", "If superuser: COPY ... FROM PROGRAM for RCE", None),
    ],
    "mongodb": [
        ("unauth", "Test unauth access, list DBs", "mongosh --host {ip} --port {port} --eval 'db.adminCommand({listDatabases:1})'"),
        ("dump", "Dump collections for creds/flags", None),
    ],
    "oracle": [
        ("sid-enum", "Enumerate SIDs", "nmap --script oracle-sid-brute -p{port} {ip}"),
        ("odat", "All-in-one (creds, TNS poison, files)", "odat all -s {ip} -p {port}"),
    ],
    "rsync": [
        ("list-modules", "List rsync modules/shares", "rsync -av --list-only rsync://{ip}:{port}/"),
        ("pull", "Pull readable module contents", "rsync -av rsync://{ip}:{port}/MODULE ./loot/"),
    ],
    "elasticsearch": [
        ("unauth", "Test unauth, list indices", "curl -s http://{ip}:{port}/_cat/indices?v"),
        ("dump", "Pull docs from interesting indices", "curl -s http://{ip}:{port}/INDEX/_search?pretty"),
    ],
}

# When importing from nmap, map port number / nmap service name -> playbook key.
# Falls back to the raw nmap service name if there's no hint here.
PORT_HINTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    88: "kerberos", 110: "pop3", 135: "rpc", 139: "smb", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "smb", 636: "ldap",
    873: "rsync", 1433: "mssql", 1521: "oracle", 2049: "nfs", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5900: "vnc", 5985: "winrm", 5986: "winrm",
    6379: "redis", 8080: "http", 8443: "https", 9200: "elasticsearch",
    27017: "mongodb",
}

# nmap's service names differ from our playbook keys; normalize the common ones.
NMAP_SERVICE_MAP = {
    "microsoft-ds": "smb", "netbios-ssn": "smb", "ms-wbt-server": "rdp",
    "domain": "dns", "ssl/http": "https", "https-alt": "https",
    "http-alt": "http", "msrpc": "rpc", "ms-sql-s": "mssql",
    "postgres": "postgresql", "mongod": "mongodb", "oracle-tns": "oracle",
    "imaps": "imap", "pop3s": "pop3", "smtps": "smtp",
}

# Baseline checks that apply to every target, regardless of services.
GLOBAL_CHECKS = [
    ("full-tcp", "Full TCP port scan (all 65535) — don't trust the top-1000 only", "nmap -p- --min-rate 2000 {ip} -oA nmap/alltcp"),
    ("udp-top", "UDP top ports (people forget UDP constantly)", "nmap -sU --top-ports 100 {ip} -oA nmap/udp"),
    ("service-scan", "Version + default scripts on found ports", "nmap -sVC -p<PORTS> {ip} -oA nmap/services"),
]


def target_file(target):
    return STATE_DIR / f"{target.replace('/', '_')}.json"


def load(target):
    f = target_file(target)
    if f.exists():
        return json.loads(f.read_text())
    return {"target": target, "created": now(), "services": [], "checks": {}, "notes": [], "creds": []}


def save(target, data):
    STATE_DIR.mkdir(exist_ok=True)
    target_file(target).write_text(json.dumps(data, indent=2))


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M")


def check_key(scope, name):
    return f"{scope}:{name}"


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
def _playbook_for(svc):
    """Checks to load for a service. https inherits the full http playbook too."""
    checks = list(PLAYBOOKS.get(svc, []))
    if svc == "https":
        # reuse the http checks but point them at the TLS scheme
        for name, desc, cmd in PLAYBOOKS["http"]:
            checks.append((name, desc, cmd.replace("http://", "https://") if cmd else cmd))
    return checks


def _add_service(data, port, svc, note=""):
    """Add one service (dedup) and load its checks. Returns (is_new, loaded_count)."""
    svc = svc.lower()
    port = str(port)
    is_new = not any(s["port"] == port and s["service"] == svc for s in data["services"])
    if is_new:
        data["services"].append({"port": port, "service": svc, "note": note, "added": now()})

    loaded = 0
    for name, desc, cmd in _playbook_for(svc):
        k = check_key(f"{svc}/{port}", name)
        if k not in data["checks"]:
            data["checks"][k] = {"desc": desc, "cmd": cmd, "done": False,
                                 "port": port, "service": svc}
            loaded += 1
    return is_new, loaded


def cmd_add(args):
    """Record an open service and auto-load its follow-up checks."""
    data = load(args.target)
    svc = args.service.lower()
    is_new, loaded = _add_service(data, args.port, svc, args.note or "")
    save(args.target, data)

    print(f"[+] {'Added' if is_new else 'Re-synced'} {svc} on port {args.port}.")
    if _playbook_for(svc):
        print(f"[+] {loaded} new follow-up check(s). Run `enum next {args.target}` to see them.")
    else:
        print(f"[!] No playbook for '{svc}' yet — add one to PLAYBOOKS in the script.")


def _render_cmd(cmd, ip, port):
    if not cmd:
        return None
    return cmd.replace("{ip}", ip).replace("{port}", str(port))


def cmd_next(args):
    """Show everything still unchecked — this is the anti-missing-points view."""
    data = load(args.target)
    ip = args.target
    pending_global = [(check_key("global", n), d, c) for n, d, c in GLOBAL_CHECKS
                      if not data["checks"].get(check_key("global", n), {}).get("done")]

    # Ensure global checks exist in state
    for n, d, c in GLOBAL_CHECKS:
        k = check_key("global", n)
        data["checks"].setdefault(k, {"desc": d, "cmd": c, "done": False, "service": "global"})
    save(ip, data)

    pending = {k: v for k, v in data["checks"].items() if not v["done"]}
    flt = getattr(args, "service", None)
    if flt:
        flt = flt.lower()
        pending = {k: v for k, v in pending.items()
                   if v.get("service") == flt or k.split(":", 1)[0].startswith(f"{flt}/")}
    if not pending:
        msg = f"for service '{flt}' " if flt else ""
        print(f"[*] Nothing pending {msg}— you're thorough, or nothing's been added yet.")
        return

    # group by scope
    by_scope = {}
    for k, v in pending.items():
        scope = k.split(":")[0]
        by_scope.setdefault(scope, []).append((k, v))

    print(f"\n=== PENDING CHECKS for {ip} ===\n")
    for scope in sorted(by_scope, key=lambda s: (s != "global", s)):
        print(f"[{scope}]")
        for k, v in by_scope[scope]:
            name = k.split(":", 1)[1]
            rendered = _render_cmd(v.get("cmd"), ip, v.get("port", ""))
            print(f"  ☐ {name:16} {v['desc']}")
            if rendered:
                print(f"      $ {rendered}")
        print()
    print(f"Mark done with:  enum done {ip} <scope>:<name>")


def _resolve_check(data, target, name):
    """Exact key, else fuzzy substring/suffix match. Returns key or None (and prints why)."""
    if name in data["checks"]:
        return name
    matches = [k for k in data["checks"] if k.endswith(name) or name in k]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        print("[!] Ambiguous. Matches:")
        for m in matches:
            print(f"    {m}")
        return None
    print(f"[!] No check matching '{name}'. Run `enum next {target}`.")
    return None


def cmd_done(args):
    data = load(args.target)
    key = _resolve_check(data, args.target, args.check)
    if key is None:
        return
    data["checks"][key]["done"] = True
    data["checks"][key]["done_at"] = now()
    save(args.target, data)
    print(f"[+] Marked done: {key}")


def cmd_undone(args):
    data = load(args.target)
    key = _resolve_check(data, args.target, args.check)
    if key is None:
        return
    data["checks"][key]["done"] = False
    data["checks"][key].pop("done_at", None)
    save(args.target, data)
    print(f"[+] Reopened: {key}")


def cmd_note(args):
    data = load(args.target)
    data["notes"].append({"t": now(), "text": args.text})
    save(args.target, data)
    print("[+] Note saved.")


def cmd_cred(args):
    data = load(args.target)
    data["creds"].append({"t": now(), "text": args.text})
    save(args.target, data)
    print(f"[+] Cred stashed: {args.text}")


def cmd_status(args):
    data = load(args.target)
    total = len(data["checks"])
    done = sum(1 for v in data["checks"].values() if v["done"])
    print(f"\n=== {args.target} ===")
    print(f"created: {data['created']}")
    svc_list = ", ".join("{}/{}".format(s["service"], s["port"]) for s in data["services"])
    print(f"services: {svc_list or '(none)'}")
    print(f"progress: {done}/{total} checks done")
    if data["creds"]:
        print("creds:")
        for c in data["creds"]:
            print(f"   - {c['text']}")
    if data["notes"]:
        print("notes:")
        for n in data["notes"][-10:]:
            print(f"   [{n['t']}] {n['text']}")
    print()


def cmd_list(args):
    STATE_DIR.mkdir(exist_ok=True)
    files = sorted(STATE_DIR.glob("*.json"))
    if not files:
        print("No targets yet. Start with:  enum add <ip> <port> <service>")
        return
    for f in files:
        d = json.loads(f.read_text())
        done = sum(1 for v in d["checks"].values() if v["done"])
        print(f"  {d['target']:20} {len(d['services'])} svc, {done}/{len(d['checks'])} checks")


def _svc_from_nmap(port, name):
    """Best-effort map a discovered port to a playbook key."""
    name = (name or "").lower().strip()
    if name in NMAP_SERVICE_MAP:
        return NMAP_SERVICE_MAP[name]
    if name in PLAYBOOKS:
        return name
    if int(port) in PORT_HINTS:
        return PORT_HINTS[int(port)]
    return name or PORT_HINTS.get(int(port), "unknown")


def _parse_nmap(text):
    """Yield (port, service) for open ports from nmap -oX (XML) or -oG (greppable)."""
    stripped = text.lstrip()
    if stripped.startswith("<?xml") or "<nmaprun" in stripped[:2000]:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(text)
        for port in root.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            name = svc.get("name") if svc is not None else ""
            yield port.get("portid"), name
        return
    # greppable: lines like  Host: 10.0.0.1 () Ports: 22/open/tcp//ssh//..., 80/open/tcp//http//
    for line in text.splitlines():
        if "Ports:" not in line:
            continue
        ports_field = line.split("Ports:", 1)[1]
        for chunk in ports_field.split(","):
            parts = chunk.strip().split("/")
            if len(parts) >= 5 and parts[1] == "open":
                yield parts[0], parts[4]


def cmd_import(args):
    """Bulk-add open ports from an nmap output file (-oX XML or -oG greppable)."""
    path = Path(args.file)
    if not path.exists():
        print(f"[!] No such file: {args.file}")
        return
    try:
        found = list(_parse_nmap(path.read_text()))
    except Exception as e:
        print(f"[!] Couldn't parse '{args.file}' as nmap XML/greppable: {e}")
        return
    if not found:
        print("[!] No open ports found. Save nmap with -oG or -oX (not -oN plain text).")
        return

    data = load(args.target)
    added, total_checks, no_pb = 0, 0, []
    for port, name in found:
        svc = _svc_from_nmap(port, name)
        is_new, loaded = _add_service(data, port, svc)
        added += is_new
        total_checks += loaded
        if not _playbook_for(svc):
            no_pb.append(f"{svc}/{port}")
    save(args.target, data)

    print(f"[+] Imported {len(found)} open port(s): {added} new, {total_checks} checks loaded.")
    if no_pb:
        print(f"[!] No playbook yet for: {', '.join(sorted(set(no_pb)))}")
    print(f"[+] Run `enum next {args.target}` to see what's pending.")


def cmd_export(args):
    """Emit a Markdown report of the whole target — for handoff / report time."""
    data = load(args.target)
    lines = [f"# Enumeration report — {data['target']}", "",
             f"*Created {data['created']}*", "", "## Services", ""]
    if data["services"]:
        for s in data["services"]:
            extra = f" — {s['note']}" if s.get("note") else ""
            lines.append(f"- **{s['service']}/{s['port']}**{extra}")
    else:
        lines.append("_(none recorded)_")

    lines += ["", "## Checks", ""]
    by_scope = {}
    for k, v in data["checks"].items():
        by_scope.setdefault(k.split(":", 1)[0], []).append((k.split(":", 1)[1], v))
    for scope in sorted(by_scope, key=lambda s: (s != "global", s)):
        lines.append(f"### {scope}")
        for name, v in by_scope[scope]:
            box = "x" if v["done"] else " "
            done_at = f" _(done {v['done_at']})_" if v.get("done_at") else ""
            lines.append(f"- [{box}] **{name}** — {v['desc']}{done_at}")
            rendered = _render_cmd(v.get("cmd"), data["target"], v.get("port", ""))
            if rendered:
                lines.append(f"  - `{rendered}`")
        lines.append("")

    if data["creds"]:
        lines += ["## Credentials", ""]
        lines += [f"- `{c['text']}` _({c['t']})_" for c in data["creds"]]
        lines.append("")
    if data["notes"]:
        lines += ["## Notes", ""]
        lines += [f"- [{n['t']}] {n['text']}" for n in data["notes"]]
        lines.append("")

    report = "\n".join(lines)
    if args.out:
        Path(args.out).write_text(report)
        print(f"[+] Wrote report to {args.out}")
    else:
        print(report)


def build_parser():
    p = argparse.ArgumentParser(prog="enum", description="Service-aware enumeration checklist tracker.")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("add", help="record an open service (auto-loads its checks)")
    a.add_argument("target"); a.add_argument("port"); a.add_argument("service")
    a.add_argument("--note", "-n")
    a.set_defaults(func=cmd_add)

    n = sub.add_parser("next", help="show all pending checks (the anti-miss view)")
    n.add_argument("target"); n.add_argument("--service", "-s", help="only this service")
    n.set_defaults(func=cmd_next)

    d = sub.add_parser("done", help="mark a check complete")
    d.add_argument("target"); d.add_argument("check")
    d.set_defaults(func=cmd_done)

    u = sub.add_parser("undone", help="reopen a check marked done by mistake")
    u.add_argument("target"); u.add_argument("check")
    u.set_defaults(func=cmd_undone)

    im = sub.add_parser("import", help="bulk-add ports from an nmap -oG/-oX file")
    im.add_argument("target"); im.add_argument("file")
    im.set_defaults(func=cmd_import)

    ex = sub.add_parser("export", help="emit a Markdown report of the target")
    ex.add_argument("target"); ex.add_argument("--out", "-o", help="write to file instead of stdout")
    ex.set_defaults(func=cmd_export)

    no = sub.add_parser("note", help="attach a note to the target")
    no.add_argument("target"); no.add_argument("text"); no.set_defaults(func=cmd_note)

    c = sub.add_parser("cred", help="stash a credential you found")
    c.add_argument("target"); c.add_argument("text"); c.set_defaults(func=cmd_cred)

    s = sub.add_parser("status", help="summary for one target")
    s.add_argument("target"); s.set_defaults(func=cmd_status)

    l = sub.add_parser("list", help="list all targets")
    l.set_defaults(func=cmd_list)

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
