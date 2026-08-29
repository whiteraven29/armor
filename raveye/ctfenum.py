#!/usr/bin/env python3
"""
ctfenum.py — a target-centric enumeration lab notebook for CTFs / offensive tasks.

The problem it solves: enumeration is a tree, and you lose track of which
branches you've explored — and by report time you've forgotten what you ran and
where the evidence lives. This keeps per-target state on disk, surfaces the
standard follow-up checks for each service, *executes and captures* those checks
(human-in-the-loop), tracks loot/creds with provenance, and exports a
report-ready Markdown lab notebook.

Everything is stored as JSON under ~/.enumhelper/<target>.json so it survives
across sessions. Artifacts land in ~/.enumhelper/<target>_loot/. Nothing is
scanned automatically and nothing runs without your say-so — `enum run` prompts
before every command and defaults to dry-run unless ENUM_LIVE=1.

Data model (one JSON per target):
    meta     : {target, created, os_hint, tags[]}
    services : [{port, service, note, added}]
    checks   : {"<scope>:<name>": {desc, cmd, state, priority, requires[], runs[]}}
               state ∈ pending | running | done | failed | skipped
               runs is an append-only history: [{t, cmd, exit, stdout, stderr, artifact}]
    loot     : [{t, path, sha256, tag, check, note}]     # provenance -> check
    creds    : [{t, user, pass, context, check}]         # structured
    notes    : [{t, text, check, scope}]
"""

import argparse
import fnmatch
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

STATE_DIR = Path.home() / ".enumhelper"
PLAYBOOK_FILE = STATE_DIR / "playbooks.json"
TEMPLATE_DIR = STATE_DIR / "templates"

STATES = ("pending", "running", "done", "failed", "skipped")
STATE_BADGE = {
    "pending": "☐", "running": "▷", "done": "✓", "failed": "✗", "skipped": "⊘",
}

# ---------------------------------------------------------------------------
# Service playbooks: for a given service keyword, the checks you should not skip.
# Extend these freely — this file is meant to grow with your own methodology,
# or drop overrides in ~/.enumhelper/playbooks.json (see `enum playbook edit`).
#
# Each entry is a tuple. Length is flexible so old 3-tuples keep working:
#   (name, desc, cmd)
#   (name, desc, cmd, priority)                     priority ∈ quick|normal|slow
#   (name, desc, cmd, priority, requires_list)      requires gate the check
# {ip}, {port}, {user}, {pass} get substituted when displayed / run.
# A `requires` token is one of:
#   creds[:label]     met once any credential is stashed for the target
#   check:<substr>    met once a check whose key matches <substr> is done
#   loot[:tag]        met once loot (optionally with that tag) exists
#   service:<svc>     met once that service has been added
# ---------------------------------------------------------------------------
PLAYBOOKS = {
    "ftp": [
        ("anon-login", "Try anonymous login", "ftp {ip} {port}  # user: anonymous, pass: anything", "quick"),
        ("version-cve", "Grab banner, check version for known CVEs", "nmap -sV -p{port} {ip}", "quick"),
        ("nmap-scripts", "Run ftp NSE scripts", "nmap --script ftp-anon,ftp-bounce,ftp-syst -p{port} {ip}", "quick"),
        ("upload-test", "If writable, test file upload (webroot?)", None, "normal"),
    ],
    "ssh": [
        ("version-cve", "Check SSH version for known CVEs / user enum", "nmap -sV -p{port} {ip}", "quick"),
        ("auth-methods", "Enumerate accepted auth methods", "ssh -v {ip} -p {port}", "quick"),
        ("weak-creds", "Try creds found elsewhere / default creds", None, "normal"),
        ("key-reuse", "Check for reused/leaked private keys on other services", None, "normal"),
    ],
    "http": [
        ("whatweb", "Fingerprint stack", "whatweb http://{ip}:{port}", "quick"),
        ("headers", "Inspect response headers / cookies", "curl -sI http://{ip}:{port}", "quick"),
        ("robots-sitemap", "Check robots.txt, sitemap.xml, .git, .env, backups", "curl -s http://{ip}:{port}/robots.txt", "quick"),
        ("source-comments", "View source for comments, JS endpoints, API keys", None, "quick"),
        ("dir-brute", "Directory & file brute force", "feroxbuster -u http://{ip}:{port} -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt", "slow"),
        ("vhost", "Virtual host / subdomain fuzzing (add host to /etc/hosts first)", "ffuf -u http://{ip}:{port}/ -H 'Host: FUZZ.target.tld' -w subdomains.txt -fs 0", "slow"),
        ("nikto", "Baseline web vuln scan", "nikto -h http://{ip}:{port}", "slow"),
        ("known-cms", "If CMS (WordPress/Joomla/etc), run targeted scanner", "wpscan --url http://{ip}:{port} --enumerate", "slow"),
    ],
    "https": [
        ("cert-info", "Read TLS cert for hostnames / emails / internal names", "openssl s_client -connect {ip}:{port} </dev/null 2>/dev/null | openssl x509 -noout -text", "quick"),
        ("same-as-http", "Then run the full http playbook against https://", None, "normal"),
    ],
    "smb": [
        ("null-session", "Try null/guest session", "smbclient -N -L //{ip}/", "quick"),
        ("enum-shares", "Enumerate shares & permissions", "netexec smb {ip} -u '' -p '' --shares", "quick"),
        ("version-cve", "OS/version → known CVEs (EternalBlue etc.)", "nmap --script smb-vuln* -p{port} {ip}", "normal"),
        ("rid-brute", "RID brute to enumerate users", "netexec smb {ip} -u guest -p '' --rid-brute", "normal"),
        ("read-shares", "Recursively pull readable shares", "smbclient //{ip}/SHARE -N  # then recurse; prompt off, mget *", "normal"),
    ],
    "rpc": [
        ("null-bind", "Anonymous rpcclient bind", "rpcclient -U '' -N {ip}", "quick"),
        ("enum-users", "enumdomusers / querydispinfo", "rpcclient -U '' -N {ip} -c 'enumdomusers'", "quick"),
    ],
    "ldap": [
        ("anon-bind", "Anonymous bind + base DN dump", "ldapsearch -x -H ldap://{ip} -s base namingcontexts", "quick"),
        ("enum", "Dump users/groups if bind works", "ldapsearch -x -H ldap://{ip} -b 'DC=domain,DC=tld'", "normal"),
    ],
    "dns": [
        ("zone-transfer", "Attempt AXFR zone transfer", "dig axfr @{ip} target.tld", "quick"),
        ("reverse", "Reverse lookups / hostname discovery", "dig -x {ip} @{ip}", "quick"),
    ],
    "mysql": [
        ("weak-creds", "Try root/no-pass and found creds", "mysql -h {ip} -u root", "normal"),
        ("version-cve", "Version → CVEs", "nmap -sV -p{port} {ip}", "quick"),
    ],
    "mssql": [
        ("login", "Login with found/default creds", "netexec mssql {ip} -u sa -p ''", "normal"),
        ("xp-cmdshell", "If admin, check command exec surface", None, "normal", ["creds"]),
    ],
    "smtp": [
        ("user-enum", "VRFY / RCPT user enumeration", "smtp-user-enum -M VRFY -U users.txt -t {ip}", "normal"),
        ("open-relay", "Test for open relay", None, "normal"),
    ],
    "snmp": [
        ("community", "Brute community strings", "onesixtyone {ip} -c community.txt", "quick"),
        ("walk", "Walk the MIB with a valid string", "snmpwalk -v2c -c public {ip}", "normal"),
    ],
    "redis": [
        ("unauth", "Test unauthenticated access", "redis-cli -h {ip} -p {port} INFO", "quick"),
        ("rce-paths", "Known RCE via config/module load if writable", None, "normal"),
    ],
    "nfs": [
        ("showmount", "List exports", "showmount -e {ip}", "quick"),
        ("mount", "Mount and inspect for creds/keys", "mount -t nfs {ip}:/export /mnt/nfs", "normal"),
    ],
    "telnet": [
        ("banner", "Grab banner, note software/version", "telnet {ip} {port}", "quick"),
        ("weak-creds", "Try default/found creds", None, "normal"),
    ],
    "pop3": [
        ("banner", "Grab banner / capabilities", "nc -nv {ip} {port}  # USER x / PASS y", "quick"),
        ("read-mail", "Login and read mail for creds/info", "openssl s_client -connect {ip}:{port}  # if TLS", "normal", ["creds"]),
    ],
    "imap": [
        ("banner", "Grab banner / capabilities", "nc -nv {ip} {port}  # a LOGIN user pass", "quick"),
        ("read-mail", "Login and list/read mailboxes", None, "normal", ["creds"]),
    ],
    "rdp": [
        ("ntlm-info", "Leak hostname/domain via NLA", "nmap --script rdp-ntlm-info -p{port} {ip}", "quick"),
        ("weak-creds", "Spray found/default creds (watch lockouts!)", "netexec rdp {ip} -u users.txt -p passwords.txt", "normal"),
        ("bluekeep", "CVE-2019-0708 if old Windows", "nmap --script rdp-vuln-ms12-020 -p{port} {ip}", "normal"),
        ("connect", "Interactive session with valid creds", "xfreerdp /v:{ip} /u:{user} /p:{pass}", "normal", ["creds"]),
    ],
    "vnc": [
        ("no-auth", "Test for no-auth / bypass", "nmap --script vnc-info,realvnc-auth-bypass -p{port} {ip}", "quick"),
        ("connect", "Connect with found password", "vncviewer {ip}:{port}", "normal"),
    ],
    "winrm": [
        ("login", "Auth with found creds", "netexec winrm {ip} -u {user} -p {pass}", "normal", ["creds"]),
        ("evil-winrm", "If creds valid → shell", "evil-winrm -i {ip} -u {user} -p {pass}", "normal", ["creds:winrm"]),
    ],
    "kerberos": [
        ("user-enum", "Enumerate valid users (no creds)", "kerbrute userenum -d domain.tld --dc {ip} users.txt", "normal"),
        ("asrep", "AS-REP roast users w/o preauth", "impacket-GetNPUsers domain.tld/ -usersfile users.txt -dc-ip {ip}", "normal"),
        ("kerberoast", "With creds, roast SPNs", "impacket-GetUserSPNs domain.tld/{user}:{pass} -dc-ip {ip} -request", "normal", ["creds"]),
    ],
    "postgresql": [
        ("weak-creds", "Try postgres/no-pass and found creds", "psql -h {ip} -p {port} -U postgres", "normal"),
        ("rce", "If superuser: COPY ... FROM PROGRAM for RCE", None, "normal", ["creds"]),
    ],
    "mongodb": [
        ("unauth", "Test unauth access, list DBs", "mongosh --host {ip} --port {port} --eval 'db.adminCommand({listDatabases:1})'", "quick"),
        ("dump", "Dump collections for creds/flags", None, "normal"),
    ],
    "oracle": [
        ("sid-enum", "Enumerate SIDs", "nmap --script oracle-sid-brute -p{port} {ip}", "normal"),
        ("odat", "All-in-one (creds, TNS poison, files)", "odat all -s {ip} -p {port}", "slow"),
    ],
    "rsync": [
        ("list-modules", "List rsync modules/shares", "rsync -av --list-only rsync://{ip}:{port}/", "quick"),
        ("pull", "Pull readable module contents", "rsync -av rsync://{ip}:{port}/MODULE ./loot/", "normal"),
    ],
    "elasticsearch": [
        ("unauth", "Test unauth, list indices", "curl -s http://{ip}:{port}/_cat/indices?v", "quick"),
        ("dump", "Pull docs from interesting indices", "curl -s http://{ip}:{port}/INDEX/_search?pretty", "normal"),
    ],
}

# When importing from a scan, map port number / service name -> playbook key.
PORT_HINTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    88: "kerberos", 110: "pop3", 135: "rpc", 139: "smb", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "smb", 636: "ldap",
    873: "rsync", 1433: "mssql", 1521: "oracle", 2049: "nfs", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5900: "vnc", 5985: "winrm", 5986: "winrm",
    6379: "redis", 8080: "http", 8443: "https", 9200: "elasticsearch",
    27017: "mongodb",
}

# scan service names differ from our playbook keys; normalize the common ones.
NMAP_SERVICE_MAP = {
    "microsoft-ds": "smb", "netbios-ssn": "smb", "ms-wbt-server": "rdp",
    "domain": "dns", "ssl/http": "https", "https-alt": "https",
    "http-alt": "http", "msrpc": "rpc", "ms-sql-s": "mssql",
    "postgres": "postgresql", "mongod": "mongodb", "oracle-tns": "oracle",
    "imaps": "imap", "pop3s": "pop3", "smtps": "smtp",
}

# Baseline checks that apply to every target, regardless of services.
GLOBAL_CHECKS = [
    ("full-tcp", "Full TCP port scan (all 65535) — don't trust the top-1000 only", "nmap -p- --min-rate 2000 {ip} -oA nmap/alltcp", "slow"),
    ("udp-top", "UDP top ports (people forget UDP constantly)", "nmap -sU --top-ports 100 {ip} -oA nmap/udp", "slow"),
    ("service-scan", "Version + default scripts on found ports", "nmap -sVC -p<PORTS> {ip} -oA nmap/services", "normal"),
]

# Regexes that flag interesting content in captured command output.
LOOT_PATTERNS = [
    ("flag", re.compile(r"(?:flag|FLAG|HTB|CTF)\{[^}]{0,200}\}")),
    ("ntlm-hash", re.compile(r"\b[0-9a-fA-F]{32}:[0-9a-fA-F]{32}\b")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----")),
    ("aws-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("password-kv", re.compile(r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*\S+")),
]

# Patterns that make a command genuinely destructive / risky. `enum run` demands
# an explicit typed confirmation before firing any of these, even when live.
DANGEROUS_PATTERNS = [
    re.compile(r"\brm\s+-[a-z]*[rf]"),
    re.compile(r"\bmkfs\b"), re.compile(r"\bdd\s+if="),
    re.compile(r">\s*/dev/sd"), re.compile(r"\b:\(\)\s*\{"),  # fork bomb
    re.compile(r"/dev/tcp/"), re.compile(r"\bnc\b.*\s-e\b"),
    re.compile(r"\bbash\s+-i\b"), re.compile(r"\bshutdown\b|\breboot\b"),
]

# Shell metacharacters that mean a command can't run under shell=False.
SHELL_META = re.compile(r"[|&;><`$()]|\|\||&&")


# ---------------------------------------------------------------------------
# Playbook loading (built-in + user overrides in ~/.enumhelper/playbooks.json)
# ---------------------------------------------------------------------------
def _norm_entry(e):
    """Normalize a playbook entry (tuple/list/dict) to a stable dict."""
    if isinstance(e, dict):
        return {
            "name": e["name"], "desc": e.get("desc", ""), "cmd": e.get("cmd"),
            "priority": e.get("priority", "normal"),
            "requires": list(e.get("requires", [])),
        }
    name = e[0]
    desc = e[1] if len(e) > 1 else ""
    cmd = e[2] if len(e) > 2 else None
    priority = e[3] if len(e) > 3 else "normal"
    requires = list(e[4]) if len(e) > 4 else []
    return {"name": name, "desc": desc, "cmd": cmd,
            "priority": priority, "requires": requires}


def load_user_playbooks():
    """Read ~/.enumhelper/playbooks.json (re-read every invocation = hot reload)."""
    if not PLAYBOOK_FILE.exists():
        return {}
    try:
        return json.loads(PLAYBOOK_FILE.read_text())
    except Exception as e:
        print(f"[!] Ignoring playbooks.json — invalid JSON: {e}", file=sys.stderr)
        return {}


def get_playbook(svc):
    """Merged checks for a service: user overrides layered over built-ins.

    https also inherits the full http playbook (pointed at the TLS scheme).
    User entries with a name that already exists replace the built-in; new
    names are appended.
    """
    merged = {}
    order = []

    def apply(entries):
        for raw in entries:
            n = _norm_entry(raw)
            if n["name"] not in merged:
                order.append(n["name"])
            merged[n["name"]] = n

    apply(PLAYBOOKS.get(svc, []))
    if svc == "https":
        for raw in PLAYBOOKS.get("http", []):
            n = _norm_entry(raw)
            n = dict(n)
            if n["cmd"]:
                n["cmd"] = n["cmd"].replace("http://", "https://")
            if n["name"] not in merged:
                order.append(n["name"])
            merged[n["name"]] = n
    apply(_USER_PLAYBOOKS.get(svc, []))
    return [merged[name] for name in order]


_USER_PLAYBOOKS = load_user_playbooks()


# ---------------------------------------------------------------------------
# State: file I/O, migration, small helpers
# ---------------------------------------------------------------------------
def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M")


def stamp():
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def safe(name):
    return name.replace("/", "_").replace(":", "_")


def target_file(target):
    return STATE_DIR / f"{safe(target)}.json"


def loot_dir(target):
    return STATE_DIR / f"{safe(target)}_loot"


def check_key(scope, name):
    return f"{scope}:{name}"


def fresh(target):
    return {
        "meta": {"target": target, "created": now(), "os_hint": "", "tags": []},
        "services": [], "checks": {}, "loot": [], "creds": [], "notes": [],
    }


def _migrate(data, target):
    """Bring an old flat-schema file up to the current three-collection model."""
    if "meta" not in data:
        data["meta"] = {
            "target": data.get("target", target),
            "created": data.get("created", now()),
            "os_hint": data.get("os_hint", ""),
            "tags": data.get("tags", []),
        }
    data.pop("target", None)
    data.pop("created", None)
    data.setdefault("services", [])
    data.setdefault("checks", {})
    data.setdefault("loot", [])
    data.setdefault("creds", [])
    data.setdefault("notes", [])

    for k, v in data["checks"].items():
        if "state" not in v:
            v["state"] = "done" if v.pop("done", False) else "pending"
        else:
            v.pop("done", None)
        v.setdefault("priority", "normal")
        v.setdefault("requires", [])
        v.setdefault("runs", [])
        # if it was marked done in the old schema, keep the timestamp visible
        if v.get("done_at") and not v["runs"]:
            v.setdefault("_done_at", v["done_at"])

    # creds: old free-text {t, text} -> structured
    fixed_creds = []
    for c in data["creds"]:
        if "user" in c or "pass" in c:
            c.setdefault("user", "")
            c.setdefault("pass", "")
            c.setdefault("context", c.get("context", ""))
            c.setdefault("check", c.get("check"))
            fixed_creds.append(c)
        else:
            fixed_creds.append({
                "t": c.get("t", now()), "user": "", "pass": "",
                "context": c.get("text", ""), "check": None,
            })
    data["creds"] = fixed_creds

    for n in data["notes"]:
        n.setdefault("check", None)
        n.setdefault("scope", "global")

    for l in data["loot"]:
        l.setdefault("sha256", "")
        l.setdefault("tag", "")
        l.setdefault("check", None)
        l.setdefault("note", "")
    return data


def load(target):
    f = target_file(target)
    if f.exists():
        return _migrate(json.loads(f.read_text()), target)
    return fresh(target)


def save(target, data):
    STATE_DIR.mkdir(exist_ok=True)
    target_file(target).write_text(json.dumps(data, indent=2))


def tgt(data):
    return data["meta"]["target"]


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Rendering + dependency gating
# ---------------------------------------------------------------------------
def pick_creds(data, svc=None):
    """Return (user, pass) from stashed creds — prefer one tied to `svc`."""
    have = [c for c in data["creds"] if c.get("user") or c.get("pass")]
    if not have:
        return "", ""
    if svc:
        for c in reversed(have):
            link = (c.get("check") or "")
            ctx = (c.get("context") or "")
            if link.startswith(f"{svc}/") or svc in link or svc in ctx.lower():
                return c.get("user", ""), c.get("pass", "")
    c = have[-1]
    return c.get("user", ""), c.get("pass", "")


def render_cmd(cmd, ip, port="", user="", password=""):
    if not cmd:
        return None
    return (cmd.replace("{ip}", ip)
               .replace("{port}", str(port))
               .replace("{user}", user or "<user>")
               .replace("{pass}", password or "<pass>"))


def _req_ok(data, req):
    kind, _, arg = req.partition(":")
    if kind == "creds":
        return len(data["creds"]) > 0
    if kind == "check":
        for k, v in data["checks"].items():
            if (k == arg or k.endswith(arg) or arg in k) and v.get("state") == "done":
                return True
        return False
    if kind == "loot":
        if arg:
            return any(l.get("tag") == arg for l in data["loot"])
        return len(data["loot"]) > 0
    if kind in ("service", "svc"):
        return any(s["service"] == arg for s in data["services"])
    return True  # unknown token never gates


def requires_met(data, requires):
    unmet = [r for r in requires if not _req_ok(data, r)]
    return (not unmet, unmet)


# ---------------------------------------------------------------------------
# Service / check bookkeeping
# ---------------------------------------------------------------------------
def _add_service(data, port, svc, note=""):
    """Add one service (dedup) and load its checks. Returns (is_new, loaded)."""
    svc = svc.lower()
    port = str(port)
    is_new = not any(s["port"] == port and s["service"] == svc for s in data["services"])
    if is_new:
        data["services"].append({"port": port, "service": svc, "note": note, "added": now()})

    loaded = 0
    for entry in get_playbook(svc):
        k = check_key(f"{svc}/{port}", entry["name"])
        if k not in data["checks"]:
            data["checks"][k] = {
                "desc": entry["desc"], "cmd": entry["cmd"], "state": "pending",
                "priority": entry["priority"], "requires": entry["requires"],
                "runs": [], "port": port, "service": svc,
            }
            loaded += 1
    return is_new, loaded


def _ensure_globals(data):
    for name, desc, cmd, prio in [(n, d, c, p) for n, d, c, p in GLOBAL_CHECKS]:
        k = check_key("global", name)
        data["checks"].setdefault(k, {
            "desc": desc, "cmd": cmd, "state": "pending", "priority": prio,
            "requires": [], "runs": [], "service": "global", "port": "",
        })


def resolve_check(data, target, name):
    """Exact key, else fuzzy substring/suffix match. Returns key or None."""
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


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
def cmd_add(args):
    data = load(args.target)
    svc = args.service.lower()
    if args.os:
        data["meta"]["os_hint"] = args.os
    if args.tag:
        for t in args.tag:
            if t not in data["meta"]["tags"]:
                data["meta"]["tags"].append(t)
    is_new, loaded = _add_service(data, args.port, svc, args.note or "")
    save(args.target, data)

    print(f"[+] {'Added' if is_new else 'Re-synced'} {svc} on port {args.port}.")
    if get_playbook(svc):
        print(f"[+] {loaded} new follow-up check(s). Run `enum next {args.target}` to see them.")
    else:
        print(f"[!] No playbook for '{svc}' yet — add one to PLAYBOOKS or playbooks.json.")


def cmd_next(args):
    """The anti-missing-points view: pending checks, split available vs blocked."""
    data = load(args.target)
    ip = tgt(data)
    _ensure_globals(data)
    save(ip, data)

    actionable = {k: v for k, v in data["checks"].items()
                  if v["state"] in ("pending", "failed")}

    flt = (getattr(args, "service", None) or "").lower()
    if flt:
        actionable = {k: v for k, v in actionable.items()
                      if v.get("service") == flt or k.split(":", 1)[0].startswith(f"{flt}/")}
    if args.quick:
        actionable = {k: v for k, v in actionable.items() if v.get("priority") == "quick"}

    available, blocked = {}, {}
    for k, v in actionable.items():
        ok, unmet = requires_met(data, v.get("requires", []))
        if ok:
            available[k] = v
        else:
            blocked[k] = (v, unmet)

    if not available and not blocked:
        scope_msg = f"for service '{flt}' " if flt else ""
        q = "quick " if args.quick else ""
        print(f"[*] Nothing {q}pending {scope_msg}— you're thorough, or nothing's been added yet.")
        return

    if not args.blocked:
        _print_checks(ip, available, header="PENDING CHECKS (available now)")
        if blocked:
            print(f"[i] {len(blocked)} check(s) blocked by unmet requirements — "
                  f"run `enum next {ip} --blocked` to see them.")
        print(f"\nMark done:  enum done {ip} <name>   |   Run it:  enum run {ip} <name>")
    else:
        if not blocked:
            print("[*] No blocked checks — everything pending is available now.")
            return
        print(f"\n=== BLOCKED CHECKS for {ip} ===\n")
        by_scope = {}
        for k, (v, unmet) in blocked.items():
            by_scope.setdefault(k.split(":", 1)[0], []).append((k, v, unmet))
        for scope in sorted(by_scope, key=lambda s: (s != "global", s)):
            print(f"[{scope}]")
            for k, v, unmet in by_scope[scope]:
                name = k.split(":", 1)[1]
                print(f"  ⊘ {name:16} {v['desc']}")
                print(f"      needs: {', '.join(unmet)}")
            print()


def _print_checks(ip, checks, header):
    if not checks:
        print(f"[*] {header}: nothing pending.")
        return
    by_scope = {}
    for k, v in checks.items():
        by_scope.setdefault(k.split(":", 1)[0], []).append((k, v))
    print(f"\n=== {header} for {ip} ===\n")
    for scope in sorted(by_scope, key=lambda s: (s != "global", s)):
        print(f"[{scope}]")
        for k, v in by_scope[scope]:
            name = k.split(":", 1)[1]
            mark = STATE_BADGE.get(v["state"], "☐")
            prio = "" if v.get("priority", "normal") == "normal" else f" ({v['priority']})"
            rendered = render_cmd(v.get("cmd"), ip, v.get("port", ""))
            print(f"  {mark} {name:16} {v['desc']}{prio}")
            if rendered:
                print(f"      $ {rendered}")
        print()


def cmd_run(args):
    """Execute a check's command, capture output, store a run record."""
    data = load(args.target)
    ip = tgt(data)
    key = resolve_check(data, ip, args.check)
    if key is None:
        return
    chk = data["checks"][key]
    if not chk.get("cmd"):
        print(f"[!] '{key}' has no command to run — it's a manual check. "
              f"Do it, then `enum done {ip} {key}`.")
        return

    user, password = pick_creds(data, chk.get("service"))
    rendered = render_cmd(chk["cmd"], ip, chk.get("port", ""), user, password)

    # 1) confirm (unless -y)
    if args.yes or not sys.stdin.isatty():
        choice = "y"
    else:
        choice = input(f"Execute: {rendered} ? [Y/n/edit] ").strip().lower()
    if choice in ("n", "no"):
        print("[*] Skipped.")
        return
    if choice in ("e", "edit"):
        edited = input("Edit command: ").strip()
        if edited:
            rendered = edited

    # 2) safety gate — dry-run unless live
    live = os.environ.get("ENUM_LIVE") == "1" or args.live
    if not live:
        print(f"[dry-run] would execute:\n    {rendered}")
        print("[dry-run] set ENUM_LIVE=1 (or pass --live) to actually run it.")
        return

    exec_cmd = re.sub(r"\s+#.*$", "", rendered)  # strip a trailing "# comment"
    if any(p.search(exec_cmd) for p in DANGEROUS_PATTERNS):
        print("[!] This command looks destructive / high-impact:")
        print(f"    {exec_cmd}")
        if input("    Type 'yes' to run it anyway: ").strip() != "yes":
            print("[*] Aborted.")
            return

    use_shell = bool(SHELL_META.search(exec_cmd))
    if use_shell and not args.shell:
        print("[!] Command uses shell features (pipe/redirect/subshell).")
        print(f"    {exec_cmd}")
        print("    Re-run with --shell to allow shell execution, or run it manually.")
        return

    print(f"[*] Running (timeout {args.timeout}s)…")
    run = {"t": now(), "cmd": rendered, "exit": None, "stdout": "", "stderr": "", "artifact": None}
    chk["state"] = "running"
    try:
        if use_shell:
            proc = subprocess.run(exec_cmd, shell=True, capture_output=True,
                                  text=True, timeout=args.timeout)
        else:
            proc = subprocess.run(shlex.split(exec_cmd), shell=False, capture_output=True,
                                  text=True, timeout=args.timeout)
        run["exit"] = proc.returncode
        run["stdout"] = proc.stdout
        run["stderr"] = proc.stderr
    except subprocess.TimeoutExpired as e:
        run["exit"] = -1
        run["stdout"] = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
        run["stderr"] = (e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or "")) + \
                        f"\n[timed out after {args.timeout}s]"
    except FileNotFoundError:
        print(f"[!] Command not found: {shlex.split(exec_cmd)[0]} — is the tool installed?")
        chk["state"] = "failed"
        save(ip, data)
        return

    # 4) persist the run immediately (crash-safe) BEFORE prompting for anything
    chk["runs"].append(run)
    chk["state"] = "failed" if run["exit"] not in (0, None) else "pending"
    save(ip, data)

    print(f"[+] exit={run['exit']}  ({len(run['stdout'].splitlines())} lines stdout)")
    if run["stdout"]:
        preview = "\n".join(run["stdout"].splitlines()[:20])
        print(preview)
        if len(run["stdout"].splitlines()) > 20:
            print(f"    … ({len(run['stdout'].splitlines()) - 20} more lines)")
    if run["stderr"].strip():
        print(f"[stderr] {run['stderr'].strip()[:500]}")

    # 5) offer to save stdout as an artifact
    art_path = None
    if args.save:
        art_path = _write_artifact(ip, key, run["stdout"], args.save)
    elif run["stdout"].strip() and sys.stdin.isatty():
        if input("Save stdout to an artifact file? [Y/n] ").strip().lower() not in ("n", "no"):
            art_path = _write_artifact(ip, key, run["stdout"], None)
    if art_path:
        run["artifact"] = str(art_path.relative_to(STATE_DIR))
        save(ip, data)
        print(f"[+] Saved artifact: {run['artifact']}")

    # 6) auto-detect loot in the output
    hits = _scan_loot(run["stdout"] + "\n" + run["stderr"])
    if hits:
        print("[!] Possible loot detected in output:")
        for label, sample in hits:
            print(f"      [{label}] {sample}")
        suggest = run["artifact"] or "<file>"
        print(f"[→] Register with:  enum loot {ip} {suggest} -c {key} -t <tag>")


def _write_artifact(target, key, content, name):
    d = loot_dir(target)
    d.mkdir(parents=True, exist_ok=True)
    suffix = safe(name) if name else "output.txt"
    if not suffix.endswith((".txt", ".log", ".out")):
        suffix += ".txt"
    fname = f"{stamp()}_{safe(key)}_{suffix}" if name else f"{stamp()}_{safe(key)}.txt"
    path = d / fname
    path.write_text(content)
    return path


def _scan_loot(text):
    hits = []
    for label, pat in LOOT_PATTERNS:
        m = pat.search(text)
        if m:
            sample = m.group(0)
            hits.append((label, sample[:80] + ("…" if len(sample) > 80 else "")))
    return hits


def cmd_done(args):
    data = load(args.target)
    key = resolve_check(data, tgt(data), args.check)
    if key is None:
        return
    chk = data["checks"][key]
    chk["state"] = "done"
    chk["_done_at"] = now()
    if chk.get("runs"):
        for r in chk["runs"]:
            r.pop("definitive", None)
        chk["runs"][-1]["definitive"] = True
    save(args.target, data)
    print(f"[+] Marked done: {key}")


def cmd_skip(args):
    data = load(args.target)
    key = resolve_check(data, tgt(data), args.check)
    if key is None:
        return
    data["checks"][key]["state"] = "skipped"
    data["checks"][key]["skip_reason"] = args.reason or ""
    data["checks"][key]["_skipped_at"] = now()
    save(args.target, data)
    r = f" ({args.reason})" if args.reason else ""
    print(f"[+] Skipped: {key}{r}")


def cmd_undone(args):
    data = load(args.target)
    key = resolve_check(data, tgt(data), args.check)
    if key is None:
        return
    chk = data["checks"][key]
    chk["state"] = "pending"
    chk.pop("_done_at", None)
    chk.pop("skip_reason", None)
    chk.pop("_skipped_at", None)
    save(args.target, data)
    print(f"[+] Reopened (pending): {key}")


def cmd_loot(args):
    data = load(args.target)
    ip = tgt(data)
    src = Path(args.path)
    if not src.exists():
        # maybe it's already a relative path inside the loot dir
        cand = STATE_DIR / args.path
        if cand.exists():
            src = cand
        else:
            print(f"[!] No such file: {args.path}")
            return

    d = loot_dir(ip)
    d.mkdir(parents=True, exist_ok=True)
    try:
        already_inside = d in src.resolve().parents
    except Exception:
        already_inside = False
    if already_inside:
        dest = src
    else:
        dest = d / f"{stamp()}_{safe(src.name)}"
        shutil.copy2(src, dest)

    digest = sha256_file(dest)
    rel = str(dest.relative_to(STATE_DIR))
    check = None
    if args.check:
        check = resolve_check(data, ip, args.check) or args.check
    data["loot"].append({
        "t": now(), "path": rel, "sha256": digest,
        "tag": args.tag or "", "check": check, "note": args.note or "",
    })
    save(ip, data)
    print(f"[+] Loot registered: {rel}")
    print(f"    sha256: {digest}")
    if check:
        print(f"    provenance: {check}")


def cmd_cred(args):
    data = load(args.target)
    ip = tgt(data)
    check = None
    if args.check:
        check = resolve_check(data, ip, args.check) or args.check
    data["creds"].append({
        "t": now(), "user": args.user or "", "pass": args.password or "",
        "context": args.context or "", "check": check,
    })
    save(ip, data)
    who = f"{args.user or ''}:{args.password or ''}"
    print(f"[+] Cred stashed: {who}" + (f"  (from {check})" if check else ""))
    # unblocking hint
    newly = [k for k, v in data["checks"].items()
             if v["state"] in ("pending", "failed") and v.get("requires")
             and requires_met(data, v["requires"])[0]
             and any(r.startswith("creds") for r in v["requires"])]
    if newly:
        print(f"[→] Unblocked {len(newly)} cred-gated check(s): run `enum next {ip}`.")


def cmd_note(args):
    data = load(args.target)
    ip = tgt(data)
    check = None
    if args.check:
        check = resolve_check(data, ip, args.check) or args.check
    data["notes"].append({
        "t": now(), "text": args.text, "check": check,
        "scope": "check" if check else "global",
    })
    save(ip, data)
    print("[+] Note saved." + (f" (linked to {check})" if check else ""))


def cmd_status(args):
    data = load(args.target)
    ip = tgt(data)
    checks = data["checks"]
    total = len(checks)
    counts = {s: 0 for s in STATES}
    for v in checks.values():
        counts[v.get("state", "pending")] = counts.get(v.get("state", "pending"), 0) + 1
    done = counts["done"]

    print(f"\n=== {ip} ===")
    m = data["meta"]
    if m.get("os_hint"):
        print(f"os: {m['os_hint']}")
    if m.get("tags"):
        print(f"tags: {', '.join(m['tags'])}")
    print(f"created: {m['created']}")
    svc_list = ", ".join(f"{s['service']}/{s['port']}" for s in data["services"])
    print(f"services: {svc_list or '(none)'}")

    pct = int(done / total * 100) if total else 0
    filled = pct // 10
    bar = "█" * filled + "░" * (10 - filled)
    print(f"progress: [{bar}] {pct}%  ({done}/{total} done)")
    state_line = "  ".join(f"{s}:{counts[s]}" for s in STATES if counts[s])
    if state_line:
        print(f"states: {state_line}")

    # last 3 runs across every check
    all_runs = []
    for k, v in checks.items():
        for r in v.get("runs", []):
            all_runs.append((r.get("t", ""), k, r.get("exit")))
    all_runs.sort(reverse=True)
    if all_runs:
        print("last runs:")
        for t, k, code in all_runs[:3]:
            print(f"   [{t}] {k}  (exit {code})")

    print(f"loot: {len(data['loot'])} item(s)   creds: {len(data['creds'])}")
    if data["creds"]:
        for c in data["creds"]:
            up = f"{c.get('user','')}:{c.get('pass','')}".strip(":")
            ctx = f"  — {c['context']}" if c.get("context") else ""
            print(f"   - {up or '(no user/pass)'}{ctx}")
    if data["notes"]:
        print("notes:")
        for n in data["notes"][-5:]:
            link = f" [{n['check']}]" if n.get("check") else ""
            print(f"   [{n['t']}]{link} {n['text']}")
    print()


def _target_files():
    """State files that are actually target notebooks (skip playbooks/templates)."""
    return [f for f in sorted(STATE_DIR.glob("*.json")) if f.name != "playbooks.json"]


def _safe_load(f):
    """Load + migrate one target file, or None if it isn't valid JSON."""
    try:
        return _migrate(json.loads(f.read_text()), f.stem)
    except Exception as e:
        print(f"[!] Skipping {f.name}: not a valid target file ({e})", file=sys.stderr)
        return None


def cmd_list(args):
    STATE_DIR.mkdir(exist_ok=True)
    files = _target_files()
    if not files:
        print("No targets yet. Start with:  enum add <ip> <port> <service>")
        return
    for f in files:
        d = _safe_load(f)
        if d is None:
            continue
        done = sum(1 for v in d["checks"].values() if v["state"] == "done")
        print(f"  {tgt(d):20} {len(d['services'])} svc, {done}/{len(d['checks'])} checks, "
              f"{len(d['loot'])} loot, {len(d['creds'])} creds")


def cmd_search(args):
    """Cross-target queries over every stored notebook."""
    STATE_DIR.mkdir(exist_ok=True)
    files = _target_files()
    svc = (args.svc or "").lower()
    matched = 0
    for f in files:
        d = _safe_load(f)
        if d is None:
            continue
        target = tgt(d)
        if args.target_glob and not fnmatch.fnmatch(target, args.target_glob):
            continue
        if svc and not any(s["service"] == svc for s in d["services"]):
            continue
        pend = {k: v for k, v in d["checks"].items() if v["state"] in ("pending", "failed")}
        if svc:
            pend = {k: v for k, v in pend.items() if v.get("service") == svc}
        if args.pending and not pend:
            continue
        if args.loot and not d["loot"]:
            continue

        matched += 1
        print(f"\n### {target}")
        svcs = ", ".join(f"{s['service']}/{s['port']}" for s in d["services"])
        print(f"    services: {svcs or '(none)'}")
        if args.pending or not (args.loot):
            shown = [k for k in pend if not svc or pend[k].get("service") == svc]
            if shown:
                print(f"    pending: {', '.join(sorted(shown))}")
        if args.loot or not args.pending:
            for l in d["loot"]:
                if svc and not (l.get("check") or "").startswith(f"{svc}/"):
                    if args.loot:
                        continue
                print(f"    loot: {l['path']}  [{l.get('tag','')}]  <- {l.get('check')}")
    if not matched:
        print("[*] No targets matched.")


# ---------------------------------------------------------------------------
# Report pipeline
# ---------------------------------------------------------------------------
def _fmt_cmd_block(cmd):
    return f"```bash\n{cmd}\n```" if cmd else ""


def _fmt_output(text, collapse_over=50, force_collapse=False):
    if not text.strip():
        return ""
    n = len(text.splitlines())
    body = f"```text\n{text.rstrip()}\n```"
    if force_collapse or n > collapse_over:
        return f"<details><summary>output — {n} lines</summary>\n\n{body}\n\n</details>"
    return body


def _linked_loot(data, key):
    return [l for l in data["loot"] if l.get("check") == key]


def _linked_notes(data, key):
    return [n for n in data["notes"] if n.get("check") == key]


def _service_checks(data, svc, port):
    prefix = f"{svc}/{port}:"
    return {k: v for k, v in data["checks"].items() if k.startswith(prefix)}


def _evidence_index(data):
    lines = ["## Evidence index", ""]
    if not data["loot"]:
        lines.append("_(no loot registered)_")
        return lines + [""]
    lines += ["| # | artifact | sha256 | from check | tag | note |",
              "|---|----------|--------|-----------|-----|------|"]
    for i, l in enumerate(data["loot"], 1):
        rel = l["path"]
        link = f"[{Path(rel).name}]({rel})"
        digest = (l.get("sha256") or "")[:16]
        lines.append(f"| {i} | {link} | `{digest}…` | {l.get('check') or '—'} | "
                     f"{l.get('tag') or '—'} | {l.get('note') or ''} |")
    return lines + [""]


def _cred_table(data):
    lines = ["## Credentials", ""]
    if not data["creds"]:
        return lines + ["_(none captured)_", ""]
    lines += ["| user | pass | context | source check | found |",
              "|------|------|---------|--------------|-------|"]
    for c in data["creds"]:
        lines.append(f"| `{c.get('user','')}` | `{c.get('pass','')}` | "
                     f"{c.get('context') or ''} | {c.get('check') or '—'} | {c.get('t','')} |")
    return lines + [""]


def _latest_run(chk):
    for r in reversed(chk.get("runs", [])):
        if r.get("definitive"):
            return r
    return chk["runs"][-1] if chk.get("runs") else None


def _render_check_block(data, key, chk, ip, collapse_all=False):
    name = key.split(":", 1)[1]
    badge = STATE_BADGE.get(chk["state"], "☐")
    lines = [f"#### {badge} {name} — {chk['desc']}  `[{chk['state']}]`"]
    if chk.get("skip_reason"):
        lines.append(f"> skipped: {chk['skip_reason']}")
    rendered = render_cmd(chk.get("cmd"), ip, chk.get("port", ""))
    if rendered:
        lines.append(_fmt_cmd_block(rendered))
    run = _latest_run(chk)
    if run and (run.get("stdout") or "").strip():
        lines.append(f"*run {run.get('t','')} — exit {run.get('exit')}*")
        lines.append(_fmt_output(run["stdout"], force_collapse=collapse_all))
    for l in _linked_loot(data, key):
        lines.append(f"- 📎 loot: [{Path(l['path']).name}]({l['path']}) "
                     f"({l.get('tag') or 'untagged'})")
    for n in _linked_notes(data, key):
        lines.append(f"- 📝 note ({n['t']}): {n['text']}")
    return lines


def _render_full(data, exec_summary=False):
    ip = tgt(data)
    m = data["meta"]
    total = len(data["checks"])
    done = sum(1 for v in data["checks"].values() if v["state"] == "done")
    pct = int(done / total * 100) if total else 0

    title = "Enumeration write-up" if exec_summary else "Enumeration lab notebook"
    lines = [f"# {title} — {ip}", ""]
    meta_bits = [f"**Created:** {m['created']}"]
    if m.get("os_hint"):
        meta_bits.append(f"**OS:** {m['os_hint']}")
    if m.get("tags"):
        meta_bits.append(f"**Tags:** {', '.join(m['tags'])}")
    lines.append("  ".join(meta_bits))
    lines += ["", "## Executive summary", "",
              f"- **Target:** {ip}",
              f"- **Services:** " + (", ".join(f"`{s['service']}/{s['port']}`"
                                               for s in data["services"]) or "none"),
              f"- **Completion:** {done}/{total} checks ({pct}%)",
              f"- **Loot:** {len(data['loot'])} artifact(s) · **Creds:** {len(data['creds'])}",
              ""]

    lines += ["## Services", ""]
    if not data["services"]:
        lines += ["_(none recorded)_", ""]
    for s in data["services"]:
        svc, port = s["service"], s["port"]
        extra = f" — {s['note']}" if s.get("note") else ""
        blocks = _service_checks(data, svc, port)
        body = []
        for key, chk in blocks.items():
            if exec_summary:
                produced = bool(_linked_loot(data, key))
                if chk["state"] == "skipped":
                    continue
                if chk["state"] != "done" and not produced:
                    continue
            body += _render_check_block(data, key, chk, ip, collapse_all=exec_summary)
            body.append("")
        # exec-summary stays narrative: drop services with nothing worth showing
        if exec_summary and not body:
            continue
        lines.append(f"### {svc}/{port}{extra}")
        if not blocks:
            lines += ["_(no checks)_", ""]
        lines += body
        lines.append("")

    lines += _evidence_index(data)
    lines += _cred_table(data)

    # global checks appendix
    glob = {k: v for k, v in data["checks"].items() if k.startswith("global:")}
    if glob and not exec_summary:
        lines += ["## Global checks (appendix)", ""]
        for key, chk in glob.items():
            lines += _render_check_block(data, key, chk, ip)
            lines.append("")

    if data["notes"]:
        loose = [n for n in data["notes"] if not n.get("check")]
        if loose:
            lines += ["## Notes", ""]
            lines += [f"- [{n['t']}] {n['text']}" for n in loose]
            lines.append("")
    return "\n".join(lines)


def _render_loot_only(data):
    ip = tgt(data)
    lines = [f"# Loot handoff — {ip}", "",
             f"*Generated {now()}* — evidence and credentials for privesc handoff.", ""]
    lines += _evidence_index(data)
    lines += _cred_table(data)
    return "\n".join(lines)


def cmd_export(args):
    data = load(args.target)
    tmpl = args.template
    if tmpl == "full":
        report = _render_full(data, exec_summary=False)
    elif tmpl == "exec-summary":
        report = _render_full(data, exec_summary=True)
    elif tmpl == "loot-only":
        report = _render_loot_only(data)
    else:
        print(f"[!] Unknown template '{tmpl}'. Use full | exec-summary | loot-only.")
        return

    if args.out:
        Path(args.out).write_text(report)
        print(f"[+] Wrote {tmpl} report to {args.out}")
        print(f"[i] Keep it beside {loot_dir(tgt(data)).name}/ so the relative loot links resolve.")
    else:
        print(report)


# ---------------------------------------------------------------------------
# Playbook management (hot-reloadable user overrides)
# ---------------------------------------------------------------------------
PLAYBOOK_SCAFFOLD = {
    "http": [
        ["graphql", "Probe for a GraphQL endpoint", "curl -s http://{ip}:{port}/graphql", "quick"],
    ],
    "example-service": [
        ["some-check", "What it does", "tool {ip} {port}", "normal", ["creds"]],
    ],
}


def cmd_playbook(args):
    STATE_DIR.mkdir(exist_ok=True)
    if args.action == "edit":
        if not PLAYBOOK_FILE.exists():
            PLAYBOOK_FILE.write_text(json.dumps(PLAYBOOK_SCAFFOLD, indent=2))
            print(f"[+] Created scaffold {PLAYBOOK_FILE}")
        editor = os.environ.get("EDITOR") or shutil.which("nano") or shutil.which("vi") or "vi"
        subprocess.call([editor, str(PLAYBOOK_FILE)])
        # validate on the way out
        cmd_playbook(argparse.Namespace(action="reload"))
    elif args.action == "reload":
        if not PLAYBOOK_FILE.exists():
            print(f"[i] No {PLAYBOOK_FILE} — using built-in playbooks only.")
            print("    Create one with `enum playbook edit`.")
            return
        try:
            data = json.loads(PLAYBOOK_FILE.read_text())
        except Exception as e:
            print(f"[!] {PLAYBOOK_FILE} is invalid JSON: {e}")
            return
        n_svc = len(data)
        n_chk = sum(len(v) for v in data.values())
        print(f"[+] {PLAYBOOK_FILE} OK — {n_chk} override check(s) across {n_svc} service(s).")
        print("    (Overrides are re-read on every `enum` invocation — no restart needed.)")
        for svc in sorted(data):
            names = ", ".join(_norm_entry(e)["name"] for e in data[svc])
            print(f"      {svc}: {names}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(prog="enum",
                                description="Target-centric enumeration lab notebook.")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("add", help="record an open service (auto-loads its checks)")
    a.add_argument("target"); a.add_argument("port"); a.add_argument("service")
    a.add_argument("--note", "-n")
    a.add_argument("--os", help="set the target OS hint (windows/linux/…)")
    a.add_argument("--tag", action="append", help="add a target tag (repeatable)")
    a.set_defaults(func=cmd_add)

    n = sub.add_parser("next", help="show pending checks (available vs blocked)")
    n.add_argument("target")
    n.add_argument("--service", "-s", help="only this service")
    n.add_argument("--quick", action="store_true", help="only quick (5-min) checks")
    n.add_argument("--blocked", action="store_true", help="show gated checks + what they need")
    n.set_defaults(func=cmd_next)

    r = sub.add_parser("run", help="execute a check's command and capture output")
    r.add_argument("target"); r.add_argument("check")
    r.add_argument("--save", help="artifact filename to save stdout under")
    r.add_argument("--yes", "-y", action="store_true", help="don't prompt before running")
    r.add_argument("--live", action="store_true", help="actually execute (else dry-run)")
    r.add_argument("--shell", action="store_true", help="allow shell features (pipes/redirects)")
    r.add_argument("--timeout", type=int, default=300, help="seconds before kill (default 300)")
    r.set_defaults(func=cmd_run)

    d = sub.add_parser("done", help="mark a check complete (keeps run history)")
    d.add_argument("target"); d.add_argument("check")
    d.set_defaults(func=cmd_done)

    sk = sub.add_parser("skip", help="deprioritize a check with a reason")
    sk.add_argument("target"); sk.add_argument("check")
    sk.add_argument("--reason", "-r", help="why you're skipping it")
    sk.set_defaults(func=cmd_skip)

    u = sub.add_parser("undone", help="reopen a done/skipped check")
    u.add_argument("target"); u.add_argument("check")
    u.set_defaults(func=cmd_undone)

    lt = sub.add_parser("loot", help="register a file/hash/screenshot as evidence")
    lt.add_argument("target"); lt.add_argument("path")
    lt.add_argument("--tag", "-t"); lt.add_argument("--check", "-c")
    lt.add_argument("--note", "-n")
    lt.set_defaults(func=cmd_loot)

    c = sub.add_parser("cred", help="stash a structured credential")
    c.add_argument("target")
    c.add_argument("--user", "-u", required=True)
    c.add_argument("--password", "-p", required=True)
    c.add_argument("--check", "-c"); c.add_argument("--context")
    c.set_defaults(func=cmd_cred)

    no = sub.add_parser("note", help="attach a note (optionally to a check)")
    no.add_argument("target"); no.add_argument("text")
    no.add_argument("--check", "-c")
    no.set_defaults(func=cmd_note)

    im = sub.add_parser("import", help="bulk-add ports from a scan file")
    im.add_argument("target"); im.add_argument("file")
    im.add_argument("--format", "-f", choices=["auto", "nmap", "rustscan", "masscan"],
                    default="auto")
    im.set_defaults(func=cmd_import)

    se = sub.add_parser("search", help="cross-target queries")
    se.add_argument("--svc", help="only targets running this service")
    se.add_argument("--pending", action="store_true", help="only targets with pending checks")
    se.add_argument("--loot", action="store_true", help="only targets with loot")
    se.add_argument("--target-glob", help="glob on target name, e.g. 10.10.*")
    se.set_defaults(func=cmd_search)

    ex = sub.add_parser("export", help="emit a Markdown report")
    ex.add_argument("target")
    ex.add_argument("--out", "-o", help="write to file instead of stdout")
    ex.add_argument("--template", "-t", choices=["full", "exec-summary", "loot-only"],
                    default="full")
    ex.set_defaults(func=cmd_export)

    s = sub.add_parser("status", help="rich summary for one target")
    s.add_argument("target"); s.set_defaults(func=cmd_status)

    l = sub.add_parser("list", help="list all targets")
    l.set_defaults(func=cmd_list)

    pb = sub.add_parser("playbook", help="edit/validate user playbook overrides")
    pb.add_argument("action", choices=["edit", "reload"])
    pb.set_defaults(func=cmd_playbook)

    return p


# ---------------------------------------------------------------------------
# Import parsers
# ---------------------------------------------------------------------------
def _svc_from_scan(port, name):
    name = (name or "").lower().strip()
    if name in NMAP_SERVICE_MAP:
        return NMAP_SERVICE_MAP[name]
    if name in PLAYBOOKS:
        return name
    try:
        if int(port) in PORT_HINTS:
            return PORT_HINTS[int(port)]
    except ValueError:
        pass
    return name or "unknown"


def _parse_nmap(text):
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
    for line in text.splitlines():
        if "Ports:" not in line:
            continue
        ports_field = line.split("Ports:", 1)[1]
        for chunk in ports_field.split(","):
            parts = chunk.strip().split("/")
            if len(parts) >= 5 and parts[1] == "open":
                yield parts[0], parts[4]


def _parse_rustscan(text):
    """rustscan plain output: lines like 'Open 10.10.10.5:22'."""
    got = False
    for m in re.finditer(r"Open\s+[\d.]+:(\d+)", text):
        got = True
        yield m.group(1), ""
    if not got:  # rustscan '-- -oG' just emits nmap greppable
        yield from _parse_nmap(text)


def _parse_masscan(text):
    """masscan -oL list format: 'open tcp 445 10.10.10.5 <ts>' (also greppable)."""
    got = False
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0] == "open":
            got = True
            yield parts[2], ""
    if not got:
        yield from _parse_nmap(text)


def cmd_import(args):
    path = Path(args.file)
    if not path.exists():
        print(f"[!] No such file: {args.file}")
        return
    text = path.read_text()
    try:
        if args.format == "nmap":
            found = list(_parse_nmap(text))
        elif args.format == "rustscan":
            found = list(_parse_rustscan(text))
        elif args.format == "masscan":
            found = list(_parse_masscan(text))
        else:  # auto
            found = list(_parse_nmap(text))
            if not found:
                found = list(_parse_rustscan(text))
            if not found:
                found = list(_parse_masscan(text))
    except Exception as e:
        print(f"[!] Couldn't parse '{args.file}' ({args.format}): {e}")
        return
    if not found:
        print("[!] No open ports found. Save the scan as nmap -oG/-oX, rustscan, or masscan output.")
        return

    data = load(args.target)
    added, total_checks, no_pb = 0, 0, []
    for port, name in found:
        svc = _svc_from_scan(port, name)
        is_new, loaded = _add_service(data, port, svc)
        added += is_new
        total_checks += loaded
        if not get_playbook(svc):
            no_pb.append(f"{svc}/{port}")
    save(args.target, data)

    print(f"[+] Imported {len(found)} open port(s): {added} new, {total_checks} checks loaded.")
    if no_pb:
        print(f"[!] No playbook yet for: {', '.join(sorted(set(no_pb)))}")
    print(f"[+] Run `enum next {args.target}` to see what's pending.")


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
