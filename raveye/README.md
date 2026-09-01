# ctfenum — enumeration lab notebook

A single-file CLI that turns CTF / offensive enumeration into a **target-centric
lab notebook**: it tracks the checklist, *executes and captures* the commands you
choose to run, records loot and credentials with provenance, and exports a
report-ready Markdown bundle when you're done.

Two workflows share one notebook:

- **Service enum** (`enum add` / `enum import` → `enum next`) — record open
  ports and pull the follow-up checklist for each service.
- **Web enum** (`enum web add` → `enum web next`) — register a URL and load the
  **OWASP Top 10 (2021)** as a per-app checklist, grouped by category.

Both feed the same store, so `run` / `done` / `skip` / `loot` / `cred` / `note`
/ `export` work on either kind of check.

Still no black box: `enum run` prompts before every command and defaults to
dry-run, so you stay in control and actually learn the methodology.

## Install

```bash
chmod +x ctfenum.py
# optional: put it on your PATH
sudo ln -s "$(pwd)/ctfenum.py" /usr/local/bin/ctfenum
```

State lives under `~/.enumhelper/`:

```
~/.enumhelper/
├── 10.10.10.5.json          # meta + services + webapps + checks (run history) + loot + creds + notes
├── 10.10.10.5_loot/         # artifacts from `enum run` and `enum loot`
├── playbooks.json           # your check overrides (re-read every invocation)
└── templates/               # (reserved for custom export templates)
```

Old flat-schema files (the `done: true/false` format) are migrated
automatically the first time you touch them — nothing to convert by hand.

## Service workflow

```bash
# 1. Recon — record ports one at a time, or bulk-import a scan.
ctfenum add 10.10.10.5 445 smb --os windows --tag ad
nmap -p- -sV -oG scan.gnmap 10.10.10.5
ctfenum import 10.10.10.5 scan.gnmap -f nmap        # also: rustscan | masscan | auto

# 2. Triage — see what's pending; --quick shows only 5-minute checks.
ctfenum next 10.10.10.5 --quick
ctfenum next 10.10.10.5 -s smb                       # filter to one service
ctfenum next 10.10.10.5 --blocked                    # gated checks + what they need

# 3. Execute & capture — prompts, runs, stores stdout/stderr/exit + an artifact.
ENUM_LIVE=1 ctfenum run 10.10.10.5 smb/445:null-session --save shares.txt
#   dry-run by default; set ENUM_LIVE=1 (or pass --live) to actually execute.

# 4. Track findings with provenance.
ctfenum loot 10.10.10.5 shares.txt -t smb-shares -c smb/445:null-session
ctfenum cred 10.10.10.5 -u admin -p hunter2 -c smb/445:read-shares --context "from backup.zip"
ctfenum note 10.10.10.5 "SSH only accepts publickey" -c ssh/22:auth-methods

# 5. State transitions.
ctfenum done   10.10.10.5 null-session                # mark definitive (keeps run history)
ctfenum skip   10.10.10.5 upload-test -r "no write access"
ctfenum undone 10.10.10.5 null-session                # reopen a done/skipped check

# 6. Report.
ctfenum status 10.10.10.5                             # progress bar, last runs, loot/creds
ctfenum search --svc smb --pending --target-glob '10.10.*'   # cross-target queries
ctfenum export 10.10.10.5 -o report.md -t full       # full | exec-summary | loot-only
```

Fuzzy matching works on check names, so `done null-session` resolves to
`smb/445:null-session` when it's unambiguous.

## Web workflow (OWASP Top 10)

Found a web app? Register the URL and get the OWASP Top 10 (2021) as a checklist.
Web checks live under their own `enum web` verbs, but execute and report through
the same shared machinery.

```bash
# 1. Register a URL — loads a recon baseline + all OWASP categories (A01–A10).
ctfenum web add 10.10.10.5 http://10.10.10.5:8080/
ctfenum web add 10.10.10.5 https://shop.box.tld/ --vhost shop.box.tld --note storefront
ctfenum web add 10.10.10.5 http://10.10.10.5/ --only A01,A03,A05   # subset (recon always loads)

# 2. Triage — pending web checks, grouped by OWASP category.
ctfenum web next 10.10.10.5                 # everything pending
ctfenum web next 10.10.10.5 --cat A03       # just Injection
ctfenum web next 10.10.10.5 --quick         # only the fast checks

# 3. Execute / mark off — the SHARED verbs, resolved by fuzzy check name.
ENUM_LIVE=1 ctfenum run  10.10.10.5 a01-verb-tampering
ctfenum done 10.10.10.5 a03-sqli
ctfenum loot 10.10.10.5 dump.txt -t sqli -c a03-sqli
ctfenum skip 10.10.10.5 a06-cms-scan -r "not a CMS"

# Housekeeping.
ctfenum web list 10.10.10.5                 # registered apps + progress
ctfenum web checklist                       # print the OWASP reference (no target)
```

Each app is scoped by host, so multiple vhosts/ports on one target coexist. Many
web checks are **manual** (IDOR, SSTI, business-logic, SSRF, JWT, deserialization)
— do the check, then `enum done`; the runnable ones ship templates for `whatweb`,
`ffuf`, `feroxbuster`, `sqlmap`, `nikto`, `wpscan`, `testssl.sh`, `wafw00f`,
`hydra`, and CORS / exposed-file `curl` probes.

`{url}` (→ `scheme://host[:port]`) and `{host}` are substituted alongside the
usual `{ip}` / `{port}` / `{user}` / `{pass}` when a web command is rendered.

> The two sections stay separate: `enum next` shows **service** checks only, and
> `enum web next` shows **web** checks only — but `enum status` and `enum export`
> count and render both.

> ⚠️ The runnable templates (`sqlmap`, `hydra`, `feroxbuster`, `nikto`, …) are
> active and, in some cases, aggressive. They still pass through the dry-run gate
> — only run them against targets you're authorized to test.

The OWASP categories, each with concrete enumeration checks:

| | category | | category |
|---|---|---|---|
| **A01** | Broken Access Control | **A06** | Vulnerable & Outdated Components |
| **A02** | Cryptographic Failures | **A07** | Identification & Auth Failures |
| **A03** | Injection | **A08** | Software & Data Integrity Failures |
| **A04** | Insecure Design | **A09** | Security Logging & Monitoring Failures |
| **A05** | Security Misconfiguration | **A10** | Server-Side Request Forgery (SSRF) |

## The execution engine (`enum run`)

1. **Renders** the command, substituting `{ip}`, `{port}`, `{url}`/`{host}` (for
   web checks), and `{user}`/`{pass}` pulled from your stashed creds.
2. **Prompts** you: `Execute: … ? [Y/n/edit]` (skip with `-y`).
3. **Runs** it and captures stdout / stderr / exit code into an append-only run
   history (you can re-run the same check with different wordlists).
4. **Persists** the run to JSON *immediately* — a crash never loses output.
5. **Offers** to save stdout as an artifact in `<target>_loot/`.
6. **Auto-detects** loot in the output (flags, NTLM hashes, private keys,
   AWS keys, `password=`) and suggests an `enum loot` line.

**Safety**

- Dry-run by default. Real execution needs `ENUM_LIVE=1` or `--live`.
- Commands with shell features (pipes, redirects, subshells) don't run under the
  safe `shell=False` path unless you add `--shell`.
- Destructive patterns (`rm -rf`, reverse shells, `mkfs`, …) demand a typed
  `yes` before firing, even when live.
- `--timeout` (default 300s) kills runaway commands.

## Report templates (`enum export -t`)

- **full** — the lab notebook: exec summary, per-service sections (command +
  latest output, collapsed with `<details>` when long), a **web application
  testing** section grouped by OWASP category, linked loot and notes, an evidence
  index with SHA-256 hashes and provenance, a credential table, and a
  global-checks appendix.
- **exec-summary** — write-up friendly: collapses all output, hides skipped
  checks and empty services, surfaces only *done* + loot-producing actions.
- **loot-only** — just the evidence index and cred table, for handing a box off
  to a teammate who needs to privesc.

Loot links are relative, so `report.md` + `<target>_loot/` form a self-contained
bundle you can drop into GitHub/GitLab or convert to PDF. Keep the report beside
the `_loot/` folder for the links to resolve.

## Dependency gating

Playbook checks can declare `requires`, and `enum next` splits the view into
**available now** vs **blocked** so post-exploitation checks don't clutter you
before you have what they need:

```
winrm  evil-winrm   requires ["creds:winrm"]   → shown only once a cred exists
```

Requirement tokens: `creds[:label]`, `check:<substr>` (that check is done),
`loot[:tag]`, `service:<svc>`.

## Making it yours

The `PLAYBOOKS` dict at the top of `ctfenum.py` is *your* methodology — every
time a box teaches you a check you forgot, add it. Entries are flexible tuples:

```python
("evil-winrm", "Shell if creds valid", "evil-winrm -i {ip} -u {user} -p {pass}",
 "normal", ["creds:winrm"])          # (name, desc, cmd, priority, requires)
```

`priority` is `quick | normal | slow` (drives `--quick`); the last two elements
are optional, so old 3-tuples keep working.

Prefer not to edit the script? Drop overrides in `~/.enumhelper/playbooks.json`
— they're re-read on every invocation (hot reload):

```bash
ctfenum playbook edit      # opens $EDITOR, scaffolds the file if missing
ctfenum playbook reload    # validate + list what your overrides add
```

Services with built-in playbooks: ftp, ssh, telnet, http, https, smb, rpc, ldap,
dns, mysql, mssql, postgresql, smtp, pop3, imap, snmp, redis, nfs, rdp, vnc,
winrm, kerberos, mongodb, oracle, rsync, elasticsearch.

The **web** checklist lives in `WEB_RECON` (discovery baseline) and `WEB_PLAYBOOK`
(one list per OWASP category) — same tuple shape, so extend them the same way
when a box teaches you a web check worth keeping.

## Where this fits vs. other tools

- **AutoRecon / nmapAutomator** run the scans. Feed their open ports into this
  (`enum import`) to track *your* decision tree and the manual follow-through.
- ctfenum is deliberately about the parts that actually cost you points:
  remembering to *do* and *finish* each branch — and having the report 90%
  written by the time you root the box.
```
