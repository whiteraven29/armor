# ctfenum — enumeration lab notebook

A single-file CLI that turns CTF / offensive enumeration into a **target-centric
lab notebook**: it tracks the checklist per service, *executes and captures* the
commands you choose to run, records loot and credentials with provenance, and
exports a report-ready Markdown bundle when you're done.

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
├── 10.10.10.5.json          # meta + services + checks (with run history) + loot + creds + notes
├── 10.10.10.5_loot/         # artifacts from `enum run` and `enum loot`
├── playbooks.json           # your check overrides (re-read every invocation)
└── templates/               # (reserved for custom export templates)
```

Old flat-schema files (the `done: true/false` format) are migrated
automatically the first time you touch them — nothing to convert by hand.

## Workflow

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

## The execution engine (`enum run`)

1. **Renders** the command, substituting `{ip}`, `{port}`, and `{user}`/`{pass}`
   pulled from your stashed creds.
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
  latest output, collapsed with `<details>` when long), linked loot and notes,
  an evidence index with SHA-256 hashes and provenance, a credential table, and
  a global-checks appendix.
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

## Where this fits vs. other tools

- **AutoRecon / nmapAutomator** run the scans. Feed their open ports into this
  (`enum import`) to track *your* decision tree and the manual follow-through.
- ctfenum is deliberately about the parts that actually cost you points:
  remembering to *do* and *finish* each branch — and having the report 90%
  written by the time you root the box.
```
