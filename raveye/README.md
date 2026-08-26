# ctfenum — enumeration checklist tracker

A tiny CLI that stops you missing points during CTF / offensive enumeration.
It keeps per-target state on disk and, whenever you record an open service,
surfaces the standard follow-up checks for that service so nothing slips.

No auto-scanning: it *prints* the commands it suggests, so you stay in control
and actually learn the methodology instead of leaning on a black box.

## Install

```bash
chmod +x ctfenum.py
# optional: put it on your PATH
sudo ln -s "$(pwd)/ctfenum.py" /usr/local/bin/ctfenum
```

State lives in `~/.enumhelper/<target>.json`.

## Workflow

```bash
# 1. As you discover ports, record them one at a time...
ctfenum add 10.10.10.5 21 ftp
ctfenum add 10.10.10.5 80 http
ctfenum add 10.10.10.5 445 smb

#    ...or bulk-import a whole scan (nmap -oG or -oX; ports auto-map to services):
nmap -p- -sV -oX scan.xml 10.10.10.5
ctfenum import 10.10.10.5 scan.xml

# 2. See everything you still haven't checked (the anti-miss view):
ctfenum next 10.10.10.5
ctfenum next 10.10.10.5 -s smb        # filter to one service

# 3. Tick things off as you go (fuzzy match on the check name works):
ctfenum done 10.10.10.5 anon-login
ctfenum done 10.10.10.5 http/80:dir-brute
ctfenum undone 10.10.10.5 anon-login  # reopen if you ticked it by mistake

# 4. Stash creds and notes so they're all in one place at report time:
ctfenum cred 10.10.10.5 "admin:hunter2 (found in /backup.zip)"
ctfenum note 10.10.10.5 "SSH only accepts publickey"

# 5. Check progress, or export a Markdown report for write-up time:
ctfenum status 10.10.10.5
ctfenum list
ctfenum export 10.10.10.5 -o 10.10.10.5.md
```

## Making it yours

The whole point is that the `PLAYBOOKS` dict at the top of `ctfenum.py` is
*your* methodology. Every time a box teaches you a check you forgot, add it to
the relevant service. Over time this becomes a personalized system that encodes
exactly the mistakes you personally tend to make — which is far more valuable
than any generic tool.

Services with playbooks so far: ftp, ssh, telnet, http, https, smb, rpc, ldap,
dns, mysql, mssql, postgresql, smtp, pop3, imap, snmp, redis, nfs, rdp, vnc,
winrm, kerberos, mongodb, oracle, rsync, elasticsearch.

`import` maps ports to these via nmap's service name, then a `PORT_HINTS` table
by port number — extend both when you teach it a new service.

## Where this fits vs. other tools

- **AutoRecon / nmapAutomator** run the scans. Great, but they don't track
  *your* decision tree or remind you of manual checks. Run one of those for the
  baseline, then feed the open ports into this to track follow-through.
- This tool is deliberately about the part that's actually failing you:
  remembering to *do* and *finish* each branch.
