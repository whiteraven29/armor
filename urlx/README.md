# urlx

**Advanced URL Encoder/Decoder & Live URL Toolkit for CTF, Pentest & Bug Bounty.**

Made by **wh1t3r4v3n** · [github.com/whiteraven29](https://github.com/whiteraven29) · X: [@draggonfly29](https://x.com/draggonfly29)

A single, dependency-free Python 3 CLI that does the whole payload loop — **encode → inject → send → analyze** — plus a few tricks no other tool bundles: a WAF-bypass encoding sweep, auto-calibrated fuzzing, and baseline-vs-payload diffing.

> ⚠️ **For authorized security testing, CTF, and bug-bounty work only.** Only test targets you have explicit permission to test.

---

## Features

- **Encoders (UTF-8 correct):** standard, form (`+`), encode-all-bytes, symbols-only, selective chars, random/mixed (seeded & reproducible), `%uXXXX` unicode (with surrogate pairs), double/triple, double-percent (`%25XX`), lowercase hex, Burp-style profiles.
- **Decoders:** single/N-round, recursive-until-stable, `%uXXXX` and form decoding.
- **URL utilities:** component analysis, defang/refang for safe reports, URL extraction, safe URL building.
- **Live HTTP:** send requests with a `FUZZ` placeholder, custom method/headers/body, proxy (Burp/ZAP), TLS-skip, redirect control.
- **WAF-bypass sweep** *(novel)*: send one payload through **every** encoding and report which variant bypasses the WAF.
- **Threaded fuzzer:** wordlist `FUZZ` fuzzing with match/filter by status/size/regex, reflection detection, JSON output.
- **Auto-calibration** *(novel)*: learns the "not found" baseline and auto-filters false positives.
- **Diff mode:** benign baseline vs payload — flags injection points by status/size/time/reflection deltas.

## Install

No dependencies — just Python 3.7+.

```bash
git clone https://github.com/whiteraven29/urlx
chmod +x urlx.py
./urlx.py --help
```

> The banner prints to **stderr**, so piping / `-o` output stays clean. Use `-q` to silence it.

---

## Encoding / Decoding

```bash
urlx "a b&c"          -e                 # standard        -> a%20b%26c
urlx "<svg onload=1>" --hex-only         # encode all      -> %3C%73%76...
urlx "id=1' or 1=1"   --symbols-only     # keep alnum only -> id%3D1%27%20or...
urlx "AND"            --encode-chars AND  # only these chars
urlx "payload"        --double-pct        # %25XX double-decode bypass
urlx "/etc/passwd"    --hex-only --lower  # lowercase hex   -> %2f%65%74...
urlx "<script>"       --unicode           # %u003C%u0073...
echo "x" | urlx --stdin --mixed --seed 7  # reproducible random encoding
urlx "%2561%2562" -d --recursive          # fully unwrap    -> ab
```

| Flag | Meaning |
|---|---|
| `-e` | standard percent-encode |
| `--plus` | form encoding (space → `+`) |
| `--hex-only` | encode every byte |
| `--symbols-only` | encode all but `[A-Za-z0-9]` |
| `--encode-chars STR` | encode only these chars |
| `--mixed [--seed N]` | randomly encode ~half (reproducible) |
| `--unicode` | `%uXXXX` (IIS/legacy) |
| `--double` / `--triple` / `--rounds N` | repeat encoding |
| `--double-pct` | `%25XX` |
| `--lower` | lowercase hex |
| `--burp {url,form,aggressive,minimal,double,path}` | Burp-style profile |
| `-d [--recursive] [--rounds N]` | decode |

## URL Utilities

```bash
urlx --analyze "https://u:p@t.com:8443/a?x=1&y=hi%20there#f"   # break into parts
urlx --extract -f page.html                                    # pull all URLs
urlx "http://evil.com/x" --defang                              # hxxp://evil[.]com/x
urlx "hxxp://evil[.]com" --refang                              # reverse
urlx --build "https://t/s" --param "q=a b" --param "id=1"      # build encoded URL
```

## Live HTTP (`FUZZ` placeholder)

```bash
urlx --send "https://target/?q=FUZZ" -e "1' OR 1=1"           # encode + inject + send
urlx --send "https://t/login" --method POST --data "u=a&p=FUZZ" -e "admin"
urlx --send "https://t/" --proxy http://127.0.0.1:8080        # route through Burp
urlx --send "https://t/" --header "X-Forwarded-For: 127.0.0.1" --show-body
```

`FUZZ` is replaced in the URL, the `--data` body, **and** headers.
Common flags: `--method --data --header --user-agent --proxy --insecure --no-redirect --timeout --show-body`.

---

## WAF-Bypass Sweep (novel)

Send **one** payload through every encoding variant and see which slips past the WAF:

```bash
urlx "<script>alert(1)</script>" --waf-sweep --send "https://target/?q=FUZZ"
```

```
    ENCODING    STATUS     SIZE REFL  BYPASS
    ----------------------------------------------
    raw            403        7    -
    standard       200       23  yes  <== BYPASS
    hex-all        200       23  yes  <== BYPASS
    unicode        200      113  yes  <== BYPASS
    ...
```

`<== BYPASS` = the raw payload was blocked but this encoding was not. Always eyeball SIZE/REFL too (some WAFs return `200` with a block page).

## Threaded Fuzzing

```bash
# path discovery with auto false-positive filtering
urlx --send "https://t/FUZZ" --wordlist paths.txt --auto-calibrate --mc 200,301

# reflected-XSS hunting, machine-readable
urlx --send "https://t/?x=FUZZ" --wordlist xss.txt --reflect-only --json | jq .

# encode each payload before sending
urlx --send "https://t/?q=FUZZ" --wordlist sqli.txt --encode-payloads --hex-only --fc 404
```

| Flag | Meaning |
|---|---|
| `--wordlist FILE` | each line replaces `FUZZ` |
| `--threads N` | concurrency (default 12) |
| `--delay SEC` | per-request delay / rate-limit |
| `--auto-calibrate` | learn junk baseline, auto-filter it |
| `--mc / --fc` | match / filter status codes |
| `--ms / --fs` | match / filter response sizes |
| `--mr / --fr` | match / filter body regex |
| `--reflect-only` | only reflected payloads |
| `--encode-payloads` | apply chosen encoder to each entry |
| `--json` | JSON lines output (pipe to `jq`) |

## Baseline-vs-Payload Diff

Spot injection points by comparing a benign baseline against your payload:

```bash
urlx "1' OR SLEEP(5)-- -" --diff --send "https://t/?id=FUZZ"
```

```
    FIELD          BASELINE      PAYLOAD
    ----------------------------------------
    status              200          200
    size                 13           23  <-- changed  (Δ +10)
    words                 1            4  <-- changed
    time(ms)              4         5012  (Δ +5008)     # time-based SQLi signal
    reflected          True         True
    [!] Response DIFFERS - possible injection point
```

Use `--baseline VALUE` to set an explicit baseline instead of a random token.

---

## Why urlx vs. the field

| Capability | urlx | ffuf/wfuzz | CyberChef | Burp |
|---|---|---|---|---|
| Encode/decode + WAF variants | ✅ | partial | ✅ | ✅ |
| Threaded wordlist fuzz | ✅ | ✅ | ❌ | ✅ (Intruder) |
| **Auto encoding-sweep bypass** | ✅ | ❌ | ❌ | ❌ |
| **Auto-calibrate FP filter** | ✅ | ❌ | ❌ | ❌ |
| **Baseline diff w/ time signal** | ✅ | ❌ | ❌ | partial |
| Defang/refang for reports | ✅ | ❌ | ✅ | ❌ |
| Stdlib-only, zero install | ✅ | ❌ | ❌ | ❌ |

urlx's niche is the **encode-and-send-and-report loop in one pipeable CLI**. For million-line wordlists at max throughput, ffuf's Go engine is still faster — urlx's edge is encoding intelligence, not raw speed.

## License / Disclaimer

Use only against systems you are authorized to test. The authors accept no liability for misuse.
