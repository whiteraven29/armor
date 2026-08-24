#!/usr/bin/env python3
"""
urlx - Advanced URL Encoder/Decoder & Live URL Toolkit (CTF, Pentest, Bug Bounty)

Author : wh1t3r4v3n
GitHub : https://github.com/whiteraven29
X      : https://x.com/draggonfly29

For authorized security testing, CTF, and bug-bounty work only.
"""
import sys
import re
import time
import json
import argparse
import urllib.parse
import urllib.request
import urllib.error
import ssl
import string
import random
import threading
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

ALNUM = string.ascii_letters + string.digits
UNRESERVED = ALNUM + "-._~"
VERSION = "2.0"

BANNER = r"""
     _   _ ____  _    __  __
    | | | |  _ \| |   \ \/ /   url encode / decode
    | | | | |_) | |    \  /    + live url toolkit
    | |_| |  _ <| |___ /  \    v{ver}
     \___/|_| \_\_____/_/\_\

   made by wh1t3r4v3n  |  github.com/whiteraven29  |  x: draggonfly29
   ------------------------------------------------------------------
   For authorized pentesting, CTF & bug-bounty use only. Be ethical.
""".format(ver=VERSION)


def banner(quiet=False):
    if not quiet:
        # stderr keeps stdout clean for piping / -o output
        print(BANNER, file=sys.stderr)


# --------------------------------------------------------------------------- #
#  I/O helpers
# --------------------------------------------------------------------------- #
def read_input(args):
    if args.stdin:
        data = sys.stdin.read()
    elif args.file:
        data = Path(args.file).read_text(encoding="utf-8")
    elif args.text is not None:
        data = args.text
    else:
        return None
    if getattr(args, "strip", False):
        data = data.strip()
    return data


def write_output(data, outfile=None):
    if outfile:
        Path(outfile).write_text(data, encoding="utf-8")
        print(f"[+] Written to {outfile}", file=sys.stderr)
    else:
        print(data)


# --------------------------------------------------------------------------- #
#  Encoders  (all operate on UTF-8 bytes -> correct for non-ASCII)
# --------------------------------------------------------------------------- #
def _fmt(lower):
    return "%{:02x}" if lower else "%{:02X}"


def hex_only_encode(data, lower=False):
    """Percent-encode EVERY byte (WAF-bypass 'encode all')."""
    f = _fmt(lower)
    return "".join(f.format(b) for b in data.encode("utf-8"))


def symbols_only_encode(data, lower=False):
    """Encode everything except [A-Za-z0-9]."""
    f = _fmt(lower)
    out = []
    for ch in data:
        if ch in ALNUM:
            out.append(ch)
        else:
            out.extend(f.format(b) for b in ch.encode("utf-8"))
    return "".join(out)


def selective_encode(data, chars, lower=False):
    """Encode only the characters listed in `chars`."""
    f = _fmt(lower)
    out = []
    for ch in data:
        if ch in chars:
            out.extend(f.format(b) for b in ch.encode("utf-8"))
        else:
            out.append(ch)
    return "".join(out)


def mixed_encode(data, lower=False, seed=None):
    """Randomly encode ~half the chars (reproducible with --seed)."""
    rng = random.Random(seed)
    f = _fmt(lower)
    out = []
    for ch in data:
        if rng.choice([True, False]):
            out.extend(f.format(b) for b in ch.encode("utf-8"))
        else:
            out.append(ch)
    return "".join(out)


def unicode_encode(data):
    """IIS/legacy %uXXXX encoding (handles astral chars via surrogate pairs)."""
    out = []
    for ch in data:
        cp = ord(ch)
        if cp > 0xFFFF:
            cp -= 0x10000
            hi = 0xD800 + (cp >> 10)
            lo = 0xDC00 + (cp & 0x3FF)
            out.append(f"%u{hi:04X}%u{lo:04X}")
        else:
            out.append(f"%u{cp:04X}")
    return "".join(out)


def double_percent_encode(data, lower=False):
    """Encode then encode the '%' signs again -> %25XX (WAF double-decode)."""
    return hex_only_encode(data, lower).replace("%", "%25" if not lower else "%25")


def standard_encode(data, plus=False, safe=""):
    if plus:
        return urllib.parse.quote_plus(data, safe=safe)
    return urllib.parse.quote(data, safe=safe)


def repeat_encode(data, rounds, plus=False):
    for _ in range(rounds):
        data = standard_encode(data, plus)
    return data


# --------------------------------------------------------------------------- #
#  Decoders
# --------------------------------------------------------------------------- #
def decode_unicode(data):
    return re.sub(r"%u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), data)


def decode(data, rounds=1, recursive=False, do_unicode=True, plus=False):
    unq = urllib.parse.unquote_plus if plus else urllib.parse.unquote

    def one(s):
        s = unq(s)
        if do_unicode:
            s = decode_unicode(s)
        return s

    if recursive:
        prev, cur, i = None, data, 0
        while cur != prev and i < 25:
            prev, cur, i = cur, one(cur), i + 1
        return cur
    for _ in range(rounds):
        data = one(data)
    return data


# --------------------------------------------------------------------------- #
#  URL utilities (recon / reporting)
# --------------------------------------------------------------------------- #
def analyze_url(url):
    p = urllib.parse.urlsplit(url)
    lines = [
        "[*] URL breakdown",
        f"    scheme   : {p.scheme}",
        f"    userinfo : {p.username or ''}{(':' + p.password) if p.password else ''}",
        f"    host     : {p.hostname or ''}",
        f"    port     : {p.port or ''}",
        f"    path     : {p.path}",
        f"    fragment : {p.fragment}",
    ]
    params = urllib.parse.parse_qsl(p.query, keep_blank_values=True)
    if params:
        lines.append(f"    params   : {len(params)}")
        for k, v in params:
            lines.append(f"        {k} = {v}")
    else:
        lines.append("    params   : (none)")
    return "\n".join(lines)


def defang_url(text):
    text = re.sub(r"https?", lambda m: m.group(0).replace("http", "hxxp"), text, flags=re.I)
    text = text.replace("://", "[://]").replace(".", "[.]").replace("@", "[@]")
    return text


def refang_url(text):
    return (text.replace("[://]", "://").replace("[.]", ".")
                .replace("[@]", "@").replace("hxxp", "http").replace("hXXp", "http"))


URL_RE = re.compile(r"\b(?:https?://|www\.)[^\s\"'<>()\]]+", re.I)


def extract_urls(text):
    seen, out = set(), []
    for m in URL_RE.findall(text):
        u = m.rstrip(".,;")
        if u not in seen:
            seen.add(u)
            out.append(u)
    return "\n".join(out)


def build_url(base, params, encode_vals=True):
    """base?k=v&... with values percent-encoded."""
    p = urllib.parse.urlsplit(base)
    existing = urllib.parse.parse_qsl(p.query, keep_blank_values=True)
    for pair in params:
        if "=" in pair:
            k, v = pair.split("=", 1)
        else:
            k, v = pair, ""
        existing.append((k, v))
    q = urllib.parse.urlencode(existing) if encode_vals else "&".join(f"{k}={v}" for k, v in existing)
    return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, q, p.fragment))


# --------------------------------------------------------------------------- #
#  Live HTTP  (send / fuzz)  -- authorized targets only
# --------------------------------------------------------------------------- #
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def safe_url(url):
    """Encode ONLY what is illegal on the wire (space, control bytes, non-ASCII)
    so raw payloads stay raw (like curl) while the request is still valid."""
    out = []
    for ch in url:
        o = ord(ch)
        if o <= 0x20 or o >= 0x7F:
            out.extend(f"%{b:02X}" for b in ch.encode("utf-8"))
        else:
            out.append(ch)
    return "".join(out)


def http_request(url, method="GET", headers=None, data=None, timeout=15,
                 proxy=None, insecure=False, allow_redirects=True, user_agent=None):
    url = safe_url(url)
    headers = dict(headers or {})
    if user_agent:
        headers.setdefault("User-Agent", user_agent)
    else:
        headers.setdefault("User-Agent", f"urlx/{VERSION} (+github.com/whiteraven29)")

    body = data.encode("utf-8") if isinstance(data, str) else data

    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    if not allow_redirects:
        handlers.append(_NoRedirect())
    opener = urllib.request.build_opener(*handlers)

    req = urllib.request.Request(url, data=body, method=method.upper(), headers=headers)
    start = time.time()
    try:
        resp = opener.open(req, timeout=timeout)
        elapsed = time.time() - start
        raw = resp.read()
        return {
            "status": resp.status, "reason": resp.reason, "url": resp.url,
            "headers": dict(resp.headers), "body": raw, "elapsed": elapsed,
        }
    except urllib.error.HTTPError as e:
        elapsed = time.time() - start
        raw = e.read()
        return {
            "status": e.code, "reason": e.reason, "url": url,
            "headers": dict(e.headers or {}), "body": raw, "elapsed": elapsed,
        }


def print_response(r, show_body=False, max_body=2000):
    print(f"[>] {r['url']}", file=sys.stderr)
    print(f"[<] {r['status']} {r['reason']}  "
          f"({len(r['body'])} bytes, {r['elapsed']*1000:.0f} ms)", file=sys.stderr)
    loc = r["headers"].get("Location")
    if loc:
        print(f"    Location: {loc}", file=sys.stderr)
    ctype = r["headers"].get("Content-Type")
    if ctype:
        print(f"    Content-Type: {ctype}", file=sys.stderr)
    if show_body:
        try:
            text = r["body"].decode("utf-8", "replace")
        except Exception:
            text = repr(r["body"])
        if len(text) > max_body:
            text = text[:max_body] + f"\n... [truncated, {len(r['body'])} bytes total]"
        print(text)


def parse_headers(header_list):
    headers = {}
    for h in header_list or []:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers


# --------------------------------------------------------------------------- #
#  Encoding dispatch
# --------------------------------------------------------------------------- #
BURP_PROFILES = {
    "url": {"mode": "standard"},
    "form": {"mode": "standard", "plus": True},
    "aggressive": {"mode": "hex"},
    "minimal": {"mode": "symbols"},
    "double": {"mode": "double"},
    "path": {"mode": "standard", "safe": "/"},
}


def do_encode(data, args):
    lower = args.lower
    if args.burp:
        prof = BURP_PROFILES[args.burp]
        m = prof["mode"]
        if m == "hex":
            return hex_only_encode(data, lower)
        if m == "symbols":
            return symbols_only_encode(data, lower)
        if m == "double":
            return repeat_encode(data, 2)
        return standard_encode(data, prof.get("plus", False), prof.get("safe", ""))

    if args.hex_only:
        return hex_only_encode(data, lower)
    if args.double_pct:
        return double_percent_encode(data, lower)
    if args.unicode:
        return unicode_encode(data)
    if args.mixed:
        return mixed_encode(data, lower, args.seed)
    if args.symbols_only:
        return symbols_only_encode(data, lower)
    if args.encode_chars:
        return selective_encode(data, args.encode_chars, lower)
    if args.rounds and args.rounds > 1:
        return repeat_encode(data, args.rounds, args.plus)
    if args.triple:
        return repeat_encode(data, 3, args.plus)
    if args.double:
        return repeat_encode(data, 2, args.plus)
    return standard_encode(data, args.plus)


# --------------------------------------------------------------------------- #
#  Encoding variants  (used by the WAF-bypass sweep)
# --------------------------------------------------------------------------- #
ENCODINGS = {
    "raw":        lambda s: s,
    "standard":   lambda s: standard_encode(s),
    "plus":       lambda s: standard_encode(s, plus=True),
    "hex-all":    lambda s: hex_only_encode(s),
    "hex-lower":  lambda s: hex_only_encode(s, lower=True),
    "symbols":    lambda s: symbols_only_encode(s),
    "double-std": lambda s: repeat_encode(s, 2),
    "double-pct": lambda s: double_percent_encode(s),
    "unicode":    lambda s: unicode_encode(s),
}


def response_stats(r):
    body = r["body"]
    try:
        text = body.decode("utf-8", "replace")
    except Exception:
        text = ""
    return {
        "status": r["status"],
        "size": len(body),
        "words": len(text.split()),
        "lines": text.count("\n") + 1,
        "text": text,
    }


def is_reflected(payload, text):
    if not payload:
        return False
    return payload in text or urllib.parse.unquote(payload) in text


# --------------------------------------------------------------------------- #
#  WAF-bypass encoding sweep  (novel: one payload -> every encoding, live)
# --------------------------------------------------------------------------- #
def waf_sweep(url_tmpl, payload, http_kwargs, data_tmpl=None, block_codes=None):
    block_codes = block_codes or {403, 406, 429, 501, 999}
    rows, baseline = [], None
    print(f"[*] WAF encoding sweep for payload: {payload!r}", file=sys.stderr)
    print(f"    {'ENCODING':<11} {'STATUS':>6} {'SIZE':>8} {'REFL':>4}  BYPASS", file=sys.stderr)
    print("    " + "-" * 46, file=sys.stderr)
    for name, fn in ENCODINGS.items():
        enc = fn(payload)
        url = url_tmpl.replace("FUZZ", enc)
        body = data_tmpl.replace("FUZZ", enc) if data_tmpl else None
        try:
            r = http_request(url, data=body, **http_kwargs)
        except (urllib.error.URLError, OSError) as e:
            print(f"    {name:<11} {'ERR':>6}  {e}", file=sys.stderr)
            continue
        st = response_stats(r)
        if baseline is None and name == "raw":
            baseline = st
        blocked = st["status"] in block_codes
        refl = is_reflected(enc, st["text"]) or is_reflected(payload, st["text"])
        # "bypass" = raw was blocked, this variant no longer blocked (or reflects)
        bypass = ""
        if baseline and baseline["status"] in block_codes and not blocked:
            bypass = "<== BYPASS"
        elif baseline and not blocked and st["status"] != baseline["status"]:
            bypass = "(diff)"
        print(f"    {name:<11} {st['status']:>6} {st['size']:>8} "
              f"{'yes' if refl else '-':>4}  {bypass}", file=sys.stderr)
        rows.append({"encoding": name, "encoded": enc, "status": st["status"],
                     "size": st["size"], "reflected": refl, "bypass": bool(bypass)})
    return rows


# --------------------------------------------------------------------------- #
#  Baseline vs payload diff  (spot injection points by response deltas)
# --------------------------------------------------------------------------- #
def diff_compare(url_tmpl, payload, http_kwargs, data_tmpl=None, baseline_value=None):
    if baseline_value is None:
        baseline_value = "".join(random.choice(ALNUM) for _ in range(8))

    def fetch(val):
        enc = val
        url = url_tmpl.replace("FUZZ", enc)
        body = data_tmpl.replace("FUZZ", enc) if data_tmpl else None
        r = http_request(url, data=body, **http_kwargs)
        st = response_stats(r)
        st["time"] = r["elapsed"]
        st["reflected"] = is_reflected(enc, st["text"])
        return st

    base = fetch(baseline_value)
    test = fetch(payload)

    def mark(a, b):
        return "  <-- changed" if a != b else ""

    print(f"[*] Baseline vs payload diff", file=sys.stderr)
    print(f"    baseline value : {baseline_value!r}", file=sys.stderr)
    print(f"    payload        : {payload!r}", file=sys.stderr)
    print(f"    {'FIELD':<10} {'BASELINE':>12} {'PAYLOAD':>12}", file=sys.stderr)
    print("    " + "-" * 40, file=sys.stderr)
    print(f"    {'status':<10} {base['status']:>12} {test['status']:>12}"
          f"{mark(base['status'], test['status'])}", file=sys.stderr)
    print(f"    {'size':<10} {base['size']:>12} {test['size']:>12}"
          f"{mark(base['size'], test['size'])}  (Δ {test['size']-base['size']:+d})", file=sys.stderr)
    print(f"    {'words':<10} {base['words']:>12} {test['words']:>12}"
          f"{mark(base['words'], test['words'])}", file=sys.stderr)
    print(f"    {'lines':<10} {base['lines']:>12} {test['lines']:>12}"
          f"{mark(base['lines'], test['lines'])}", file=sys.stderr)
    print(f"    {'time(ms)':<10} {base['time']*1000:>12.0f} {test['time']*1000:>12.0f}"
          f"  (Δ {(test['time']-base['time'])*1000:+.0f})", file=sys.stderr)
    print(f"    {'reflected':<10} {str(base['reflected']):>12} {str(test['reflected']):>12}"
          f"{mark(base['reflected'], test['reflected'])}", file=sys.stderr)

    interesting = (base["status"] != test["status"]
                   or abs(test["size"] - base["size"]) > 0
                   or (test["reflected"] and not base["reflected"])
                   or (test["time"] - base["time"]) > 3)
    verdict = "[!] Response DIFFERS - possible injection point" if interesting \
        else "[*] No significant difference"
    print(f"    {verdict}", file=sys.stderr)
    return {"baseline": base, "payload": test, "interesting": interesting}


# --------------------------------------------------------------------------- #
#  Wordlist fuzzer  (FUZZ placeholder, threaded, with match/filter + calibrate)
# --------------------------------------------------------------------------- #
def _passes(st, refl, f):
    if f["mc"] and st["status"] not in f["mc"]:
        return False
    if f["fc"] and st["status"] in f["fc"]:
        return False
    if f["ms"] and st["size"] not in f["ms"]:
        return False
    if f["fs"] and st["size"] in f["fs"]:
        return False
    if f["mr"] and not re.search(f["mr"], st["text"]):
        return False
    if f["fr"] and re.search(f["fr"], st["text"]):
        return False
    if f["reflect_only"] and not refl:
        return False
    return True


def fuzz(url_tmpl, words, http_kwargs, data_tmpl=None, header_tmpls=None,
         threads=12, delay=0.0, filters=None, encoder=None, calibrate=False,
         as_json=False):
    filters = filters or {}
    filters.setdefault("mc", None)
    for k in ("fc", "ms", "fs"):
        filters.setdefault(k, None)
    filters.setdefault("mr", None)
    filters.setdefault("fr", None)
    filters.setdefault("reflect_only", False)
    lock = threading.Lock()
    hits = [0]

    # auto-calibrate: learn the "nonsense payload" response size, auto-filter it
    if calibrate:
        junk = "".join(random.choice(ALNUM) for _ in range(16))
        enc = encoder(junk) if encoder else junk
        try:
            r = http_request(url_tmpl.replace("FUZZ", enc),
                             data=(data_tmpl.replace("FUZZ", enc) if data_tmpl else None),
                             **http_kwargs)
            st = response_stats(r)
            fs = set(filters["fs"] or [])
            fs.add(st["size"])
            filters["fs"] = fs
            print(f"[*] Calibrated: baseline junk -> {st['status']} "
                  f"{st['size']}b (auto-filtering size {st['size']})", file=sys.stderr)
        except (urllib.error.URLError, OSError) as e:
            print(f"[!] Calibration failed: {e}", file=sys.stderr)

    if not as_json:
        print(f"    {'STATUS':>6} {'SIZE':>8} {'WORDS':>6} {'LINES':>6} {'REFL':>4}  PAYLOAD",
              file=sys.stderr)
        print("    " + "-" * 60, file=sys.stderr)

    def work(word):
        if delay:
            time.sleep(delay)
        enc = encoder(word) if encoder else word
        url = url_tmpl.replace("FUZZ", enc)
        body = data_tmpl.replace("FUZZ", enc) if data_tmpl else None
        hk = dict(http_kwargs)
        if header_tmpls:
            hk = dict(hk)
            hk["headers"] = {k: v.replace("FUZZ", enc)
                             for k, v in (hk.get("headers") or {}).items()}
        try:
            r = http_request(url, data=body, **hk)
        except (urllib.error.URLError, OSError):
            return None
        st = response_stats(r)
        refl = is_reflected(enc, st["text"]) or is_reflected(word, st["text"])
        if not _passes(st, refl, filters):
            return None
        with lock:
            hits[0] += 1
            if as_json:
                print(json.dumps({"payload": word, "status": st["status"],
                                  "size": st["size"], "words": st["words"],
                                  "lines": st["lines"], "reflected": refl,
                                  "url": url}))
            else:
                print(f"    {st['status']:>6} {st['size']:>8} {st['words']:>6} "
                      f"{st['lines']:>6} {'yes' if refl else '-':>4}  {word}")
        return True

    with ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
        list(as_completed(ex.submit(work, w) for w in words))
    print(f"[*] Done. {hits[0]} match(es) from {len(words)} payloads.", file=sys.stderr)


# --------------------------------------------------------------------------- #
#  Main
# --------------------------------------------------------------------------- #
def main():
    p = argparse.ArgumentParser(
        prog="urlx",
        description="urlx v%s - Advanced URL Encoder/Decoder & Live URL Toolkit "
                    "(CTF / Pentest / Bug Bounty) by wh1t3r4v3n" % VERSION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  urlx "a b&c" -e                       standard encode
  urlx "<svg>" --hex-only               encode every byte  (%3C%73...)
  urlx "id=1' or 1=1" --symbols-only    keep alnum, encode the rest
  urlx "AND" --encode-chars "AND"       encode only these chars
  urlx "payload" --double-pct           %25XX  (double-decode WAF bypass)
  echo "x" | urlx --stdin --mixed --seed 7   reproducible random encoding
  urlx "%2561" -d --recursive           fully unwrap nested encoding
  urlx --analyze "https://t/a?x=1&y=2"  break a URL into parts
  urlx --extract -f page.html           pull all URLs out of a file
  urlx "http://evil.com/x" --defang     hxxp://evil[.]com/x  (safe reports)
  urlx --send "https://target/?q=FUZZ" -e "1' OR 1=1"  encode + inject + send
  urlx --send "https://t/login" --method POST --data "u=a&p=b" --proxy http://127.0.0.1:8080
  urlx "<script>alert(1)</script>" --waf-sweep --send "https://t/?q=FUZZ"
                                        try every encoding, see which bypasses the WAF
  urlx --send "https://t/FUZZ" --wordlist paths.txt --auto-calibrate --mc 200,301
                                        threaded fuzz, auto false-positive filtering
  urlx --send "https://t/?x=FUZZ" --wordlist xss.txt --reflect-only --json | jq .
                                        find reflected payloads, machine-readable output
  urlx "1' OR SLEEP(5)-- -" --diff --send "https://t/?id=FUZZ"
                                        compare benign baseline vs payload response
""")

    # input
    p.add_argument("text", nargs="?", help="input text / payload")
    p.add_argument("--stdin", action="store_true", help="read input from stdin")
    p.add_argument("-f", "--file", help="read input from file")
    p.add_argument("-o", "--output", help="write output to file")
    p.add_argument("--strip", action="store_true", help="strip surrounding whitespace/newlines")
    p.add_argument("-q", "--quiet", action="store_true", help="suppress banner")

    # encode
    g = p.add_argument_group("encoding")
    g.add_argument("-e", "--encode", action="store_true")
    g.add_argument("--double", action="store_true", help="encode twice")
    g.add_argument("--triple", action="store_true", help="encode three times")
    g.add_argument("--rounds", type=int, help="encode/decode N times")
    g.add_argument("--hex-only", action="store_true", help="percent-encode every byte")
    g.add_argument("--double-pct", action="store_true", help="double-percent (%%25XX)")
    g.add_argument("--symbols-only", action="store_true", help="encode all but [A-Za-z0-9]")
    g.add_argument("--encode-chars", help="encode only these characters")
    g.add_argument("--mixed", action="store_true", help="randomly encode ~half")
    g.add_argument("--seed", type=int, help="seed for --mixed (reproducible)")
    g.add_argument("--unicode", action="store_true", help="%%uXXXX (IIS/legacy)")
    g.add_argument("--plus", action="store_true", help="form (+) encoding")
    g.add_argument("--lower", action="store_true", help="lowercase hex (%%2f)")
    g.add_argument("--burp", choices=BURP_PROFILES.keys(), help="Burp-style profile")

    # decode
    d = p.add_argument_group("decoding")
    d.add_argument("-d", "--decode", action="store_true")
    d.add_argument("--recursive", action="store_true", help="decode until stable")

    # url utilities
    u = p.add_argument_group("url utilities")
    u.add_argument("--analyze", metavar="URL", help="break a URL into components")
    u.add_argument("--extract", action="store_true", help="extract URLs from input")
    u.add_argument("--defang", action="store_true", help="defang URLs (hxxp, [.])")
    u.add_argument("--refang", action="store_true", help="refang defanged URLs")
    u.add_argument("--build", metavar="BASE", help="build URL: --build BASE --param k=v ...")
    u.add_argument("--param", action="append", default=[], help="k=v pair for --build")

    # live http
    h = p.add_argument_group("live http (authorized targets only)")
    h.add_argument("--send", metavar="URL", help="send request; 'FUZZ' is replaced by encoded input")
    h.add_argument("--method", default="GET", help="HTTP method (default GET)")
    h.add_argument("--data", help="request body ('FUZZ' replaced by encoded input)")
    h.add_argument("--header", action="append", help="add header 'Name: Value' (repeatable)")
    h.add_argument("--user-agent", help="custom User-Agent")
    h.add_argument("--proxy", help="proxy URL (e.g. Burp http://127.0.0.1:8080)")
    h.add_argument("--insecure", action="store_true", help="skip TLS verification")
    h.add_argument("--no-redirect", action="store_true", help="do not follow redirects")
    h.add_argument("--timeout", type=float, default=15, help="request timeout seconds")
    h.add_argument("--show-body", action="store_true", help="print response body to stdout")

    # waf bypass sweep
    w = p.add_argument_group("waf bypass (novel)")
    w.add_argument("--waf-sweep", action="store_true",
                   help="try EVERY encoding of the payload against --send URL/--data (FUZZ), "
                        "report which variant bypasses the WAF")
    w.add_argument("--diff", action="store_true",
                   help="compare a benign baseline vs the payload response (status/size/time/reflection)")
    w.add_argument("--baseline", help="explicit baseline value for --diff (default: random benign token)")

    # wordlist fuzzing
    fz = p.add_argument_group("fuzzing (authorized targets only)")
    fz.add_argument("--wordlist", help="wordlist file; each line replaces FUZZ in --send")
    fz.add_argument("--threads", type=int, default=12, help="concurrent requests (default 12)")
    fz.add_argument("--delay", type=float, default=0.0, help="per-request delay seconds")
    fz.add_argument("--encode-payloads", action="store_true",
                    help="apply the chosen encoder to each wordlist entry")
    fz.add_argument("--auto-calibrate", action="store_true",
                    help="learn baseline junk response and auto-filter it (kills false positives)")
    fz.add_argument("--reflect-only", action="store_true", help="only show reflected payloads")
    fz.add_argument("--json", action="store_true", help="emit JSON lines (pipe to jq)")
    fz.add_argument("--mc", help="match status codes, comma list (e.g. 200,301)")
    fz.add_argument("--fc", help="filter (hide) status codes, comma list (e.g. 404,403)")
    fz.add_argument("--ms", help="match response sizes, comma list")
    fz.add_argument("--fs", help="filter (hide) response sizes, comma list")
    fz.add_argument("--mr", help="match body regex")
    fz.add_argument("--fr", help="filter (hide) body regex")

    args = p.parse_args()
    banner(args.quiet)

    # ---- URL-only utilities that take their own arg ----
    if args.analyze:
        write_output(analyze_url(args.analyze), args.output)
        return
    if args.build:
        write_output(build_url(args.build, args.param), args.output)
        return

    data = read_input(args)

    # ---- text-transform utilities ----
    if args.extract:
        write_output(extract_urls(data or ""), args.output)
        return
    if args.defang:
        write_output(defang_url(data or ""), args.output)
        return
    if args.refang:
        write_output(refang_url(data or ""), args.output)
        return

    http_kwargs = dict(
        method=args.method, headers=parse_headers(args.header), timeout=args.timeout,
        proxy=args.proxy, insecure=args.insecure, allow_redirects=not args.no_redirect,
        user_agent=args.user_agent,
    )

    # ---- WAF bypass sweep ----
    if args.waf_sweep:
        if not args.send or data is None:
            sys.exit("[!] --waf-sweep needs --send URL (with FUZZ) and a payload")
        waf_sweep(args.send, data, http_kwargs, data_tmpl=args.data)
        return

    # ---- baseline vs payload diff ----
    if args.diff:
        if not args.send or data is None:
            sys.exit("[!] --diff needs --send URL (with FUZZ) and a payload")
        diff_compare(args.send, data, http_kwargs, data_tmpl=args.data,
                     baseline_value=args.baseline)
        return

    # ---- wordlist fuzzing ----
    if args.wordlist:
        if not args.send:
            sys.exit("[!] --wordlist needs --send URL containing FUZZ")
        words = [ln.rstrip("\n") for ln in Path(args.wordlist).read_text(
            encoding="utf-8", errors="replace").splitlines() if ln.strip()]

        def to_set(s):
            return {int(x) for x in s.split(",")} if s else None
        filters = {
            "mc": to_set(args.mc), "fc": to_set(args.fc),
            "ms": to_set(args.ms), "fs": to_set(args.fs),
            "mr": args.mr, "fr": args.fr, "reflect_only": args.reflect_only,
        }
        encoder = (lambda s: do_encode(s, args)) if args.encode_payloads else None
        fuzz(args.send, words, http_kwargs, data_tmpl=args.data,
             header_tmpls=args.header, threads=args.threads, delay=args.delay,
             filters=filters, encoder=encoder, calibrate=args.auto_calibrate,
             as_json=args.json)
        return

    # ---- live http ----
    if args.send:
        payload = ""
        if data is not None:
            payload = do_encode(data, args) if (args.encode or _any_encode_flag(args)) else data
        url = args.send.replace("FUZZ", payload)
        body = args.data.replace("FUZZ", payload) if args.data else None
        r = http_request(url, data=body, **http_kwargs)
        print_response(r, show_body=args.show_body)
        return

    # ---- decode ----
    if args.decode:
        if data is None:
            sys.exit("[!] No input provided")
        rounds = args.rounds or (3 if args.triple else 2 if args.double else 1)
        res = decode(data, rounds=rounds, recursive=args.recursive,
                     plus=args.plus)
        write_output(res, args.output)
        return

    # ---- encode ----
    if data is None:
        p.print_help()
        return
    if not (args.encode or _any_encode_flag(args)):
        p.print_help()
        return
    write_output(do_encode(data, args), args.output)


def _any_encode_flag(a):
    return any([a.double, a.triple, a.hex_only, a.double_pct, a.symbols_only,
                a.encode_chars, a.mixed, a.unicode, a.burp,
                bool(a.rounds and a.rounds > 1)])


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\n[!] Interrupted")
    except (urllib.error.URLError, OSError) as e:
        sys.exit(f"[!] Network/IO error: {e}")
