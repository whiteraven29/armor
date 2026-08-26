# 🛡️ armor

A personal arsenal of security tools built by **wh1t3r4v3n** for CTF, penetration testing, and bug-bounty work.

[github.com/whiteraven29](https://github.com/whiteraven29) · X: [@draggonfly29](https://x.com/draggonfly29)

> ⚠️ **Authorized use only.** Everything here is for legal, authorized security testing, CTF competitions, and education. Only test systems you own or have explicit written permission to test. The author accepts no liability for misuse.

---

## Tools

| Tool | Description | Language |
|------|-------------|----------|
| [urlx](urlx/) | Advanced URL encoder/decoder + live URL toolkit (WAF-bypass sweep, threaded fuzzer, baseline diff) | Python |
| [raveye](raveye/) | A tool for tracking enumeration process and help to keep tracks of enumeration for all services discovered so you don't miss a point| Python |

_More tools land here over time — each in its own folder with its own README._

---

## Layout

```
armor/
├── README.md          # this index
├── LICENSE
├── .gitignore
└── <tool>/            # one folder per tool
    ├── README.md      # tool-specific docs
    └── <tool files>
```

Each tool is self-contained. Prefer standard-library / zero-dependency where possible; when a tool needs packages, it ships a `requirements.txt` inside its own folder.

## Usage

Clone the whole arsenal:

```bash
git clone https://github.com/whiteraven29/armor
cd armor/urlx
./urlx.py --help
```

## License

[MIT](LICENSE) — see the disclaimer above.
