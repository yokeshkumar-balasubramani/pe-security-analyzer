
---

```markdown
# 🔍 DLL Analyzer

A Python-based static analysis tool to inspect PE (Portable Executable) files such as `.dll` and `.exe` for security features, digital signatures, obfuscation, and other important metadata.

---

## 🚀 Features

- ✅ Authenticode signature check
- 🔒 ASLR, DEP, CFG, SafeSEH, Force Integrity, High-Entropy ASLR checks
- 🧠 Obfuscation detection (based on `.text` section readability)
- 📦 Subsystem version detection
- 📊 Security score calculation based on protective flags
- 📁 Recursive directory scanning with file extension filters
- 📄 Exports results in CSV format
- ⚙️ Configurable via `config.json` or command-line arguments

---

## 🧰 Requirements

- Python 3.6+
- Install dependencies using:

```bash
pip install pefile oscrypto asn1crypto
```

---

## 🛠 Usage

### 🔧 Option 1: Using Command Line Arguments

```bash
python pe-security-analyzer.py "C:\Windows\System32" output.csv
```

### 🔧 Option 2: Using `config.json`

Create a `config.json` file:

```json
{
  "directory_to_analyze": "C:/Windows/System32",
  "output_csv": "dll_analysis_results.csv",
  "file_extensions": [".dll", ".exe"]
}
```

Then just run:

```bash
python pe-security-analyzer.py
```

---

## 📦 Output

The output CSV will contain the following fields:

- `File Path`
- `Signature`
- `ASLR`
- `DEP`
- `CFG`
- `Obfuscation`
- `Relocation Table`
- `Subsystem Version`
- `SafeSEH`
- `High-Entropy ASLR`
- `Force Integrity`
- `Terminal Server Aware`
- `Security Score`
- `Error` (if any)

---

## 💡 Security Score Logic

| Feature                 | Points |
|-------------------------|--------|
| ASLR                   | 20     |
| DEP                    | 20     |
| CFG                    | 20     |
| Relocation Table       | 10     |
| SafeSEH                | 10     |
| High-Entropy ASLR      | 10     |
| Force Integrity        | 5      |
| Terminal Server Aware  | 5      |
| **Total**               | 100    |

---

## 🛡 Branch Protections (for maintainers)

If you open-source this project, consider setting up:

- ✅ Required PR reviews
- ✅ CI status checks (lint/test)
- ✅ No force-pushes or branch deletions on `main`
- ✅ Signed commits (optional)

---

## 📄 License

MIT License

---

## ✨ Contributing

PRs, issues, and suggestions are welcome! Please read the `CONTRIBUTING.md` before submitting.

---
```
