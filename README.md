# pki-parser
This repository contains a simple Python library and CLI for parsing
X.509 certificates (PEM or DER) and displaying a subset of fields in a
Markdown table.  It requires the `cryptography` library; install dependencies
using `pip install -e .[test]` before running the tool, otherwise you'll see a
clear error message pointing out the missing package.

disclaimer: fully built with Copilot. Use at your own risk.

## Quickstart

```bash
# create a virtualenv and install
python -m venv venv
source venv/bin/activate
pip install -e .

# parse one or more certificates
pki-parser path/to/cert1.pem [path/to/cert2.pem ...]

The CLI now accepts multiple file paths and will emit a single Markdown
table with one row per certificate.```

The CLI prints the core certificate fields listed below in a **single
horizontal Markdown table** (one certificate per row), rather than JSON or
multiple sections. The first row contains column headers matching the field
names in the exact order shown.

- subject (DN attributes combined; `countryName`→`C`, `organizationName`→`O`, `commonName`→`CN`).
  The individual components are joined with commas.
- issuer (same abbreviations apply)
- serial number (hex digits grouped in pairs separated by `:`)
- key algorithm
- key size
- digest algorithm
- not before (date only)
- not after (date only)
- subject key identifier
- SHA-256 fingerprint (displayed in uppercase for readability)
