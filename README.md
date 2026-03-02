# pki-parser
probably vibe-coded PKI-parser for extracting data from x.509 certificates

This repository contains a simple Python library and CLI for parsing
X.509 certificates (PEM or DER) and displaying a subset of fields in a
Markdown table.  It requires the `cryptography` library; install dependencies
using `pip install -e .[test]` before running the tool, otherwise you'll see a
clear error message pointing out the missing package.

## Quickstart

```bash
# create a virtualenv and install
python -m venv venv
source venv/bin/activate
pip install -e .

# parse a certificate
pki-parser path/to/cert.pem
```

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
