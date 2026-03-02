# pki-parser
This repository contains a simple Python library and CLI for parsing
X.509 certificates (PEM or DER) from local files or remote URIs, with support 
for multiple output formats (Markdown, JSON, CSV). The default output (without any switches) is a Markdown table. For now the dataset is fixed (see below) but I'm thinking about producing different data sets based on demand.

The tool requires the `cryptography` 
library; install dependencies using `pip install -e .` before running the 
tool, otherwise you'll see a clear error message pointing out the missing package.

disclaimer: fully built with Copilot. Use at your own risk.

## Quickstart

```bash
# create a virtualenv and install
python -m venv venv
source venv/bin/activate
pip install -e .

# parse one or more certificates (local files or URLs)
pki-parser path/to/cert1.pem [path/to/cert2.pem ...]

# fetch from remote URLs (auto-detected or explicit)
pki-parser https://example.com/cert.pem
pki-parser --uri https://example.com/cert.pem

# output as JSON instead of Markdown
pki-parser path/to/cert.pem --format json

# output as CSV (semicolon-separated)
pki-parser path/to/cert.pem --format csv

# mix local files and remote URLs with custom output and saving to file on disk
pki-parser /local/cert.pem https://example.com/cert.pem --format csv -o output.csv
```

The CLI accepts multiple file paths (local or remote) and emits a formatted 
table with one row per certificate.

## Command-Line Options

```
pki-parser [-h] [-o OUTPUT] [-f {markdown,json,csv}] [-u] files [files ...]

Positional arguments:
  files              Path(s) to certificate file(s) (PEM or DER) or URI(s)

Optional arguments:
  -h, --help         Show help message and exit
  -o, --output FILE  Write output to file instead of stdout
  -f, --format {markdown,json,csv}
                     Output format (default: markdown)
                     - markdown: Markdown table
                     - json: JSON array of certificate objects
                     - csv: CSV with semicolon delimiters
  -u, --uri          Treat arguments as URIs and fetch from the network
                     (URIs starting with http:// or https:// are auto-detected)
```

## Output Formats

### Markdown (default)
A formatted Markdown table, suitable for documents and reports:
```
# Certificate

| subject | issuer | serial_number | ... |
| --- | --- | --- | ... |
| CN=example.com,O=Example,C=US | CN=Root CA,O=Example,C=US | ab:cd:ef | ... |
```

### JSON
A JSON array of certificate objects, suitable for programmatic consumption:
```json
[
  {
    "subject": {"commonName": "example.com", "organizationName": "Example", "countryName": "US"},
    "issuer": {...},
    "serial_number": "0xabcdef",
    ...
  }
]
```

### CSV
A CSV file with semicolon delimiters, suitable for spreadsheets:
```
subject;issuer;serial_number;key_algorithm;key_size;...
CN=example.com, O=Example, C=US;CN=Root CA, O=Example, C=US;ab:cd:ef;RSA;2048;...
```

## Certificate Fields

The following fields are included in all output formats:

- **subject**: Distinguished Name with abbreviations (`C`=country, `O`=organization, `CN`=commonName)
- **issuer**: Distinguished Name (same abbreviations as subject)
- **serial_number**: Hex digits grouped in pairs separated by `:`
- **key_algorithm**: RSA, ECDSA, DSA, etc.
- **key_size**: Key size in bits
- **digest_algorithm**: Signature digest algorithm
- **not_before**: Certificate validity start date
- **not_after**: Certificate validity end date
- **subject_key_identifier**: SKI extension value
- **sha256_fingerprint**: SHA-256 fingerprint in uppercase hex
