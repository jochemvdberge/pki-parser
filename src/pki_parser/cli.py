"""Command line interface for the PKI parser."""
from __future__ import annotations

import argparse
import sys
import datetime
import json
import csv
from io import StringIO
from typing import Any, Iterable, List, Mapping
from urllib.request import urlopen
from urllib.error import URLError



def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Read one or more x.509 certificates and print selected fields."
    )
    parser.add_argument(
        "files",
        nargs="+",
        help="Path(s) to certificate file(s) (PEM or DER) or URI(s)",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="If specified, write output to this file instead of stdout.",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["markdown", "json", "csv"],
        default="markdown",
        help="Output format: markdown (default), json, or csv (semicolon-separated).",
    )
    parser.add_argument(
        "-u",
        "--uri",
        action="store_true",
        help="Treat file arguments as URIs and fetch them from the network.",
    )
    args = parser.parse_args(argv)

    try:
        from .parser import X509Parser
    except RuntimeError as e:
        print(str(e), file=sys.stderr)
        return 1
    except Exception as e:
        # fallback in case import issues
        print(f"Failed to import parser: {e}", file=sys.stderr)
        return 1

    infos: list[dict] = []
    for path in args.files:
        try:
            data = _load_certificate_data(path, args.uri)
        except OSError as e:
            print(f"Error reading {path}: {e}", file=sys.stderr)
            return 1
        except URLError as e:
            print(f"Error fetching {path}: {e}", file=sys.stderr)
            return 1

        try:
            parser_obj = X509Parser(data)
            info = parser_obj.get_info()
        except Exception as e:
            print(f"Failed to parse certificate {path}: {e}", file=sys.stderr)
            return 1

        infos.append(info)

    # format output based on specified format
    if args.format == "json":
        text = _format_json(infos)
    elif args.format == "csv":
        text = _format_csv(infos)
    else:  # markdown (default)
        text = _format_markdown(infos)
    
    if args.output:
        with open(args.output, "w") as f:
            f.write(text)
    else:
        print(text)

    return 0


def _load_certificate_data(source: str, is_uri: bool) -> bytes:
    """Load certificate data from a local file or URI.
    
    Args:
        source: Path to local file or URI
        is_uri: If True, treat source as URI; if False, treat as local path.
                If False but source looks like a URI, fetch it anyway.
    
    Returns:
        Raw certificate data as bytes
        
    Raises:
        OSError: If file cannot be read
        URLError: If URI cannot be fetched
    """
    if is_uri or source.startswith(("http://", "https://")):
        # Fetch from URI
        with urlopen(source) as response:
            return response.read()
    else:
        # Read from local file
        with open(source, "rb") as f:
            return f.read()


def _format_markdown(infos: Iterable[dict]) -> str:
    """Render one or more parsed certificate info dicts as a Markdown table.

    ``infos`` may be a single dict or an iterable of dicts.  The table header is
    built from the union of fields present across all entries but always
    respects the canonical column order required by the CLI spec.
    """

    # make sure we work uniformly with a list
    if isinstance(infos, dict):
        infos = [infos]
    infos = list(infos)  # consume iterator if necessary

    title = "Certificate" if len(infos) == 1 else "Certificates"
    lines: list[str] = [f"# {title}"]

    # helper to collapse DNs and format a single info into a flat mapping
    abbrev = {"countryName": "C", "organizationName": "O", "commonName": "CN"}

    def collapse(d: Mapping[str, Any]) -> str:
        parts: list[str] = []
        for k, v in d.items():
            key = abbrev.get(k, k)
            parts.append(f"{key}={v}")
        return ", ".join(parts)

    def fmt_serial(s: str) -> str:
        if s.startswith(("0x", "0X")):
            s = s[2:]
        if len(s) % 2 == 1:
            s = "0" + s
        pairs = [s[i : i + 2] for i in range(0, len(s), 2)]
        return ":".join(pairs)

    def fmt_date(date_str: str) -> str:
        try:
            dt = datetime.datetime.fromisoformat(date_str)
            return dt.strftime("%d %b %Y")
        except Exception:
            return date_str.split("T")[0]

    # canonical header order required by tests/CLI description
    base_order = [
        "subject",
        "issuer",
        "serial_number",
        "key_algorithm",
        "key_size",
        "digest_algorithm",
        "not_before",
        "not_after",
        "subject_key_identifier",
        "sha256_fingerprint",
    ]

    rows: list[dict] = []
    extras: List[str] = []  # any additional fields beyond base_order

    for info in infos:
        row: dict[str, str] = {}
        subj = info.get("subject") or {}
        issuer = info.get("issuer") or {}
        if subj:
            row["subject"] = collapse(subj)
        if issuer:
            row["issuer"] = collapse(issuer)
        if info.get("serial_number") is not None:
            row["serial_number"] = fmt_serial(info["serial_number"])
        for name in ("key_algorithm", "key_size", "digest_algorithm"):
            if info.get(name) is not None:
                row[name] = str(info[name])
        if info.get("not_before"):
            row["not_before"] = fmt_date(info["not_before"])
        if info.get("not_after"):
            row["not_after"] = fmt_date(info["not_after"])
        if info.get("subject_key_identifier") is not None:
            row["subject_key_identifier"] = str(info["subject_key_identifier"])
        fp = info.get("sha256_fingerprint")
        if fp is not None:
            row["sha256_fingerprint"] = fp.upper()

        # capture any unexpected fields for completeness
        for key, val in info.items():
            if key not in base_order and key not in row:
                extras.append(key)
                row[key] = str(val)
        rows.append(row)

    # build final headers list
    headers: List[str] = []
    for h in base_order + extras:
        if h not in headers:
            headers.append(h)

    # construct markdown table
    header_line = "| " + " | ".join(headers) + " |"
    sep_line = "| " + " | ".join("-----" for _ in headers) + " |"
    lines.append("")
    lines.append(header_line)
    lines.append(sep_line)

    for row in rows:
        values = [row.get(h, "") for h in headers]
        lines.append("| " + " | ".join(values) + " |")

    return "\n".join(lines)


def _format_json(infos: Iterable[dict]) -> str:
    """Render one or more parsed certificate info dicts as JSON."""
    if isinstance(infos, dict):
        infos = [infos]
    infos = list(infos)
    return json.dumps(infos, indent=2)


def _format_csv(infos: Iterable[dict]) -> str:
    """Render one or more parsed certificate info dicts as CSV with semicolon separator.
    
    DNS are collapsed with abbreviations (C, O, CN), and dates are formatted
    consistently with the markdown output.
    """
    if isinstance(infos, dict):
        infos = [infos]
    infos = list(infos)
    
    abbrev = {"countryName": "C", "organizationName": "O", "commonName": "CN"}

    def collapse(d: Mapping[str, Any]) -> str:
        parts: list[str] = []
        for k, v in d.items():
            key = abbrev.get(k, k)
            parts.append(f"{key}={v}")
        return ", ".join(parts)

    def fmt_serial(s: str) -> str:
        if s.startswith(("0x", "0X")):
            s = s[2:]
        if len(s) % 2 == 1:
            s = "0" + s
        pairs = [s[i : i + 2] for i in range(0, len(s), 2)]
        return ":".join(pairs)

    def fmt_date(date_str: str) -> str:
        try:
            dt = datetime.datetime.fromisoformat(date_str)
            return dt.strftime("%d %b %Y")
        except Exception:
            return date_str.split("T")[0]

    base_order = [
        "subject",
        "issuer",
        "serial_number",
        "key_algorithm",
        "key_size",
        "digest_algorithm",
        "not_before",
        "not_after",
        "subject_key_identifier",
        "sha256_fingerprint",
    ]

    rows: list[dict] = []
    extras: List[str] = []

    for info in infos:
        row: dict[str, str] = {}
        subj = info.get("subject") or {}
        issuer = info.get("issuer") or {}
        if subj:
            row["subject"] = collapse(subj)
        if issuer:
            row["issuer"] = collapse(issuer)
        if info.get("serial_number") is not None:
            row["serial_number"] = fmt_serial(info["serial_number"])
        for name in ("key_algorithm", "key_size", "digest_algorithm"):
            if info.get(name) is not None:
                row[name] = str(info[name])
        if info.get("not_before"):
            row["not_before"] = fmt_date(info["not_before"])
        if info.get("not_after"):
            row["not_after"] = fmt_date(info["not_after"])
        if info.get("subject_key_identifier") is not None:
            row["subject_key_identifier"] = str(info["subject_key_identifier"])
        fp = info.get("sha256_fingerprint")
        if fp is not None:
            row["sha256_fingerprint"] = fp.upper()

        for key, val in info.items():
            if key not in base_order and key not in row:
                extras.append(key)
                row[key] = str(val)
        rows.append(row)

    headers: List[str] = []
    for h in base_order + extras:
        if h not in headers:
            headers.append(h)

    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=headers, delimiter=";")
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue().rstrip("\n")


if __name__ == "__main__":
    sys.exit(main())
