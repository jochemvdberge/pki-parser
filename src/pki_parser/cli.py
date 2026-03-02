"""Command line interface for the PKI parser."""
from __future__ import annotations

import argparse
import sys
import datetime



def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Read an x.509 certificate and print selected fields in a Markdown table."
    )
    parser.add_argument("file", help="Path to certificate file (PEM or DER)")
    parser.add_argument(
        "-o",
        "--output",
        help="If specified, write Markdown output to this file instead of stdout.",
    )
    args = parser.parse_args(argv)

    try:
        with open(args.file, "rb") as f:
            data = f.read()
    except OSError as e:
        print(f"Error reading {args.file}: {e}", file=sys.stderr)
        return 1

    try:
        from .parser import X509Parser
    except RuntimeError as e:
        print(str(e), file=sys.stderr)
        return 1
    except Exception as e:
        # fallback in case import issues
        print(f"Failed to import parser: {e}", file=sys.stderr)
        return 1

    try:
        parser = X509Parser(data)
        info = parser.get_info()
    except Exception as e:
        print(f"Failed to parse certificate: {e}", file=sys.stderr)
        return 1

    # format output in markdown instead of JSON
    text = _format_markdown(info)
    if args.output:
        with open(args.output, "w") as f:
            f.write(text)
    else:
        print(text)

    return 0


def _format_markdown(info: dict) -> str:
    # simple markdown representation of certificate data
    lines: list[str] = []
    lines.append("# Certificate")
    subj = info.get("subject", {})
    issuer = info.get("issuer", {})
    serial = info.get("serial_number")
    not_before = info.get("not_before")
    not_after = info.get("not_after")
    # extra fields may exist in info dict (key_algorithm, key_size, etc.)

    # horizontal table: header row lists fields, second row provides values
    headers = []
    values: list[str] = []

    # subject and issuer combined strings with certain abbreviations
    # abbreviate some DN attributes; commonName becomes CN
    abbrev = {"countryName": "C", "organizationName": "O", "commonName": "CN"}
    def collapse(d: dict) -> str:
        parts: list[str] = []
        for k, v in d.items():
            key = abbrev.get(k, k)
            parts.append(f"{key}={v}")
        return ", ".join(parts)

    if subj:
        subj_str = collapse(subj)
        headers.append("subject")
        values.append(subj_str)
    if issuer:
        issuer_str = collapse(issuer)
        headers.append("issuer")
        values.append(issuer_str)

    def add_field(name: str, val: Any) -> None:
        if val is not None:
            headers.append(name)
            values.append(str(val))

    # serial number should show colon separators every two hex digits
    def fmt_serial(s: str) -> str:
        # strip 0x prefix if present
        if s.startswith("0x") or s.startswith("0X"):
            s = s[2:]
        # ensure even length
        if len(s) % 2 == 1:
            s = "0" + s
        pairs = [s[i : i + 2] for i in range(0, len(s), 2)]
        return ":".join(pairs)

    if serial is not None:
        add_field("serial_number", fmt_serial(serial))
    # insert other core fields in the prescribed order
    add_field("key_algorithm", info.get("key_algorithm"))
    add_field("key_size", info.get("key_size"))
    add_field("digest_algorithm", info.get("digest_algorithm"))
    # split validity into two columns and format dates human-readable
    def fmt(date_str: str) -> str:
        try:
            # input like YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS
            dt = datetime.datetime.fromisoformat(date_str)
            return dt.strftime("%d %b %Y")
        except Exception:
            return date_str.split("T")[0]

    if not_before:
        add_field("not_before", fmt(not_before))
    if not_after:
        add_field("not_after", fmt(not_after))
    add_field("subject_key_identifier", info.get("subject_key_identifier"))
    # fingerprints are easier to read in uppercase
    fp = info.get("sha256_fingerprint")
    if fp is not None:
        add_field("sha256_fingerprint", fp.upper())

    # generate rows
    header_line = "| " + " | ".join(headers) + " |"
    sep_line = "| " + " | ".join("-----" for _ in headers) + " |"
    value_line = "| " + " | ".join(values) + " |"

    lines.append("")
    lines.extend([header_line, sep_line, value_line])
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())