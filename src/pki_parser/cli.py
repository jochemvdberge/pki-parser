"""Command line interface for the PKI parser."""
from __future__ import annotations

import argparse
import sys
import datetime
from typing import Any, Iterable, List, Mapping



def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Read one or more x.509 certificates and print selected fields in a Markdown table."
    )
    parser.add_argument(
        "files",
        nargs="+",
        help="Path(s) to certificate file(s) (PEM or DER)",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="If specified, write Markdown output to this file instead of stdout.",
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
            with open(path, "rb") as f:
                data = f.read()
        except OSError as e:
            print(f"Error reading {path}: {e}", file=sys.stderr)
            return 1

        try:
            parser_obj = X509Parser(data)
            info = parser_obj.get_info()
        except Exception as e:
            print(f"Failed to parse certificate {path}: {e}", file=sys.stderr)
            return 1

        infos.append(info)

    # format output in markdown instead of JSON
    text = _format_markdown(infos)
    if args.output:
        with open(args.output, "w") as f:
            f.write(text)
    else:
        print(text)

    return 0



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


if __name__ == "__main__":
    sys.exit(main())