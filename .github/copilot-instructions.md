# pki-parser AI Agent Guidelines

This project is deliberately simple; its goal is to parse an x.509 certificate
and emit a small JSON summary. An AI agent should be able to read and extend
the codebase quickly. Below are the key points you need to know.

## Architecture & Components

- **Language**: Python 3. The package lives under `src/pki_parser` and is
  installable with `pip install -e .` once dependencies (see `pyproject.toml`)
  are installed.

- **Core logic**: `parser.py` contains `X509Parser`, a lightweight wrapper
  around `cryptography.x509`. It loads PEM or DER data and exposes
  `get_info()` returning a `dict` of fields. Helper methods convert names and
  extensions to serializable dictionaries.

- **CLI**: `cli.py` provides a command‑line entry point (`pki-parser` after
  installation). It reads a file, imports and invokes `X509Parser` (with a runtime check
  that the `cryptography` package is installed) and prints a
  **single horizontal Markdown table** (fields as columns, one row per
  certificate) containing only the required certificate
  attributes (subject and issuer DN collapsed into strings, with
  `countryName`→`C`, `organizationName`→`O` and `commonName`→`C` before
  collapsing, serial number,
  key algorithm, key size, digest algorithm, separate `not_before` and
  `not_after` date columns, subject key identifier and SHA‑256 fingerprint).
  Columns are emitted in this precise sequence: subject, issuer, serial_number,
  key_algorithm, key_size, digest_algorithm, not_before, not_after,
  subject_key_identifier, sha256_fingerprint. Unneeded extensions or other metadata
  are omitted. The CLI is a simple Python script and is tested by calling
  `main()` from tests.

- **Tests**: `tests/` contains pytest tests. A small PEM fixture is under
  `tests/fixtures/test_cert.pem`. Tests exercise both the parser and CLI.

## Developer Workflows

- **Environment setup**:
  ```bash
  python -m venv venv
  source venv/bin/activate
  pip install -e .[test]
  ```
  `cryptography` is the only runtime dependency; `pytest` is used for tests.

- **Running tests**: `pytest` from project root. The CI (not yet configured)
  would run the same.

- **Installing CLI**: after `pip install -e .`, the `pki-parser` command becomes
  available. Example: `pki-parser /path/to/cert.pem > out.json`.

- **Adding features**: pick new methods in `X509Parser`, update tests and CLI
  accordingly. There are no complex build steps or generated code.

## Conventions & Patterns

- The project uses **explicit relative imports** (e.g. `from .parser import
  X509Parser`) and follows a standard `src/` layout.

- Errors are handled minimally; CLI prints to stderr and returns exit codes.
  Library code may raise exceptions (tests may assert on them).

- **Serialization**: any value returned by `X509Parser.get_info()` should be
  JSON serializable; helper methods like `_name_to_dict` and `_extensions_to_dict`
  are the reference patterns for conversion.

- **Extensibility**: new extensions or fields should be added by pattern-matching
  on cryptography types; look at `_extension_value` for examples.

## External Dependencies & Integration

- **cryptography**: used for all certificate parsing. The CLI/ parser
  will raise a clear runtime error if this package is missing; ensure it is
  listed in `pyproject.toml` and installed via the development instructions.
  Review its docs when adding support for additional extension types.

- No network, no database, no other services. The parser only operates on
  provided file bytes.

- There are no CI configuration files yet; keep changes localized and tests
  lightweight.

## Notes for AI Agents

- The repo is intentionally minimal; don’t over-engineer. Aim for clarity and
  readability.

- There’s no existing `.github/copilot-instructions.md`; this file will be the
  go-to reference for future AI edits.

- When adding code, replicate existing style: small functions, clear names,
  and simple control flow. Refer to `tests/test_parser.py` for how to exercise
  functionality.

> After making changes, run `pytest` locally to ensure the basic parser still
> works.

Let me know if any part of the codebase seems unclear or if you need more
examples to complete your task.