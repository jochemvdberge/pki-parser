#!/usr/bin/env python3
"""Commit and push changes for PR."""
import subprocess
import sys

def run(cmd, description):
    """Run command and report results."""
    print(f"\n{description}...")
    proc = subprocess.run(cmd, capture_output=True, text=True, shell=isinstance(cmd, str))
    print(proc.stdout)
    if proc.returncode != 0:
        print(f"Error: {proc.stderr}", file=sys.stderr)
        return False
    return True

# Stage all changes
if not run(['git', 'add', '-A'], "Staging changes"):
    sys.exit(1)

# Show what we're committing
run(['git', 'status', '--short'], "Changes to commit")

# Create commit
commit_msg = """Implement certificate display formatting updates

- Change commonName abbr: 'C' → 'CN' for clarity
- Format serial_number with colon separators (e.g. 67:d3:b0:43)
- Display sha256_fingerprint in uppercase

Also regenerate test fixture with valid certificate.
"""

if not run(['git', 'commit', '-m', commit_msg], "Creating commit"):
    sys.exit(1)

# Create feature branch and push
branch_name = "feature/certificate-display-formats"
if not run(f"git checkout -b {branch_name}", f"Creating branch {branch_name}"):
    pass  # May already exist

if not run(['git', 'push', '-u', 'origin', 'HEAD'], "Pushing to origin"):
    sys.exit(1)

print("\n✅ Changes committed and pushed!")
print(f"   Branch: {branch_name}")
print(f"   Next: Open PR on GitHub")
