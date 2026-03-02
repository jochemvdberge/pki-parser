#!/usr/bin/env python3
import subprocess
import os

os.chdir('/workspaces/pki-parser')

# Show status
print("=== Git Status ===")
result = subprocess.run(['git', 'status', '--short'], capture_output=True, text=True)
print(result.stdout)

# Stage all
print("\n=== Staging Changes ===")
result = subprocess.run(['git', 'add', '-A'], capture_output=True, text=True)
if result.returncode != 0:
    print(f"Error: {result.stderr}")
else:
    print("All changes staged")

# Check git config
print("\n=== Git Config ===")
subprocess.run(['git', 'config', 'user.name'])
subprocess.run(['git', 'config', 'user.email'])

# Commit
print("\n=== Creating Commit ===")
msg = """Implement certificate display formatting updates

- Change commonName abbr: 'C' → 'CN' for clarity
- Format serial_number with colon separators (e.g. 67:d3:b0:43)
- Display sha256_fingerprint in uppercase

Also regenerate test fixture with valid certificate."""

result = subprocess.run(['git', 'commit', '-m', msg], capture_output=True, text=True)
print(result.stdout)
if result.returncode != 0:
    print(f"Error: {result.stderr}")

# Create branch
print("\n=== Creating Branch ===")
branch = 'feature/certificate-display-formats'
result = subprocess.run(['git', 'checkout', '-b', branch], capture_output=True, text=True)
if 'already exists' in result.stderr:
    print(f"Branch {branch} already exists")
    result = subprocess.run(['git', 'checkout', branch], capture_output=True, text=True)
print(result.stdout or result.stderr)

# Push
print("\n=== Pushing to Origin ===")
result = subprocess.run(['git', 'push', '-u', 'origin', 'HEAD'], capture_output=True, text=True)
print(result.stdout)
if result.returncode != 0:
    print(f"Error: {result.stderr}")
else:
    print(f"✅ Pushed to {branch}")
