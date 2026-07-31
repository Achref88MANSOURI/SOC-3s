#!/usr/bin/env bash
# Run this first, before touching any real service. Everything here is
# local — no network calls, no API keys required.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== 1/4  syntax check (every .py file parses) =="
python3 -c "
import ast, pathlib, sys
errors = []
for p in pathlib.Path('.').rglob('*.py'):
    if '__pycache__' in str(p):
        continue
    try:
        ast.parse(p.read_text(), filename=str(p))
    except SyntaxError as e:
        errors.append((str(p), str(e)))
if errors:
    for f, e in errors:
        print(f'SYNTAX ERROR in {f}: {e}')
    sys.exit(1)
print('OK — all files parse')
"

echo
echo "== 2/4  install dependencies =="
pip install --break-system-packages -q -r requirements.txt -r requirements-dev.txt

echo
echo "== 3/4  run unit tests (mocked Redis/TheHive, no real infra needed) =="
python3 -m pytest -q

echo
echo "== 4/4  import every module + confirm graph compiles + FastAPI routes exist =="
python3 -c "
import main
routes = [r.path for r in main.app.routes]
assert '/health' in routes and '/triage' in routes, 'expected routes missing'
print('OK — main.py imports, graph compiles, routes registered:', routes)
"

echo
echo "All static/local checks passed."
echo "Next: fill in .env, then run ./scripts/smoke_test.sh against a live server."