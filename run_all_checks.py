"""run_all_checks.py - Runs the file check and the whole pytest suite, then summarises."""
import subprocess
import sys

STEPS = [
    ("Environment", [sys.executable, "check_setup.py"], ("All checks passed",)),
    ("File layout", [sys.executable, "check_files.py"], ("All files are in place",)),
    ("Test suite", [sys.executable, "-m", "pytest"], (" passed",)),
]

summary = []
for name, command, markers in STEPS:
    result = subprocess.run(command, capture_output=True, text=True, timeout=900)
    output = result.stdout + result.stderr
    ok = (result.returncode == 0 and any(m in output for m in markers)
          and "[FAIL]" not in output and "[MISSING]" not in output and "failed" not in output)
    summary.append((name, "PASS" if ok else "FAIL"))
    if not ok:
        print(f"\n----- {name}: output -----\n{output[-2500:]}")

print("\n=== Summary ===")
for name, status in summary:
    print(f"  {status:<6} {name}")
bad = [n for n, s in summary if s != "PASS"]
print("\nEverything passed." if not bad else f"\nNeeds attention: {', '.join(bad)}")
