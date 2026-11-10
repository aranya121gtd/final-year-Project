"""
Quick sanity check — run this BEFORE app.py if you're not sure everything is in place.

Usage:
    python check_setup.py
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ARTIFACT_DIR = os.path.join(HERE, "artifacts")

REQUIRED_FILES = [
    "spam_agent.joblib",
    "spam_vectorizer.joblib",
    "packet_agent.joblib",
    "session_agent.joblib",
    "coordinator_config.joblib",
]

print(f"Project folder : {HERE}")
print(f"Looking for    : {ARTIFACT_DIR}")
print()

ok = True

if not os.path.isdir(ARTIFACT_DIR):
    print(f"[MISSING] No 'artifacts' folder found next to app.py.")
    print(f"          Create it and put the 5 .joblib files inside:")
    print(f"          {ARTIFACT_DIR}")
    ok = False
else:
    print("[OK] 'artifacts' folder found.")
    for fname in REQUIRED_FILES:
        fpath = os.path.join(ARTIFACT_DIR, fname)
        if os.path.isfile(fpath):
            size_kb = os.path.getsize(fpath) / 1024
            print(f"  [OK]      {fname}  ({size_kb:.1f} KB)")
        else:
            print(f"  [MISSING] {fname}")
            ok = False

print()

if not ok:
    print("Result: NOT READY. Fix the missing item(s) above, then re-run this script.")
    sys.exit(1)

# Try actually loading them, in case a file is corrupted / wrong version
try:
    import joblib
    for fname in REQUIRED_FILES:
        joblib.load(os.path.join(ARTIFACT_DIR, fname))
    print("Result: READY. All artifacts found and load correctly.")
    print("You can now run: uvicorn app:app --reload")
except ImportError:
    print("Result: Folder layout is correct, but 'joblib' isn't installed yet.")
    print("Run: pip install -r requirements.txt")
    sys.exit(1)
except Exception as e:
    print(f"Result: NOT READY. A file exists but failed to load: {e}")
    sys.exit(1)
