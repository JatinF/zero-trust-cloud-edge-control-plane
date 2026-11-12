"""Reject PEM private keys committed in the tree.

The marker is assembled so this file does not match itself.
"""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SKIP = {".git", "bin", "tools"}
MARKERS = [
    "-----BEGIN " + "PRIVATE KEY-----",
    "-----BEGIN " + "RSA PRIVATE KEY-----",
    "-----BEGIN " + "EC PRIVATE KEY-----",
    "-----BEGIN " + "OPENSSH PRIVATE KEY-----",
]


def main() -> int:
    found = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for marker in MARKERS:
            if marker in text:
                found.append(str(path.relative_to(ROOT)))
                break
    if found:
        print("private key material found:")
        for item in found:
            print(item)
        return 1
    print("no private key markers")
    return 0


if __name__ == "__main__":
    sys.exit(main())
