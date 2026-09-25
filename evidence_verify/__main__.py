"""CLI entry: python -m evidence_verify <pack.zip-or-dir> [--json]."""
import sys

from evidence_verify.verify import main

if __name__ == "__main__":
    sys.exit(main())
