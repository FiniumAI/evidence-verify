"""Root conftest: make ``tests/`` helpers and the package importable whether
the suite runs via unittest discovery from the repo root or via pytest.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
