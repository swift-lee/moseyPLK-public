"""Host paths; all local build inputs and outputs live in the ignored work area."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / 'moseyPLK-assets'
BUILD_ROOT = ASSETS / 'build'
DIST = ASSETS / 'dist'
