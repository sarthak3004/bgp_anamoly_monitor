from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

ALERTS_LOG = str(DATA_DIR / "alerts.csv")
INVENTORY_FILE = str(DATA_DIR / "inventory.csv")
MRT_FILE = str(DATA_DIR / "updates.20261001.0000.bz2")
MRT_FILE_ALIGNED = MRT_FILE
MRT_FILE_DRIFTED = str(DATA_DIR / "updates.20261101.0000.bz2")
OUTPUT_CSV = str(DATA_DIR / "inventory.csv")
RESULTS_CSV = str(DATA_DIR / "synthetic_eval_results.csv")
ROA_PATTERN = str(DATA_DIR / "roas/roas_*.csv")
ROGUE_ASN = "66600"
SIMULATING_ASN = "64512"
MIN_PREFIXES = 15
MAX_PREFIXES = 50
UNROA_COUNT = 2