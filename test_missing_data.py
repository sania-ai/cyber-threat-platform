from pathlib import Path
from unittest.mock import patch
from etl.pipeline import run_pipeline

original_exists = Path.exists

def simulated_exists(path):
    if str(path).replace("\\", "/") == "data/raw/recent_urls.json":
        return False
    return original_exists(path)

print("Testing pipeline when API and saved raw data are unavailable...")

with patch("etl.pipeline.extract_urls", return_value=False):
    with patch.object(Path, "exists", simulated_exists):
        result = run_pipeline()

if result is False:
    print("TEST PASSED: Pipeline stopped safely because no raw data was available.")
else:
    print("TEST FAILED: Unexpected pipeline result.")