from pathlib import Path
from unittest.mock import patch
from etl.pipeline import run_pipeline

raw_file = Path("data/raw/recent_urls.json")

if not raw_file.exists():
    print("TEST FAILED: Previous raw data file is missing.")
else:
    print("Testing pipeline with simulated API failure...")

    with patch("etl.pipeline.extract_urls", return_value=False):
        result = run_pipeline()

    if result:
        print("TEST PASSED: Pipeline successfully used saved data.")
    else:
        print("TEST FAILED: Pipeline could not continue.")