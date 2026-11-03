from unittest.mock import patch
from etl.pipeline import run_pipeline

print("Testing database connection failure...")

with patch("etl.pipeline.extract_urls", return_value=False):
    with patch(
        "etl.database.sqlite3.connect",
        side_effect=Exception("Simulated database connection failure")
    ):
        result = run_pipeline()

if result is False:
    print("TEST PASSED: Pipeline handled the database failure.")
else:
    print("TEST FAILED: Unexpected pipeline result.")