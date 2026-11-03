
import time
from pathlib import Path

from etl.logger import logger
from etl.extract import extract_urls
from etl.validate import validate_records
from etl.clean import clean_data
from etl.database import store_data


def run_pipeline():

    start_time = time.perf_counter()

    logger.info("=" * 50)
    logger.info("CYBER THREAT INTELLIGENCE ETL PIPELINE STARTED")
    logger.info("=" * 50)

    raw_file = Path("data/raw/recent_urls.json")
    database_file = Path("data/database/threat_intel.db")

    try:

        # STEP 1: Extract data
        logger.info("STEP 1: Starting data extraction.")

        extraction_success = extract_urls()

        if extraction_success:
            logger.info("Fresh data extraction completed successfully.")

        elif raw_file.exists():
            logger.warning(
                "API extraction failed. Using previously saved raw data."
            )

        else:
            logger.error(
                "Extraction failed and no previous raw data is available."
            )
            return False

        # STEP 2: Validate data
        logger.info("STEP 2: Starting data validation.")

        validation_success = validate_records()

        if not validation_success:
            logger.error("Validation failed. Pipeline stopped.")
            return False

        logger.info("Validation stage completed successfully.")

        # STEP 3: Clean data
        logger.info("STEP 3: Starting data cleaning.")

        cleaning_success = clean_data()

        if not cleaning_success:
            logger.error("Data cleaning failed. Pipeline stopped.")
            return False

        logger.info("Cleaning stage completed successfully.")

        # STEP 4: Store data
        logger.info("STEP 4: Starting database storage.")

        storage_success = store_data()

        if not storage_success:
            logger.error("Database storage failed. Pipeline stopped.")
            return False

        logger.info("Database storage stage completed successfully.")

        # Verify database file
        if not database_file.exists():
            logger.error("Database file not found after storage.")
            return False

        # Calculate processing time
        end_time = time.perf_counter()
        duration = end_time - start_time

        logger.info("=" * 50)
        logger.info("ETL PIPELINE COMPLETED SUCCESSFULLY.")
        logger.info("Total processing time: %.2f seconds", duration)
        logger.info("Database: %s", database_file)
        logger.info("=" * 50)

        return True

    except Exception as error:

        logger.exception("ETL pipeline failed: %s", error)
        return False

    finally:

        logger.info("ETL pipeline execution finished.")


if __name__ == "__main__":
    success = run_pipeline()

    if success:
        print("\nETL Pipeline Result: SUCCESS")
    else:
        print("\nETL Pipeline Result: FAILED")
