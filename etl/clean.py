
import json
import pandas as pd
from pathlib import Path
from etl.logger import logger


def clean_data():

    logger.info("Starting data cleaning.")

    input_file = Path("data/processed/validated_urls.json")
    output_folder = Path("data/processed")

    output_file = output_folder / "cleaned_urls.csv"
    temporary_file = output_folder / "cleaned_urls.tmp"

    output_folder.mkdir(parents=True, exist_ok=True)

    # Check whether validated data exists
    if not input_file.exists():
        logger.error("Validated data file not found: %s", input_file)
        return False

    try:
        # Load validated records
        with open(input_file, "r", encoding="utf-8") as file:
            records = json.load(file)

        if not isinstance(records, list):
            logger.error("Invalid data format. Expected a list of records.")
            return False

        if not records:
            logger.warning("No records available for cleaning.")
            return False

        # Convert records into a Pandas DataFrame
        df = pd.DataFrame(records)

        # Check required column
        if "url" not in df.columns:
            logger.error("Required URL column is missing.")
            return False

        original_count = len(df)

        logger.info("Original records: %s", original_count)

        # Remove duplicate URLs
        before_duplicates = len(df)
        df = df.drop_duplicates(subset=["url"])
        duplicates_removed = before_duplicates - len(df)

        # Remove missing URLs
        before_missing = len(df)
        df = df.dropna(subset=["url"])
        missing_removed = before_missing - len(df)

        # Remove empty URLs
        df["url"] = df["url"].astype(str).str.strip()

        before_empty = len(df)
        df = df[df["url"] != ""]
        empty_removed = before_empty - len(df)

        # Check whether any records remain
        if df.empty:
            logger.error("No valid records remain after cleaning.")
            return False

        # Clean text columns
        text_columns = df.select_dtypes(
            include=["object", "str"]
        ).columns

        for column in text_columns:
            df[column] = df[column].apply(
                lambda value: value.strip()
                if isinstance(value, str)
                else value
            )

        # Convert date_added into proper date format
        if "date_added" in df.columns:
            df["date_added"] = pd.to_datetime(
                df["date_added"],
                errors="coerce",
                utc=True
            )

        # Calculate cleaning statistics
        clean_count = len(df)

        total_removed = (
            duplicates_removed
            + missing_removed
            + empty_removed
        )

        # Save cleaned records to temporary CSV
        df.to_csv(temporary_file, index=False)

        # Replace previous output after successful saving
        temporary_file.replace(output_file)

        # Log cleaning results
        logger.info("Data cleaning completed successfully.")
        logger.info("Original records: %s", original_count)
        logger.info("Clean records: %s", clean_count)
        logger.info("Duplicate URLs removed: %s", duplicates_removed)
        logger.info("Missing URLs removed: %s", missing_removed)
        logger.info("Empty URLs removed: %s", empty_removed)
        logger.info("Total records removed: %s", total_removed)

        logger.info(
            "Missing values per column:\n%s",
            df.isnull().sum().to_string()
        )

        logger.info("Cleaned data saved to: %s", output_file)

        return True

    except (OSError, json.JSONDecodeError, pd.errors.ParserError) as error:
        logger.exception("Data cleaning error: %s", error)
        return False

    except Exception as error:
        logger.exception("Unexpected cleaning error: %s", error)
        return False

    finally:
        if temporary_file.exists():
            try:
                temporary_file.unlink()
            except OSError:
                logger.warning("Could not remove cleaning temporary file.")


if __name__ == "__main__":
    clean_data()
