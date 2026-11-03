
import json
from pathlib import Path
from pydantic import BaseModel, ConfigDict, ValidationError
from etl.logger import logger


class URLRecord(BaseModel):

    # Allow additional URLhaus fields
    model_config = ConfigDict(extra="allow")

    # Every valid record must have a URL string
    url: str


def validate_records():

    logger.info("Starting data validation.")

    input_file = Path("data/raw/recent_urls.json")
    output_folder = Path("data/processed")

    output_file = output_folder / "validated_urls.json"
    temporary_file = output_folder / "validated_urls.tmp"

    output_folder.mkdir(parents=True, exist_ok=True)

    if not input_file.exists():
        logger.error("Extracted JSON file not found: %s", input_file)
        return False

    try:
        # Read extracted JSON data
        with open(input_file, "r", encoding="utf-8") as file:
            data = json.load(file)

        # Check JSON structure
        if not isinstance(data, dict):
            logger.error("Invalid JSON structure: expected a dictionary.")
            return False

        records = data.get("urls")

        if not isinstance(records, list):
            logger.error("Invalid API data: URLs must be a list.")
            return False

        valid_records = []
        invalid_count = 0

        logger.info("Total records received: %s", len(records))

        # Validate each record
        for record in records:

            try:
                validated = URLRecord.model_validate(record)

                valid_records.append(
                    validated.model_dump(mode="json")
                )

            except ValidationError:
                invalid_count += 1

        # Do not save an empty result
        if records and not valid_records:
            logger.error("No valid records found. Validation failed.")
            return False

        # Save to temporary file first
        with open(temporary_file, "w", encoding="utf-8") as file:
            json.dump(valid_records, file, indent=4)

        # Replace previous output after successful saving
        temporary_file.replace(output_file)

        logger.info("Validation completed successfully.")
        logger.info("Total records: %s", len(records))
        logger.info("Valid records: %s", len(valid_records))
        logger.info("Invalid records: %s", invalid_count)
        logger.info("Validated data saved to: %s", output_file)

        return True

    except (OSError, json.JSONDecodeError) as error:

        logger.exception("Validation file error: %s", error)
        return False

    except Exception as error:

        logger.exception("Unexpected validation error: %s", error)
        return False

    finally:
        if temporary_file.exists():
            try:
                temporary_file.unlink()
            except OSError:
                logger.warning("Could not remove validation temporary file.")


if __name__ == "__main__":
    validate_records()
