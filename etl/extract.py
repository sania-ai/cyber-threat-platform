
import os
import json
import time
import requests
from pathlib import Path
from dotenv import load_dotenv
from etl.logger import logger

# Load environment variables
load_dotenv()


def extract_urls():

    logger.info("Starting URLhaus data extraction.")

    api_key = os.getenv("URLHAUS_AUTH_KEY")

    if not api_key:
        logger.error("API key not found. Check your .env file.")
        return False

    url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"

    headers = {
        "Auth-Key": api_key
    }

    max_attempts = 3

    output_folder = Path("data/raw")
    output_file = output_folder / "recent_urls.json"
    temporary_file = output_folder / "recent_urls.tmp"

    for attempt in range(1, max_attempts + 1):

        try:
            logger.info(
                "Connecting to URLhaus API. Attempt %s/%s",
                attempt,
                max_attempts
            )

            response = requests.get(
                url,
                headers=headers,
                timeout=15
            )

            response.raise_for_status()

            data = response.json()

            # Validate API response structure
            if not isinstance(data, dict):
                logger.error("API returned an invalid JSON structure.")
                return False

            if data.get("query_status") != "ok":
                logger.error("API did not return a successful query.")
                return False

            records = data.get("urls", [])

            if not isinstance(records, list):
                logger.error("API returned an invalid records format.")
                return False

            # Create raw data folder
            output_folder.mkdir(parents=True, exist_ok=True)

            # Save to a temporary file first
            with open(temporary_file, "w", encoding="utf-8") as file:
                json.dump(data, file, indent=4)

            # Replace old file only after successful saving
            temporary_file.replace(output_file)

            logger.info("Extraction successful!")
            logger.info("Records extracted: %s", len(records))
            logger.info("Data saved to: %s", output_file)

            return True

        except requests.RequestException as error:

            logger.error("API request failed: %s", error)

            if attempt < max_attempts:

                wait_time = 2 ** attempt

                logger.warning(
                    "Retrying in %s seconds...",
                    wait_time
                )

                time.sleep(wait_time)

            else:
                logger.error("All API attempts failed.")

        except (ValueError, OSError) as error:

            logger.exception(
                "Data processing or saving failed: %s",
                error
            )

            return False

        finally:
            # Remove incomplete temporary files
            if temporary_file.exists():
                try:
                    temporary_file.unlink()
                except OSError:
                    logger.warning("Could not remove temporary file.")

    logger.info("URLhaus extraction process finished.")

    return False


if __name__ == "__main__":
    extract_urls()
