
import os
import time
import requests

from dotenv import load_dotenv
from etl.logger import logger
from etl.models import ThreatRecord

load_dotenv()

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/urls/recent/"


def fetch_urlhaus_records(max_attempts=3):

    api_key = os.getenv("URLHAUS_AUTH_KEY")

    if not api_key:
        logger.error("URLhaus API key is missing.")
        return []

    headers = {"Auth-Key": api_key}
    normalized_records = []

    for attempt in range(1, max_attempts + 1):

        try:
            logger.info(
                "Fetching URLhaus records. Attempt %s/%s",
                attempt,
                max_attempts
            )

            response = requests.get(
                URLHAUS_API,
                headers=headers,
                timeout=20
            )

            response.raise_for_status()
            data = response.json()

            if not isinstance(data, dict):
                raise ValueError("Invalid API response structure.")

            if data.get("query_status") != "ok":
                raise ValueError(
                    f"URLhaus query status: {data.get('query_status')}"
                )

            records = data.get("urls")

            if not isinstance(records, list):
                raise ValueError("URLhaus records must be a list.")

            for record in records:

                if not isinstance(record, dict):
                    continue

                url = record.get("url")
                threat = record.get("threat")
                date_added = record.get("date_added")

                if not url or not threat:
                    continue

                normalized = {
                    "indicator": url,
                    "indicator_type": "url",
                    "threat_type": threat,
                    "source": "URLhaus",
                    "first_seen": date_added,
                    "url_status": record.get("url_status"),
                    "host": record.get("host"),
                    "tags": record.get("tags"),
                    "reporter": record.get("reporter"),
                    "urlhaus_reference": record.get(
                        "urlhaus_reference"
                    )
                }

                try:
                    validated = ThreatRecord.model_validate(normalized)

                    normalized_records.append(
                        validated.model_dump(mode="json")
                    )

                except Exception as error:
                    logger.warning(
                        "Skipping invalid URLhaus record: %s",
                        error
                    )

            logger.info(
                "URLhaus records successfully normalized: %s",
                len(normalized_records)
            )

            return normalized_records

        except (requests.RequestException, ValueError) as error:

            logger.error("URLhaus extraction failed: %s", error)

            if attempt < max_attempts:
                wait_time = 2 ** attempt
                logger.warning("Retrying in %s seconds.", wait_time)
                time.sleep(wait_time)

    logger.error("URLhaus extraction failed after all attempts.")
    return []


if __name__ == "__main__":

    records = fetch_urlhaus_records()

    print("URLhaus records:", len(records))

    if records:
        print("First record:")
        print(records[0])
