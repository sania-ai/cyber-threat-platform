
import ipaddress
import requests

from etl.logger import logger
from etl.models import ThreatRecord


FEODO_FEED_URL = (
    "https://feodotracker.abuse.ch/downloads/"
    "ipblocklist_recommended.txt"
)


def fetch_feodo_records():

    logger.info("Fetching Feodo Tracker records.")

    try:
        response = requests.get(
            FEODO_FEED_URL,
            timeout=20
        )
        response.raise_for_status()

        records = []

        for line in response.text.splitlines():

            line = line.strip()

            if not line or line.startswith("#"):
                continue

            try:
                ip = ipaddress.ip_address(line)

                record = ThreatRecord(
                    indicator=str(ip),
                    indicator_type=(
                        "ipv4" if ip.version == 4 else "ipv6"
                    ),
                    threat_type="botnet_c2",
                    source="Feodo Tracker"
                )

                records.append(
                    record.model_dump(mode="json")
                )

            except (ValueError, TypeError) as error:
                logger.warning(
                    "Skipping invalid Feodo record: %s",
                    error
                )

        logger.info(
            "Feodo records normalized: %s",
            len(records)
        )

        return records

    except requests.RequestException as error:

        logger.exception(
            "Feodo feed request failed: %s",
            error
        )

        return []
