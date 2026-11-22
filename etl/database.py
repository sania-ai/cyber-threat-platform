
import sqlite3
import json
import pandas as pd

from pathlib import Path
from datetime import datetime, timezone

from etl.logger import logger


DATABASE_FILE = Path("data/database/threat_intel.db")


# ============================================================
# ORIGINAL URLHAUS DATABASE STORAGE
# This function is preserved for the existing dashboard.
# ============================================================

def store_data():

    logger.info("Starting database storage.")

    input_file = Path("data/processed/cleaned_urls.csv")
    database_folder = Path("data/database")

    database_folder.mkdir(parents=True, exist_ok=True)

    database_file = database_folder / "threat_intel.db"

    if not input_file.exists():
        logger.error("Cleaned CSV file not found: %s", input_file)
        return False

    connection = None

    try:
        df = pd.read_csv(input_file)

        if df.empty:
            logger.warning("No records available to store.")
            return False

        required_columns = [
            "url",
            "host",
            "url_status",
            "date_added"
        ]

        missing_columns = [
            column for column in required_columns
            if column not in df.columns
        ]

        if missing_columns:
            logger.error(
                "Required database columns are missing: %s",
                missing_columns
            )
            return False

        logger.info("Records received: %s", len(df))

        connection = sqlite3.connect(database_file)

        df.head(0).to_sql(
            "urlhaus_urls",
            connection,
            if_exists="append",
            index=False
        )

        connection.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_url
            ON urlhaus_urls(url)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_urlhaus_host
            ON urlhaus_urls(host)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_urlhaus_status
            ON urlhaus_urls(url_status)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_urlhaus_date_added
            ON urlhaus_urls(date_added)
        """)

        logger.info("Database indexes checked successfully.")

        df = df.astype(object).where(pd.notna(df), None)

        columns = list(df.columns)

        column_names = ", ".join(
            '"' + column.replace('"', '""') + '"'
            for column in columns
        )

        placeholders = ", ".join(["?"] * len(columns))

        query = f"""
            INSERT OR IGNORE INTO urlhaus_urls
            ({column_names})
            VALUES ({placeholders})
        """

        cursor = connection.cursor()

        cursor.executemany(
            query,
            df.itertuples(index=False, name=None)
        )

        inserted_records = cursor.rowcount
        ignored_records = len(df) - inserted_records

        connection.commit()

        cursor.execute("SELECT COUNT(*) FROM urlhaus_urls")
        total_records = cursor.fetchone()[0]

        logger.info("Database storage completed successfully.")
        logger.info("New records inserted: %s", inserted_records)
        logger.info("Duplicate records ignored: %s", ignored_records)
        logger.info("Total database records: %s", total_records)
        logger.info("Database location: %s", database_file)

        return True

    except (sqlite3.Error, OSError, pd.errors.ParserError, ValueError) as error:

        if connection:
            connection.rollback()

        logger.exception("Database storage failed: %s", error)
        return False

    except Exception as error:

        if connection:
            connection.rollback()

        logger.exception("Unexpected database error: %s", error)
        return False

    finally:
        if connection:
            connection.close()


# ============================================================
# NEW MULTI-SOURCE THREAT INTELLIGENCE DATABASE
# ============================================================

def store_normalized_records(records):

    logger.info("Starting normalized threat-record storage.")

    if not records:
        logger.warning("No normalized threat records received.")
        return False

    DATABASE_FILE.parent.mkdir(parents=True, exist_ok=True)

    connection = None

    try:
        connection = sqlite3.connect(DATABASE_FILE)

        cursor = connection.cursor()

        # Create a separate table without modifying urlhaus_urls.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_records (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                indicator TEXT NOT NULL,

                indicator_type TEXT NOT NULL,

                threat_type TEXT NOT NULL,

                source TEXT NOT NULL,

                first_seen TEXT,

                last_seen TEXT,

                confidence INTEGER,

                metadata_json TEXT,

                ingested_at TEXT NOT NULL,

                UNIQUE(source, indicator, threat_type)
            )
        """)

        # Indexes for faster searching and filtering.
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_threat_indicator
            ON threat_records(indicator)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_threat_type
            ON threat_records(threat_type)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_threat_source
            ON threat_records(source)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_threat_indicator_type
            ON threat_records(indicator_type)
        """)

        logger.info("Threat-record indexes checked successfully.")

        inserted_records = 0
        ignored_records = 0

        for record in records:

            if hasattr(record, "model_dump"):
                record = record.model_dump(mode="json")

            if not isinstance(record, dict):
                ignored_records += 1
                continue

            required_fields = [
                "indicator",
                "indicator_type",
                "threat_type",
                "source"
            ]

            if any(
                not record.get(field)
                for field in required_fields
            ):
                ignored_records += 1
                continue

            known_fields = {
                "indicator",
                "indicator_type",
                "threat_type",
                "source",
                "first_seen",
                "last_seen",
                "confidence"
            }

            metadata = {
                key: value
                for key, value in record.items()
                if key not in known_fields
            }

            cursor.execute("""
                INSERT OR IGNORE INTO threat_records (
                    indicator,
                    indicator_type,
                    threat_type,
                    source,
                    first_seen,
                    last_seen,
                    confidence,
                    metadata_json,
                    ingested_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                record["indicator"],
                record["indicator_type"],
                record["threat_type"],
                record["source"],
                record.get("first_seen"),
                record.get("last_seen"),
                record.get("confidence"),
                json.dumps(metadata, default=str),
                datetime.now(timezone.utc).isoformat()
            ))

            if cursor.rowcount > 0:
                inserted_records += 1
            else:
                ignored_records += 1

        connection.commit()

        cursor.execute("""
            SELECT COUNT(*) FROM threat_records
        """)

        total_records = cursor.fetchone()[0]

        logger.info("Normalized threat storage completed.")
        logger.info("New records inserted: %s", inserted_records)
        logger.info("Duplicate/invalid records ignored: %s", ignored_records)
        logger.info("Total normalized records: %s", total_records)

        return True

    except (sqlite3.Error, OSError, ValueError, TypeError) as error:

        if connection:
            connection.rollback()

        logger.exception(
            "Normalized threat storage failed: %s",
            error
        )

        return False

    except Exception as error:

        if connection:
            connection.rollback()

        logger.exception(
            "Unexpected normalized storage error: %s",
            error
        )

        return False

    finally:

        if connection:
            connection.close()


if __name__ == "__main__":
    store_data()
