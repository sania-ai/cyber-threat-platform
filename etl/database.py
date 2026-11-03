
import sqlite3
import pandas as pd
from pathlib import Path
from etl.logger import logger


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
        # Read cleaned CSV data
        df = pd.read_csv(input_file)

        if df.empty:
            logger.warning("No records available to store.")
            return False

        # Check required columns used by the dashboard
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

        # Connect to SQLite database
        connection = sqlite3.connect(database_file)

        # Create table if it does not exist
        df.head(0).to_sql(
            "urlhaus_urls",
            connection,
            if_exists="append",
            index=False
        )

        # Create a unique index to prevent duplicate URLs
        connection.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_url
            ON urlhaus_urls(url)
        """)

        # Create indexes to improve dashboard query performance
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

        # Replace Pandas missing values with Python None
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

        # Insert records and ignore duplicate URLs
        cursor.executemany(
            query,
            df.itertuples(index=False, name=None)
        )

        inserted_records = cursor.rowcount
        ignored_records = len(df) - inserted_records

        # Commit database changes
        connection.commit()

        # Count total database records
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


if __name__ == "__main__":
    store_data()
