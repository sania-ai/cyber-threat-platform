
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from etl.risk.scoring import calculate_risk

DB_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "database"
    / "threat_intel.db"
)


def update_risk_scores():
    connection = sqlite3.connect(DB_PATH)

    try:
        cursor = connection.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS risk_scores (
                threat_record_id INTEGER PRIMARY KEY,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                category_score INTEGER,
                confidence_score INTEGER,
                freshness_score INTEGER,
                evidence_score INTEGER,
                calculated_at TEXT NOT NULL,
                FOREIGN KEY (threat_record_id)
                    REFERENCES threat_records(id)
            )
        """)

        cursor.execute("""
            SELECT id, threat_type, first_seen,
                   confidence, metadata_json
            FROM threat_records
        """)

        records = cursor.fetchall()
        updated = 0

        for record_id, threat_type, first_seen, confidence, metadata_json in records:
            try:
                metadata = json.loads(metadata_json) if metadata_json else {}
            except (json.JSONDecodeError, TypeError):
                metadata = {}

            risk_input = {
                "threat_type": threat_type,
                "first_seen": first_seen,
                "confidence": confidence,
                "metadata": metadata
            }

            result = calculate_risk(risk_input)

            cursor.execute("""
                INSERT OR REPLACE INTO risk_scores (
                    threat_record_id, risk_score, risk_level,
                    category_score, confidence_score,
                    freshness_score, evidence_score, calculated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                record_id,
                result["risk_score"],
                result["risk_level"],
                result["category_score"],
                result["confidence_score"],
                result["freshness_score"],
                result["evidence_score"],
                datetime.now(timezone.utc).isoformat()
            ))

            updated += 1

        connection.commit()
        print("Risk scores updated:", updated)

        print("Risk-level summary:")
        for row in cursor.execute("""
            SELECT risk_level, COUNT(*)
            FROM risk_scores
            GROUP BY risk_level
        """):
            print(row)

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


if __name__ == "__main__":
    update_risk_scores()
