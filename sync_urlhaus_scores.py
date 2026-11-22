import sqlite3
import json
from pathlib import Path
from datetime import datetime, timezone

from etl.risk.scoring import calculate_risk

DB_PATH = Path("data/database/threat_intel.db")


def sync_urlhaus_scores():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    try:
        cur = conn.cursor()

        cur.execute("SELECT * FROM urlhaus_urls")
        urls = cur.fetchall()

        inserted = 0
        scored = 0

        for row in urls:
            data = dict(row)

            indicator = data.get("url")
            threat_type = data.get("threat") or "malware_download"

            metadata = {
                "urlhaus_reference": data.get("urlhaus_reference"),
                "url_status": data.get("url_status"),
                "host": data.get("host"),
                "tags": data.get("tags"),
                "reporter": data.get("reporter"),
                "blacklists": data.get("blacklists"),
                "larted": data.get("larted"),
            }

            first_seen = data.get("date_added")

            cur.execute("""
                INSERT OR IGNORE INTO threat_records (
                    indicator,
                    indicator_type,
                    threat_type,
                    source,
                    first_seen,
                    confidence,
                    metadata_json,
                    ingested_at
                )
                VALUES (?, 'url', ?, 'URLhaus', ?, NULL, ?, ?)
            """, (
                indicator,
                threat_type,
                first_seen,
                json.dumps(metadata),
                datetime.now(timezone.utc).isoformat()
            ))

            cur.execute("""
                SELECT id
                FROM threat_records
                WHERE source = 'URLhaus'
                  AND indicator = ?
                  AND threat_type = ?
            """, (indicator, threat_type))

            result = cur.fetchone()

            if not result:
                continue

            record_id = result["id"]

            risk_input = {
                "threat_type": threat_type,
                "first_seen": first_seen,
                "confidence": None,
                "metadata": metadata
            }

            score = calculate_risk(risk_input)

            cur.execute("""
                INSERT OR REPLACE INTO risk_scores (
                    threat_record_id,
                    risk_score,
                    risk_level,
                    category_score,
                    confidence_score,
                    freshness_score,
                    evidence_score,
                    calculated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                record_id,
                score["risk_score"],
                score["risk_level"],
                score["category_score"],
                score["confidence_score"],
                score["freshness_score"],
                score["evidence_score"],
                datetime.now(timezone.utc).isoformat()
            ))

            inserted += 1
            scored += 1

        conn.commit()

        print("URLhaus records processed:", inserted)
        print("Risk scores generated:", scored)

        print("\nRisk level summary:")
        for row in cur.execute("""
            SELECT risk_level, COUNT(*)
            FROM risk_scores
            GROUP BY risk_level
        """):
            print(row)

    except Exception as error:
        conn.rollback()
        raise error

    finally:
        conn.close()


if __name__ == "__main__":
    sync_urlhaus_scores()