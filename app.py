
import sqlite3
from pathlib import Path

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

# Resolve the database relative to this project file.
BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "data" / "database" / "threat_intel.db"


def get_database_connection():
    """Connect to SQLite and return rows as dictionaries."""
    connection = sqlite3.connect(DATABASE, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


def database_exists():
    return DATABASE.exists()


@app.route("/")
def home():
    return render_template("index.html")


# --------------------------------------------------
# Dashboard summary (original URLhaus statistics)
# --------------------------------------------------

@app.route("/api/summary")
def summary():
    if not database_exists():
        return jsonify({"error": "Database not found"}), 500

    connection = get_database_connection()

    try:
        total = connection.execute(
            "SELECT COUNT(*) FROM urlhaus_urls"
        ).fetchone()[0]

        online = connection.execute(
            "SELECT COUNT(*) FROM urlhaus_urls WHERE url_status = ?",
            ("online",)
        ).fetchone()[0]

        offline = connection.execute(
            "SELECT COUNT(*) FROM urlhaus_urls WHERE url_status = ?",
            ("offline",)
        ).fetchone()[0]

        hosts = connection.execute(
            "SELECT COUNT(DISTINCT host) FROM urlhaus_urls"
        ).fetchone()[0]

        return jsonify({
            "total_urls": total,
            "online_urls": online,
            "offline_urls": offline,
            "unique_hosts": hosts
        })

    except sqlite3.Error:
        app.logger.exception("Summary query failed")
        return jsonify({"error": "Database query failed"}), 500

    finally:
        connection.close()


# --------------------------------------------------
# Multi-source threat intelligence summary
# --------------------------------------------------

@app.route("/api/threat-summary")
def threat_summary():
    if not database_exists():
        return jsonify({"error": "Database not found"}), 500

    connection = get_database_connection()

    try:
        total = connection.execute(
            "SELECT COUNT(*) FROM threat_records"
        ).fetchone()[0]

        source_count = connection.execute(
            "SELECT COUNT(DISTINCT source) FROM threat_records"
        ).fetchone()[0]

        category_count = connection.execute(
            "SELECT COUNT(DISTINCT threat_type) FROM threat_records"
        ).fetchone()[0]

        risk_counts = connection.execute("""
            SELECT r.risk_level, COUNT(*) AS total
            FROM risk_scores r
            GROUP BY r.risk_level
        """).fetchall()

        return jsonify({
            "total_threat_records": total,
            "source_count": source_count,
            "category_count": category_count,
            "risk_distribution": {
                row["risk_level"]: row["total"]
                for row in risk_counts
            }
        })

    except sqlite3.Error:
        app.logger.exception("Threat summary query failed")
        return jsonify({"error": "Database query failed"}), 500

    finally:
        connection.close()


# --------------------------------------------------
# Threat intelligence sources
# --------------------------------------------------

@app.route("/api/sources")
def get_sources():
    connection = get_database_connection()

    try:
        rows = connection.execute("""
            SELECT
                t.source,
                COUNT(*) AS total_records
            FROM threat_records t
            GROUP BY t.source
            ORDER BY total_records DESC
        """).fetchall()

        return jsonify([
            {
                "source": row["source"],
                "total_records": row["total_records"]
            }
            for row in rows
        ])

    except sqlite3.Error:
        app.logger.exception("Source query failed")
        return jsonify({"error": "Database query failed"}), 500

    finally:
        connection.close()


# --------------------------------------------------
# Threat category statistics
# --------------------------------------------------

@app.route("/api/categories")
def get_categories():
    connection = get_database_connection()

    try:
        rows = connection.execute("""
            SELECT
                threat_type,
                COUNT(*) AS total_records
            FROM threat_records
            GROUP BY threat_type
            ORDER BY total_records DESC
        """).fetchall()

        return jsonify([
            {
                "threat_type": row["threat_type"],
                "total_records": row["total_records"]
            }
            for row in rows
        ])

    except sqlite3.Error:
        app.logger.exception("Category query failed")
        return jsonify({"error": "Database query failed"}), 500

    finally:
        connection.close()


# --------------------------------------------------
# URLhaus URL records (existing dashboard endpoint)
# --------------------------------------------------

@app.route("/api/urls")
def get_urls():
    if not database_exists():
        return jsonify({"error": "Database not found"}), 500

    search = request.args.get("search", "").strip()
    status_filter = request.args.get("status", "").strip()
    risk_filter = request.args.get("risk", "").strip()

    allowed_risks = ("", "High", "Medium", "Low", "Unclassified")

    if risk_filter not in allowed_risks:
        return jsonify({"error": "Invalid risk filter"}), 400

    try:
        page = max(1, int(request.args.get("page", 1)))
        per_page = min(
            100,
            max(1, int(request.args.get("per_page", 10))))
    except ValueError:
        return jsonify({"error": "Invalid pagination values"}), 400

    conditions = []
    parameters = []

    if search:
        conditions.append("(u.url LIKE ? OR u.host LIKE ?)")
        parameters.extend([f"%{search}%", f"%{search}%"])

    if status_filter in ("online", "offline"):
        conditions.append("u.url_status = ?")
        parameters.append(status_filter)

    # Risk is taken from the stored normalized score,
    # not from online/offline status.
    risk_expression = """
        COALESCE(
            (
                SELECT r.risk_level
                FROM threat_records t
                JOIN risk_scores r
                    ON r.threat_record_id = t.id
                WHERE t.source = 'URLhaus'
                  AND t.indicator = u.url
                ORDER BY r.calculated_at DESC
                LIMIT 1
            ),
            'Unclassified'
        )
    """

    if risk_filter:
        conditions.append(f"({risk_expression}) = ?")
        parameters.append(risk_filter)

    where_clause = (
        " WHERE " + " AND ".join(conditions)
        if conditions else ""
    )

    connection = get_database_connection()

    try:
        total = connection.execute(
            "SELECT COUNT(*) FROM urlhaus_urls u" + where_clause,
            parameters
        ).fetchone()[0]

        offset = (page - 1) * per_page

        rows = connection.execute("""
            SELECT
                u.url,
                u.host,
                u.url_status,
                u.threat,
                u.date_added,
                """ + risk_expression + """ AS risk_level,
                (
                    SELECT r.risk_score
                    FROM threat_records t
                    JOIN risk_scores r
                        ON r.threat_record_id = t.id
                    WHERE t.source = 'URLhaus'
                      AND t.indicator = u.url
                    ORDER BY r.calculated_at DESC
                    LIMIT 1
                ) AS risk_score
            FROM urlhaus_urls u
            """ + where_clause + """
            ORDER BY u.date_added DESC
            LIMIT ? OFFSET ?
        """, parameters + [per_page, offset]).fetchall()

        return jsonify({
            "records": [dict(row) for row in rows],
            "total_records": total,
            "current_page": page,
            "per_page": per_page,
            "total_pages": (total + per_page - 1) // per_page
        })

    except sqlite3.Error:
        app.logger.exception("URL records query failed")
        return jsonify({"error": "Database query failed"}), 500

    finally:
        connection.close()


# --------------------------------------------------
# Normalized threat intelligence records
# --------------------------------------------------

@app.route("/api/threat-records")
def get_threat_records():
    if not database_exists():
        return jsonify({"error": "Database not found"}), 500

    search = request.args.get("search", "").strip()
    source_filter = request.args.get("source", "").strip()
    category_filter = request.args.get("category", "").strip()
    risk_filter = request.args.get("risk", "").strip()

    allowed_risks = ("", "High", "Medium", "Low")

    if risk_filter not in allowed_risks:
        return jsonify({"error": "Invalid risk filter"}), 400

    try:
        page = max(1, int(request.args.get("page", 1)))
        per_page = min(
            100,
            max(1, int(request.args.get("per_page", 10))))
    except ValueError:
        return jsonify({"error": "Invalid pagination values"}), 400

    conditions = []
    parameters = []

    if search:
        conditions.append("t.indicator LIKE ?")
        parameters.append(f"%{search}%")

    if source_filter:
        conditions.append("t.source = ?")
        parameters.append(source_filter)

    if category_filter:
        conditions.append("t.threat_type = ?")
        parameters.append(category_filter)

    if risk_filter:
        conditions.append("r.risk_level = ?")
        parameters.append(risk_filter)

    where_clause = (
        " WHERE " + " AND ".join(conditions)
        if conditions else ""
    )

    connection = get_database_connection()

    try:
        total = connection.execute("""
            SELECT COUNT(*)
            FROM threat_records t
            LEFT JOIN risk_scores r
                ON r.threat_record_id = t.id
        """ + where_clause, parameters).fetchone()[0]

        offset = (page - 1) * per_page

        rows = connection.execute("""
            SELECT
                t.indicator,
                t.indicator_type,
                t.threat_type,
                t.source,
                t.first_seen,
                t.last_seen,
                t.confidence,
                r.risk_score,
                r.risk_level
            FROM threat_records t
            LEFT JOIN risk_scores r
                ON r.threat_record_id = t.id
        """ + where_clause + """
            ORDER BY r.risk_score DESC, t.first_seen DESC
            LIMIT ? OFFSET ?
        """, parameters + [per_page, offset]).fetchall()

        return jsonify({
            "records": [dict(row) for row in rows],
            "total_records": total,
            "current_page": page,
            "per_page": per_page,
            "total_pages": (total + per_page - 1) // per_page
        })

    except sqlite3.Error:
        app.logger.exception("Threat records query failed")
        return jsonify({"error": "Database query failed"}), 500

    finally:
        connection.close()


# --------------------------------------------------
# Top hosts (original dashboard)
# --------------------------------------------------

@app.route("/api/top-hosts")
def top_hosts():
    connection = get_database_connection()

    try:
        rows = connection.execute("""
            SELECT host, COUNT(*) AS total
            FROM urlhaus_urls
            GROUP BY host
            ORDER BY total DESC
            LIMIT 10
        """).fetchall()

        return jsonify([
            {"host": row["host"], "total": row["total"]}
            for row in rows
        ])

    except sqlite3.Error:
        app.logger.exception("Top hosts query failed")
        return jsonify({"error": "Database query failed"}), 500

    finally:
        connection.close()


# --------------------------------------------------
# Daily trends
# --------------------------------------------------

@app.route("/api/trends")
def get_trends():
    if not database_exists():
        return jsonify({"error": "Database not found"}), 500

    connection = get_database_connection()

    try:
        rows = connection.execute("""
            SELECT
                substr(date_added, 1, 10) AS date,
                COUNT(*) AS total
            FROM urlhaus_urls
            WHERE date_added IS NOT NULL
              AND date_added != ''
            GROUP BY substr(date_added, 1, 10)
            ORDER BY date ASC
        """).fetchall()

        return jsonify([
            {
                "date": row["date"],
                "total": row["total"]
            }
            for row in rows
        ])

    except sqlite3.Error:
        app.logger.exception("Trends query failed")
        return jsonify({"error": "Could not load trends"}), 500

    finally:
        connection.close()


# --------------------------------------------------
# Health check
# --------------------------------------------------

@app.route("/api/status")
def status():
    if not database_exists():
        return jsonify({
            "application": "running",
            "database": "unavailable"
        }), 503

    connection = None

    try:
        connection = get_database_connection()
        connection.execute("SELECT 1")

        return jsonify({
            "application": "running",
            "database": "connected"
        })

    except sqlite3.Error:
        app.logger.exception("Health check failed")

        return jsonify({
            "application": "running",
            "database": "unavailable"
        }), 503

    finally:
        if connection is not None:
            connection.close()


if __name__ == "__main__":
    app.run(debug=False)
