
import sqlite3
from pathlib import Path

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

# Database location
DATABASE = Path("data/database/threat_intel.db")


def get_database_connection():
    """Connect to the SQLite database."""
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


@app.route("/")
def home():
    """Display the dashboard homepage."""
    return render_template("index.html")


@app.route("/api/summary")
def summary():
    """Return important dashboard statistics."""

    if not DATABASE.exists():
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

    finally:
        connection.close()


@app.route("/api/top-hosts")
def top_hosts():
    """Return the ten most frequent hosts."""

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

    finally:
        connection.close()


@app.route("/api/status")
def status():
    """Check application and database availability."""

    if not DATABASE.exists():
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
        app.logger.exception("Database health check failed")

        return jsonify({
            "application": "running",
            "database": "unavailable"
        }), 503

    finally:
        if connection is not None:
            connection.close()


@app.route("/api/urls")
def get_urls():
    """Return searchable, filterable and paginated URL records."""

    if not DATABASE.exists():
        return jsonify({"error": "Database not found"}), 500

    search = request.args.get("search", "").strip()
    status_filter = request.args.get("status", "").strip()
    risk_filter = request.args.get("risk", "").strip()

    # Validate risk filter
    allowed_risks = ("", "High", "Medium", "Unclassified")

    if risk_filter not in allowed_risks:
        return jsonify({"error": "Invalid risk filter"}), 400

    # Validate pagination
    try:
        page = max(1, int(request.args.get("page", 1)))

        per_page = min(100, max(1, int(
            request.args.get("per_page", 10)
        )))

    except ValueError:
        return jsonify({"error": "Invalid pagination values"}), 400

    conditions = []
    parameters = []

    # Search by URL or host
    if search:
        conditions.append("(url LIKE ? OR host LIKE ?)")

        parameters.extend([
            f"%{search}%",
            f"%{search}%"
        ])

    # Filter by online/offline status
    if status_filter in ("online", "offline"):
        conditions.append("url_status = ?")
        parameters.append(status_filter)

    # Filter by risk level
    if risk_filter:
        conditions.append("""
            CASE
                WHEN url_status = 'online' THEN 'High'
                WHEN url_status = 'offline' THEN 'Medium'
                ELSE 'Unclassified'
            END = ?
        """)

        parameters.append(risk_filter)

    where_clause = ""

    if conditions:
        where_clause = " WHERE " + " AND ".join(conditions)

    connection = get_database_connection()

    try:
        # Count matching records
        total = connection.execute(
            "SELECT COUNT(*) FROM urlhaus_urls" + where_clause,
            parameters
        ).fetchone()[0]

        offset = (page - 1) * per_page

        # Retrieve matching records
        rows = connection.execute(
            """
            SELECT
                url,
                host,
                url_status,
                threat,
                date_added,
                CASE
                    WHEN url_status = 'online' THEN 'High'
                    WHEN url_status = 'offline' THEN 'Medium'
                    ELSE 'Unclassified'
                END AS risk_level
            FROM urlhaus_urls
            """ + where_clause +
            " ORDER BY date_added DESC LIMIT ? OFFSET ?",
            parameters + [per_page, offset]
        ).fetchall()

        return jsonify({
            "records": [dict(row) for row in rows],
            "total_records": total,
            "current_page": page,
            "per_page": per_page,
            "total_pages": (total + per_page - 1) // per_page
        })

    except sqlite3.Error:
        app.logger.exception("Failed to retrieve URL records")

        return jsonify({
            "error": "Database query failed"
        }), 500

    finally:
        connection.close()


@app.route("/api/trends")
def get_trends():
    """Return daily URL addition counts."""

    if not DATABASE.exists():
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
        app.logger.exception("Failed to retrieve URL trends")

        return jsonify({
            "error": "Could not load trends"
        }), 500

    finally:
        connection.close()


if __name__ == "__main__":
    app.run(debug=True)
