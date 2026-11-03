
import sqlite3
import time

DATABASE = "data/database/threat_intel.db"

connection = sqlite3.connect(DATABASE)

query = """
    SELECT url, host, url_status, date_added
    FROM urlhaus_urls
    ORDER BY date_added DESC
    LIMIT 10
"""

# Run the query 100 times
total_time = 0

for i in range(100):
    start_time = time.perf_counter()

    connection.execute(query).fetchall()

    end_time = time.perf_counter()

    total_time += end_time - start_time

average_time = total_time / 100

print("DATABASE PERFORMANCE TEST")
print("--------------------------")
print("Total queries: 100")
print(f"Average query time: {average_time * 1000:.4f} ms")

connection.close()
