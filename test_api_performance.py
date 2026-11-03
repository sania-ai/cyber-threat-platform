
import time
from app import app

# Create a Flask test client
client = app.test_client()

# Warm-up requests
for _ in range(5):
    client.get("/api/summary")

# Measure 100 API requests
total_time = 0
successful_requests = 0

for _ in range(100):

    start_time = time.perf_counter()

    response = client.get("/api/summary")

    end_time = time.perf_counter()

    if response.status_code == 200:
        successful_requests += 1

    total_time += end_time - start_time

average_time = total_time / 100

print("FLASK API PERFORMANCE TEST")
print("--------------------------")
print("Total requests: 100")
print("Successful requests:", successful_requests)
print(f"Average response time: {average_time * 1000:.4f} ms")

# Display API response
print("\nAPI RESPONSE:")
print(response.get_json())
