
import time
from app import app

client = app.test_client()

tests = [
    ("Normal pagination", "/api/urls?page=1&per_page=10"),
    ("Online status filter", "/api/urls?status=online"),
    ("Search test", "/api/urls?search=com"),
    ("Pagination test", "/api/urls?page=2&per_page=10")
]

print("SEARCH AND PAGINATION PERFORMANCE")
print("----------------------------------")

for test_name, endpoint in tests:

    total_time = 0
    successful_requests = 0

    for _ in range(100):

        start = time.perf_counter()
        response = client.get(endpoint)
        end = time.perf_counter()

        total_time += end - start

        if response.status_code == 200:
            successful_requests += 1

    average_time = (total_time / 100) * 1000

    print(f"\nTest: {test_name}")
    print(f"Successful requests: {successful_requests}/100")
    print(f"Average response time: {average_time:.4f} ms")

