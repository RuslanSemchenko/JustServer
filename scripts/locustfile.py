"""
JustServer Load Test with Locust
Usage:
    pip install locust
    locust -f scripts/locustfile.py --host http://127.0.0.1:8080

Web UI will be available at http://localhost:8089
"""

from locust import HttpUser, task, between, events
import json
import time


class StaticFileUser(HttpUser):
    """Simulates users browsing static pages"""
    wait_time = between(0.1, 1.0)
    weight = 5  # Most common user type

    @task(10)
    def get_index(self):
        self.client.get("/index.html", name="Static: index.html")

    @task(5)
    def get_html_js_test(self):
        self.client.get("/test_html_js.html", name="Static: test_html_js.html")

    @task(3)
    def get_interactive(self):
        self.client.get("/test_interactive.html", name="Static: test_interactive.html")

    @task(3)
    def get_css_js(self):
        self.client.get("/test_css_js.html", name="Static: test_css_js.html")

    @task(1)
    def get_404(self):
        with self.client.get("/nonexistent.html", name="Static: 404",
                             catch_response=True) as resp:
            if resp.status_code == 404:
                resp.success()


class PHPUser(HttpUser):
    """Simulates users hitting PHP endpoints via FastCGI"""
    wait_time = between(0.5, 2.0)
    weight = 2

    @task(5)
    def get_php_test(self):
        self.client.get("/test_php.php", name="PHP: test_php.php")

    @task(5)
    def get_api(self):
        self.client.get("/test_api.php", name="PHP API: GET")

    @task(3)
    def post_api(self):
        payload = {
            "test": "load_test",
            "timestamp": time.time(),
            "data": "x" * 100
        }
        self.client.post("/test_api.php",
                         json=payload,
                         name="PHP API: POST")


class MetricsUser(HttpUser):
    """Simulates monitoring system scraping metrics"""
    wait_time = between(5, 15)
    weight = 1

    @task
    def scrape_metrics(self):
        with self.client.get("/metrics", name="Metrics: /metrics",
                             catch_response=True) as resp:
            if resp.status_code == 200:
                # Verify it looks like Prometheus format
                if "justserver_requests_total" in resp.text:
                    resp.success()
                else:
                    resp.failure("Missing expected metrics")


class WAFTestUser(HttpUser):
    """Tests WAF by sending known attack patterns (should be blocked)"""
    wait_time = between(2, 5)
    weight = 1

    @task(3)
    def path_traversal(self):
        with self.client.get("/../../etc/passwd",
                             name="WAF: path traversal",
                             catch_response=True) as resp:
            if resp.status_code == 403:
                resp.success()
            else:
                resp.failure(f"Expected 403, got {resp.status_code}")

    @task(3)
    def sql_injection(self):
        with self.client.get("/test?id=1'+OR+1=1--",
                             name="WAF: SQL injection",
                             catch_response=True) as resp:
            if resp.status_code in (403, 404):
                resp.success()

    @task(2)
    def xss_attempt(self):
        with self.client.get("/test?q=<script>alert(1)</script>",
                             name="WAF: XSS",
                             catch_response=True) as resp:
            if resp.status_code in (403, 404):
                resp.success()

    @task(1)
    def blocked_user_agent(self):
        with self.client.get("/index.html",
                             headers={"User-Agent": "sqlmap/1.0"},
                             name="WAF: blocked UA",
                             catch_response=True) as resp:
            if resp.status_code == 403:
                resp.success()
            else:
                resp.failure(f"Expected 403, got {resp.status_code}")


class DDoSSimulator(HttpUser):
    """Rapid-fire requests to test DDoS protection"""
    wait_time = between(0, 0.01)  # Nearly zero wait
    weight = 1

    @task
    def rapid_requests(self):
        self.client.get("/index.html", name="DDoS: rapid fire")


@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    print("="*60)
    print("  JustServer Load Test Starting")
    print(f"  Target: {environment.host}")
    print("  User types: Static, PHP, Metrics, WAF, DDoS")
    print("="*60)


@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    print("="*60)
    print("  Load Test Complete")
    stats = environment.runner.stats
    print(f"  Total requests: {stats.total.num_requests}")
    print(f"  Failures: {stats.total.num_failures}")
    print(f"  Avg response time: {stats.total.avg_response_time:.2f}ms")
    if stats.total.num_requests > 0:
        print(f"  RPS: {stats.total.current_rps:.2f}")
    print("="*60)
