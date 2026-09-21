"""Send SQLi and benign Apache Combined Log Format test events to Kafka."""

import argparse
import os
import time
from datetime import datetime, timezone

from kafka import KafkaProducer

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "access-logs")

ENTRIES = [
    ("SQLi", "10.0.0.1", "GET", "/product?id=1%27%20OR%201=1--", 200, 128, "sqlmap/1.7"),
    ("SQLi", "10.0.0.2", "GET", "/search?q=1%20UNION%20SELECT%201,2,3--", 200, 256, "sqlmap/1.7"),
    ("SQLi", "10.0.0.3", "GET", "/page?id=1%20AND%20SLEEP(5)--", 200, 64, "sqlmap/1.7"),
    ("SQLi", "10.0.0.4", "GET", "/login?user=admin%27--&next=/home", 200, 512, "Mozilla/5.0"),
    ("Benign", "192.168.1.10", "GET", "/products?category=electronics&page=2", 200, 2048, "Mozilla/5.0"),
    ("Benign", "192.168.1.11", "GET", "/search?q=laptop&sort=price", 200, 512, "Mozilla/5.0"),
    ("Benign", "192.168.1.12", "GET", "/user?id=42&tab=settings", 200, 1024, "Mozilla/5.0"),
    ("Benign", "192.168.1.13", "GET", "/index.html", 200, 1024, "Mozilla/5.0"),
]


def build_log_line(ip, method, url, status, size, ua):
    now = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{now}] "{method} {url} HTTP/1.1" {status} {size} "-" "{ua}"'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--loop", type=int, default=1)
    parser.add_argument("--delay", type=float, default=0.0)
    args = parser.parse_args()

    producer = KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP,
        value_serializer=lambda value: value.encode("utf-8"),
    )

    for iteration in range(args.loop):
        for category, ip, method, url, status, size, ua in ENTRIES:
            line = build_log_line(ip, method, url, status, size, ua)
            producer.send(KAFKA_TOPIC, value=line)
            print(f"[{category}] {line}")
            time.sleep(0.05)
        if iteration < args.loop - 1 and args.delay:
            time.sleep(args.delay)

    producer.flush()


if __name__ == "__main__":
    main()
