"""Kafka -> QPRA -> SQLi RF -> OpenSearch consumer.

This repository contains only the SQL injection detector used in the paper.
It intentionally does not inspect HTTP request bodies: standard Apache/Nginx
access logs do not contain bodies by default, and indiscriminate body logging
can expose credentials, PII, and other sensitive application data.
"""

import logging
import os
import re
from datetime import datetime, timezone

from kafka import KafkaConsumer
from opensearchpy import OpenSearch

from pipeline import load_detector, process

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("sqli-consumer")

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:29092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "access-logs")
KAFKA_GROUP_ID = os.getenv("KAFKA_GROUP_ID", "sqli-consumer")
OS_HOST = os.getenv("OPENSEARCH_HOST", "http://opensearch:9200")
OS_INDEX = os.getenv("OPENSEARCH_INDEX", "sqli-detections")
INDEX_MODE = os.getenv("INDEX_MODE", "scored").lower()

LOG_PATTERN = re.compile(
    r'(?P<client_ip>\S+)'
    r' \S+ \S+ '
    r'\[(?P<time>[^\]]+)\]'
    r' "(?P<method>\S+) '
    r'(?P<url>.+?) '
    r'(?P<protocol>HTTP/\d\.\d)"'
    r' (?P<status>\d{3})'
    r' (?P<bytes>\S+)'
    r' "(?P<referer>[^"]*)"'
    r' "(?P<user_agent>[^"]*)"'
)
LOG_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def parse_log_timestamp(time_str: str) -> str | None:
    try:
        dt = datetime.strptime(time_str, LOG_TIME_FORMAT)
        return dt.astimezone(timezone.utc).isoformat()
    except ValueError:
        return None


def parse_log_line(raw: str) -> dict | None:
    m = LOG_PATTERN.match(raw.strip())
    if not m:
        return None
    d = m.groupdict()
    d["bytes"] = int(d["bytes"]) if d["bytes"].isdigit() else 0
    d["status"] = int(d["status"])
    return d


def should_index(tier: str) -> bool:
    if INDEX_MODE == "all":
        return True
    if INDEX_MODE in ("scored", "no_qs"):
        return tier != "NO_QS"
    if INDEX_MODE == "alerts_only":
        return tier in ("ATTACK", "SUSPICIOUS")
    raise ValueError(
        f"Unsupported INDEX_MODE={INDEX_MODE!r}; expected all, scored, no_qs, alerts_only"
    )


def build_document(parsed: dict, result: dict) -> dict:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "log_timestamp": parse_log_timestamp(parsed["time"]),
        "client_ip": parsed["client_ip"],
        "method": parsed["method"],
        "url": parsed["url"],
        "status_code": parsed["status"],
        "bytes": parsed["bytes"],
        "referer": parsed["referer"],
        "user_agent": parsed["user_agent"],
        "sqli_tier": result["tier"],
        "sqli_score": result["max_score"],
        "has_query_string": result["tier"] != "NO_QS",
        "param_scores": result["param_scores"],
        "thresholds": {
            "t_low": result["t_low"],
            "t_high": result["t_high"],
        },
        "model_version": result.get("model_version"),
    }


def main() -> None:
    logger.info("Loading SQLi detector...")
    load_detector()

    logger.info("Connecting to Kafka at %s, topic=%s", KAFKA_BOOTSTRAP, KAFKA_TOPIC)
    consumer = KafkaConsumer(
        KAFKA_TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP,
        group_id=KAFKA_GROUP_ID,
        auto_offset_reset="latest",
        value_deserializer=lambda m: m.decode("utf-8", errors="replace"),
    )

    logger.info("Connecting to OpenSearch at %s, index=%s", OS_HOST, OS_INDEX)
    os_client = OpenSearch(hosts=[OS_HOST])
    if not os_client.indices.exists(index=OS_INDEX):
        os_client.indices.create(index=OS_INDEX)
        logger.info("Created index: %s", OS_INDEX)

    logger.info("SQLi consumer started — INDEX_MODE=%s", INDEX_MODE)

    for message in consumer:
        parsed = parse_log_line(message.value)
        if parsed is None:
            logger.debug("Unparseable line skipped: %s", message.value[:80])
            continue

        result = process(parsed["url"])
        if not should_index(result["tier"]):
            continue

        doc = build_document(parsed, result)
        try:
            os_client.index(index=OS_INDEX, body=doc)
            if result["tier"] in ("ATTACK", "SUSPICIOUS"):
                logger.warning(
                    "[%s] score=%s url=%s",
                    result["tier"],
                    result["max_score"],
                    parsed["url"],
                )
        except Exception as exc:
            logger.error("Failed to index document: %s", exc)


if __name__ == "__main__":
    main()
