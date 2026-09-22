"""Score one or more request URLs locally without Kafka/OpenSearch."""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "consumer"))

from detectors import SQLiDetector  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Score HTTP request targets for SQL injection")
    parser.add_argument("url", nargs="+", help="Request target(s), e.g. /page?id=1%%20AND%%20SLEEP(5)--")
    args = parser.parse_args()

    detector = SQLiDetector(ROOT / "models" / "sqli_detector_config.json")
    for url in args.url:
        print(json.dumps({"url": url, **detector.score(url)}, indent=2))


if __name__ == "__main__":
    main()
