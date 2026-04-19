import json
import os
import time
from pathlib import Path

import requests

LOGSTASH_URL = os.getenv("LOGSTASH_URL", "http://10.10.0.10:64305")
STATE_DIR = os.getenv("STATE_DIR", "/data/state")
POLL_INTERVAL = float(os.getenv("POLL_INTERVAL", "2"))
HTTP_TIMEOUT = int(os.getenv("HTTP_TIMEOUT", "5"))
VERIFY_TLS = os.getenv("VERIFY_TLS", "false").lower() == "true"
TPOT_IP_EXT = os.getenv("TPOT_IP_EXT", "")
TPOT_NAME = os.getenv("TPOT_NAME", "tpot-unknown")
TPOT_SITE = os.getenv("TPOT_SITE", "unknown")

HEADERS = {"Content-Type": "application/json"}

SOURCES = [
    {"name": "suricata", "path": os.getenv("SURICATA_LOG", "/data/suricata/log/eve.json")},
    {"name": "cowrie", "path": os.getenv("COWRIE_LOG", "/data/cowrie/log/cowrie.json")},
    {"name": "dionaea", "path": os.getenv("DIONAEA_LOG", "/data/dionaea/log/dionaea.json")},
    {"name": "beelzebub", "path": os.getenv("BEELZEBUB_LOG", "/data/beelzebub/log/beelzebub.json")},
    {"name": "galah", "path": os.getenv("GALAH_LOG", "/data/galah/log/galah.json")},
]


def ensure_dir(path_str: str) -> None:
    Path(path_str).mkdir(parents=True, exist_ok=True)


def state_file_for(source_name: str) -> str:
    return str(Path(STATE_DIR) / f"{source_name}.offset")


def load_offset(source_name: str) -> int:
    try:
        return int(Path(state_file_for(source_name)).read_text(encoding="utf-8").strip())
    except Exception:
        return 0


def save_offset(source_name: str, offset: int) -> None:
    ensure_dir(STATE_DIR)
    Path(state_file_for(source_name)).write_text(str(offset), encoding="utf-8")


def should_keep_event(source_name: str, payload: dict) -> bool:
    if source_name == "suricata":
        return payload.get("event_type") in {"alert", "http", "ssh", "dns", "tls"}
    return True


def build_event(source_name: str, payload: dict) -> dict:
    if isinstance(payload, dict):
        event = payload.copy()
    else:
        event = {"message": str(payload)}

    event["honeypot"] = source_name
    event["t-pot_hostname"] = TPOT_NAME
    event["tpot_site"] = TPOT_SITE
    event["debug_marker"] = "NEW_FORMAT_OK"
    event["tpot_ip_ext"] = TPOT_IP_EXT
    if "@timestamp" not in event and "timestamp" in event:
        event["@timestamp"] = event["timestamp"]

    return event


def send_event(event: dict) -> bool:
    try:
        response = requests.post(
            LOGSTASH_URL,
            headers=HEADERS,
            data=json.dumps(event),
            timeout=HTTP_TIMEOUT,
            verify=VERIFY_TLS,
        )
        return 200 <= response.status_code < 300
    except requests.RequestException:
        return False


def process_source(source: dict) -> None:
    source_name = source["name"]
    source_path = source["path"]

    if not Path(source_path).exists():
        print(f"[forwarder:{source_name}] waiting for log file: {source_path}")
        return

    offset = load_offset(source_name)

    try:
        with open(source_path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(offset)

            while True:
                pos_before = f.tell()
                line = f.readline()

                if not line:
                    save_offset(source_name, f.tell())
                    break

                if not line.strip():
                    save_offset(source_name, f.tell())
                    continue

                try:
                    payload = json.loads(line)
                    if not isinstance(payload, dict):
                        payload = {"raw": payload}
                except json.JSONDecodeError:
                    payload = {"message": line.strip()}

                if not should_keep_event(source_name, payload):
                    save_offset(source_name, f.tell())
                    continue

                event = build_event(source_name, payload)

                if send_event(event):
                    new_offset = f.tell()
                    save_offset(source_name, new_offset)
                    print(f"[forwarder:{source_name}] sent event at offset={new_offset}")
                else:
                    print(f"[forwarder:{source_name}] send failed, retry later")
                    f.seek(pos_before)
                    break

    except Exception as e:
        print(f"[forwarder:{source_name}] error: {e}")


def main() -> None:
    ensure_dir(STATE_DIR)
    print(f"[forwarder] starting multi-source forwarder to {LOGSTASH_URL}")

    while True:
        for source in SOURCES:
            process_source(source)
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
