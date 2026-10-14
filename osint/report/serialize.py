# osint/report/serialize.py
import hashlib
import json
from dataclasses import asdict


def _canonical(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")


def to_dict(report) -> dict:
    data = asdict(report)
    data.pop("integrity", None)
    data["integrity"] = {
        "algorithm": "SHA-256",
        "covers": "all other top-level fields, canonical JSON (sorted keys, no whitespace)",
        "sha256": hashlib.sha256(_canonical(data)).hexdigest(),
    }
    return data


def verify(data: dict) -> bool:
    body = {k: v for k, v in data.items() if k != "integrity"}
    return hashlib.sha256(_canonical(body)).hexdigest() == data["integrity"]["sha256"]


def stem(data: dict) -> str:
    return f"{data['target']}_{data['run_id']}"