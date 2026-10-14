# osint/report/json_writer.py
import json
import os
from pathlib import Path

from osint.report.serialize import stem


def write_json(data: dict, out_dir="output") -> Path:
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    path = Path(out_dir) / f"{stem(data)}.json"
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    os.chmod(path, 0o600)  # recon data: owner-only
    return path