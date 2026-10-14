import json
import re
import shlex
import shutil
import subprocess

from osint.base import Module
from osint.models import ModuleResult

RESULT_GROUPS = ("RESULTS_EXPLOIT", "RESULTS_SHELLCODE", "RESULTS_PAPERS")
FIELDS = ("Search", "Title", "EDB-ID", "Date", "Author", "Type", "Platform", "Path")
SIGNALS = {"server", "x-powered-by", "x-generator", "meta-generator"}
MAX_QUERIES, MAX_RESULTS = 3, 100


def inferred_queries(results):
    queries = []
    for result in results:
        if result.id != "fingerprint" or result.status != "ok":
            continue
        for row in result.rows:
            if len(row) < 2 or str(row[0]).lower() not in SIGNALS:
                continue
            value = str(row[1])
            match = re.search(
                r"\b([A-Za-z][A-Za-z0-9_.+-]{1,30})\s*(?:/|\s+v(?:ersion)?\s*)"
                r"([0-9][A-Za-z0-9_.+-]{0,20})\b", value, re.I)
            if match:
                query = f"{match.group(1)} {match.group(2)}"
            else:
                if str(row[0]).lower() == "server":
                    continue
                match = re.search(
                    r"\b([A-Za-z][A-Za-z0-9_.+-]{1,30})\b", value)
                query = match.group(1) if match else ""
            if query and query.casefold() not in {item.casefold() for item in queries}:
                queries.append(query)
                if len(queries) == MAX_QUERIES:
                    return queries
    return queries


class SearchSploit(Module):
    name, phase = "SearchSploit references", "passive"

    def __init__(self, context):
        self.context = context

    def run(self, _target):
        override = self.context.options.get("exploit_query", "").strip()
        queries = [override] if override else inferred_queries(self.context.results)
        if not queries:
            return ModuleResult(
                self.name,
                self.phase,
                status="skipped",
                error="no software or version indicators found; exploit search was not run",
            )
        executable = shutil.which("searchsploit")
        if not executable:
            raise RuntimeError("searchsploit is not installed or is not on PATH")

        rows = []
        seen = set()
        for query in queries:
            try:
                result = subprocess.run(
                    [executable, "--json", "--", *shlex.split(query)],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError("searchsploit exceeded the 10-second query limit") from exc
            if result.returncode:
                detail = result.stderr.strip() or result.stdout.strip() or "no diagnostic output"
                raise RuntimeError(
                    f"searchsploit exited with status {result.returncode}: {detail[:240]}")
            try:
                data = json.loads(result.stdout)
            except json.JSONDecodeError as exc:
                raise RuntimeError("searchsploit returned invalid JSON") from exc
            if not isinstance(data, dict):
                raise RuntimeError("searchsploit returned an unexpected JSON structure")

            for group in RESULT_GROUPS:
                entries = data.get(group, [])
                if not isinstance(entries, list):
                    raise RuntimeError(f"searchsploit returned invalid {group} data")
                for entry in entries:
                    if isinstance(entry, dict):
                        values = tuple(str(entry.get(field, "")) for field in FIELDS[1:])
                        key = values[1] or values[0]
                        if key in seen:
                            continue
                        seen.add(key)
                        rows.append((query, *values))
                        if len(rows) >= MAX_RESULTS:
                            break
                if len(rows) >= MAX_RESULTS:
                    break
            if len(rows) >= MAX_RESULTS:
                        break
        if not rows:
            rows = [(query, "No matching references", "", "", "", "", "", "")
                    for query in queries]
        return self.result(FIELDS, rows)
