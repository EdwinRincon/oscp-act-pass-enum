# osint/passive/searchsploit.py
import json
import re
import shlex
import shutil
import subprocess
from itertools import islice

from osint.base import Module
from osint.models import ModuleResult

RESULT_GROUPS = ("RESULTS_EXPLOIT", "RESULTS_SHELLCODE", "RESULTS_PAPERS")
FIELDS = ("Search", "Title", "EDB-ID", "Date", "Author", "Type", "Platform", "Path")
SIGNALS = {"server", "x-powered-by", "x-generator", "meta-generator"}
MAX_QUERIES, MAX_RESULTS, QUERY_TIMEOUT = 3, 100, 15

VERSIONED_RE = re.compile(
    r"\b([A-Za-z][A-Za-z0-9_.+-]{1,30})\s*(?:/|\s+v(?:ersion)?\s*)"
    r"([0-9][A-Za-z0-9_.+-]{0,20})\b", re.I)
PRODUCT_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9_.+-]{1,30})\b")


def query_from_signal(header, value):
    match = VERSIONED_RE.search(value)
    if match:
        return f"{match.group(1)} {match.group(2)}"
    if header == "server":
        return ""
    match = PRODUCT_RE.search(value)
    return match.group(1) if match else ""


def inferred_queries(results):
    queries, seen = [], set()
    for result in results:
        if result.id != "fingerprint" or result.status != "ok":
            continue
        for row in result.rows:
            if len(row) < 2 or str(row[0]).lower() not in SIGNALS:
                continue
            query = query_from_signal(str(row[0]).lower(), str(row[1]))
            if query and query.casefold() not in seen:
                seen.add(query.casefold())
                queries.append(query)
                if len(queries) == MAX_QUERIES:
                    return queries
    return queries


def run_query(executable, query):
    if len(query) > 200 or any(ord(char) < 32 for char in query):
        raise ValueError("invalid exploit query")
    terms = shlex.split(query)
    if not terms:
        raise ValueError("empty exploit query")
    try:
        proc = subprocess.run([executable, "--json", "--", *terms],
                              stdin=subprocess.DEVNULL, capture_output=True, text=True,
                              timeout=QUERY_TIMEOUT, check=False)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"timed out after {QUERY_TIMEOUT}s") from exc
    if proc.returncode:
        detail = proc.stderr.strip() or proc.stdout.strip() or "no diagnostic output"
        raise RuntimeError(f"exit status {proc.returncode}: {detail[:200]}")
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("invalid JSON output") from exc
    if not isinstance(data, dict):
        raise RuntimeError("unexpected JSON structure")
    return data


def entry_to_row(query, entry):
    def text(*keys):
        return next((str(entry[k]) for k in keys if entry.get(k)), "")
    return (query, text("Title"), text("EDB-ID"), text("Date_Published", "Date"),
            text("Author"), text("Type"), text("Platform"), text("Path"))


def parse_entries(data, query, seen):
    for group in RESULT_GROUPS:
        entries = data.get(group, [])
        if not isinstance(entries, list):
            raise RuntimeError(f"invalid {group} data")
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            row = entry_to_row(query, entry)
            key = row[2] or row[1]
            if key in seen:
                continue
            seen.add(key)
            yield row


def placeholder_row(query, message):
    return (query, message, "", "", "", "", "", "")


class SearchSploit(Module):
    name, phase = "SearchSploit references", "passive"

    def __init__(self, context):
        self.context = context

    def run(self, _target):
        override = str(self.context.options.get("exploit_query", "")).strip()
        queries = [override] if override else inferred_queries(self.context.results)
        if not queries:
            return ModuleResult(self.name, self.phase, status="skipped",
                                error="no software or version indicators found; "
                                      "exploit search was not run")
        executable = shutil.which("searchsploit")
        if not executable:
            raise RuntimeError("searchsploit is not installed or is not on PATH")

        rows, seen, failures = [], set(), []
        for query in queries:
            remaining = MAX_RESULTS - len(rows)
            if remaining <= 0:
                break
            try:
                data = run_query(executable, query)
                found = list(islice(parse_entries(data, query, seen), remaining))
            except (RuntimeError, ValueError) as exc:
                failures.append(f"{query}: {exc}")
                rows.append(placeholder_row(query, f"Query failed: {exc}"[:160]))
                continue
            rows.extend(found or [placeholder_row(query, "No matching references")])

        if len(failures) == len(queries):
            raise RuntimeError("; ".join(failures)[:300])
        return self.result(FIELDS, rows)