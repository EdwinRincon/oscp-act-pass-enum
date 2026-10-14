# enum_tool.py
import sys
from collections import Counter
from dataclasses import dataclass, replace
from typing import Literal, Optional

import typer
from InquirerPy import inquirer
from rich import box
from rich.console import Console as RichConsole
from rich.progress import (BarColumn, Progress, SpinnerColumn, TaskProgressColumn,
                           TextColumn, TimeElapsedColumn)
from rich.table import Table
from rich.text import Text

from osint import __version__
from osint.active.rustscan import (DEFAULT_BATCH, DEFAULT_EXECUTION_TIMEOUT, DEFAULT_PORTS,
                                   MAX_BATCH, MIN_BATCH)
from osint.http_client import DEFAULT_UA
from osint.models import ScanError
from osint.registry import SPECS, candidates, default_ids, is_available, unavailable
from osint.report.html_report import write_html
from osint.report.json_writer import write_json
from osint.report.serialize import to_dict
from osint.runner import INTERRUPTED
from osint.service import (normalize_target, prepare, run_scan, validate_http_options,
                           validate_module_options)

app = typer.Typer(
    name="osint-enum",
    help="Passive and active enumeration for authorised assessments.",
    invoke_without_command=True,
    no_args_is_help=False,
    add_completion=False,
)

MODE_CHOICES = [
    {"name": "Passive — public sources; no requests to the target", "value": "passive"},
    {"name": "Active — requests the target; authorisation required", "value": "active"},
    {"name": "Passive + active — authorisation required", "value": "all"},
]
STATUS_COLORS = {"ok": "green", "failed": "red", "skipped": "yellow"}


@dataclass(frozen=True)
class ScanArgs:
    domain: Optional[str]
    mode: str
    only: Optional[str]
    exclude: Optional[str]
    authorised: bool
    timeout: int
    user_agent: str
    headers: list
    rustscan_ports: Optional[str]
    rustscan_timeout: int
    rustscan_batch: int
    exploit_query: str
    operator: str
    note: str
    json: bool
    html: bool
    quiet: bool


def csv(value):
    return [part.strip() for part in value.split(",") if part.strip()] if value else None


def _passes(validator, *args):
    try:
        validator(*args)
        return True
    except ScanError:
        return False


def _valid_target(value):
    return _passes(normalize_target, value)


def _valid_ports(value):
    return _passes(validate_module_options, {"rustscan_ports": value})


# ---------- presentación ----------

def show_modules(console):
    table = Table(box=box.SIMPLE_HEAD, header_style="bold cyan", show_lines=False)
    for heading in ("ID", "PHASE", "KIND", "CONFIDENCE", "RUNS", "AVAILABLE", "SOURCE"):
        table.add_column(heading, overflow="fold")
    for spec in SPECS:
        available = is_available(spec)
        table.add_row(
            spec.id, spec.phase, spec.kind, spec.confidence,
            "--only" if spec.opt_in else "default",
            Text("yes" if available else "no", style="green" if available else "yellow"),
            spec.source,
        )
    console.print(table)


def render_result(console, result):
    color = STATUS_COLORS.get(result.status, "white")
    console.print(
        f"\n[bold {color}]{result.phase.upper()} · {result.name}[/bold {color}] "
        f"[dim]{result.elapsed:.1f}s · {result.status}[/dim]"
    )
    if result.source:
        console.print(f"[dim]Source: {result.source} · Confidence: {result.confidence}[/dim]")
    if result.status == "failed":
        console.print(Text(f"Error: {result.error}", style="red"))
    elif result.status == "skipped":
        console.print(Text(f"Skipped: {result.error}", style="yellow"))
    elif not result.rows:
        console.print("[dim]No data returned.[/dim]")
    else:
        table = Table(box=box.SIMPLE_HEAD, header_style="bold", show_lines=False)
        for heading in result.headers:
            table.add_column(str(heading), overflow="fold")
        for row in result.rows:
            table.add_row(*(Text(str(value)) for value in row))
        console.print(table)


# ---------- asistente interactivo ----------

def _ask_modules(args, mode):
    missing = unavailable(mode)
    if missing:
        RichConsole().print(
            "[yellow]Optional tools not installed are omitted from this menu: "
            f"{', '.join(s.id for s in missing)}. "
            "Check `osint-enum modules` for availability.[/yellow]")
    preselected = set(csv(args.only) or ()) or default_ids(mode)
    choices = [
        {"name": f"{s.title} [{s.id}]" + (f" — {s.source}" if s.executable else ""),
         "value": s.id, "enabled": s.id in preselected}
        for s in candidates(mode)
    ]
    chosen = inquirer.checkbox(
        message="Select modules to run", choices=choices, pointer="»",
        instruction="Space toggles; Enter confirms",
        validate=lambda values: bool(values), invalid_message="Select at least one module.",
    ).execute()
    return [s.id for s in SPECS if s.id in chosen]


def _confirm_authorisation(args, domain, selected):
    if args.authorised:
        return True
    if not any(s.phase == "active" for s in SPECS if s.id in selected):
        return False
    confirmed = inquirer.confirm(
        message=f"Do you have explicit authorisation to test {domain}?", default=False).execute()
    if not confirmed:
        raise ScanError("scan cancelled; explicit authorisation is required")
    return True


def _ask_advanced(args):
    timeout = int(inquirer.number(
        message="HTTP timeout in seconds (3–30)", default=args.timeout,
        min_allowed=3, max_allowed=30).execute())
    user_agent = inquirer.text(message="HTTP User-Agent", default=args.user_agent).execute()
    headers = list(args.headers)
    while len(headers) < 40 and inquirer.confirm(
            message="Add a custom HTTP header?", default=False).execute():
        headers.append(inquirer.text(message="Header in Name: value format").execute())
    operator = inquirer.text(message="Operator / analyst name", default=args.operator).execute()
    note = inquirer.text(message="Engagement or ticket reference", default=args.note).execute()
    return replace(args, timeout=timeout, user_agent=user_agent, headers=headers,
                   operator=operator, note=note)


def _ask_rustscan(args):
    ports = inquirer.text(
        message="RustScan ports (comma-separated)",
        default=args.rustscan_ports or DEFAULT_PORTS,
        validate=_valid_ports,
        invalid_message="Use unique ports from 1 to 65535, e.g. 80,443",
    ).execute()
    batch = int(inquirer.number(
        message=f"RustScan batch size ({MIN_BATCH}–{MAX_BATCH})",
        default=args.rustscan_batch, min_allowed=MIN_BATCH, max_allowed=MAX_BATCH).execute())
    return replace(args, rustscan_ports=ports, rustscan_batch=batch)


def _ask_formats(args):
    formats = inquirer.checkbox(
        message="Select report formats",
        choices=[
            {"name": "JSON — machine-readable and integrity-hashed", "value": "json",
             "enabled": args.json},
            {"name": "HTML — reviewable report", "value": "html", "enabled": args.html},
        ],
        instruction="Space toggles; Enter confirms (select none to skip reports)",
    ).execute()
    return replace(args, json="json" in formats, html="html" in formats)


def run_wizard(args):
    domain = inquirer.text(
        message="Target domain or IPv4 address", default=args.domain or "",
        validate=_valid_target, invalid_message="Enter a valid domain or IPv4 address.",
    ).execute()
    mode = inquirer.select(
        message="Choose the scan profile", choices=MODE_CHOICES,
        default="all" if args.only else args.mode,
        pointer="»", instruction="Use arrow keys and Enter",
    ).execute()
    selected = _ask_modules(args, mode)
    authorised = _confirm_authorisation(args, domain, selected)
    args = replace(args, domain=domain, mode=mode, only=",".join(selected),
                   authorised=authorised)
    if inquirer.confirm(message="Configure advanced HTTP and engagement options?",
                        default=False).execute():
        args = _ask_advanced(args)
    if "rustscan" in selected:
        args = _ask_rustscan(args)
    return _ask_formats(args)


# ---------- ejecución ----------

def _make_progress(console, quiet):
    return Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
        BarColumn(), TaskProgressColumn(), TimeElapsedColumn(),
        console=console, transient=True, disable=quiet or not console.is_terminal,
    )


def run_scan_command(console, args, out):
    selected_mode = "all" if args.only else args.mode
    try:
        timeout, user_agent, _ = validate_http_options(
            args.timeout, args.user_agent, args.headers)
        domain, specs = prepare(args.domain, selected_mode, csv(args.only),
                                csv(args.exclude), args.authorised)
        module_options = validate_module_options(
            {"rustscan_ports": args.rustscan_ports or DEFAULT_PORTS,
             "rustscan_timeout": args.rustscan_timeout,
             "rustscan_batch": args.rustscan_batch,
             "exploit_query": args.exploit_query},
            specs)
    except ScanError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc

    console.print(f"[bold cyan]osint-enum {__version__}[/bold cyan]  "
                  f"[bold]Target:[/bold] {domain}  [bold]Profile:[/bold] {selected_mode}")
    progress = _make_progress(console, args.quiet)
    with progress:
        task = progress.add_task("Preparing modules", total=len(specs))

        def on_start(spec):
            progress.update(task, description=f"Running {spec.title}")

        def on_result(result):
            if not args.quiet:
                render_result(console, result)
            progress.advance(task)

        report = run_scan(
            domain, selected_mode, csv(args.only), csv(args.exclude), timeout,
            args.operator, args.note, args.authorised,
            on_start=on_start, on_result=on_result, user_agent=user_agent,
            headers=args.headers, module_options=module_options)

    _finish(console, report, args, out)


def _finish(console, report, args, out):
    data = to_dict(report)
    counts = Counter(result.status for result in report.results)
    interrupted = any(r.status == "failed" and r.error == INTERRUPTED for r in report.results)
    console.print(
        f"[bold]Completed:[/bold] {len(report.results)} modules · "
        f"[green]{counts['ok']} ok[/green] · [red]{counts['failed']} failed[/red] · "
        f"[yellow]{counts['skipped']} skipped[/yellow] · {report.duration:.1f}s")
    if args.json:
        console.print("JSON report:", Text(str(write_json(data, out)), style="green"))
    if args.html:
        console.print("HTML report:", Text(str(write_html(data, out)), style="green"))
    console.print(f"[dim]SHA-256: {data['integrity']['sha256']}[/dim]")
    if interrupted:
        console.print("[yellow]Scan interrupted; reports contain partial results.[/yellow]")
        raise typer.Exit(code=130)
    if report.results and counts["failed"] == len(report.results):
        raise typer.Exit(code=1)


# ---------- comandos ----------

@app.callback()
def scan(
    ctx: typer.Context,
    domain: Optional[str] = typer.Option(None, "--domain", "-d", help="Target domain or IPv4"),
    mode: Literal["passive", "active", "all"] = typer.Option(
        "passive", "--mode", "-m", help="passive, active or all"),
    only: Optional[str] = typer.Option(
        None, "--only", help="Comma-separated module IDs (overrides --mode)"),
    exclude: Optional[str] = typer.Option(None, "--exclude", help="Comma-separated module IDs"),
    interactive: bool = typer.Option(False, "--interactive", "-i", help="Guided scan wizard"),
    list_modules: bool = typer.Option(False, "--list-modules", help="List registered modules"),
    json_report: bool = typer.Option(False, "--json", help="Write JSON report"),
    html_report: bool = typer.Option(False, "--html", help="Write HTML report"),
    out: str = typer.Option("output", "--out", help="Report directory"),
    operator: str = typer.Option("", "--operator", help="Analyst name recorded in report"),
    note: str = typer.Option("", "--note", help="Engagement/ticket reference"),
    timeout: int = typer.Option(10, "--timeout", help="HTTP timeout in seconds (3–30)"),
    user_agent: str = typer.Option(DEFAULT_UA, "--user-agent", help="HTTP User-Agent"),
    headers: Optional[list[str]] = typer.Option(
        None, "--header", help="Custom header; repeatable"),
    rustscan_ports: Optional[str] = typer.Option(None, "--rustscan-ports", help="RustScan ports"),
    rustscan_timeout: int = typer.Option(
        DEFAULT_EXECUTION_TIMEOUT, "--rustscan-timeout",
        help="RustScan execution limit in seconds (10–300)"),
    rustscan_batch: int = typer.Option(
        DEFAULT_BATCH, "--rustscan-batch",
        help=f"RustScan concurrent connections ({MIN_BATCH}–{MAX_BATCH})"),
    exploit_query: str = typer.Option(
        "", "--exploit-query", help="Override the automatic local SearchSploit query"),
    no_color: bool = typer.Option(False, "--no-color", help="Disable terminal colors"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Summary only"),
    authorised: bool = typer.Option(
        False, "--i-have-permission", help="Confirm explicit authorisation for active scans"),
):
    if ctx.invoked_subcommand:
        return

    console = RichConsole(no_color=no_color)
    if list_modules:
        show_modules(console)
        return

    args = ScanArgs(
        domain=domain, mode=mode, only=only, exclude=exclude, authorised=authorised,
        timeout=timeout, user_agent=user_agent, headers=headers or [],
        rustscan_ports=rustscan_ports, rustscan_timeout=rustscan_timeout,
        rustscan_batch=rustscan_batch, exploit_query=exploit_query,
        operator=operator, note=note, json=json_report, html=html_report, quiet=quiet)

    if interactive or (domain is None and sys.stdin.isatty()):
        try:
            args = run_wizard(args)
        except (KeyboardInterrupt, EOFError):
            console.print("\n[yellow]Scan setup cancelled.[/yellow]")
            raise typer.Exit(code=130)
        except ScanError as exc:
            console.print(f"[yellow]{exc}[/yellow]")
            raise typer.Exit(code=130) from exc
    elif not domain:
        console.print("[bold red]Error:[/bold red] provide --domain or use --interactive")
        raise typer.Exit(code=2)

    try:
        run_scan_command(console, args, out)
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan cancelled.[/yellow]")
        raise typer.Exit(code=130)


@app.command("modules")
def modules_command():
    """List modules and whether optional external tools are available."""
    show_modules(RichConsole())


def main(argv=None):
    app(args=argv)


if __name__ == "__main__":
    main()