import shutil
import sys
from typing import Literal, Optional

import typer
from InquirerPy import inquirer
from rich import box
from rich.console import Console as RichConsole
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from osint import __version__
from osint.active.rustscan import DEFAULT_EXECUTION_TIMEOUT, DEFAULT_PORTS
from osint.http_client import DEFAULT_UA
from osint.models import ScanError
from osint.registry import SPECS
from osint.report.html_report import write_html
from osint.report.json_writer import write_json
from osint.report.serialize import to_dict
from osint.service import prepare, run_scan, validate_http_options, validate_module_options

app = typer.Typer(
    name="osint-enum",
    help="Passive and active enumeration for authorised assessments.",
    invoke_without_command=True,
    no_args_is_help=False,
    add_completion=False,
)


def csv(value):
    return [part.strip() for part in value.split(",") if part.strip()] if value else None


def show_modules(console):
    table = Table(box=box.SIMPLE_HEAD, header_style="bold cyan", show_lines=False)
    for heading in ("ID", "PHASE", "KIND", "CONFIDENCE", "AVAILABLE", "SOURCE"):
        table.add_column(heading, overflow="fold")
    for spec in SPECS:
        available = not spec.executable or bool(shutil.which(spec.executable))
        table.add_row(
            spec.id,
            spec.phase,
            spec.kind,
            spec.confidence,
            Text("yes" if available else "no",
                 style="green" if available else "yellow"),
            spec.source,
        )
    console.print(table)


def run_wizard(defaults):
    modes = [
        {"name": "Passive — public sources; no requests to the target", "value": "passive"},
        {"name": "Active — requests the target; authorisation required", "value": "active"},
        {"name": "Passive + active — authorisation required", "value": "all"},
    ]
    domain = inquirer.text(
        message="Target domain or IPv4 address",
        default=defaults["domain"] or "",
        validate=lambda value: bool(value.strip()),
        invalid_message="Enter a target to continue.",
    ).execute()
    mode = inquirer.select(
        message="Choose the scan profile",
        choices=modes,
        default="all" if defaults["only"] else defaults["mode"],
        pointer="»",
        instruction="Use arrow keys and Enter",
    ).execute()

    relevant_phases = {"passive", "active"} if mode == "all" else {mode}
    auto_active = mode in ("active", "all")
    candidates = [
        spec for spec in SPECS
        if spec.phase in relevant_phases or (auto_active and spec.auto_when_active)
    ]
    available = {
        spec.id for spec in candidates
        if not spec.executable or shutil.which(spec.executable)
    }
    default_ids = set(csv(defaults["only"]) or ())
    if not defaults["only"]:
        default_ids = {
            spec.id for spec in candidates
            if not spec.executable or (auto_active and spec.auto_when_active)
        }
    choices = [
        {
            "name": (f"{spec.title} [{spec.id}]"
                     + (f" — {spec.source}" if spec.executable else "")),
            "value": spec.id,
            "enabled": spec.id in default_ids and spec.id in available,
        }
        for spec in candidates if spec.id in available
    ]
    if any(spec.executable and spec.id not in available for spec in candidates):
        RichConsole().print(
            "[yellow]Optional tools not installed are omitted from this menu. "
            "Check `osint-enum modules` for availability.[/yellow]"
        )
    selected = inquirer.checkbox(
        message="Select modules to run",
        choices=choices,
        pointer="»",
        instruction="Space toggles; Enter confirms",
        validate=lambda values: bool(values),
        invalid_message="Select at least one module.",
    ).execute()
    selected_specs = [spec for spec in SPECS if spec.id in selected]
    authorised = False
    if any(spec.phase == "active" for spec in selected_specs):
        authorised = inquirer.confirm(
            message=f"Do you have explicit authorisation to test {domain}?",
            default=False,
        ).execute()
        if not authorised:
            raise ScanError("scan cancelled; explicit authorisation is required")

    options = {
        "timeout": defaults["timeout"],
        "user_agent": defaults["user_agent"],
        "headers": list(defaults["headers"]),
        "rustscan_ports": defaults["rustscan_ports"] or DEFAULT_PORTS,
        "rustscan_timeout": defaults.get("rustscan_timeout", DEFAULT_EXECUTION_TIMEOUT),
        "exploit_query": defaults["exploit_query"],
        "operator": defaults["operator"],
        "note": defaults["note"],
    }
    if inquirer.confirm(message="Configure advanced HTTP and engagement options?",
                        default=False).execute():
        options["timeout"] = int(inquirer.number(
            message="HTTP timeout in seconds (3–30)",
            default=options["timeout"],
            min_allowed=3,
            max_allowed=30,
        ).execute())
        options["user_agent"] = inquirer.text(
            message="HTTP User-Agent", default=options["user_agent"]).execute()
        while len(options["headers"]) < 40 and inquirer.confirm(
                message="Add a custom HTTP header?", default=False).execute():
            options["headers"].append(inquirer.text(
                message="Header in Name: value format").execute())
        options["operator"] = inquirer.text(
            message="Operator / analyst name", default=options["operator"]).execute()
        options["note"] = inquirer.text(
            message="Engagement or ticket reference", default=options["note"]).execute()

    if "rustscan" in selected:
        options["rustscan_ports"] = inquirer.text(
            message="RustScan ports (comma-separated)",
            default=options["rustscan_ports"],
        ).execute()
    formats = inquirer.checkbox(
        message="Select report formats",
        choices=[
            {"name": "JSON — machine-readable and integrity-hashed", "value": "json",
             "enabled": defaults["json"]},
            {"name": "HTML — reviewable report", "value": "html",
             "enabled": defaults["html"]},
        ],
        instruction="Space toggles; Enter confirms (select none to skip reports)",
    ).execute()
    return {
        "domain": domain,
        "mode": mode,
        "only": selected,
        "exclude": defaults.get("exclude"),
        "authorised": authorised,
        "json": "json" in formats,
        "html": "html" in formats,
        "quiet": defaults.get("quiet", False),
        **options,
    }


def run_scan_command(console, *, domain, mode, only, exclude, authorised, timeout,
                     user_agent, headers, rustscan_ports, rustscan_timeout,
                     exploit_query, operator, note, out, json_report, html_report, quiet):
    selected_mode = "all" if only else mode
    try:
        timeout, user_agent, _ = validate_http_options(timeout, user_agent, headers)
        domain, specs = prepare(domain, selected_mode, csv(only), csv(exclude), authorised)
        module_options = validate_module_options(
            {"rustscan_ports": rustscan_ports or DEFAULT_PORTS,
             "rustscan_timeout": rustscan_timeout,
             "exploit_query": exploit_query},
            specs,
        )
    except ScanError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc

    console.print(
        f"[bold cyan]osint-enum {__version__}[/bold cyan]  "
        f"[bold]Target:[/bold] {domain}  [bold]Profile:[/bold] {selected_mode}"
    )
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
        disable=quiet or not console.is_terminal,
    )
    with progress:
        task = progress.add_task("Preparing modules", total=len(specs))

        def on_start(spec):
            progress.update(task, description=f"Running {spec.title}")

        def on_result(result):
            if not quiet:
                render_result(console, result)
            progress.advance(task)

        report = run_scan(
            domain,
            selected_mode,
            csv(only),
            csv(exclude),
            timeout,
            operator,
            note,
            authorised,
            on_start=on_start,
            on_result=on_result,
            user_agent=user_agent,
            headers=headers,
            module_options=module_options,
        )
    data = to_dict(report)
    ok = sum(result.status == "ok" for result in report.results)
    failed = sum(result.status == "failed" for result in report.results)
    skipped = sum(result.status == "skipped" for result in report.results)
    console.print(
        f"[bold]Completed:[/bold] {len(report.results)} modules · "
        f"[green]{ok} ok[/green] · [red]{failed} failed[/red] · "
        f"[yellow]{skipped} skipped[/yellow] · "
        f"{report.duration:.1f}s"
    )
    if json_report:
        console.print("JSON report:", Text(str(write_json(data, out)), style="green"))
    if html_report:
        console.print("HTML report:", Text(str(write_html(data, out)), style="green"))
    console.print(f"[dim]SHA-256: {data['integrity']['sha256']}[/dim]")
    if report.results and failed == len(report.results):
        raise typer.Exit(code=1)


def render_result(console, result):
    color = {"ok": "green", "failed": "red", "skipped": "yellow"}.get(
        result.status, "white")
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


@app.callback()
def scan(
    ctx: typer.Context,
    domain: Optional[str] = typer.Option(None, "--domain", "-d", help="Target domain or IPv4"),
    mode: Literal["passive", "active", "all"] = typer.Option(
        "passive", "--mode", "-m", help="passive, active or all"),
    only: Optional[str] = typer.Option(None, "--only", help="Comma-separated module IDs"),
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
    headers: Optional[list[str]] = typer.Option(None, "--header", help="Custom header; repeatable"),
    rustscan_ports: Optional[str] = typer.Option(None, "--rustscan-ports", help="RustScan ports"),
    rustscan_timeout: int = typer.Option(
        DEFAULT_EXECUTION_TIMEOUT, "--rustscan-timeout",
        help="RustScan execution limit in seconds (10–300)"),
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

    args = {
        "domain": domain,
        "mode": mode,
        "only": only,
        "exclude": exclude,
        "authorised": authorised,
        "timeout": timeout,
        "user_agent": user_agent,
        "headers": headers or [],
        "rustscan_ports": rustscan_ports,
        "rustscan_timeout": rustscan_timeout,
        "exploit_query": exploit_query,
        "operator": operator,
        "note": note,
        "json": json_report,
        "html": html_report,
    }
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

    run_scan_command(
        console,
        domain=args["domain"],
        mode=args["mode"],
        only=",".join(args["only"]) if isinstance(args["only"], list) else args["only"],
        exclude=args.get("exclude"),
        authorised=args["authorised"],
        timeout=args["timeout"],
        user_agent=args["user_agent"],
        headers=args["headers"],
        rustscan_ports=args["rustscan_ports"],
        rustscan_timeout=args.get("rustscan_timeout", DEFAULT_EXECUTION_TIMEOUT),
        exploit_query=args["exploit_query"],
        operator=args["operator"],
        note=args["note"],
        out=out,
        json_report=args["json"],
        html_report=args["html"],
        quiet=args.get("quiet", quiet),
    )


@app.command("modules")
def modules_command():
    """List modules and whether optional external tools are available."""
    show_modules(RichConsole())


def main(argv=None):
    app(args=argv)


if __name__ == "__main__":
    main()
