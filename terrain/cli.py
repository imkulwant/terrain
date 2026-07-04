from __future__ import annotations

from typing import NoReturn

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from terrain import __version__
from terrain.models import AuditSeverity, Item, ItemType

app = typer.Typer(
    name="terrain",
    help="macOS system inventory and audit tool",
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"terrain {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: bool | None = typer.Option(
        None,
        "--version",
        "-V",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    pass


def _abort(msg: str) -> NoReturn:
    err_console.print(f"[red]Error:[/red] {msg}")
    raise typer.Exit(1)


@app.command()
def scan(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show scanner errors"),
) -> None:
    """Scan this Mac and save a snapshot."""
    from terrain import store
    from terrain.scanner import scan_all

    items: list[Item] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Starting scan...", total=None)

        def progress_callback(scanner_name: str, idx: int, total: int) -> None:
            progress.update(task, description=f"[cyan]Scanning[/cyan] {scanner_name} ({idx + 1}/{total})")

        items = scan_all(progress_callback=progress_callback, verbose=verbose)

    snapshot_id = store.save_snapshot(items)

    critical = sum(
        1 for item in items for flag in item.audit_flags
        if flag.severity == AuditSeverity.critical
    )
    warnings = sum(
        1 for item in items for flag in item.audit_flags
        if flag.severity == AuditSeverity.warning
    )
    infos = sum(
        1 for item in items for flag in item.audit_flags
        if flag.severity == AuditSeverity.info
    )

    console.print(f"\n[bold green]Scan complete[/bold green] (snapshot #{snapshot_id})")
    console.print(f"  Items found: [bold]{len(items)}[/bold]")
    console.print("  Audit flags: ", end="")
    if critical:
        console.print(f"[bold red][!] {critical} critical[/bold red]  ", end="")
    if warnings:
        console.print(f"[yellow][~] {warnings} warnings[/yellow]  ", end="")
    if infos:
        console.print(f"[blue][i] {infos} info[/blue]  ", end="")
    if not (critical or warnings or infos):
        console.print("[green]none[/green]", end="")
    console.print()


@app.command()
def status() -> None:
    """Show status from the latest snapshot."""
    from terrain import store
    from terrain.reporters.overview import render_status

    latest = store.latest_snapshot()
    if not latest:
        _abort("No snapshots found. Run 'terrain scan' first.")
    previous = store.previous_snapshot()
    render_status(console, latest, previous)


@app.command("list")
def list_items(
    type_filter: str | None = typer.Option(
        None, "--type", "-t",
        help="Filter by item type (package, cask, binary, ai_config, ...)",
    ),
    source_filter: str | None = typer.Option(
        None, "--source", "-s",
        help="Filter by source (brew, pip, npm, cargo, ...)",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """List items from the latest snapshot."""
    import json as _json

    from terrain import store

    latest = store.latest_snapshot()
    if not latest:
        _abort("No snapshots found. Run 'terrain scan' first.")

    items = latest.items

    if type_filter:
        items = [i for i in items if i.item_type.value == type_filter]
    if source_filter:
        items = [i for i in items if source_filter.lower() in i.source.lower()]

    if json_output:
        typer.echo(_json.dumps([i.model_dump(mode="json") for i in items], indent=2))
        return

    if not items:
        console.print("[dim]No items match the filter.[/dim]")
        return

    t = Table(show_header=True, header_style="bold blue")
    t.add_column("Name", style="cyan")
    t.add_column("Version")
    t.add_column("Source", style="green")
    t.add_column("Type", style="dim")
    t.add_column("Flags", justify="right")

    for item in sorted(items, key=lambda x: (x.source, x.name)):
        flag_count = len(item.audit_flags)
        flag_str = ""
        if flag_count:
            crit = sum(1 for f in item.audit_flags if f.severity == AuditSeverity.critical)
            warn = sum(1 for f in item.audit_flags if f.severity == AuditSeverity.warning)
            if crit:
                flag_str = f"[red]{flag_count}[/red]"
            elif warn:
                flag_str = f"[yellow]{flag_count}[/yellow]"
            else:
                flag_str = f"[blue]{flag_count}[/blue]"
        t.add_row(
            item.name,
            item.version or "-",
            item.source,
            item.item_type.value,
            flag_str or "-",
        )

    console.print(t)
    console.print(f"\n[dim]{len(items)} items[/dim]")


@app.command()
def show(
    name: str = typer.Argument(..., help="Item name to show details for"),
) -> None:
    """Show detailed info for a specific item."""
    from terrain import store
    from terrain.reporters.detail import render_item

    latest = store.latest_snapshot()
    if not latest:
        _abort("No snapshots found. Run 'terrain scan' first.")

    matches = [i for i in latest.items if i.name.lower() == name.lower()]
    if not matches:
        # Partial match fallback
        matches = [i for i in latest.items if name.lower() in i.name.lower()]

    if not matches:
        _abort(f"No item found with name '{name}'")

    for item in matches:
        render_item(console, item)
        if len(matches) > 1:
            console.print("")


@app.command()
def diff() -> None:
    """Show diff between the two most recent snapshots."""
    from terrain import store
    from terrain.reporters.diff import render_diff

    latest = store.latest_snapshot()
    if not latest:
        _abort("No snapshots found. Run 'terrain scan' first.")

    previous = store.previous_snapshot()
    if not previous:
        _abort("Only one snapshot exists. Need at least two to diff.")

    render_diff(console, latest, previous)


@app.command()
def audit(
    json_output: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Show all audit flags from the latest snapshot."""
    import json as _json

    from terrain import store
    from terrain.audit.secrets import scan_common_dotfiles
    from terrain.reporters.audit import render_audit

    latest = store.latest_snapshot()
    if not latest:
        _abort("No snapshots found. Run 'terrain scan' first.")

    extra_flags = scan_common_dotfiles()

    if json_output:
        all_flags = []
        for item in latest.items:
            for flag in item.audit_flags:
                all_flags.append({"item": item.name, **flag.model_dump(mode="json")})
        for flag in extra_flags:
            all_flags.append({"item": "secrets-scan", **flag.model_dump(mode="json")})
        typer.echo(_json.dumps(all_flags, indent=2))
        return

    render_audit(console, latest, extra_flags)


@app.command()
def bins(
    orphans_only: bool = typer.Option(
        False, "--orphans-only", help="Only show direct/curl installs"
    ),
) -> None:
    """List all binaries found in PATH directories."""
    from terrain import store

    latest = store.latest_snapshot()
    if not latest:
        _abort("No snapshots found. Run 'terrain scan' first.")

    bin_items = [i for i in latest.items if i.item_type == ItemType.binary]

    if orphans_only:
        bin_items = [i for i in bin_items if i.source == "direct_install"]

    if not bin_items:
        console.print("[dim]No binaries found.[/dim]")
        return

    t = Table(show_header=True, header_style="bold blue")
    t.add_column("Name", style="cyan")
    t.add_column("Location")
    t.add_column("Source", style="green")
    t.add_column("Permissions")
    t.add_column("Version")
    t.add_column("Modified", style="dim")

    for item in sorted(bin_items, key=lambda x: x.name):
        loc = item.locations[0] if item.locations else "-"
        perm = item.permissions.get(loc, "-") if loc != "-" else "-"
        modified = item.metadata.get("modified", "-")
        if modified and modified != "-":
            modified = modified[:10]  # date only
        t.add_row(
            item.name,
            loc,
            item.source,
            perm,
            item.version or "-",
            modified,
        )

    console.print(t)
    console.print(f"\n[dim]{len(bin_items)} binaries[/dim]")


@app.command()
def ai() -> None:
    """Show all AI tool configurations."""
    from terrain import store

    latest = store.latest_snapshot()
    if not latest:
        _abort("No snapshots found. Run 'terrain scan' first.")

    ai_items = [i for i in latest.items if i.item_type == ItemType.ai_config]
    if not ai_items:
        console.print("[dim]No AI config items found.[/dim]")
        return

    import json

    from rich.panel import Panel

    for item in ai_items:
        content_lines: list[str] = []

        # Source
        content_lines.append(f"[dim]Source:[/dim] {item.source}")

        # Models configured
        models = item.metadata.get("models") or (
            [item.metadata["model"]] if item.metadata.get("model") else []
        )
        if models:
            content_lines.append(f"[dim]Models:[/dim] {', '.join(str(m) for m in models)}")

        # MCP servers
        mcp = item.metadata.get("mcp_servers", [])
        if mcp:
            content_lines.append(f"[dim]MCP Servers:[/dim] {', '.join(mcp)}")

        # Hooks
        hooks = item.metadata.get("hooks")
        if hooks:
            content_lines.append(f"[dim]Hooks:[/dim] {json.dumps(hooks, indent=None)[:200]}")

        # Server running (Ollama)
        if "server_running" in item.metadata:
            running = item.metadata["server_running"]
            status = "[green]running[/green]" if running else "[dim]stopped[/dim]"
            content_lines.append(f"[dim]Server:[/dim] {status}")

        # Config paths
        if item.config_paths:
            content_lines.append("\n[dim]Config files:[/dim]")
            for cp in item.config_paths[:8]:
                content_lines.append(f"  {cp}")
            if len(item.config_paths) > 8:
                content_lines.append(f"  ... and {len(item.config_paths) - 8} more")

        # Audit flags
        if item.audit_flags:
            content_lines.append("\n[bold]Audit flags:[/bold]")
            for flag in item.audit_flags:
                if flag.severity.value == "critical":
                    icon = "[bold red][!][/bold red]"
                elif flag.severity.value == "warning":
                    icon = "[yellow][~][/yellow]"
                else:
                    icon = "[blue][i][/blue]"
                content_lines.append(f"  {icon} {flag.message}")

        body = "\n".join(content_lines)

        console.print(Panel(
            body,
            title=f"[bold cyan]{item.name}[/bold cyan]",
            border_style="cyan",
        ))


@app.command()
def where(
    name: str = typer.Argument(..., help="Tool or binary name to locate"),
) -> None:
    """Find where a tool or binary lives across all items."""
    from terrain import store

    latest = store.latest_snapshot()
    if not latest:
        _abort("No snapshots found. Run 'terrain scan' first.")

    name_lower = name.lower()
    results: list[tuple[Item, str]] = []  # (item, matching_location)

    for item in latest.items:
        # Match by item name
        if name_lower in item.name.lower():
            for loc in item.locations:
                results.append((item, loc))
            if not item.locations:
                results.append((item, "-"))

        # Match by location path
        else:
            for loc in item.locations:
                if name_lower in loc.lower():
                    results.append((item, loc))

    if not results:
        console.print(f"[dim]Nothing found for '{name}'[/dim]")
        return

    t = Table(show_header=True, header_style="bold blue")
    t.add_column("Name", style="cyan")
    t.add_column("Location")
    t.add_column("Source", style="green")
    t.add_column("Version")
    t.add_column("Type", style="dim")

    seen: set[tuple[str, str]] = set()
    for item, loc in results:
        key = (item.name, loc)
        if key in seen:
            continue
        seen.add(key)
        t.add_row(item.name, loc, item.source, item.version or "-", item.item_type.value)

    console.print(t)


if __name__ == "__main__":
    app()
