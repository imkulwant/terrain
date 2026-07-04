from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from terrain.models import AuditFlag, AuditSeverity, Item, Snapshot

SEVERITY_STYLE = {
    AuditSeverity.critical: ("bold red", "[!]"),
    AuditSeverity.warning: ("yellow", "[~]"),
    AuditSeverity.info: ("blue", "[i]"),
}


def render_audit(
    console: Console,
    snapshot: Snapshot,
    extra_flags: list[AuditFlag] | None = None,
) -> None:
    """Render full audit report grouped by severity."""

    # Collect all flags
    all_flags: list[tuple[str, AuditFlag]] = []  # (item_name, flag)
    for item in snapshot.items:
        for flag in item.audit_flags:
            all_flags.append((item.name, flag))

    if extra_flags:
        for flag in extra_flags:
            all_flags.append(("secrets-scan", flag))

    critical = [(n, f) for n, f in all_flags if f.severity == AuditSeverity.critical]
    warnings = [(n, f) for n, f in all_flags if f.severity == AuditSeverity.warning]
    infos = [(n, f) for n, f in all_flags if f.severity == AuditSeverity.info]

    console.print(Panel(
        Text(
            f"Audit Report - Snapshot #{snapshot.id}\n"
            f"[!] {len(critical)} critical  "
            f"[~] {len(warnings)} warnings  "
            f"[i] {len(infos)} info",
            style="bold",
        ),
        border_style="red" if critical else ("yellow" if warnings else "green"),
    ))

    def render_section(
        title: str,
        items_with_flags: list[tuple[str, AuditFlag]],
        severity: AuditSeverity,
    ) -> None:
        if not items_with_flags:
            return
        style, icon = SEVERITY_STYLE[severity]
        t = Table(
            show_header=True,
            header_style="bold",
            box=None,
            padding=(0, 1),
        )
        t.add_column("Item")
        t.add_column("Message")
        t.add_column("Location")

        for item_name, flag in items_with_flags:
            t.add_row(
                Text(item_name, style="cyan"),
                Text(flag.message, style=style),
                Text(flag.location or "-", style="dim"),
            )

        console.print(Panel(
            t,
            title=f"{icon} {title} ({len(items_with_flags)})",
            border_style=style.replace("bold ", ""),
        ))

    render_section("Critical", critical, AuditSeverity.critical)
    render_section("Warnings", warnings, AuditSeverity.warning)
    render_section("Info", infos, AuditSeverity.info)

    if not all_flags:
        console.print("[bold green]No audit flags found. System looks clean.[/bold green]")
