from collections import Counter
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from terrain.models import AuditSeverity, ItemType, Snapshot


def render_status(
    console: Console,
    latest: Snapshot,
    previous: Snapshot | None = None,
) -> None:
    """Render the status overview panel."""
    # Counts by type
    type_counts: Counter = Counter()
    source_counts: Counter = Counter()
    flag_counts: Counter = Counter()
    total_flags = 0

    for item in latest.items:
        type_counts[item.item_type] += 1
        source_counts[item.source] += 1
        for flag in item.audit_flags:
            flag_counts[flag.severity] += 1
            total_flags += 1

    # Time info
    scanned_at = latest.scanned_at.strftime("%Y-%m-%d %H:%M:%S")
    time_text = Text(f"Last scan: {scanned_at}", style="dim")

    # Build type table
    type_table = Table(show_header=True, header_style="bold blue", box=None)
    type_table.add_column("Type", style="cyan")
    type_table.add_column("Count", justify="right")

    type_order = [
        ItemType.package,
        ItemType.cask,
        ItemType.app_store,
        ItemType.language_version,
        ItemType.binary,
        ItemType.ai_config,
        ItemType.launch_agent,
        ItemType.launch_daemon,
        ItemType.shell_config,
    ]
    for itype in type_order:
        count = type_counts.get(itype, 0)
        if count > 0:
            type_table.add_row(itype.value, str(count))

    # Audit flags summary
    critical = flag_counts.get(AuditSeverity.critical, 0)
    warning = flag_counts.get(AuditSeverity.warning, 0)
    info = flag_counts.get(AuditSeverity.info, 0)

    flags_text = Text()
    if critical:
        flags_text.append(f"[!] {critical} critical", style="bold red")
        flags_text.append("  ")
    if warning:
        flags_text.append(f"[~] {warning} warning", style="yellow")
        flags_text.append("  ")
    if info:
        flags_text.append(f"[i] {info} info", style="blue")

    if not total_flags:
        flags_text.append("[+] No audit flags", style="green")

    # What changed since previous scan
    diff_text = Text()
    if previous:
        prev_names = {(item.name, item.source) for item in previous.items}
        curr_names = {(item.name, item.source) for item in latest.items}
        added = curr_names - prev_names
        removed = prev_names - curr_names
        if added or removed:
            diff_text.append(f"[+] {len(added)} added  ", style="green")
            diff_text.append(f"[-] {len(removed)} removed", style="red")
        else:
            diff_text.append("No changes since previous scan", style="dim")
    else:
        diff_text.append("No previous snapshot to compare", style="dim")

    # Compose panel
    from rich.columns import Columns
    from rich import box as rich_box

    summary_lines = [
        time_text,
        Text(f"Total items: {len(latest.items)}", style="bold"),
        Text(""),
        type_table,
        Text(""),
        Text("Audit flags:", style="bold"),
        flags_text,
        Text(""),
        Text("Changes:", style="bold"),
        diff_text,
    ]

    # Render each element
    console.print(Panel(
        Text(f"terrain - system inventory snapshot #{latest.id}", style="bold white"),
        border_style="blue",
    ))
    console.print(time_text)
    console.print(Text(f"Total items: {len(latest.items)}", style="bold"))
    console.print("")
    console.print(type_table)
    console.print("")
    console.print(Text("Audit flags:", style="bold"))
    console.print(flags_text)
    console.print("")
    console.print(Text("Changes:", style="bold"))
    console.print(diff_text)
