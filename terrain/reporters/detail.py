import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from terrain.models import AuditSeverity, Item

SEVERITY_STYLE = {
    AuditSeverity.critical: ("bold red", "[!]"),
    AuditSeverity.warning: ("yellow", "[~]"),
    AuditSeverity.info: ("blue", "[i]"),
}


def render_item(console: Console, item: Item) -> None:
    """Render a detailed view of a single item."""

    # Header panel
    header = Text()
    header.append(item.name, style="bold white")
    header.append(f"  ({item.item_type.value})", style="dim")
    if item.version:
        header.append(f"\nVersion: {item.version}", style="cyan")
    header.append(f"\nSource: {item.source}", style="green")

    console.print(Panel(header, title="[bold]Item Detail[/bold]", border_style="blue"))

    # Locations
    if item.locations:
        loc_table = Table(show_header=True, header_style="bold", box=None)
        loc_table.add_column("Location")
        loc_table.add_column("Permissions")
        for loc in item.locations:
            perm = item.permissions.get(loc, "")
            loc_table.add_row(loc, perm or "-")
        console.print(Panel(loc_table, title="Locations", border_style="dim"))

    # Config paths
    if item.config_paths:
        config_table = Table(show_header=False, box=None)
        config_table.add_column("Path")
        for cp in item.config_paths:
            config_table.add_row(cp)
        console.print(Panel(config_table, title="Config Files", border_style="dim"))

    # Env vars
    if item.env_vars:
        ev_text = Text("\n".join(item.env_vars))
        console.print(Panel(ev_text, title="Env Vars", border_style="dim"))

    # Metadata
    if item.metadata:
        meta_table = Table(show_header=True, header_style="bold", box=None)
        meta_table.add_column("Key", style="cyan")
        meta_table.add_column("Value")
        for k, v in item.metadata.items():
            if isinstance(v, (list, dict)):
                val_str = json.dumps(v, indent=None)
                if len(val_str) > 120:
                    val_str = json.dumps(v, indent=2)
            else:
                val_str = str(v)
            meta_table.add_row(k, val_str)
        console.print(Panel(meta_table, title="Metadata", border_style="dim"))

    # Audit flags
    if item.audit_flags:
        flag_table = Table(show_header=True, header_style="bold", box=None)
        flag_table.add_column("Severity")
        flag_table.add_column("Message")
        flag_table.add_column("Location")
        for flag in item.audit_flags:
            style, icon = SEVERITY_STYLE[flag.severity]
            flag_table.add_row(
                Text(f"{icon} {flag.severity.value}", style=style),
                flag.message,
                flag.location or "-",
            )
        console.print(Panel(flag_table, title="Audit Flags", border_style="red"))
    else:
        console.print("[green]No audit flags[/green]")
