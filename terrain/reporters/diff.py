from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from terrain.models import Item, ItemType, Snapshot


def _item_key(item: Item) -> tuple[str, str]:
    return (item.name, item.source)


def render_diff(
    console: Console,
    latest: Snapshot,
    previous: Snapshot,
) -> None:
    """Render a diff between two snapshots."""
    prev_map = {_item_key(i): i for i in previous.items}
    curr_map = {_item_key(i): i for i in latest.items}

    prev_keys = set(prev_map.keys())
    curr_keys = set(curr_map.keys())

    added_keys = curr_keys - prev_keys
    removed_keys = prev_keys - curr_keys
    common_keys = prev_keys & curr_keys

    # Find changed items (version changed)
    changed: list[tuple[Item, Item]] = []  # (old, new)
    for key in common_keys:
        old = prev_map[key]
        new = curr_map[key]
        if old.version != new.version:
            changed.append((old, new))

    added = [curr_map[k] for k in sorted(added_keys)]
    removed = [prev_map[k] for k in sorted(removed_keys)]

    if not added and not removed and not changed:
        console.print("[green]No changes between snapshots.[/green]")
        return

    prev_time = previous.scanned_at.strftime("%Y-%m-%d %H:%M:%S")
    curr_time = latest.scanned_at.strftime("%Y-%m-%d %H:%M:%S")
    console.print(Panel(
        Text(f"Comparing snapshot #{previous.id} ({prev_time})\n"
             f"     with snapshot #{latest.id} ({curr_time})"),
        title="[bold]Diff[/bold]",
        border_style="blue",
    ))

    # Group by type
    def group_by_type(items: list[Item]) -> dict[str, list[Item]]:
        groups: dict[str, list[Item]] = {}
        for item in items:
            groups.setdefault(item.item_type.value, []).append(item)
        return groups

    if added:
        console.print(f"\n[bold green][+] Added ({len(added)})[/bold green]")
        for type_name, type_items in sorted(group_by_type(added).items()):
            console.print(f"  [dim]{type_name}[/dim]")
            t = Table(show_header=False, box=None, padding=(0, 2))
            t.add_column("Name", style="green")
            t.add_column("Version", style="cyan")
            t.add_column("Source", style="dim")
            for item in type_items:
                t.add_row(f"[+] {item.name}", item.version or "-", item.source)
            console.print(t)

    if removed:
        console.print(f"\n[bold red][-] Removed ({len(removed)})[/bold red]")
        for type_name, type_items in sorted(group_by_type(removed).items()):
            console.print(f"  [dim]{type_name}[/dim]")
            t = Table(show_header=False, box=None, padding=(0, 2))
            t.add_column("Name", style="red")
            t.add_column("Version", style="cyan")
            t.add_column("Source", style="dim")
            for item in type_items:
                t.add_row(f"[-] {item.name}", item.version or "-", item.source)
            console.print(t)

    if changed:
        console.print(f"\n[bold yellow][~] Updated ({len(changed)})[/bold yellow]")
        t = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
        t.add_column("Name")
        t.add_column("Old Version", style="red")
        t.add_column("New Version", style="green")
        t.add_column("Source", style="dim")
        for old, new in sorted(changed, key=lambda x: x[0].name):
            t.add_row(
                f"[~] {new.name}",
                old.version or "-",
                new.version or "-",
                new.source,
            )
        console.print(t)
