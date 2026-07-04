import sys
import traceback
from typing import Callable

from terrain.models import Item
from terrain.scanners.base import BaseScanner
from terrain.scanners.brew import BrewScanner
from terrain.scanners.pip import PipScanner
from terrain.scanners.npm import NpmScanner
from terrain.scanners.cargo import CargoScanner
from terrain.scanners.gem import GemScanner
from terrain.scanners.mas import MasScanner
from terrain.scanners.pyenv import PyenvScanner
from terrain.scanners.jenv import JenvScanner
from terrain.scanners.nvm import NvmScanner
from terrain.scanners.mise import MiseScanner
from terrain.scanners.bins import BinsScanner
from terrain.scanners.ai_configs import AIConfigsScanner
from terrain.scanners.launchd import LaunchdScanner
from terrain.scanners.shell import ShellScanner
from terrain.scanners.ssh import SSHScanner
from terrain.scanners.path_dirs import PathDirsScanner

# BinsScanner is handled separately for post-processing
_BINS_SCANNER = BinsScanner()

_PRIMARY_SCANNERS: list[BaseScanner] = [
    BrewScanner(),
    PipScanner(),
    NpmScanner(),
    CargoScanner(),
    GemScanner(),
    MasScanner(),
    PyenvScanner(),
    JenvScanner(),
    NvmScanner(),
    MiseScanner(),
    AIConfigsScanner(),
    LaunchdScanner(),
    ShellScanner(),
    SSHScanner(),
    PathDirsScanner(),
]

ALL_SCANNERS: list[BaseScanner] = _PRIMARY_SCANNERS + [_BINS_SCANNER]


def scan_all(
    progress_callback: Callable[[str, int, int], None] | None = None,
    verbose: bool = False,
) -> list[Item]:
    items: list[Item] = []
    total = len(ALL_SCANNERS)

    # Run primary scanners first
    for idx, scanner in enumerate(_PRIMARY_SCANNERS):
        if progress_callback:
            progress_callback(scanner.name, idx, total)
        try:
            result = scanner.scan()
            items.extend(result)
        except Exception as e:
            if verbose:
                print(
                    f"[scanner:{scanner.name}] ERROR: {e}",
                    file=sys.stderr,
                )
                traceback.print_exc(file=sys.stderr)

    # Pass known items to BinsScanner for orphan cross-referencing
    _BINS_SCANNER.set_known_items(items)

    if progress_callback:
        progress_callback(_BINS_SCANNER.name, len(_PRIMARY_SCANNERS), total)

    try:
        bin_results = _BINS_SCANNER.scan()
        items.extend(bin_results)
    except Exception as e:
        if verbose:
            print(f"[scanner:bins] ERROR: {e}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)

    return items
