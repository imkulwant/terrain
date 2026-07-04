import subprocess
import sys
from typing import Any

from terrain.models import Item


class BaseScanner:
    name: str = "base"

    def scan(self) -> list[Item]:
        raise NotImplementedError

    def _run(self, cmd: list[str], **kwargs) -> tuple[str, int]:
        """Run a shell command, return (stdout, returncode). Never raises."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=kwargs.pop("timeout", 30),
                **kwargs,
            )
            return result.stdout.strip(), result.returncode
        except subprocess.TimeoutExpired:
            return "", 1
        except FileNotFoundError:
            return "", 127
        except Exception as e:
            if "--verbose" in sys.argv:
                print(f"[{self.name}] error running {cmd}: {e}", file=sys.stderr)
            return "", 1

    def _run_shell(self, cmd: str, **kwargs) -> tuple[str, int]:
        """Run a shell string command (uses shell=True). Never raises."""
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=kwargs.pop("timeout", 30),
                **kwargs,
            )
            return result.stdout.strip(), result.returncode
        except subprocess.TimeoutExpired:
            return "", 1
        except Exception as e:
            if "--verbose" in sys.argv:
                print(f"[{self.name}] error running shell cmd: {e}", file=sys.stderr)
            return "", 1

    def _which(self, name: str) -> str | None:
        """Return path to binary or None if not found."""
        out, rc = self._run(["which", name])
        if rc == 0 and out:
            return out
        return None
