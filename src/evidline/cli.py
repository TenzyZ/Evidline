"""Foundation command-line interface for Evidline."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from evidline import __version__


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="evidline")
    parser.add_argument("--version", action="version", version=__version__)
    parser.parse_args(argv)
    return 0
