"""Allow ``python -m phase13`` when ``tools`` is on ``sys.path``."""

from .cli import main

raise SystemExit(main())
