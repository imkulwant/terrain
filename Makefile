PYTHON := /Users/kulsin/.local/pipx/venvs/terrain/bin/python

.PHONY: check install test lint typecheck clean

check: install lint typecheck test

install:
	$(PYTHON) -m pip install -e ".[dev]" -q

test:
	$(PYTHON) -m pytest

lint:
	$(PYTHON) -m ruff check terrain/ tests/

typecheck:
	$(PYTHON) -m mypy terrain/

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name ".mypy_cache" -exec rm -rf {} +
