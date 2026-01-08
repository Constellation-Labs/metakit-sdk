.PHONY: help install test lint format build clean

help:
	@echo "Constellation Metagraph SDK"
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@echo "  install     Install dependencies for all packages"
	@echo "  test        Run tests for all packages"
	@echo "  lint        Run linters for all packages"
	@echo "  format      Format code in all packages"
	@echo "  build       Build all packages"
	@echo "  clean       Clean build artifacts"
	@echo ""
	@echo "Per-language targets:"
	@echo "  install-ts, test-ts, lint-ts, format-ts, build-ts"
	@echo "  install-py, test-py, lint-py, format-py"
	@echo "  install-rs, test-rs, lint-rs, format-rs, build-rs"
	@echo "  install-go, test-go, lint-go, format-go, build-go"

# TypeScript targets
install-ts:
	cd packages/typescript && npm install

test-ts:
	cd packages/typescript && npm test

lint-ts:
	cd packages/typescript && npm run lint

format-ts:
	cd packages/typescript && npm run format

build-ts:
	cd packages/typescript && npm run build

clean-ts:
	rm -rf packages/typescript/dist packages/typescript/coverage packages/typescript/node_modules

# Python targets
PYTHON_VENV := packages/python/.venv
PYTHON := $(PYTHON_VENV)/bin/python

install-py:
	python3 -m venv $(PYTHON_VENV)
	$(PYTHON) -m pip install --upgrade pip setuptools wheel
	$(PYTHON) -m pip install -e packages/python[dev]

test-py:
	$(PYTHON) -m pytest packages/python/tests

lint-py:
	$(PYTHON) -m ruff check packages/python/src packages/python/tests
	$(PYTHON) -m black --check packages/python/src packages/python/tests
	$(PYTHON) -m isort --check-only packages/python/src packages/python/tests

format-py:
	$(PYTHON) -m black packages/python/src packages/python/tests
	$(PYTHON) -m isort packages/python/src packages/python/tests

clean-py:
	rm -rf packages/python/.venv packages/python/.pytest_cache packages/python/.mypy_cache packages/python/dist packages/python/*.egg-info packages/python/src/*.egg-info

# Rust targets
install-rs:
	@echo "Rust dependencies managed by Cargo"

test-rs:
	cd packages/rust && cargo test

lint-rs:
	cd packages/rust && cargo clippy -- -D warnings

format-rs:
	cd packages/rust && cargo fmt

build-rs:
	cd packages/rust && cargo build --release

clean-rs:
	cd packages/rust && cargo clean

# Go targets
install-go:
	cd packages/go && go mod download

test-go:
	cd packages/go && go test -v ./...

lint-go:
	cd packages/go && go vet ./...

format-go:
	cd packages/go && go fmt ./...

build-go:
	cd packages/go && go build ./...

clean-go:
	cd packages/go && go clean

# Combined targets
install: install-ts install-py install-go
	@echo "Note: Rust uses Cargo for dependencies"

test: test-ts test-py test-rs test-go

lint: lint-ts lint-py lint-rs lint-go

format: format-ts format-py format-rs format-go

build: build-ts build-rs build-go

clean: clean-ts clean-py clean-rs clean-go