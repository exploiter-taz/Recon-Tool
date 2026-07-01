# Module Contract

> Official development guide for contributors to the Reconnaissance Framework.

---

## 1. Purpose

This document defines the contract every recon module must satisfy. It is the single source of truth for how modules interact with the engine, the shared context, and the logging system.

Contributors **must** read this document before implementing any module.

---

## 2. Architecture Overview

The framework follows a linear pipeline architecture:

```
CLI ──→ Engine ──→ [Module₁, Module₂, …, Moduleₙ] ──→ Context
```

| Layer | Responsibility |
|---|---|
| `cli.py` | Parse CLI arguments into a namespace. |
| `core/engine.py` | Orchestrate module execution sequentially. |
| `core/context.py` | Carry shared state across the pipeline. |
| `core/logger.py` | Provide centralized logging (console + file). |
| `modules/` | Implement recon logic — each module is a class. |
| `reports/` | Format results (not covered by this contract). |

All modules share a single `Context` instance. Each module reads what it needs and writes what it produces. The engine never inspects module internals — it only calls `validate()` and `run()`.

---

## 3. BaseReconModule Contract

Every module **must** inherit from `BaseReconModule` and implement all four members.

```python
from abc import ABC, abstractmethod
from core.context import Context


class BaseReconModule(ABC):

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this module (e.g. ``"whois"``)."""

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of what this module does."""

    @abstractmethod
    def validate(self, context: Context) -> bool:
        """Return True if the module can run with the given context."""

    @abstractmethod
    def run(self, context: Context) -> None:
        """Execute the module and write results into *context*."""
```

### Rules

- `name` must be a short, lowercase, unique string.
- `description` must be a complete sentence.
- `validate()` must be side-effect-free — it only inspects, never modifies context.
- `run()` must **never** return a value. All output goes into `context`.
- `run()` must handle its own errors internally (see §7).

---

## 4. Context Object

`Context` is the shared state object passed between all modules. New fields may be introduced when they become part of the project's public contract.

```python
@dataclass
class Context:
    target: str
    whois:        dict[str, Any] | None = None
    dns:          dict[str, Any] | None = None
    subdomains:   list[str]        | None = None
    open_ports:   list[int]        | None = None
    banners:      list[dict[str, Any]] | None = None
    technologies: list[dict[str, Any]] | None = None
    data:         dict[str, Any]   = field(default_factory=dict)
```

### Access rules

| Access pattern | Allowed? | Example |
|---|---|---|
| Attribute read | ✅ | `context.target` |
| Attribute write | ✅ | `context.whois = {...}` |
| `data` dict read/write | ✅ | `context.data["raw_html"] = ...` |
| Subscript on top-level fields | ❌ | `context["target"]` — `Context` is **not** a dict |

### When to use `data`

Use the `data` dictionary for module-specific or ephemeral values that do not warrant a dedicated field on `Context`. Promotable fields (used by multiple modules) should be added to `Context` as first-class attributes.

---

## 5. Module Lifecycle

Each module passes through four phases during a single scan.

```
                      ┌─────────────┐
                      │  Instantiate │  (engine startup)
                      └──────┬──────┘
                             ▼
                      ┌─────────────┐
                      │  validate() │  side-effect-free check
                      └──────┬──────┘
                      ┌──────┴──────┐
                      │    True     │  False → module skipped, log warning
                      └──────┬──────┘
                             ▼
                      ┌─────────────┐
                      │    run()    │  mutate context, may raise
                      └──────┬──────┘
                      ┌──────┴──────┐
                      │  on error   │  log exception, continue pipeline
                      └─────────────┘
```

### Sequence guarantees

- Modules run in the order they are passed to `Engine(modules)`.
- `validate()` is called immediately before `run()` for the same module.
- The engine never reorders, skips (except on validation failure), or parallelises modules.

---

## 6. Logging Rules

The framework uses Python's standard `logging` module. The root logger is configured once at application startup by `core.logger.setup_logger()` (console + file handler).

### How to log in a module

```python
import logging

logger = logging.getLogger(__name__)   # ← correct pattern

logger.debug("…")
logger.info("…")
logger.warning("…")
logger.error("…")
```

### Rules

| Do | Don't |
|---|---|
| Use `logging.getLogger(__name__)` | ❌ Use `logging.getLogger("my_module")` |
| Use structured messages (%-formatting) | ❌ Use f-strings in log calls |
| Log at `INFO` for normal lifecycle events | ❌ Log at `DEBUG` for errors |
| Log at `WARNING` for recoverable issues | ❌ Log at `ERROR` for validation failures |
| Log at `ERROR` for unexpected failures | ❌ Suppress exceptions silently |

**Never** call `logging.basicConfig()` or `setup_logger()` inside a module — configuration is the application entry point's responsibility.

---

## 7. Error Handling

Modules are responsible for their own error recovery. The engine wraps every `run()` call in a `try/except Exception` to guarantee pipeline continuity.

### Guidelines

- **Recoverable errors** (timeout, rate-limit, empty response) → log at `WARNING`, set the relevant context field to `None` or `[]`, and return normally.
- **Unrecoverable errors** (invalid target format, missing dependency) → preferably catch in `validate()` and return `False` so the module is skipped cleanly.
- **Genuine bugs** → let them raise. The engine catches `Exception`, logs the traceback, and moves to the next module. The scan continues.

### Anti-pattern

```python
# ❌ Do not let the engine catch everything — handle known failures.
def run(self, context: Context) -> None:
    try:
        data = api.call(context.target)
    except ApiError:
        logger.warning("WHOIS API unavailable for %s", context.target)
        context.whois = None
        return
    context.whois = data
```

---

## 8. Coding Standards

| Requirement | Standard |
|---|---|
| Python version | 3.12 |
| Type hints | Required on every public method and property |
| Docstrings | Google-style (as shown in `BaseReconModule`) |
| Class style | One module class per file, single responsibility |
| Max line length | 88 characters (soft) |
| Imports | Standard library → third-party → project, one section per blank line |
| Naming | `snake_case` for methods/attributes, `PascalCase` for classes, `UPPER_CASE` for constants |

All code MUST pass `mypy --strict` and `ruff` (or equivalent linter) before submission.

---

## 9. Project Flow

A complete scan proceeds as follows:

```
                ┌──────────────┐
                │  User runs   │
                │  recon-tool  │
                └──────┬───────┘
                       ▼
                ┌──────────────┐
                │  cli.parse_  │  returns argparse.Namespace
                │  args()      │
                └──────┬───────┘
                       ▼
                ┌──────────────┐
                │  Create      │  Context(target=args.target)
                │  Context     │
                └──────┬───────┘
                       ▼
                ┌──────────────┐
                │  Select      │  based on --flags / --all
                │  modules     │
                └──────┬───────┘
                       ▼
                ┌──────────────┐
                │  Engine(     │
                │   modules)   │
                │  .run(       │
                │   context)   │
                └──────┬───────┘
                       ▼
                ┌──────────────┐
                │  for each    │  validate() → run()
                │  module      │
                └──────┬───────┘
                       ▼
                ┌──────────────┐
                │  Report      │  read context, format output
                │  generator   │
                └──────────────┘
```

The application entry point (`main.py`) is responsible for:
1. Calling `setup_logger()`.
2. Calling `parse_args()`.
3. Building the `Context`.
4. Selecting modules based on flags.
5. Running `Engine(modules).run(context)`.
6. Dispatching to the appropriate report generator.

---

## 10. Do's and Don'ts

### Do

- ✅ Inherit from `BaseReconModule`.
- ✅ Use `logging.getLogger(__name__)` for all loggers.
- ✅ Mutate `context` directly in `run()`.
- ✅ Keep `validate()` pure — no side effects, no network calls.
- ✅ Catch and handle known failure modes inside the module.
- ✅ Write one module class per file.
- ✅ Add new fields to `Context` or use `context.data` when a module produces novel data.

### Don't

- ❌ Return a value from `run()` — the engine ignores it.
- ❌ Treat `context` as a `dict` — use attribute access.
- ❌ Call `setup_logger()` or `logging.basicConfig()` from a module.
- ❌ Use f-strings in log messages (`logger.info(f"...")`) — use `%`-formatting.
- ❌ Import from `core.engine` inside a module — you only need `Context`.
- ❌ Import from `core.logger` inside a module — use the project's logging configuration instead.
- ❌ Add async/await — the current implementation is synchronous. Async execution is reserved for future versions.
- ❌ Modify the module contract (`BaseReconModule`, `Context`) — changes require approval from the project maintainers.
- ❌ Create new top-level directories — major architectural changes should be discussed before implementation.

---

## 11. Example Module Skeleton

```python
"""WHOIS lookup module."""

import logging
from datetime import datetime

from core.context import Context
from modules.base import BaseReconModule

logger = logging.getLogger(__name__)


class WhoisModule(BaseReconModule):
    """Retrieve WHOIS information for the target domain."""

    @property
    def name(self) -> str:
        return "whois"

    @property
    def description(self) -> str:
        return "Perform a WHOIS lookup against the target domain."

    def validate(self, context: Context) -> bool:
        # Accept only non-empty targets that look like domain names.
        return bool(context.target) and "." in context.target

    def run(self, context: Context) -> None:
        try:
            # Perform lookup — implementation omitted.
            data = self._lookup(context.target)
        except ConnectionError:
            logger.warning("WHOIS server unreachable for %s", context.target)
            context.whois = None
            return

        context.whois = data
        logger.info("WHOIS data collected for %s", context.target)

    def _lookup(self, target: str) -> dict:
        # Private helper — not part of the contract.
        ...
```

---

## 12. Best Practices

### Composition over inheritance

Use private methods (prefixed with `_`) inside your module to break complex logic into readable steps. The module class is a **controller** — it orchestrates, not implements every detail.

### Defensive validation

Be generous in what you accept, but validate early. If a module requires `context.open_ports` to be set, check for `None` in `validate()` and return `False` instead of crashing in `run()`.

### Granular context writes

Write only the fields your module owns. Do not clear or overwrite fields set by other modules. If your module depends on another module's output, document the dependency in the module's docstring.

### Log context

Log the module name and target in every significant log line so that logs are traceable without grepping for timestamps.

### Keep data portable

Prefer primitive types (`dict`, `list`, `str`, `int`) in context fields. Avoid storing custom class instances, file handles, or network sockets — the context must be serialisable for report generation.

### Test in isolation

Each module should be unit-testable without the engine. Instantiate a `Context` with known values, call `run()`, and assert on the relevant context field.

```
tests/
├── test_whois.py
├── test_dns.py
├── test_portscan.py
└── ...
```

---

## 13. Git Workflow

The team follows a feature-branch workflow. Direct commits to `main` are **never** permitted.

```
main ────●────────────────────●────────────────
          \                  /
feature  └──●──●──●─────────┘
            commit  commit  Pull Request
                            → review → merge
                            → delete branch
```

### Steps

1. **Create a feature branch** from the latest `main`.

   | Task | Branch name |
   |---|---|
   | WHOIS module | `feature/whois` |
   | DNS module | `feature/dns` |
   | Engine implementation | `feature/engine` |
   | HTML report | `feature/report-html` |

2. **Commit frequently** with meaningful, present-tense messages.

   ```
   Add WHOIS lookup via python-whois
   Handle connection timeout gracefully
   Populate context.whois with parsed record
   ```

3. **Push the branch** to the remote.

   ```
   git push origin feature/whois
   ```

4. **Open a Pull Request** against `main`.

5. **Request a review** from at least one maintainer.

6. **Address all review comments** before merging.

7. **Delete the branch** after the PR is merged (remote and local).

---

## 14. Getting Started for Contributors

Follow these steps to start contributing after cloning the repository.

### Setup

```bash
# 1. Clone the repository
git clone <repo-url>
cd recon-tool

# 2. Create and activate a Python virtual environment
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

### Development workflow

1. Read `docs/module_contract.md` — this document.
2. Read the assigned GitHub Issue or task description carefully.
3. Create a feature branch:

   ```bash
   git checkout -b feature/your-module
   ```

4. Implement only the assigned module.
5. Follow the `BaseReconModule` contract (§3).
6. Test the module in isolation (§12).
7. Commit your changes:

   ```bash
   git add modules/active/your_module.py
   git commit -m "Add your-module implementation"
   ```

8. Push the branch and open a Pull Request.

### Before opening a Pull Request — checklist

- [ ] Code follows the `BaseReconModule` contract.
- [ ] No architecture changes — no new folders, no renamed files, no new abstractions.
- [ ] Logging uses `logging.getLogger(__name__)` with `%`-formatting.
- [ ] Type hints are present on every public method and property.
- [ ] Tests pass.
- [ ] No unnecessary dependencies added to `requirements.txt`.

---

*Last updated: 2026-07-01*
*Contract version: 1.0.0*
