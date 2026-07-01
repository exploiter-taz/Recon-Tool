# Contributing

Thank you for your interest in contributing to **Recon Tool**. We welcome all kinds of contributions — whether it is a new feature, a bug fix, improved documentation, writing tests, or simply asking a question.

This project is driven by its community. Every issue report, pull request, and discussion helps make the tool better for everyone.

This document describes how to contribute code, report issues, and work with the team. For details about the module architecture and the `BaseReconModule` contract, see [`docs/module_contract.md`](docs/module_contract.md).

---

## Before You Start

1. **Read [`README.md`](README.md)** — understand the project scope.
2. **Read [`docs/module_contract.md`](docs/module_contract.md)** — understand the module contract, the `Context` object, logging rules, and coding standards.
3. **Understand your assigned task** before writing any code. If the task is unclear, ask in the related GitHub Issue or Discussion.

---

## Development Workflow

```
main    ──●─────────────────────────●──
           \                       /
feature   └──●──●──●──●──●──●─────┘
             commit  …  push   Pull Request
                                → review → merge
```

1. **Pull the latest changes** from `main`.
2. **Create a feature branch** (see [Branch Naming](#branch-naming)).
3. **Implement only the assigned task.** Do not refactor unrelated code.
4. **Test locally** — verify the module works and existing tests still pass.
5. **Commit with meaningful messages** (see [Commit Message Convention](#commit-message-convention)).
6. **Push the branch** to the remote.
7. **Open a Pull Request** against `main`.
8. **Address review comments** — discuss, amend, and push updates.
9. **Merge after approval** — a maintainer will merge once all feedback is resolved.

---

## Branch Naming

Use a short prefix that describes the type of work, followed by a slash and a descriptive name.

| Work type | Branch example |
|---|---|
| New feature | `feature/whois` |
| New feature | `feature/dns` |
| New feature | `feature/subdomains` |
| New feature | `feature/portscan` |
| New feature | `feature/engine` |
| New feature | `feature/report-html` |
| Bug fix | `fix/logger` |
| Documentation | `docs/readme` |
| Tests | `test/portscan` |

Branch names should describe the task being implemented, not the developer.

✅ `feature/whois`
❌ `feature/mohamed`

Use lowercase and hyphens to separate words.

---

## Commit Message Convention

This project uses [Conventional Commits](https://www.conventionalcommits.org/).

```
<type>(<scope>): <short summary>
```

**Types:** `feat`, `fix`, `docs`, `test`, `refactor`, `chore`

**Scope:** module or component name (e.g. `whois`, `core`, `passive`, `report`, `engine`)

### Examples

```
feat(whois): implement WHOIS lookup
feat(core): implement execution engine
feat(passive): add DNS lookup
feat(report): generate HTML report
fix(engine): handle module failures without halting
docs: update contribution guide
test(portscan): add unit tests for port scanning
refactor(logger): simplify handler setup
chore(deps): pin requests to >=2.32
```

- Use the imperative, present tense ("add", not "added" / "adds").
- Keep the summary under 72 characters.
- Do not end with a period.

---

## Pull Request Guidelines

- **One feature per PR.** A single PR should address one task or issue.
- **Keep PRs small.** A Pull Request should be reviewable within approximately 15–30 minutes. If it becomes too large, split it into multiple PRs.
- **Describe changes clearly.** Explain what the PR does and why.
- **Reference related issues** using `Closes #123` or `Relates to #456` in the PR description.
- **Do not include unrelated changes** — no formatting cleanups, no renamed variables outside the scope of the task.

---

## Code Quality Expectations

- **Follow the module contract** — see [`docs/module_contract.md`](docs/module_contract.md) for the `BaseReconModule` interface, `Context` usage, and validation rules.
- **Use type hints** on every public method and property.
- **Write Google-style docstrings** for every public method.
- **Use centralized logging** — call `logging.getLogger(__name__)`, never configure loggers yourself.
- **Do not introduce unnecessary dependencies.** Before adding a package to `requirements.txt`, consider whether the standard library suffices.
- **Keep functions focused and readable.** A function should do one thing.
- **Prefer readability over clever code.** Write code that is easy to understand at a glance.
- **Avoid premature optimization.** Optimise only when profiling shows it is necessary.

---

## Pull Request Checklist

Before opening a PR, confirm the following:

- [ ] I have read [`docs/module_contract.md`](docs/module_contract.md).
- [ ] My code follows the project architecture and module contract.
- [ ] All existing tests pass, and I have added tests for new functionality.
- [ ] Logging follows the project convention (`logging.getLogger(__name__)`, `%`-formatting).
- [ ] Type hints are present on all public methods and properties.
- [ ] No unnecessary dependencies have been added.
- [ ] Documentation has been updated if my change requires it.

---

## Code Review Expectations

Every pull request is reviewed with the following criteria in mind:

- **Correctness** — Does the code do what it is supposed to do?
- **Readability** — Can another contributor understand the code without effort?
- **Maintainability** — Will the code be easy to change in the future?
- **Architecture compliance** — Does the change respect the existing project structure?
- **Module contract compliance** — Does the module correctly implement `BaseReconModule` and use `Context` appropriately?

Reviews are intended to improve the code, not to criticise the contributor. Everyone makes mistakes — the review process is a collaboration. If a reviewer leaves feedback, it is because they want the project to be better, not because your work is not appreciated.

---

## Need Help?

- **Open a GitHub Discussion** for questions, ideas, or general help — especially before making architectural changes.
- **Contact the maintainers** if you are unsure whether your change fits the project. A quick Discussion can save hours of rework.

If you plan to change something outside the existing module contract or project structure, start a Discussion first. Not every good idea fits every project, and the maintainers can help guide your contribution so it has the best chance of being accepted.

---

Happy hacking!

Thank you for helping improve **Recon Tool**.
