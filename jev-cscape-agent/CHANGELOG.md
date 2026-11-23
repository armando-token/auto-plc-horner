# Changelog: JEV Cscape Agent

All notable changes to the `jev-cscape-agent` project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - 2026-10-01

### Added
- Initial project scaffolding for `jev-cscape-agent` at `C:\HornerAI\jev-cscape-agent\`.
- Local-only Git change tracking configuration with zero remote push targets.
- Environment bootstrap script `scripts/bootstrap.ps1` with idempotent Python 3.12 resolution.
- System and safety diagnostic script `scripts/doctor.ps1` enforcing 4-state reporting.
- Fail-closed security architecture locking out hardware COM ports, flashing utilities, and download commands.
- Python project packaging configuration in `pyproject.toml`.
- Operational tracking ledgers in `ops/` (`backlog.json`, `gates.json`, `blockers.json`, `decisions.jsonl`).
- Hardware and environment reference profiles in `profiles/`.
- Dependency inventory in `docs/DEPENDENCIES.md` and locked skeleton in `DEPENDENCIES.lock.json`.
