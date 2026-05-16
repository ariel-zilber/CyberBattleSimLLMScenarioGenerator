# Available Claude Code Skills

Quick reference for all skills available in this project. Invoke with `/skill-name` in the Claude Code prompt.

---

## Project-Specific Skills

| Skill | Command | Purpose |
|-------|---------|---------|
| Auto-Generate | `/auto-generate` | Phase 1 pipeline: generate a CBS domain config YAML, validate, and quality-check |
| Full Pipeline | `/full-pipeline` | End-to-end: Auto-Generate → Phase 2 → Evaluate → Retry until passing |
| Phase 2 | `/phase2` | Stratified scenario generation + heuristic agent runtime evaluation |
| Generate Domain | `/generate-domain` | Generate a single CBS domain configuration YAML |
| Evaluate Domain | `/evaluate-domain` | Evaluate a CBS domain config (structural + realism check) |
| Evaluate Quality | `/evaluate-quality` | Score a generated scenario on the 5-dimension quality rubric |
| Bitnami Report | `/bitnami-report` | Regenerate Bitnami CVE EDA figures, LaTeX, and PDF from live JSON |

---

## Planning & Design Skills

| Skill | Command | Purpose |
|-------|---------|---------|
| Explore | `/opsx:explore` | Open-ended thinking partner — investigate problems, clarify requirements, no implementation |
| Propose | `/opsx:propose` | Create a new change proposal with design, specs, and tasks in one step |
| Apply | `/opsx:apply` | Implement tasks from an existing OpenSpec change |
| Archive | `/opsx:archive` | Finalize and archive a completed change |
| Grill with Docs | `/grill-with-docs` | Stress-test a plan against the domain model and existing docs |

---

## Tooling & Configuration Skills

| Skill | Command | Purpose |
|-------|---------|---------|
| Update Config | `/update-config` | Configure Claude Code hooks, permissions, and env vars via settings.json |
| Keybindings | `/keybindings-help` | Customize keyboard shortcuts in `~/.claude/keybindings.json` |
| Fewer Prompts | `/fewer-permission-prompts` | Scan transcripts and add an allowlist to reduce permission prompts |
| Loop | `/loop` | Run a prompt or command on a recurring interval (e.g. `/loop 5m /phase2`) |
| Schedule | `/schedule` | Create and manage scheduled remote agents on a cron schedule |
| Init | `/init` | Initialize a new `CLAUDE.md` file for the project |
| Simplify | `/simplify` | Review changed code for quality and efficiency, then fix issues found |

---

## General Skills

| Skill | Command | Purpose |
|-------|---------|---------|
| Claude API | `/claude-api` | Build, debug, and optimize Claude API / Anthropic SDK applications |
| Review PR | `/review` | Review a pull request |
| Security Review | `/security-review` | Security review of pending changes on the current branch |
| Network Diagram | `/network-diagram-generator` | Generate network diagrams from descriptions |
