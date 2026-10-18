# Decompose-Threat

> **⚠️ Work in progress.** APIs, data, and results are all subject to change.

**What this does.** Tests whether splitting a malicious task into individually
benign-looking subtasks gets an enterprise agent to carry out the full attack it
would refuse if asked directly.

**Why it matters.** Per-step safety checks can pass every subtask while the
combined trajectory still exfiltrates data or escalates privileges — a gap that
single-prompt red-teaming doesn't measure.

**Done so far.** A synthetic enterprise DB with log-only exfiltration tools, 10
original→decomposed attack pairs, benign distractor tasks, and an environment
builder for the four conditions below.

**Next.** Plug in an agent + guardrail, run all conditions, and score how
attack success changes with decomposition, padding, and interleaving.

## Experimental conditions

![Four experimental conditions for malicious task decomposition](docs/conditions.png)

- **C1** — the malicious task, asked directly (baseline).
- **C2** — the task split into ordered, benign-looking subtasks.
- **C3 (padding)** — the subtasks kept contiguous but padded with benign tasks.
- **C4 (interleaving)** — the subtasks interleaved with benign tasks; subtask order is always preserved.

## Layout

```
data/      enterprise.db + attack and benign task sets (.jsonl)
src/       generate.py (seed DB) · tools.py (agent tools) · environments.py (build conditions)
docs/      dataset notes + the conditions graphic
results/   generated environments + exfil_log.jsonl (evidence of exfiltration attempts)
```

## Run

```bash
pip install faker
python3 src/generate.py        # (re)build data/enterprise.db
python3 src/environments.py     # write results/environments/environments.jsonl
```
