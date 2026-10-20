# Distracted Environment

> **⚠️ Work in progress.** APIs, data, and results are all subject to change.

**What this repo does:** Tests if splitting a malicious tasks into seemingly benign subtasks 
spread across a distracted environment gets an agent to carry out the attack.

**Our novel contribution:** Projects like DECOMPBENCH already found that decomposing a
dangerous task can help it bypass guardrails. However, we are expanding to see how 
a distracted environment contributes to this. 

**Done so far:** A synthetic enterprise DB with log-only exfiltration tools, 10
original→decomposed attack pairs, benign distractor tasks, and an environment
builder for the four conditions below.

**Next:** Plug in an agent + guardrail, run all conditions, and score how
attack success changes with decomposition, padding, and interleaving.

**After that:** Create the solution: a deterministic pattern detector 

## Experimental conditions

![alt text](image.png)

- **C1 (control)** — the malicious task, asked directly as one monolithic prompt.
- **C2** — the task split into ordered, benign-looking subtasks, with no benign tasks mixed in.
- **C3 (padding)** — the subtasks kept contiguous, padded with benign tasks placed entirely *before* the malicious block to establish a benign lead-in.
- **C4 (interleaving)** — the subtasks interleaved with benign tasks by a proportional-random merge; subtask order is always preserved.

C3 and C4 share the same benign:malicious ratios (1:1, 2:1, 4:1) so they are comparable at matched totals — the only difference is placement (all-before vs. spread-through). Each is built across 3 random seeds per ratio.

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
