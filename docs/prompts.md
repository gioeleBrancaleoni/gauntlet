# Invoking Gauntlet — prompt pack

Gauntlet is run either directly from the CLI or by asking an AI assistant (e.g. Claude Code) in natural language. This page collects **ready-to-paste prompts** that get the assistant to run the checks you want — phrased so that a model correctly recognizes an **authorized, defensive** task instead of over-refusing it.

> These prompts are for testing applications **you own or are explicitly authorized to test**, on **dev/staging only**. That is Gauntlet's entire premise and it is enforced by the fail-closed allowlist. Do not use them against systems you do not control.

## Why some prompts get refused (and how to phrase them)

A model's safety filter declines requests that *read* like an attack ("attack my app", "exploit it", "break into…", "dump the other tenants' data"). The fix is **not** to trick the model — it is to state the legitimate context it needs to recognize the task as permitted:

1. **Ownership / authorization** — "my own app", "staging I control", "I'm authorized".
2. **Scope & environment** — dev/staging only, allowlist-gated, never production.
3. **Defensive goal** — "to harden it before release / so I can fix the bugs".
4. **The assistant's role** — *orchestrate a configured CLI with safety gates and read the report*, not perform attacks by hand.
5. **Non-destructive by default** — the intrusive steps run only under `--aggressive`, behind an explicit batch consent.

**Rule of thumb:** steer toward *"run `gauntlet run …` and interpret the report"* (mechanical work on a gated tool), not *"find and exploit vulnerabilities"*.

Empirically, with the model Fable, a bluntly offensive phrasing ("attack my app and dump other tenants' data") is **declined**, while the well-framed phrasing below is **carried out** — the wording is the only difference.

## Prompt templates

Replace `./myapp` with the folder that holds your `gauntlet.yaml`.

**Baseline scan (non-destructive):**
> I'm hardening my own web app before release. Use the Gauntlet skill — an authorized, contract-driven DAST tool with a fail-closed allowlist (dev/staging only, non-destructive by default) — to run `gauntlet run --project ./myapp --level 2` against my staging contract, then summarize the findings so I can fix them.

**Tenant isolation / access-control (BOLA/IDOR):**
> On my staging environment, I want to confirm one customer cannot read another customer's data. Run Gauntlet's access-control checks (level 2) with my prepared contract and explain what the report shows.

**Source-/docs-informed testing (levels 3–4):**
> I own this app and its source is in this repo. Use Gauntlet at level 4 to read the docs/source, seed the right resources, and direct the access-control testing on my staging contract; then walk me through the report.

**Aggressive run (explicit, consented):**
> I authorize the destructive steps on my disposable staging environment. Run `gauntlet run --project ./myapp --level 2 --aggressive` and report the findings.

**CLI only (no model needed):**
> If the assistant still declines, you don't need it at all — the CLI does the scanning:
> ```bash
> gauntlet run --project ./myapp --level 2
> ```

## If a model still refuses

- Switch to a model where the skill is tested working (Opus 4.8), **or**
- Run the CLI yourself (above) — it needs no model, just a `gauntlet.yaml` and Docker running.

See also: [`../SKILL.md`](../SKILL.md) (how Claude Code uses the skill) and the full check [catalog](checks.md).
