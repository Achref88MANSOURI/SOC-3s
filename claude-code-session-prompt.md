# Claude Code — SOC-3s Agent Service Build Session

## Before you write a single line of code — read this fully

You are about to work on a real security operations platform. The codebase already
exists. Your job is to migrate it, fix it, and extend it according to a detailed
architecture spec. This document tells you exactly how to behave during this session.

---

## Step 0 — Your first action (mandatory, before anything else)

**Read these files in this exact order:**

1. `ARCHITECTURE.md` — the complete v2 architecture specification. This is your
   primary reference. Every decision is documented here with a rationale. Do not
   deviate from it without flagging it to me first.
2. `architecture-revision-v2.md` — the research behind the decisions (why v1 needed
   a rethink, what papers and projects were reviewed). Read this if you encounter a
   situation where the architecture spec seems unclear.
3. Every file in `agent-service/` — read the full current codebase before touching
   anything. Understand what exists, what's broken, and what needs to be built.

After reading, do two things before writing any code:

**A — Report what you found:**
List every file you read, its current state (solid / has bugs / needs rewrite /
needs to be created), and whether it matches what `ARCHITECTURE.md` says it should
contain.

**B — Report your plan:**
For Phase 1 (bug fixes), list each bug from `ARCHITECTURE.md §18` mapped to the
exact file and the exact fix you will apply. Get my confirmation before proceeding.

---

## How to handle unknowns — the most important rule

**Never assume. Never search. Ask me first.**

If you encounter anything you are not certain about — a configuration value, a
network address, a version number, an API endpoint format, an infrastructure detail —
**stop and ask me** before proceeding. Do not search the internet for it. Do not guess.
Do not fill it in with a placeholder silently.

Specifically, always ask me before acting on:

- **Network addresses or ports** you don't find in the `.env` file
  (e.g. "What IP/port does the cortex-mcp server run on? Is it on the same VM as
  Cortex at 172.20.24.221, or a separate VM?")
- **External services running on separate VMs** — some components (like the
  cortex-mcp Node.js server) may need to run on a different machine than the
  agent-service. Ask me where each external process runs and how it's reachable
  before writing connection code.
- **TheHive API version specifics** — the `extraData` key name for Cortex reports
  has shifted across TheHive 5.0/5.1/5.2. Ask me which TheHive version is deployed
  before hardcoding the query shape.
- **Filesystem paths** not already in the `.env` file
  (e.g. sigma rules path, cortex-mcp binary path)
- **Anything about the Security Onion deployment** — version (2.4 vs 3.0), whether
  port 9200 is already open for the agent-service IP, whether the Sigma rules path
  exists
- **Qdrant collection name** — the current code uses `triage_kb` but the architecture
  doc mentions separate collections. Ask me what's actually deployed before querying.

---

## How to handle missing credentials and config values

If a credential or URL is needed but does NOT exist in the `.env` file:

**Use a clearly named placeholder and add it to the tracking log (see below).**

Placeholder format:
```python
# PLACEHOLDER — ask user for this value before running
CORTEX_MCP_URL = os.getenv("CORTEX_MCP_URL", "PLACEHOLDER_CORTEX_MCP_URL")
```

The placeholder must:
- Be ALL_CAPS with a `PLACEHOLDER_` prefix
- Match the env var name exactly
- Have an inline comment saying "ask user for this value before running"
- Be logged in `CHANGES.md` under "Placeholders requiring configuration"

Do NOT invent a value. Do NOT use `localhost` as a default unless you've confirmed
with me that the service runs on the same host as the agent-service.

---

## The tracking log — CHANGES.md

**Create `CHANGES.md` in the repo root on your first code edit and keep it updated
throughout the session.** This is how I know what you changed, what's still missing,
and what questions are unresolved.

Structure it exactly like this:

```markdown
# SOC-3s Agent Service — Change Log
Last updated: <timestamp of your last edit>

## Phases completed
- [ ] Phase 1 — Bug fixes
- [ ] Phase 2 — New input contract
- [ ] Phase 3 — Agent 1 (perceive.py)
- [ ] Phase 4 — Cortex MCP integration
- [ ] Phase 5 — Agent 2 structured output
- [ ] Phase 6 — Agent 3 two-pass MITRE
- [ ] Phase 7 — Format output fixes + end-to-end
- [ ] Phase 8 — Case action stub
- [ ] Phase 9 — n8n integration notes
- [ ] Phase 10 — Tests

## Files modified
| File | Change summary | Phase |
|------|---------------|-------|
| schemas.py | Added ExistingCaseContext, Literal aliases, PerceptionResult | 1 |
| nodes/perceive.py | Created — replaces correlate.py | 3 |
| ... | ... | ... |

## Files created
| File | Purpose | Phase |
|------|---------|-------|
| alert_builder.py | Builds CanonicalAlert from TheHive fetch + raw_alert | 2 |
| nodes/case_action.py | Post-approval TheHive write operations | 8 |
| ... | ... | ... |

## Files deleted / renamed
| Old name | New name / action | Reason |
|----------|------------------|--------|
| nodes/correlate.py | nodes/perceive.py | Role changed to LLM agent |

## Placeholders requiring configuration
Before running the service, the user must provide values for:
| Placeholder | Env var | Where used | Question to ask user |
|-------------|---------|------------|----------------------|
| PLACEHOLDER_CORTEX_MCP_URL | CORTEX_MCP_URL | tools/cortex_mcp.py | What IP/port does cortex-mcp run on? Same VM as Cortex (172.20.24.221) or separate? |
| ... | ... | ... | ... |

## Questions asked to user (resolved)
| Question | Answer | Phase |
|----------|--------|-------|
| ... | ... | ... |

## Questions pending user response
| Question | Why needed | Blocking phase |
|----------|-----------|----------------|
| ... | ... | ... |

## Known issues / TODOs
- [ ] Verify TheHive extraData key name against live instance Swagger UI
- [ ] cortex-mcp source review required before enabling in production
- [ ] ES port 9200 firewall rule prerequisite (must be done on Security Onion)
- [ ] ...

## Test results
| Phase | Tests run | Pass | Fail | Notes |
|-------|----------|------|------|-------|
| 1 | pytest tests/ -v | ? | ? | run after bug fixes |
```

Update this file after every meaningful change — not just at the end.

---

## Build rules — follow these throughout the session

### Rule 1: Phases in order, tests before moving on
Work through the phases from `ARCHITECTURE.md §19` in order. After each phase, run
`pytest tests/ -v` and report results. Do not start the next phase until the current
phase is green (or until I explicitly tell you to continue despite failures).

### Rule 2: Read before you write
Before modifying any existing file, read its current content in full. The codebase may
have drifted from what the architecture doc says. What's on disk takes precedence over
what any document describes — verify first, then act.

### Rule 3: One file at a time, show your work
When modifying a file:
1. Show me the specific change you're about to make (old vs new, for non-trivial edits)
2. Make the change
3. Confirm it was applied correctly
4. Update `CHANGES.md`

For new files, show the complete file content before creating it.

### Rule 4: Never refactor what works
These files were reviewed and are solid — touch them ONLY where a phase explicitly
requires it:
- `config.py` — extend (add new env vars), never restructure
- `nodes/analyze.py` — only Phase 6 (add mitre_mapping input)
- `main.py` — only Phase 2 (add AlertWebhookPayload endpoint)

### Rule 5: Placeholder discipline
Every placeholder must appear in exactly two places:
1. In the code where it's used (with `PLACEHOLDER_` prefix and inline comment)
2. In `CHANGES.md` under "Placeholders requiring configuration"

No silent gaps. No invented values.

### Rule 6: External process dependencies — always ask
Some components of this architecture involve processes running on other VMs or as
separate services (Ollama on 172.20.24.225, Qdrant on 172.20.24.224, the new
cortex-mcp Node.js server, etc.). Before writing any connection code to a service
that isn't clearly addressed in the existing `.env` file, ask me:
- What IP/port does it run on?
- Is it on the same VM as agent-service or a separate one?
- Is it already running, or does it need to be set up first?
- If it needs setup — should I write setup instructions, or will you handle it?

### Rule 7: Security-sensitive code — flag before implementing
Before implementing anything that:
- Stores or logs credentials, API keys, or tokens
- Reads or writes case data, alert data, or observable data to disk
- Spawns child processes or shell commands
- Makes outbound network connections to new endpoints

...flag it to me first with a brief description of what it does and how it handles
the sensitive data. Wait for my go-ahead.

### Rule 8: cortex-mcp requires source review
`ARCHITECTURE.md §17` explicitly states that `solomonneas/cortex-mcp` must be
reviewed before deployment. When you reach Phase 4, do not write the integration
code blindly. Instead:
1. Tell me: "I'm about to integrate cortex-mcp. Before I write the code, can you
   confirm you've reviewed the source at github.com/solomonneas/cortex-mcp and are
   comfortable deploying it?"
2. Wait for my confirmation before proceeding.

---

## What "done" means for each phase

A phase is done when:
1. `pytest tests/ -v` passes for all tests related to that phase
2. `CHANGES.md` is updated with the phase checked off and all modified files listed
3. Any new placeholders are documented
4. Any new questions that came up are listed under "Questions pending"
5. You've told me the phase is complete and what the next phase will touch

---

## Specific questions to ask me before starting Phase 3 (perceive.py)

These are known unknowns that will block Agent 1 implementation. Ask them all at
once before starting Phase 3, not one by one as you encounter them:

1. **TheHive version:** What version of TheHive 5 is deployed? (5.0.x, 5.1.x, 5.2.x,
   5.3.x, 5.4.x, 5.5.x?) This determines the exact `extraData` field name for
   fetching Cortex reports via the Query API.

2. **cortex-mcp deployment:** Should `solomonneas/cortex-mcp` run on the same VM as
   Cortex (172.20.24.221), or on the agent-service VM? What port should it listen on?
   Is Node.js already installed on the target VM?

3. **Qdrant collection names:** The current code in `tools/qdrant.py` references
   `triage_kb` as a combined collection. `ARCHITECTURE.md` mentions potentially
   separate collections (`mitre_attack`, `playbooks`, `cve`). Which is actually
   deployed at 172.20.24.224:6333? Run
   `curl http://172.20.24.224:6333/collections` and tell me the result.

4. **Sigma rules path:** Is `/opt/so/rules/sigma/` accessible from the machine where
   agent-service runs, or is it on the Security Onion manager node? If it's on a
   separate machine, how should the agent-service read it (mounted volume, SSH, API)?

5. **ES firewall rule:** Has the agent-service IP already been added to Security
   Onion's `elasticsearch_rest` host group, or does that still need to be done? If not
   done, the ES queries in Phase 1 tests will fail.

---

## Quick reference — deployment network

From the `.env` file already in the repo:

| Service | Address | Notes |
|---------|---------|-------|
| Cortex | http://172.20.24.221:9001 | Also hosts TheHive on :9000 |
| TheHive | http://172.20.24.221:9000 | |
| iTop | http://172.20.24.223/itop | |
| Elasticsearch (Security Onion) | https://172.20.24.58 | Port 9200, firewall rule needed |
| Ollama / LLM | http://172.20.24.225/v1 | model: qwen3:30b-a3b (UPDATE .env) |
| Qdrant | http://172.20.24.224:6333 | |
| cortex-mcp | UNKNOWN — ask user | Node.js process, location TBD |
| Redis | UNKNOWN — ask user | Optional, dedup only |

---

## How to start this session

Say the following out loud (in your first response) to confirm you've read and
understood this prompt:

> "I've read the session rules. My first action is to read ARCHITECTURE.md,
> architecture-revision-v2.md, and every file in agent-service/. I will not write
> any code until I've reported what I found and gotten your confirmation on the
> Phase 1 plan. I will ask you before acting on any unknown — network address,
> version, external service location, or missing credential."

Then read the files and report back.