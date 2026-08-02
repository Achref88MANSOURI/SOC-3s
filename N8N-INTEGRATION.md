# n8n Integration — Required Workflow Changes

**Status:** documentation only. n8n is not part of this repo (see `CLAUDE.md`) —
this file describes the changes needed in the n8n workflow itself, to be applied
by whoever maintains it. Nothing here has been applied to a live n8n instance;
treat exact HTTP node configurations as a starting point to verify, the same way
`tools/thehive.py`'s new write functions are flagged as unverified in
`CHANGES.md`.

**Net effect: the n8n workflow gets simpler, not more complex.** Two things are
removed (the Cortex Switch/analyzer nodes, the observable-ID fetch step) and one
thing changes shape (the payload to `/triage` gets slimmer). Nothing new needs
to be added beyond adjusting the existing POST-to-agent-service node.

---

## 1. What changed in agent-service

### `/triage`'s request contract is now slim

Before this migration, `/triage` expected a fully-built `CanonicalAlert` — n8n
(or whatever called it) had to construct the entire normalized alert object
itself. As of Phase 2, `/triage` takes n8n's raw materials instead and builds
the `CanonicalAlert` on the agent-service side:

```json
{
  "thehive_alert_id": "~1156182192",
  "raw_alert": { "...": "n8n's Alert Builder node output, unchanged shape" },
  "asset_context": { "organization_name": "TrustShield", "business_criticity": "high" }
}
```

See §2 below for the exact `raw_alert` shape expected.

### agent-service now fetches its own full alert + Cortex reports

`tools/thehive.py::get_full_alert_with_analysis(thehive_alert_id)` fetches the
alert, its observables, and each observable's existing Cortex reports directly
from TheHive — agent-service only needs `thehive_alert_id` to do this. **n8n no
longer needs to separately fetch and forward observable IDs.**

### Cortex is no longer triggered by n8n at all

Agent 2 (`nodes/investigate.py`) calls Cortex itself, selectively, based on its
own reasoning (skip observables that already have a report, skip common
infrastructure, only analyze what's worth the tool budget). The blanket
per-observable-type Cortex triggering that used to run inside n8n is gone —
**remove those nodes** (see §3).

### The response shape (`TriageResult`) is close to what n8n already routes on

`action`, `severity`, `merge_into_case`, `severity_change`, `urgency` are all
still present with the same meaning. Nothing here should require rebuilding the
Switch node's routing logic from scratch — see §4 for the current field list
and §5 for one behavior change (`close_fp` semantics, if n8n's TheHive write
step used to check for a `"FP"` status value anywhere — see the callout in §5).

---

## 2. The `raw_alert` shape n8n's Alert Builder node must produce

This is unchanged from before this migration — restated here for reference.
`raw_alert` is n8n's existing Alert Builder Python node output, forwarded
as-is:

```json
{
  "type": "sigma",
  "source": "security-onion",
  "sourceRef": "6qS9fp8BiUkBvoTNPeON",
  "title": "[HIGH] Suspicious Invoke-WebRequest Execution - win-kvkmd51ggkq",
  "description": "Detection engine: sigma\nRule: Suspicious Invoke-WebRequest Execution (5e3cc4d8-3e68-43db-8656-eaaeefdec9cc)\nHost: win-kvkmd51ggkq (172.20.24.99)\nAgent ID: 1a52ee32-ef93-4f5a-b876-65bd1b7c795a\nCommand line: ...",
  "severity": 3,
  "tlp": 2,
  "pap": 2,
  "date": 1784710559000,
  "tags": ["172.20.24.99", "agent-id:...", "engine:sigma", "rule:...", "security-onion", "win-kvkmd51ggkq"],
  "observables": [
    {"dataType": "domain", "data": "github.com", "ioc": true},
    {"dataType": "url", "data": "https://github.com/audibleblink/xordump/releases/download/v0.0.1/xordump.exe", "ioc": true},
    {"dataType": "hash", "data": "1c84c8632c5269f24876ed9f49fa810b49f77e1e92e8918fc164c34b020f9a94", "ioc": true, "tags": ["sha256"]}
  ]
}
```

`agent_builder.py`'s `_parse_rule`/`_parse_host`/`_parse_process` functions
parse the `description` field with regexes matching this exact "Label: value"
format (`Rule: <name> (<uuid>)`, `Host: <hostname> (<ip>)`,
`Command line: <text>`) — if the Alert Builder node's description format ever
changes, those regexes (in `alert_builder.py`) need to change too, or the
deterministic pre-pass silently produces gaps for Agent 1 to fill instead.

**Known n8n quirk, already handled downstream — no n8n-side fix needed:** the
Alert Builder node sometimes tags a URL observable with `dataType: "domain"`.
`alert_builder.py`'s `_classify_observable_type()` already corrects this (any
value starting with `http(s)://` is always treated as a URL regardless of the
stated `dataType`). This used to need a defensive fix on the n8n side or in
Agent 1's prompt; it's now handled deterministically before either agent runs.

---

## 3. Nodes to remove from the n8n workflow

- **Switch1** (or whatever the per-observable-type routing node is named) and
  every **per-type Cortex analyzer node** downstream of it. Cortex analysis is
  now entirely Agent 2's responsibility, invoked selectively through
  `cortex_analyze` (`tools/cortex.py`, direct REST — see `CHANGES.md`'s Phase 4
  section for why this isn't `cortex-mcp`).
- The **observable-ID fetch step**, if n8n has one, that runs after alert
  creation to pass observable IDs to agent-service. `get_full_alert_with_analysis()`
  fetches them itself from `thehive_alert_id`.

## 4. What stays the same / needs no change

- Webhook node receiving the raw Security Onion alert.
- The Alert Builder Python node (§2) — same output shape as before.
- `POST` → TheHive: create alert with observables.
- `GET`/lookup → iTop: fetch asset context (`asset_context` in the slim
  payload — `organization_name`, `status`, `business_criticity`, `asset_number`
  per `SOC-3s-ARCHITECTURE-v2.md` §3).

## 5. The one node that changes shape: POST to `/triage`

Change the HTTP Request node's body from a full `CanonicalAlert` to:

```json
{
  "thehive_alert_id": "{{ $json.thehive_alert_id }}",
  "raw_alert": "{{ $json.alert_builder_output }}",
  "asset_context": "{{ $json.itop_response }}"
}
```

(Field names above are illustrative — map to whatever n8n's actual node/variable
names are for the alert-builder output and iTop response.)

`POST http://<agent-service-host>:8000/triage`, no auth header currently
required (`main.py` doesn't enforce any auth on this route as of this writing —
worth confirming that's still the intended posture before this goes live, since
it means anything that can reach the agent-service port can trigger a triage
run).

## 6. Switch node — routing on `triage_result.action`

Response shape (`TriageResult`, `schemas.py`):

```json
{
  "alert_id": "~1156182192",
  "action": "create_case | close_fp | needs_review | merge_quiet | merge_and_retier | deduplicated",
  "verdict": "true_positive | false_positive | needs_review | null",
  "severity": "low | medium | high | critical | null",
  "likelihood": "unlikely | possible | likely | near_certain | null",
  "impact_if_true": "minor | moderate | severe | critical | null",
  "mitre_mapping": [{"tactic": "...", "technique": "...", "sub_technique": null, "confidence": "...", "basis": "..."}],
  "reasoning": "...",
  "summary": "...",
  "merge_into_case": "case-id or null",
  "severity_change": "medium -> high | no_change | null",
  "urgency": "escalate | routine_merge | null",
  "evidence_package": { "...": "full EvidencePackage or DeltaEvidence dump" },
  "investigation_trace": [{"tool": "...", "params": {}, "result_summary": "..."}],
  "correlation_result": { "...": "full CorrelationResult dump" }
}
```

| `action` | n8n behavior |
|---|---|
| `create_case` | Promote alert to case. Set title/severity/tags from the response. Post `summary` + `reasoning` as a case comment. |
| `close_fp` | Update alert status to **`"Ignored"`** — **not `"FP"`**, see callout below. Post `reasoning` as a comment. |
| `merge_quiet` | Merge alert into `merge_into_case`. Post `summary` (includes urgency + scope change) as a case comment. |
| `merge_and_retier` | Merge into `merge_into_case`, update case severity to `severity`, and **send an actual SOC notification** (Slack/email/whatever n8n already uses for urgent alerts) — this is an n8n-side responsibility; agent-service's `nodes/case_action.py` (currently unwired — see §7) only sets an `urgent_notification_required` flag internally, it doesn't send anything itself. |
| `needs_review` | No automated action — flag for analyst. |
| `deduplicated` | Log only, no action. |

> **Callout — status value fix:** if n8n's existing case-action workflow (from
> before this migration) ever set an alert status of `"FP"`, that's invalid on
> TheHive 5.6.1 — verified against the live instance's UI, which only has the
> built-in `New`/`Updated`/`Ignored`/`Imported` statuses. `"Ignored"` is
> TheHive's built-in status for false-positive/not-actionable alerts. This was
> also just fixed in `nodes/case_action.py` (see `CHANGES.md`) for consistency,
> even though that module isn't wired in yet.

## 7. What agent-service does NOT do (yet)

`nodes/case_action.py::execute_case_action()` exists as a stub (Phase 8) but is
**not called by anything** — `graph.py` and `main.py` don't reference it. Today,
n8n is still the thing that actually writes to TheHive based on
`triage_result.action`, exactly as before this migration. The stub is future
work for an analyst-approval-gated flow where agent-service performs the write
itself instead of n8n — don't build against it yet, and don't remove n8n's
case-action HTTP nodes on the assumption agent-service will do it.

If n8n's existing case-action HTTP nodes already work against the live TheHive
instance, **prefer reusing their exact endpoint configuration** over
`tools/thehive.py`'s new write functions (`promote_alert_to_case`, `update_case`,
etc.) if the two ever need to be reconciled — those are unverified against the
live instance (see `CHANGES.md`), while n8n's, if already in production, are
presumably already correct.

## 8. Testing checklist

- [ ] `GET /health` returns `200 {"status": "ok", ...}` from the n8n network.
- [ ] Send one real Security Onion alert through the full n8n workflow and
      confirm the `/triage` POST body matches §1/§2's shape (check via n8n's
      execution log, not assumption).
- [ ] Confirm `/triage` returns `200` with a well-formed `TriageResult` (not a
      500 — if the alert can't be found via `thehive_alert_id`,
      `get_full_alert_with_analysis()` returns `None` and `alert_builder.py`
      still builds a `CanonicalAlert` from `raw_alert` alone, so this should
      degrade gracefully, not crash — verify this actually holds against a
      real TheHive alert ID that doesn't exist yet, e.g. from a race condition
      between alert creation and the `/triage` call).
- [ ] Confirm the Switch node's four+ branches (§6) still route correctly on
      the new field names — they haven't changed, but re-verify since the
      overall response is unchanged only in shape, not necessarily in typical
      values now that Agent 1/2/3 reasoning replaces some deterministic logic.
- [ ] Confirm the removed Cortex Switch/analyzer nodes' removal doesn't leave
      any now-orphaned n8n error-handling branches that expected those nodes
      to exist.
- [ ] Confirm ES firewall + Sigma rules path prerequisites from
      `SOC-3s-ARCHITECTURE-v2.md` §16 are in place — separate from n8n, but
      required for Agent 2 to function once traffic starts flowing.
