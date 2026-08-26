---
name: AuthMind Secrets and Credential Risk
description: >
  Investigate credential and secret exposure in AuthMind via the v2 Secrets
  API plus high-score identities and accesses (MFA gaps, auth failures,
  unknown identities). Secrets endpoints return metadata only — never secret
  material.
category: detection
required_tools:
  - authmind_authmind_list_secrets
  - authmind_authmind_get_secret_details
  - authmind_authmind_get_identity_details
  - authmind_authmind_list_accesses
  - authmind_authmind_get_access_details
  - authmind_authmind_list_identities
input_schema:
  type: object
  properties:
    secret_id:
      type: string
      description: Specific AuthMind secret id / name to qualify.
    identity:
      type: string
      description: Optional identity to scope the credential hunt.
    asset:
      type: string
      description: Optional asset to scope the credential hunt.
    score:
      type: number
      description: Minimum secret score filter (default 50).
  required: []
execution_steps:
  - step_id: "1"
    type: mcp_tool_call
    tool: authmind_authmind_get_secret_details
    when_all: [secret_id]
    input_mapping:
      id: "{{secret_id}}"
    output_key: secret_details
  - step_id: "2"
    type: mcp_tool_call
    tool: authmind_authmind_list_secrets
    input_mapping:
      score: "{{score}}"
      size: 25
    output_key: high_score_secrets
  - step_id: "3"
    type: mcp_tool_call
    tool: authmind_authmind_list_accesses
    when_any: [identity, asset]
    input_mapping:
      identity_name: "{{identity}}"
      asset_name: "{{asset}}"
      size: 25
    output_key: related_accesses
  - step_id: "4"
    type: mcp_tool_call
    tool: authmind_authmind_get_identity_details
    when_all: [identity]
    input_mapping:
      id: "{{identity}}"
    output_key: identity_details
output_schema:
  type: object
  properties:
    disposition:
      type: string
      enum: [confirmed, suspicious, benign, insufficient_data]
    summary:
      type: string
    credential_findings:
      type: array
      items:
        type: object
    recommended_actions:
      type: array
      items:
        type: string
---

# AuthMind Secrets & Credential Risk Investigation

Investigate credential / secret exposure in AuthMind.

Parameters: secret_id={{secret_id}}, identity={{identity}}, asset={{asset}},
score={{score}}.

AuthMind v2 **does** expose a Secrets API (`/posture/secrets`). It returns
metadata (name, type, provider, score, playbooks) and **never** secret
material. Pair it with identity and access posture for blast radius.

AuthMind MCP tools are server-prefixed at runtime as `authmind_<tool>`.

## 1. Collect high-risk secrets
- If `secret_id` is set: call `authmind_authmind_get_secret_details`.
- Else: call `authmind_authmind_list_secrets` with `score` ≥ 50 (or the
  provided threshold). Sort by score descending.
- Record type, provider, score, `is_known`, matched `playbooks`, and
  `latest_activity_time`. Do not ask for or expect `secret_value`.

## 2. Pivot to identities and accesses
For each high-score secret:
- Call `authmind_authmind_get_identity_details` for implicated identities
  (from the finding, the secret payload, or the case).
- Call `authmind_authmind_list_accesses` scoped to those identities or
  assets. Watch `auth_failed_percent` and unknown identities.
- Deep-dive top flows with `authmind_authmind_get_access_details`.

## 3. Qualify secret / credential exposure
For each finding decide:
- Is the secret high-score because of reuse, weak type, or playbook match?
- Is the exposure active (recent access flows) or historical?
- What systems (directory / IdP / asset) are reachable with that credential?

## 4. Report
Return:
1. **Disposition** — confirmed / suspicious / benign / insufficient_data
2. **Credential findings** — secret id, type, provider, score, identities,
   assets
3. **Why it matters** — blast radius if the secret is abused
4. **Next actions** — reset password, revoke tokens/sessions, enforce MFA,
   rotate service credentials, isolate impacted hosts, escalate

If the token lacks `posture` or a list returns empty, say so explicitly —
do not invent compromise evidence.
