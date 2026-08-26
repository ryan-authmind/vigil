---
name: AuthMind Identity Investigation
description: >
  Enrich an investigation by profiling an AuthMind identity — posture score,
  hosts, directory/IdP systems, matched playbooks, and related accesses —
  to validate whether the alerted identity is compromised, misconfigured,
  or behaving normally.
category: enrichment
required_tools:
  - authmind_authmind_get_identity_details
  - authmind_authmind_list_identity_hosts
  - authmind_authmind_list_accesses
  - authmind_authmind_list_identity_systems
  - authmind_authmind_get_identity_system_details
input_schema:
  type: object
  properties:
    identity:
      type: string
      description: >
        Identity id (UPN / username) from the finding, AuthMind alert, or
        case entity_context.usernames.
    identity_type:
      type: string
      description: Optional identity type (User, Role, Service Account, etc.).
  required:
    - identity
execution_steps:
  - step_id: "1"
    type: mcp_tool_call
    tool: authmind_authmind_get_identity_details
    when_all: [identity]
    input_mapping:
      id: "{{identity}}"
    output_key: identity_details
  - step_id: "2"
    type: mcp_tool_call
    tool: authmind_authmind_list_identity_hosts
    when_all: [identity]
    input_mapping:
      id: "{{identity}}"
      size: 25
    output_key: identity_hosts
  - step_id: "3"
    type: mcp_tool_call
    tool: authmind_authmind_list_accesses
    when_all: [identity]
    input_mapping:
      identity_name: "{{identity}}"
      identity_type: "{{identity_type}}"
      size: 25
    output_key: identity_accesses
  - step_id: "4"
    type: mcp_tool_call
    tool: authmind_authmind_list_identity_systems
    input_mapping:
      size: 25
    output_key: identity_systems
output_schema:
  type: object
  properties:
    disposition:
      type: string
      enum: [confirmed, suspicious, benign, insufficient_data]
    summary:
      type: string
    risk_factors:
      type: array
      items:
        type: string
    related_assets:
      type: array
      items:
        type: string
    recommended_actions:
      type: array
      items:
        type: string
---

# AuthMind Identity Investigation

Investigate identity **{{identity}}** (type={{identity_type}}).

AuthMind MCP tools are server-prefixed at runtime as `authmind_<tool>`
(e.g. `authmind_authmind_get_identity_details`). Call them in this order:

## 1. Profile the identity
- Call `authmind_authmind_get_identity_details` with `id={{identity}}`.
- Record posture `score`, `identity_type`, `identity_statuses`, `is_known`,
  `playbooks`, and `latest_activity_time`.
- Note: `/posture/identities` has **no name filter** — do not page the full
  identity catalog hoping to find a match. Prefer details + access pivots.

## 2. Map exposure surface
- Call `authmind_authmind_list_identity_hosts` with `id={{identity}}`.
- Call `authmind_authmind_list_accesses` with `identity_name={{identity}}`
  (and `identity_type` if known). Sort attention to high `score` rows.
- For each high-score access, note the destination asset name / type /
  protocol and directory.

## 3. Directory / IdP context
- Call `authmind_authmind_list_identity_systems` (optionally filter
  `directory_type` to On-premise or Cloud IDP).
- Drill into relevant systems with
  `authmind_authmind_get_identity_system_details` (`id` from the list).

## 4. Qualify the alert
Return a concise SOC note with:
1. **Disposition** — confirmed / suspicious / benign / insufficient_data
2. **Why** — posture score, unknown flag, anomalous hosts, high-risk
   accesses, matched playbooks
3. **Blast radius** — assets and directories touched by this identity
4. **Next actions** — disable account, force MFA, revoke sessions, escalate,
   or close as expected behaviour

Do not invent AuthMind fields. If a tool 401s (JWT missing `posture`) or
403s (IP allow-list), say so and continue with what you can reach.
