---
name: AuthMind Alert Qualification
description: >
  Validate and qualify an AuthMind (or identity-security) alert by pivoting
  across Issues, Identity, Assets, Accesses, and Secrets. Use as the first
  skill when a federated AuthMind finding or case needs triage. Prefer v1
  issue tools when an issue_id is present; otherwise start from the
  identity, asset, or secret on the finding.
category: enrichment
required_tools:
  - authmind_authmind_list_issues
  - authmind_authmind_list_issue_accesses
  - authmind_authmind_get_identity_details
  - authmind_authmind_list_identity_hosts
  - authmind_authmind_get_asset_details
  - authmind_authmind_list_asset_hosts
  - authmind_authmind_list_accesses
  - authmind_authmind_get_access_details
  - authmind_authmind_list_access_source_hosts
  - authmind_authmind_list_access_destination_hosts
  - authmind_authmind_get_secret_details
input_schema:
  type: object
  properties:
    issue_id:
      type: string
      description: AuthMind issue id from a federated finding (v1 /v1/issues).
    identity:
      type: string
      description: Identity id (UPN / username) from the finding or case.
    asset:
      type: string
      description: Asset id from the finding or case.
    asset_type:
      type: string
      description: Asset type required for asset details/hosts (e.g. SaaS, Server).
    secret_id:
      type: string
      description: Secret id / name from a federated secret finding.
    finding_title:
      type: string
      description: Alert / finding title for context.
    entity_kind:
      type: string
      description: Federated entity kind — issue, identity, asset, or secret.
  required: []
execution_steps:
  - step_id: "1"
    type: mcp_tool_call
    tool: authmind_authmind_list_issues
    when_all: [issue_id]
    input_mapping:
      issue_id: "{{issue_id}}"
      size: 5
    output_key: issue
  - step_id: "2"
    type: mcp_tool_call
    tool: authmind_authmind_list_issue_accesses
    when_all: [issue_id]
    input_mapping:
      incident_id: "{{issue_id}}"
      size: 25
    output_key: issue_accesses
  - step_id: "3"
    type: mcp_tool_call
    tool: authmind_authmind_get_identity_details
    when_all: [identity]
    input_mapping:
      id: "{{identity}}"
    output_key: identity_details
  - step_id: "4"
    type: mcp_tool_call
    tool: authmind_authmind_list_identity_hosts
    when_all: [identity]
    input_mapping:
      id: "{{identity}}"
      size: 25
    output_key: identity_hosts
  - step_id: "5"
    type: mcp_tool_call
    tool: authmind_authmind_get_asset_details
    when_all: [asset, asset_type]
    input_mapping:
      id: "{{asset}}"
      asset_type: "{{asset_type}}"
    output_key: asset_details
  - step_id: "6"
    type: mcp_tool_call
    tool: authmind_authmind_list_asset_hosts
    when_all: [asset, asset_type]
    input_mapping:
      id: "{{asset}}"
      asset_type: "{{asset_type}}"
      size: 25
    output_key: asset_hosts
  - step_id: "7"
    type: mcp_tool_call
    tool: authmind_authmind_list_accesses
    when_any: [identity, asset]
    input_mapping:
      identity_name: "{{identity}}"
      asset_name: "{{asset}}"
      asset_type: "{{asset_type}}"
      size: 50
    output_key: access_flows
  - step_id: "8"
    type: mcp_tool_call
    tool: authmind_authmind_get_secret_details
    when_all: [secret_id]
    input_mapping:
      id: "{{secret_id}}"
    output_key: secret_details
output_schema:
  type: object
  properties:
    disposition:
      type: string
      enum: [true_positive, suspicious, false_positive, insufficient_data]
    confidence:
      type: string
      enum: [high, medium, low]
    summary:
      type: string
    evidence:
      type: array
      items:
        type: string
    pivots:
      type: object
    recommended_actions:
      type: array
      items:
        type: string
---

# AuthMind Alert Qualification

Qualify this AuthMind / identity-security alert.

Context: title={{finding_title}}, kind={{entity_kind}},
issue_id={{issue_id}}, identity={{identity}}, asset={{asset}},
asset_type={{asset_type}}, secret_id={{secret_id}}.

Goal: decide true_positive / suspicious / false_positive / insufficient_data
with enough evidence to defend the call. Prefer AuthMind MCP tools over
guesswork. Tools are server-prefixed as `authmind_<tool>` at runtime.

AuthMind is dual-version: **v1** (`/amapi/v1`) owns issues and playbooks;
**v2** (`/amapi/v2/posture`) owns identities, assets, accesses, and secrets.
Federated findings are usually v1 issues (`external_id=<issue_id>`). High-score
posture entities appear only when the token cannot read issues.

## 0. Choose the entry point
1. If `issue_id` is present → start at the v1 issue, then pivot to the
   identities / assets named in the message and issue accesses.
2. Else if `identity` is present → start at Identity profile.
3. Else if `asset` + `asset_type` are present → start at Asset profile.
4. Else if `secret_id` is present → start at Secret details, then pivot to
   identities / assets named in the payload.
5. Else stop and ask for an issue id, identity, asset, or secret id.

## 1. Issue enrichment (v1)
- `authmind_authmind_list_issues` with `issue_id={{issue_id}}`
- Record `issue_type`, `playbook_name`, `risk`, `message`, flow/access counts
- `authmind_authmind_list_issue_accesses` with `incident_id={{issue_id}}`

## 2. Identity enrichment (v2)
- `authmind_authmind_get_identity_details` with `id={{identity}}`
- Record `score`, `identity_type`, `identity_statuses`, `is_known`,
  `playbooks`, `latest_activity_time`
- `authmind_authmind_list_identity_hosts`
- `authmind_authmind_list_accesses` filtered by `identity_name`

## 3. Asset enrichment (v2)
- `authmind_authmind_get_asset_details` with `id` + `asset_type`
- `authmind_authmind_list_asset_hosts`
- `authmind_authmind_list_accesses` filtered by `asset_name`

## 4. Access deep-dive (top 1–3 high-score flows)
- `authmind_authmind_get_access_details`
- `authmind_authmind_list_access_source_hosts`
- `authmind_authmind_list_access_destination_hosts`

## 5. Secrets overlay
If `secret_id` is set or details mention a secret, call
`authmind_authmind_get_secret_details`. Never expect `secret_value` — v2
returns metadata only.

## 6. Qualification verdict
Return a structured SOC triage note:

1. **Disposition** — true_positive / suspicious / false_positive /
   insufficient_data
2. **Confidence** — high / medium / low
3. **Evidence** — issue type/risk, scores, playbooks, hosts, flows,
   known/unknown flags
4. **Pivots** — identities, assets, secrets still worth chasing
5. **Recommended actions** — contain / revoke / force MFA / escalate /
   close with rationale

Do not invent fields. If AuthMind returns empty or 401/403, say so and
lower confidence rather than filling gaps with speculation.
