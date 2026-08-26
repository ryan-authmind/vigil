---
name: AuthMind Asset Investigation
description: >
  Enrich an investigation by profiling an AuthMind asset — posture score,
  hosts, inbound accesses, and matched playbooks — to validate whether the
  alerted asset is exposed, shadow, or under attack.
category: enrichment
required_tools:
  - authmind_authmind_list_assets
  - authmind_authmind_get_asset_details
  - authmind_authmind_list_asset_hosts
  - authmind_authmind_list_accesses
  - authmind_authmind_get_access_details
input_schema:
  type: object
  properties:
    asset_name:
      type: string
      description: Asset id from the finding, AuthMind alert, or entity_context.hostnames.
    asset_type:
      type: string
      description: Asset type (SaaS, Server, Database, …). Required for details/hosts.
  required:
    - asset_name
execution_steps:
  - step_id: "1"
    type: mcp_tool_call
    tool: authmind_authmind_list_accesses
    when_all: [asset_name]
    input_mapping:
      asset_name: "{{asset_name}}"
      asset_type: "{{asset_type}}"
      size: 25
    output_key: asset_accesses
  - step_id: "2"
    type: mcp_tool_call
    tool: authmind_authmind_get_asset_details
    when_all: [asset_name, asset_type]
    input_mapping:
      id: "{{asset_name}}"
      asset_type: "{{asset_type}}"
    output_key: asset_details
  - step_id: "3"
    type: mcp_tool_call
    tool: authmind_authmind_list_asset_hosts
    when_all: [asset_name, asset_type]
    input_mapping:
      id: "{{asset_name}}"
      asset_type: "{{asset_type}}"
      size: 25
    output_key: asset_hosts
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
    related_identities:
      type: array
      items:
        type: string
    recommended_actions:
      type: array
      items:
        type: string
---

# AuthMind Asset Investigation

Investigate asset **{{asset_name}}** (type={{asset_type}}).

AuthMind MCP tools are server-prefixed at runtime as `authmind_<tool>`.

## 1. Resolve the asset
- If `asset_type` is already known, call
  `authmind_authmind_get_asset_details` with `id={{asset_name}}` +
  `asset_type`. There is no free-text search on `/posture/assets`.
- Record posture `score`, `is_known`, `is_saas`, `playbooks`, and
  `latest_activity_time`.

## 2. Host inventory
- Call `authmind_authmind_list_asset_hosts` with `id` + `asset_type`.
- Flag unexpected hostnames, geo anomalies, or low-trust endpoints.

## 3. Who is accessing it
- Call `authmind_authmind_list_accesses` with `asset_name={{asset_name}}`
  (and `asset_type` if known).
- Prioritize high `score` rows and unusual identity / identity_type pairs
  (service accounts, unknown users, cloud IdP outliers).
- For top offenders call `authmind_authmind_get_access_details` with the
  identity_name, identity_type, asset_name, and asset_type from the row.

## 4. Qualify the alert
Return:
1. **Disposition** — confirmed / suspicious / benign / insufficient_data
2. **Why** — posture, unknown/shadow flag, exposed hosts, anomalous
   accessors, matched playbooks
3. **Blast radius** — identities and directories touching this asset
4. **Next actions** — isolate host, revoke access, tighten MFA, escalate,
   or close as expected service traffic

Do not invent AuthMind fields. If a tool 401s/403s, report the permission
gap and continue with reachable data.
