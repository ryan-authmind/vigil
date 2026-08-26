---
name: AuthMind Access Investigation
description: >
  Trace identity-to-asset access flows in AuthMind — including source and
  destination hosts — to validate lateral movement, shadow access, MFA gaps,
  and unauthorized access alerts.
category: enrichment
required_tools:
  - authmind_authmind_list_accesses
  - authmind_authmind_get_access_details
  - authmind_authmind_list_access_source_hosts
  - authmind_authmind_list_access_destination_hosts
input_schema:
  type: object
  properties:
    identity:
      type: string
      description: Source identity name (optional if asset is set).
    identity_type:
      type: string
      description: Optional identity type for access details lookups.
    asset:
      type: string
      description: Destination asset name (optional if identity is set).
    asset_type:
      type: string
      description: Optional asset type for access details lookups.
    latest_activity_time_gt:
      type: string
      description: Optional lower bound (RFC 3339 or YYYY-MM-DD HH:MM:SS).
  required: []
execution_steps:
  - step_id: "1"
    type: mcp_tool_call
    tool: authmind_authmind_list_accesses
    when_any: [identity, asset]
    input_mapping:
      identity_name: "{{identity}}"
      identity_type: "{{identity_type}}"
      asset_name: "{{asset}}"
      asset_type: "{{asset_type}}"
      latest_activity_time_gt: "{{latest_activity_time_gt}}"
      size: 50
    output_key: access_flows
output_schema:
  type: object
  properties:
    disposition:
      type: string
      enum: [confirmed, suspicious, benign, insufficient_data]
    summary:
      type: string
    high_risk_flows:
      type: array
      items:
        type: object
    recommended_actions:
      type: array
      items:
        type: string
---

# AuthMind Access Investigation

Investigate AuthMind access flows.

Parameters: identity={{identity}}, identity_type={{identity_type}},
asset={{asset}}, asset_type={{asset_type}},
latest_activity_time_gt={{latest_activity_time_gt}}.

At least one of identity or asset should be present. If both are empty,
stop and ask for an entity id.

AuthMind MCP tools are server-prefixed at runtime as `authmind_<tool>`.
AM API v2 has no issue-accesses endpoint — list `/posture/accesses`
filtered by identity_name / asset_name instead.

## 1. Collect candidate flows
Call `authmind_authmind_list_accesses` with whichever of `identity_name`,
`asset_name`, `identity_type`, `asset_type`, and `latest_activity_time_gt`
are known. Prefer high `score` first.

## 2. Deep-dive suspicious flows
For each high-risk row (top score, unexpected protocol, shadow / unknown
parties):
- Call `authmind_authmind_get_access_details` with identity_name,
  identity_type, asset_name, asset_type (and directory_name when present).
- Call `authmind_authmind_list_access_source_hosts` with the access `id`
  (hash from the list row).
- Call `authmind_authmind_list_access_destination_hosts` with the same `id`.
- Note auth fail rates, directory type, known/unknown flags, and host
  geography when present.

## 3. Qualify the alert
Return:
1. **Disposition** — confirmed / suspicious / benign / insufficient_data
2. **High-risk flows** — identity → asset, score, protocol, hosts
3. **Why it matters** — lateral movement, shadow access, MFA gap, geo anomaly
4. **Next actions** — revoke the access path, isolate hosts, force MFA,
   escalate, or close as expected business traffic

Do not invent AuthMind fields. If a tool 401s/403s, report the permission gap.
