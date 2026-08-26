# AuthMind investigation skills

Parameterized SOC playbooks that teach Vigil agents how to validate and
qualify AuthMind alerts by pivoting across **Identity**, **Assets**,
**Accesses**, and **Secrets**.

These skills target **AM API v1 + v2**. v1 (`/amapi/v1`) owns issues and
playbooks — that is the federated alert stream. v2 (`/amapi/v2/posture/*`)
owns identities, assets, accesses, identity systems, and secrets. Matched
playbooks also live on v2 entity detail payloads.

| Skill | Category | When to use |
|-------|----------|-------------|
| [AuthMind Alert Qualification](alert-qualification/SKILL.md) | enrichment | First skill for federated AuthMind findings / identity alerts |
| [AuthMind Identity Investigation](identity-investigation/SKILL.md) | enrichment | Profile a user / role / service account |
| [AuthMind Asset Investigation](asset-investigation/SKILL.md) | enrichment | Profile an application / service / host |
| [AuthMind Access Investigation](access-investigation/SKILL.md) | enrichment | Trace identity→asset flows and endpoint hosts |
| [AuthMind Secrets and Credential Risk](secrets-credential-risk/SKILL.md) | detection | High-score secrets, credential exposure, MFA / auth-fail signals |

Skills are DB-backed at runtime (see `core/skills/`). These `SKILL.md` files
are the versioned source of truth; import them into the running instance:

```bash
# Seed / refresh all AuthMind skills into the local DB
python scripts/seed_authmind_skills.py
```

Or import one at a time from the UI: **Workflows → Skills → Import Zip**
(zip must contain only `SKILL.md`).

## Notes

- MCP tools are double-prefixed at runtime (`authmind_authmind_list_accesses`)
  because the server key is `authmind` and the tool names already start with
  `authmind_`. The skill prompts use the runtime names agents actually call.
- `/posture/identities` and `/posture/assets` have no free-text search —
  prefer details endpoints and access pivots when you already know the entity
  id. List filters are type, status, score, and `latest_activity_time_gt`.
- Secrets tools return metadata only (name, type, provider, score). They
  never return secret material.
- The JWT needs `issues` for v1 issue tools, `playbooks` for the playbook
  list, and `posture` for v2 inventory/secrets. A 401 with a missing-scope
  message is a token problem, not an outage.
