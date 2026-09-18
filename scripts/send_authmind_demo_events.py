#!/usr/bin/env python3
"""
Agentic SOC Demo: send sample events to Vigil's generic webhook.

Pushes the demo events (Okta noise, Vault dual-auth, CloudTrail S3 misuse,
CloudTrail AssumeRole geo anomaly, CrowdStrike EDR, Windows NTLM posture,
and — opt-in via --include-authmind — the AuthMind "after" correlated
incident) to the daemon's generic webhook receiver (services/daemon/poller.py,
POST /ingest on DAEMON_WEBHOOK_PORT), then triggers an investigation per
finding so the AuthMind skill tools (skills/authmind/*) are available to
enrich them.

The AuthMind-sourced event is excluded by default: AuthMind is configured
for skills/enrichment only (see core/integrations/authmind/client.py's
get_authmind_mode()), so its data shouldn't be manually injected as a
finding source.

Usage:
    python scripts/send_authmind_demo_events.py
    python scripts/send_authmind_demo_events.py --webhook-url http://localhost:8081/ingest
    python scripts/send_authmind_demo_events.py --skip-investigate
    python scripts/send_authmind_demo_events.py --fresh --skip-investigate
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def _load_dotenv_token() -> str:
    """Best-effort read of DAEMON_WEBHOOK_TOKEN from .env without adding a
    python-dotenv dependency to this one-off script."""
    env_path = PROJECT_ROOT / ".env"
    if not env_path.exists():
        return ""
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if line.startswith("DAEMON_WEBHOOK_TOKEN="):
            return line.split("=", 1)[1].strip().strip('"')
    return ""


# ---------------------------------------------------------------------------
# The seven demo events, each mapped to a webhook-ingest body. Only these
# fields are recognized by core/ingestion/ingestion_service.py::ingest_finding:
# finding_id, mitre_predictions, anomaly_score, timestamp, data_source,
# external_id, description, entity_context, evidence_links, cluster_id,
# severity, status. Full vendor JSON is preserved under entity_context.raw_event
# so nothing is lost even though it isn't auto-parsed by the webhook.
# ---------------------------------------------------------------------------

OKTA_EVENTS = [
    {
        "actor": {"id": "00u1a2b3c4D5e6F7g8h9", "type": "User", "alternateId": "alex.chen@authmind.com", "displayName": "Alex Chen"},
        "client": {"userAgent": {"rawUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15", "os": "Mac OS X", "browser": "SAFARI"}, "geographicalContext": {"city": "Arlington", "state": "Virginia", "country": "United States", "geolocation": {"lat": 38.8816, "lon": -77.0910}}, "ipAddress": "203.0.113.44"},
        "displayMessage": "User single sign-on to app",
        "eventType": "user.authentication.sso",
        "outcome": {"result": "SUCCESS"},
        "published": "2026-09-16T13:02:11.000Z",
        "target": [{"id": "0oa9cursor00sh4tapp", "type": "AppInstance", "alternateId": "cursor.sh", "displayName": "Cursor (Agentic Coding)"}],
    },
    {
        "actor": {"id": "00u2b3c4d5E6f7G8h9i0", "type": "User", "alternateId": "priya.natarajan@authmind.com", "displayName": "Priya Natarajan"},
        "client": {"userAgent": {"rawUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/128.0", "os": "Windows 10", "browser": "CHROME"}, "geographicalContext": {"city": "Bethesda", "state": "Maryland", "country": "United States", "geolocation": {"lat": 38.9847, "lon": -77.0947}}, "ipAddress": "198.51.100.17"},
        "displayMessage": "User single sign-on to app",
        "eventType": "user.authentication.sso",
        "outcome": {"result": "SUCCESS"},
        "published": "2026-09-16T14:15:47.000Z",
        "target": [{"id": "0oa8anthropic0api00", "type": "AppInstance", "alternateId": "api.anthropic.com", "displayName": "Anthropic API"}],
    },
    {
        "actor": {"id": "00u1a2b3c4D5e6F7g8h9", "type": "User", "alternateId": "alex.chen@authmind.com", "displayName": "Alex Chen"},
        "client": {"userAgent": {"rawUserAgent": "cursor-agent/1.4.2 (agentic-cli)", "os": "Mac OS X", "browser": "UNKNOWN"}, "geographicalContext": {"city": "Arlington", "state": "Virginia", "country": "United States", "geolocation": {"lat": 38.8816, "lon": -77.0910}}, "ipAddress": "203.0.113.44"},
        "displayMessage": "OAuth2 token grant for agentic session",
        "eventType": "app.oauth2.token.grant",
        "outcome": {"result": "SUCCESS"},
        "published": "2026-09-16T16:40:23.000Z",
        "target": [{"id": "0oa9cursor00agentn5", "type": "AppInstance", "alternateId": "agentn.api5.cursor.sh", "displayName": "Cursor Agentic API"}],
    },
]

VAULT_DUAL_AUTH_EVENTS = [
    {"time": "2026-09-16T18:47:12.918Z", "type": "response", "auth": {"client_token": "hmac-sha256:1c2f...redacted", "accessor": "hmac-sha256:8a91...redacted", "display_name": "userpass-reporting-svc", "policies": ["default", "reporting-readonly"], "token_type": "service"}, "request": {"id": "9f3a7c1e-2b4d-4e6a-9f21-6d3b1a0c7e55", "operation": "update", "mount_type": "userpass", "mount_point": "auth/userpass/", "path": "auth/userpass/login/reporting-app-role", "remote_address": "10.59.39.79", "remote_port": 51422}, "response": {"auth": {"policies": ["default", "reporting-readonly"], "token_ttl": 3600}}},
    {"time": "2026-09-16T18:47:53.204Z", "type": "response", "auth": {"client_token": "hmac-sha256:7be2...redacted", "accessor": "hmac-sha256:44dd...redacted", "display_name": "aws-reporting-app-role", "policies": ["default", "reporting-app-role-policy"], "token_type": "service", "metadata": {"role_arn": "arn:aws:iam::123456789012:role/reporting-app-role", "auth_type": "iam"}}, "request": {"id": "2b6e9d4f-8c1a-4f7b-b3e0-1a9c4d6f8e02", "operation": "update", "mount_type": "aws", "mount_point": "auth/aws/", "path": "auth/aws/login", "remote_address": "10.59.39.79", "remote_port": 51498}, "response": {"auth": {"policies": ["default", "reporting-app-role-policy"], "token_ttl": 3600}}},
    {"time": "2026-09-16T18:48:10.552Z", "type": "response", "auth": {"display_name": "aws-reporting-app-role", "policies": ["default", "reporting-app-role-policy"], "token_type": "service"}, "request": {"id": "6a1d8f3b-4e2c-4a9d-8f61-3b7e2d5c9a44", "operation": "read", "mount_type": "aws", "mount_point": "aws/", "path": "aws/creds/reporting-app-role", "remote_address": "10.59.39.79", "remote_port": 51512}, "response": {"data": {"access_key": "AKIA-REDACTED-DEMO", "lease_id": "aws/creds/reporting-app-role/2n8x7v1qF3k9dR5tYbL2mNcZ", "lease_duration": 3600}}},
]

CLOUDTRAIL_S3_MISUSE = {
    "eventVersion": "1.09", "eventTime": "2026-09-16T18:49:31Z", "eventSource": "s3.amazonaws.com", "eventName": "GetObject", "awsRegion": "us-east-1", "sourceIPAddress": "10.59.39.79", "userAgent": "aws-cli/2.15.30 Python/3.11.6 Linux/5.15.0 exe/x86_64",
    "userIdentity": {"type": "AssumedRole", "principalId": "AROAEXAMPLE123:aws-reporting-app-role", "arn": "arn:aws:sts::123456789012:assumed-role/reporting-app-role/aws-reporting-app-role", "accountId": "123456789012", "sessionContext": {"sessionIssuer": {"type": "Role", "principalId": "AROAEXAMPLE123", "arn": "arn:aws:iam::123456789012:role/reporting-app-role", "accountId": "123456789012", "userName": "reporting-app-role"}, "attributes": {"creationDate": "2026-09-16T18:47:53Z", "mfaAuthenticated": "false"}, "sourceIdentity": "vault-issued-lease-2n8x7v1qF3k9dR5tYbL2mNcZ"}},
    "requestParameters": {"bucketName": "am-qa-reports", "key": "internal/customer-deployment-exports/acme_corp_export_2026Q3.csv", "Host": "am-qa-reports.s3.amazonaws.com"},
    "responseElements": None,
    "additionalEventData": {"SignatureVersion": "SigV4", "AuthenticationMethod": "AuthHeader", "x-amz-server-side-encryption": "AES256"},
    "eventID": "d4c8f1a2-9b3e-4f6a-8c1d-7e2b9a4f6c31", "readOnly": True,
    "resources": [{"type": "AWS::S3::Object", "ARN": "arn:aws:s3:::am-qa-reports/internal/customer-deployment-exports/acme_corp_export_2026Q3.csv"}, {"accountId": "123456789012", "type": "AWS::S3::Bucket", "ARN": "arn:aws:s3:::am-qa-reports"}],
    "eventType": "AwsApiCall", "managementEvent": False, "recipientAccountId": "123456789012", "eventCategory": "Data",
}

CLOUDTRAIL_ASSUMEROLE_GEO_ANOMALY = {
    "eventVersion": "1.09", "eventTime": "2026-09-16T19:34:41Z", "eventSource": "sts.amazonaws.com", "eventName": "AssumeRole", "awsRegion": "us-east-1", "sourceIPAddress": "13.126.71.204", "userAgent": "aws-cli/2.15.30 Python/3.11.6 Linux/5.15.0 exe/x86_64",
    "userIdentity": {"type": "IAMUser", "principalId": "AIDAEXAMPLE456", "arn": "arn:aws:iam::123456789012:user/hashicorp-vault-user", "accountId": "123456789012", "userName": "hashicorp-vault-user"},
    "requestParameters": {"roleArn": "arn:aws:iam::123456789012:role/hashicorp-s3-access-role", "roleSessionName": "hashicorp-vault-user-session", "durationSeconds": 3600},
    "responseElements": {"credentials": {"accessKeyId": "ASIA-REDACTED-DEMO", "sessionToken": "REDACTED", "expiration": "Sep 16, 2026, 8:34:41 PM"}, "assumedRoleUser": {"assumedRoleId": "AROAEXAMPLE789:hashicorp-vault-user-session", "arn": "arn:aws:sts::123456789012:assumed-role/hashicorp-s3-access-role/hashicorp-vault-user-session"}},
    "additionalEventData": {"SignatureVersion": "SigV4", "AuthenticationMethod": "AuthHeader"},
    "eventID": "7e1b4d9c-3a6f-4e8b-9c2d-5f1a8e3b6d94", "eventType": "AwsApiCall", "managementEvent": True, "recipientAccountId": "123456789012", "eventCategory": "Management", "vpcEndpointId": None,
}

CROWDSTRIKE_ALERT = {
    "detect_id": "ldt:8f3a1c9e2b4d4e6a9f21:6d3b1a0c7e55f9a2", "created_timestamp": "2026-09-16T18:47:58Z", "max_severity": 60, "max_severity_displayname": "Medium", "status": "new",
    "device": {"device_id": "d4c8f1a29b3e4f6a8c1d7e2b9a4f6c31", "hostname": "pam-test-machine", "local_ip": "10.59.39.79", "platform_name": "Linux", "os_version": "Ubuntu 22.04", "agent_version": "7.18.16406.0"},
    "behaviors": [{"behavior_id": "9a2f7c1e3b4d4e6a9f21", "tactic": "Credential Access", "tactic_id": "TA0006", "technique": "Unsecured Credentials", "technique_id": "T1552", "objective": "Gain Access", "description": "Process 'vault' invoked twice within 41 seconds against distinct authentication backends (userpass, then aws) from a host with no prior Vault CLI activity in the last 30 days.", "cmdline": "vault login -method=userpass username=reporting-app-role", "parent_details": {"parent_cmdline": "/bin/bash /opt/reporting/run_export.sh", "parent_process_id": "48213"}, "user_name": "svc_reporting", "severity": 60, "confidence": 70, "ioc_type": "process_pattern", "false_positive": False}],
    "seconds_to_triaged": None, "seconds_to_resolved": None, "email_sent": False, "first_behavior": "2026-09-16T18:47:12Z", "last_behavior": "2026-09-16T18:47:53Z", "product": "epp", "source_products": ["Falcon Insight"], "source_vendors": ["CrowdStrike"],
}

WINDOWS_NTLM_POSTURE = {
    "log_source": "Windows Security Event Log", "host": "AM-AD-DC-03.Authmind.local",
    "summary_window": {"start": "2026-04-16T00:00:00Z", "end": "2026-09-16T20:00:00Z", "aggregated_flow_count": 306847},
    "sample_events": [
        {"EventID": 4776, "TimeCreated": "2026-09-16T19:58:02Z", "Channel": "Security", "Computer": "AM-AD-DC-03.Authmind.local", "EventData": {"PackageName": "NTLM V2", "TargetUserName": "svc_reporting", "Workstation": "PAM-TEST-MACHINE", "Status": "0x0"}, "Message": "The computer attempted to validate the credentials for an account using NTLM."},
        {"EventID": 4624, "TimeCreated": "2026-09-16T19:58:02Z", "Channel": "Security", "Computer": "AM-AD-DC-03.Authmind.local", "EventData": {"LogonType": 3, "AuthenticationPackageName": "NTLM", "TargetUserName": "svc_reporting", "WorkstationName": "PAM-TEST-MACHINE", "IpAddress": "10.59.39.79"}, "Message": "An account was successfully logged on (Network logon, NTLM)."},
    ],
    "note": "Not a discrete alert, a standing posture finding (AuthMind incident 'Unsecure Protocols'). Surfaced here as blast-radius context: the same host observed in the Vault dual-auth event (pam-test-machine) already has a live network path to an NTLM-accepting domain controller.",
}

NETSKOPE_PHISH_ENTRA_LOOKALIKE = {
    "timestamp": 1750939200,
    "alert_type": "phish",
    "alert_name": "Phishing page detected - Credential Harvesting (Microsoft Entra ID lookalike)",
    "action": "alert",
    "severity": "high",
    "policy": "NSPolicy - Threat Protection - Real-time Threat Detection",
    "user": "meenal.yadav@authmind.com",
    "device": "AM-Sec-Win11-1",
    "os": "Windows 11",
    "browser": "Chrome",
    "srcip": "10.42.8.117",
    "app": "Unknown Web",
    "category": "Phishing",
    "traffic_type": "Web",
    "dsthost": "login-microsftonline.com",
    "url": "https://login-microsftonline.com/common/oauth2/authorize?client_id=00000003-0000-0ff1-ce00-000000000000&redirect_uri=https%3A%2F%2Foutlook.office365.com",
    "dstip": "185.220.101.47",
    "cci": 9,
    "ccl": "poor",
    "malsite_category": ["Phishing", "Credential Theft"],
    "malsite_confidence": "high",
    "organization_unit": "AuthMind/Corporate",
    "netskope_tenant": "indexnine.goskope.com",
}

AUTHMIND_CORRELATED_INCIDENT = {
    "authmind_incident": {
        "incident_id": "DEMO-990214", "status": "Open", "risk": "Critical", "playbook": "Unauthorized Role Impersonation + Misuse of Secrets (Correlated)", "opened": "2026-09-16T19:35:02Z",
        "headline": "hashicorp-vault-user (User) began acting like a Service/Service Account and assumed hashicorp-s3-access-role from a never-before-seen geography, 47 minutes after reporting-app-role probed two Vault auth methods from pam-test-machine and pulled AWS credentials used outside its documented scope.",
        "correlated_from": [
            {"source": "HashiCorp Vault Audit Log", "file": "02_vault_audit_dual_auth.json", "events": 3},
            {"source": "AWS CloudTrail (Data Events)", "file": "03_cloudtrail_s3_secret_misuse.json", "events": 1},
            {"source": "AWS CloudTrail (Management Events)", "file": "04_cloudtrail_assumerole_geo_anomaly.json", "events": 1},
            {"source": "CrowdStrike Falcon", "file": "05_crowdstrike_edr_alert.json", "events": 1},
            {"source": "Windows Security Event Log", "file": "06_windows_ntlm_legacy_auth.json", "events": "background posture context"},
        ],
        "identity_findings": [
            {"identity": "hashicorp-vault-user", "identity_system": "AWS IAM (123456789012)", "provisioned_as": "User", "observed_behavior": "Acts Like Service/Service Account", "access_type": "Impersonate (sts:AssumeRole)", "target_asset": "hashicorp-s3-access-role", "geo_baseline": "Bethesda, MD / Arlington, VA (90-day history)", "geo_observed": "Mumbai, Maharashtra, India", "geo_anomaly": True, "first_time_source_asn": True},
            {"identity": "reporting-app-role", "identity_system": "HashiCorp Vault", "provisioned_as": "Role (Service/Application)", "observed_behavior": "Dual auth-method usage within 41s (userpass, aws)", "baseline_behavior": "Single auth method (aws) from scheduled job runner, ~once per hour", "source_host": "pam-test-machine (10.59.39.79)", "downstream_access": "s3://am-qa-reports (outside documented reporting-readonly scope)", "policy_violated": "Misuse of Secrets"},
        ],
        "posture_context": [{"finding": "Unsecure Protocols", "asset": "AM-AD-DC-03.Authmind.local", "detail": "NTLM still accepted; 306,847 flows over trailing 5 months", "relevance": "Same source host (pam-test-machine) as the Vault dual-auth event has an active NTLM path to this DC, raising lateral-movement blast radius"}],
        "noise_suppressed": {"count": 47, "rule": "Access not from Israel", "reason_auto_closed": "Known corporate identities, consistent device fingerprint, established 90-day access pattern from U.S. offices; no privilege change detected", "examples": ["api.anthropic.com", "agentn.api5.cursor.sh"]},
        "confidence": 0.91,
        "recommended_actions": [
            "Revoke and rotate AWS access keys for IAM user hashicorp-vault-user",
            "Revoke active Vault leases and rotate the token for reporting-app-role",
            "Quarantine or decommission pam-test-machine pending investigation",
            "Force Kerberos-only authentication on AM-AD-DC-03.Authmind.local",
            "Require MFA + AWS auth method exclusively for reporting-app-role (disable userpass mount for service identities)",
        ],
        "agentic_soc_summary_for_human_analyst": "1 correlated critical case (was 5 raw alerts across 4 tools + 47 suppressed low-value alerts). A previously human-only AWS identity impersonated a service role from an unrecognized country, minutes after the Vault-managed role it depends on was accessed via two different auth methods from a stale test host and used outside its documented S3 scope. Adjacent NTLM exposure on the domain controller increases urgency. Recommended actions drafted and awaiting one-click approval.",
    }
}


# Latest of the original (non-AuthMind) event timestamps — the Windows NTLM
# posture window end. --fresh shifts every timestamp by (now - this), so the
# whole 41-minute story keeps its original pacing but lands "just now".
_ORIGINAL_LATEST_TS = "2026-09-16T20:00:00.000Z"


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _format_ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def build_events(
    run_tag: Optional[str] = None,
    fresh: bool = False,
    include_authmind: bool = False,
) -> List[Dict[str, Any]]:
    """Map each of the demo events onto a webhook-ingest body.

    By default this excludes the AuthMind-sourced "correlated incident"
    event — AuthMind is configured for skills/enrichment only, so its data
    shouldn't be manually injected as a finding source. Pass
    include_authmind=True to add it back for e.g. a fully scripted replay.

    run_tag, if given, suffixes finding_id/external_id so this run creates
    new rows instead of colliding with (or silently no-op'ing against) a
    prior run's. fresh shifts every timestamp so the story lands "now"
    while preserving the original relative spacing between events.
    """
    offset = timedelta(0)
    if fresh:
        offset = datetime.now(timezone.utc) - _parse_ts(_ORIGINAL_LATEST_TS)

    def fid(base: str) -> str:
        return f"{base}-{run_tag}" if run_tag else base

    def extid(base: Optional[str]) -> Optional[str]:
        return f"{base}-{run_tag}" if (base is not None and run_tag) else base

    def ts(original: str) -> str:
        return _format_ts(_parse_ts(original) + offset) if fresh else original

    events = [
        {
            "finding_id": fid("demo-okta-noise-cursor-sh"),
            "data_source": "okta",
            # No console incident number applies to this specific event (only
            # agentn.api5.cursor.sh / 898243 and api.anthropic.com / 709611 are
            # listed entities) — left unset rather than reusing 898243, which
            # would collide with the uniq_findings_source_extid constraint.
            "external_id": None,
            "timestamp": ts(OKTA_EVENTS[0]["published"]),
            "severity": "informational",
            "description": "Alex Chen SSO to Cursor (Agentic Coding) from Arlington, VA — trips 'Access not from Israel' baseline.",
            "entity_context": {"identity": "alex.chen@authmind.com", "asset": "cursor.sh", "playbook": "Access not from Israel", "raw_event": OKTA_EVENTS[0]},
        },
        {
            "finding_id": fid("demo-okta-noise-anthropic-api"),
            "data_source": "okta",
            "external_id": extid("709611"),
            "timestamp": ts(OKTA_EVENTS[1]["published"]),
            "severity": "informational",
            "description": "Priya Natarajan SSO to Anthropic API from Bethesda, MD — trips 'Access not from Israel' baseline.",
            "entity_context": {"identity": "priya.natarajan@authmind.com", "asset": "api.anthropic.com", "playbook": "Access not from Israel", "raw_event": OKTA_EVENTS[1]},
        },
        {
            "finding_id": fid("demo-okta-noise-cursor-agentic-api"),
            "data_source": "okta",
            "external_id": extid("898243"),
            "timestamp": ts(OKTA_EVENTS[2]["published"]),
            "severity": "informational",
            "description": "Alex Chen OAuth2 token grant for Cursor Agentic API from Arlington, VA — trips 'Access not from Israel' baseline.",
            "entity_context": {"identity": "alex.chen@authmind.com", "asset": "agentn.api5.cursor.sh", "playbook": "Access not from Israel", "raw_event": OKTA_EVENTS[2]},
        },
        {
            "finding_id": fid("demo-vault-dual-auth-reporting-app-role"),
            "data_source": "hashicorp_vault",
            "external_id": extid("685040"),
            "timestamp": ts(VAULT_DUAL_AUTH_EVENTS[0]["time"]),
            "severity": "high",
            "description": "reporting-app-role authenticated via two different Vault auth methods (userpass, then aws) 41s apart, from pam-test-machine — deviates from its single-method hourly baseline.",
            "entity_context": {"identity": "reporting-app-role", "asset": "pam-test-machine", "playbook": "Misuse of Secrets", "raw_event": VAULT_DUAL_AUTH_EVENTS},
        },
        {
            "finding_id": fid("demo-cloudtrail-s3-secret-misuse"),
            "data_source": "aws_cloudtrail",
            "external_id": extid("685040"),
            "timestamp": ts(CLOUDTRAIL_S3_MISUSE["eventTime"]),
            "severity": "high",
            "description": "Vault-issued AWS credential for reporting-app-role used to GetObject from s3://am-qa-reports, outside the role's documented reporting-readonly scope.",
            "entity_context": {"identity": "reporting-app-role", "asset": "am-qa-reports", "playbook": "Misuse of Secrets", "raw_event": CLOUDTRAIL_S3_MISUSE},
        },
        {
            "finding_id": fid("demo-cloudtrail-assumerole-geo-anomaly"),
            "data_source": "aws_cloudtrail",
            "external_id": extid("905946"),
            "timestamp": ts(CLOUDTRAIL_ASSUMEROLE_GEO_ANOMALY["eventTime"]),
            "severity": "critical",
            "description": "hashicorp-vault-user (normally a human login from the US) assumed hashicorp-s3-access-role from a Mumbai NAT gateway — first-time source ASN/geo, acting like a service account.",
            "entity_context": {"identity": "hashicorp-vault-user", "asset": "hashicorp-s3-access-role", "playbook": "Unauthorized Role Impersonation", "raw_event": CLOUDTRAIL_ASSUMEROLE_GEO_ANOMALY},
        },
        {
            "finding_id": fid("demo-crowdstrike-edr-pam-test-machine"),
            "data_source": "crowdstrike",
            "external_id": extid("685040"),
            "timestamp": ts(CROWDSTRIKE_ALERT["created_timestamp"]),
            "severity": "medium",
            "description": "Falcon EDR independently detected 'vault' invoked twice in 41s against distinct auth backends on pam-test-machine — corroborates the Vault dual-auth finding via a second tool.",
            "entity_context": {"identity": "svc_reporting", "asset": "pam-test-machine", "playbook": "Misuse of Secrets", "raw_event": CROWDSTRIKE_ALERT},
        },
        {
            "finding_id": fid("demo-windows-ntlm-am-ad-dc-03"),
            "data_source": "windows_security",
            "external_id": extid("697833"),
            "timestamp": ts(WINDOWS_NTLM_POSTURE["summary_window"]["end"]),
            "severity": "low",
            "description": "AM-AD-DC-03 has accepted legacy NTLM authentication for 5 months (306,847 flows) — standing posture exposure, blast-radius context for hosts on its network path.",
            "entity_context": {"asset": "AM-AD-DC-03.Authmind.local", "playbook": "Unsecure Protocols", "raw_event": WINDOWS_NTLM_POSTURE},
        },
        {
            "finding_id": fid("netskope-phish-entra-lookalike-meenal"),
            "data_source": "netskope",
            "external_id": None,
            "timestamp": ts(
                _format_ts(
                    datetime.fromtimestamp(
                        NETSKOPE_PHISH_ENTRA_LOOKALIKE["timestamp"], tz=timezone.utc
                    )
                )
            ),
            "severity": "high",
            "description": "Netskope blocked meenal.yadav@authmind.com's browser from a Microsoft Entra ID / Office 365 OAuth lookalike phishing page (login-microsftonline.com, typosquatting login.microsoftonline.com) — high-confidence credential-harvesting page, Cloud Confidence Index 9/poor.",
            "entity_context": {
                "identity": "meenal.yadav@authmind.com",
                "asset": "login-microsftonline.com",
                "playbook": "Phishing - Credential Harvesting",
                "raw_event": NETSKOPE_PHISH_ENTRA_LOOKALIKE,
            },
        },
        {
            "finding_id": fid("demo-authmind-correlated-990214"),
            "data_source": "authmind",
            "external_id": extid("DEMO-990214"),
            "timestamp": ts(AUTHMIND_CORRELATED_INCIDENT["authmind_incident"]["opened"]),
            "severity": "critical",
            "description": AUTHMIND_CORRELATED_INCIDENT["authmind_incident"]["headline"],
            "entity_context": {
                "identity": "hashicorp-vault-user",
                "asset": "hashicorp-s3-access-role",
                "playbook": AUTHMIND_CORRELATED_INCIDENT["authmind_incident"]["playbook"],
                "raw_event": AUTHMIND_CORRELATED_INCIDENT,
            },
        },
    ]

    if not include_authmind:
        events = [e for e in events if e["data_source"] != "authmind"]

    return events


def send_event(webhook_url: str, token: str, event: Dict[str, Any]) -> bool:
    resp = requests.post(
        webhook_url,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json=event,
        timeout=10,
    )
    ok = resp.status_code == 200 and resp.json().get("ingested", 0) >= 1
    print(f"  {'OK ' if ok else 'FAIL'} {event['finding_id']:45s} -> {resp.status_code} {resp.text.strip()}")
    return ok


def trigger_investigation(api_base_url: str, finding_id: str, agent_id: str = "investigator") -> None:
    """Build the investigation prompt for `finding_id` (POST /api/agents/agents/investigate
    — the router double-prefixes: ROUTER_META prefix "/api/agents" + route "/agents/investigate",
    which only constructs a prompt — it runs nothing) and actually execute it as a
    chat turn (POST /api/claude/chat/stream), which is where the agent-serve/
    agent-worker layer runs the real LLM tool-calling loop and can choose to call
    an AuthMind skill_* tool.

    The SSE stream deliberately never reports which tool ran (see
    services/agent/workflows/chat/sse.ts) so this can't assert a skill fired from
    the response alone. Check logs/backend.log for "internal tool invoke: skill_*"
    to confirm (added in core/agents/tools_router.py for this reason).
    """
    inv = requests.post(
        f"{api_base_url}/api/agents/agents/investigate",
        json={"finding_id": finding_id, "agent_id": agent_id},
        timeout=15,
    )
    if inv.status_code != 200:
        print(f"  FAIL investigate {finding_id}: {inv.status_code} {inv.text.strip()}")
        return
    prompt = inv.json()["prompt"]

    with requests.post(
        f"{api_base_url}/api/claude/chat/stream",
        json={
            "messages": [{"role": "user", "content": prompt}],
            "agent_id": agent_id,
            "session_id": f"demo-{finding_id}",
        },
        stream=True,
        timeout=180,
    ) as resp:
        if resp.status_code != 200:
            print(f"  FAIL chat/stream {finding_id}: {resp.status_code} {resp.text.strip()}")
            return
        text_chunks: List[str] = []
        saw_error = None
        for line in resp.iter_lines(decode_unicode=True):
            if not line or not line.startswith("data: "):
                continue
            try:
                event = json.loads(line[len("data: "):])
            except json.JSONDecodeError:
                continue
            if event.get("type") == "text":
                text_chunks.append(event["content"])
            elif "error" in event:
                saw_error = event["error"]

    if saw_error:
        print(f"  FAIL chat/stream {finding_id}: {saw_error}")
        return
    summary = "".join(text_chunks).strip().replace("\n", " ")[:160]
    print(f"  OK  investigate {finding_id} -> {summary!r}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--webhook-url", default=os.environ.get("VIGIL_WEBHOOK_URL", "http://localhost:8081/ingest"))
    parser.add_argument("--webhook-token", default=os.environ.get("DAEMON_WEBHOOK_TOKEN") or _load_dotenv_token())
    parser.add_argument("--api-base-url", default=os.environ.get("VIGIL_API_URL", "http://127.0.0.1:6987"))
    parser.add_argument("--agent-id", default="investigator", help="Agent to run the investigation as, e.g. 'investigator' or 'correlator'")
    parser.add_argument("--skip-investigate", action="store_true", help="Only ingest events, skip the AuthMind-skill investigation trigger")
    parser.add_argument("--skip-ingest", action="store_true", help="Only run investigation, skip (re-)sending events to the webhook")
    parser.add_argument("--finding-id", action="append", dest="finding_ids", help="Only investigate this finding_id (repeatable). Ingests all events regardless unless --skip-ingest is also set.")
    parser.add_argument("--fresh", action="store_true", help="Shift all timestamps so the story lands 'now' (preserves original relative spacing)")
    parser.add_argument("--run-tag", default=None, help="Suffix finding_id/external_id with this tag so the run adds new rows instead of colliding with a prior run's. Auto-generated from the current time when --fresh is set and this is omitted.")
    parser.add_argument("--include-authmind", action="store_true", help="Also (re-)send the AuthMind-sourced 'correlated incident' event. Omitted by default since AuthMind is configured for skills/enrichment only, not as a finding source.")
    args = parser.parse_args()

    if not args.webhook_token:
        print("ERROR: no webhook token found. Set DAEMON_WEBHOOK_TOKEN or pass --webhook-token.")
        sys.exit(1)

    run_tag = args.run_tag
    if args.fresh and not run_tag:
        run_tag = datetime.now(timezone.utc).strftime("%m%d%H%M%S")

    events = build_events(run_tag=run_tag, fresh=args.fresh, include_authmind=args.include_authmind)

    if args.skip_ingest:
        sent = events
    else:
        print(f"Sending {len(events)} events to {args.webhook_url}...")
        sent = [e for e in events if send_event(args.webhook_url, args.webhook_token, e)]
        print(f"{len(sent)}/{len(events)} events ingested.\n")
        # Ingestion is async (webhook -> queue -> daemon processor), give it a
        # moment to land before we look the findings up for investigation.
        time.sleep(2)

    if args.skip_investigate:
        return

    if args.finding_ids:
        wanted = set(args.finding_ids)
        sent = [e for e in sent if e["finding_id"] in wanted]

    print(f"Triggering AuthMind-skill investigation for {len(sent)} findings as agent '{args.agent_id}'...")
    for event in sent:
        trigger_investigation(args.api_base_url, event["finding_id"], args.agent_id)

    print(
        "\nTo confirm which AuthMind skill(s) actually fired, check:\n"
        "  grep 'internal tool invoke: skill_' logs/backend.log"
    )


if __name__ == "__main__":
    main()
