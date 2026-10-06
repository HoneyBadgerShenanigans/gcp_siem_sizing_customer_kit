#!/usr/bin/env python3
"""
2_prepare_siem_sizing_report.py

Converts raw Google Cloud Asset Inventory (CAI) NDJSON exports
(cai_resource.json, cai_iam-policy.json, cai_org-policy.json) into:
  1. gcp_siem_sizing_inventory.md   (Human & LLM-ready Markdown sizing report)
  2. gcp_siem_sizing_inventory.json (Compact, valid JSON stripped of CVE/schema/secret bloat)

Optional flags:
  --with-metrics : Queries 7-day Cloud Logging byte volume (logging.googleapis.com/byte_count)
                   across all discovered active projects via the Cloud Monitoring API.
  --redact       : Anonymizes user/group/serviceAccount emails and IP CIDRs before saving.
"""

import argparse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime
import hashlib
import json
import os
import re
import ssl
import subprocess
import time
from typing import Any, Iterator
import urllib.error
import urllib.parse
import urllib.request


# Asset types whose raw payloads contain massive CVE arrays, column schemas,
# or repetitive per-zone boilerplate that bloat LLM context windows.
SUMMARY_ONLY_ASSET_TYPES = {
    "osconfig.googleapis.com/VulnerabilityReport",
    "bigquery.googleapis.com/Table",
    "cloudsecuritycompliance.googleapis.com/CloudControlDeployment",
    "compute.googleapis.com/Route",
    "compute.googleapis.com/InstanceSettings",
    "compute.googleapis.com/Snapshot",
    "serviceusage.googleapis.com/Service",
}

DATABASE_ASSET_TYPES = {
    "sqladmin.googleapis.com/Instance",
    "spanner.googleapis.com/Instance",
    "alloydb.googleapis.com/Cluster",
    "alloydb.googleapis.com/Instance",
    "bigtableadmin.googleapis.com/Instance",
    "redis.googleapis.com/Instance",
    "firestore.googleapis.com/Database",
}

AUDIT_DB_FLAG_PREFIXES = (
    "cloudsql.enable_pgaudit",
    "pgaudit.",
    "general_log",
    "slow_query_log",
    "log_",
    "audit_",
)

# Resource data keys that may contain plaintext secrets, startup scripts, SSH keys,
# or environment variables and must be stripped before exporting resources_detailed.
SENSITIVE_RESOURCE_KEYS = {
    "metadata",
    "commonInstanceMetadata",
    "environmentVariables",
    "buildEnvironmentVariables",
    "secretEnvironmentVariables",
    "env",
    "privateKeyData",
    "publicKeyData",
    "oauth2ClientId",
    "clientSecret",
    "password",
    "rootPassword",
    "masterAuth",
}

AUDIT_LOG_TYPE_MAP = {
    1: "ADMIN_READ",
    2: "DATA_WRITE",
    3: "DATA_READ",
    "ADMIN_READ": "ADMIN_READ",
    "DATA_WRITE": "DATA_WRITE",
    "DATA_READ": "DATA_READ",
}

PROJECT_ID_RE = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")

# Bounded email regex to prevent polynomial backtracking (ReDoS) on large inputs
EMAIL_RE = re.compile(
    r"(?<![a-zA-Z0-9_.+-])"
    r"[a-zA-Z0-9_.+-]{1,64}@[a-zA-Z0-9-]{1,63}(?:\.[a-zA-Z0-9-]{1,63})+"
    r"(?![a-zA-Z0-9_.+-])"
)

# Matches valid IPv4 octets (0-255) and optional CIDR prefix (0-32),
# avoiding 4-part software version strings like 10.0.19041.1 or v1.2.3.4.
IPV4_RE = re.compile(
    r"(?<![\d.vV])"
    r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(?:/(?:3[0-2]|[12]?\d))?"
    r"(?![\d.])"
)


def redact_text(text: str) -> str:
    """Redacts email addresses and valid IPv4 CIDR ranges using a deterministic short hash."""
    if not text:
        return text

    def _hash_match(match: re.Match) -> str:
        val = match.group(0)
        digest = hashlib.sha256(val.encode("utf-8")).hexdigest()[:8]
        return f"<REDACTED:{digest}>"

    text = EMAIL_RE.sub(_hash_match, text)
    text = IPV4_RE.sub(_hash_match, text)
    return text


def sanitize_resource_data(obj: Any) -> Any:
    """Recursively strips sensitive fields (VM metadata, env vars, keys, secrets) from resource data."""
    if isinstance(obj, dict):
        return {
            k: ("<STRIPPED_SENSITIVE_FIELD>" if k in SENSITIVE_RESOURCE_KEYS else sanitize_resource_data(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [sanitize_resource_data(item) for item in obj]
    return obj


def md_escape(val: Any) -> str:
    """Sanitizes untrusted strings for safe inclusion inside Markdown table cells and inline code."""
    s = str(val if val is not None else "")
    s = s.replace("\r", " ").replace("\n", " ").replace("|", "\\|").replace("`", "'")
    return re.sub(r"[\x00-\x1f\x7f]", "", s)


def write_secure_file(path: str, content: str) -> None:
    """Writes a file with 0600 (owner read/write only) permissions."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
    except AttributeError:
        pass
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(content)


def iter_ndjson(path: str, do_redact: bool = False, warn_missing: bool = True) -> Iterator[dict]:
    """Streams an NDJSON file line-by-line to keep memory usage bounded on large exports."""
    if not os.path.exists(path):
        if warn_missing:
            print(f"WARNING: File not found: {path} (continuing with empty stream)")
        return
    with open(path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            if do_redact:
                line = redact_text(line)
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"WARNING: Skipping malformed JSON at {path}:{line_num} ({exc})")


def _build_ssl_context(insecure: bool = False) -> ssl.SSLContext:
    """Builds a verified SSLContext using certifi or system trust store unless --insecure is set."""
    if insecure:
        return ssl._create_unverified_context()
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def _query_project_logging_bytes(
    pid: str,
    token: str,
    quota_proj: str,
    start: str,
    end: str,
    ssl_ctx: ssl.SSLContext,
) -> tuple[str, dict | None]:
    """Queries 7-day logging.googleapis.com/byte_count for a single project with pagination & retry."""
    if not PROJECT_ID_RE.match(pid):
        print(f"  WARNING: Skipping invalid project ID format: {pid!r}")
        return pid, None
    if quota_proj and not PROJECT_ID_RE.match(quota_proj):
        print(f"  WARNING: Invalid billing/quota project ID format: {quota_proj!r}")
        return pid, None

    safe_pid = urllib.parse.quote(pid, safe="")
    base_url = (
        f"https://monitoring.googleapis.com/v3/projects/{safe_pid}/timeSeries"
        f"?filter=metric.type%3D%22logging.googleapis.com%2Fbyte_count%22"
        f"&interval.startTime={start}&interval.endTime={end}"
        f"&aggregation.alignmentPeriod=604800s"
        f"&aggregation.perSeriesAligner=ALIGN_SUM"
        f"&aggregation.crossSeriesReducer=REDUCE_SUM"
        f"&aggregation.groupByFields=metric.label.log"
    )

    by_log: dict[str, int] = {}
    total_7d = 0
    page_token = ""

    while True:
        url = (
            f"{base_url}&pageToken={urllib.parse.quote(page_token, safe='')}"
            if page_token
            else base_url
        )
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "X-Goog-User-Project": quota_proj or pid,
            },
        )
        payload = None
        for attempt in range(3):
            try:
                with urllib.request.urlopen(req, context=ssl_ctx, timeout=20) as resp:
                    payload = json.loads(resp.read().decode("utf-8"))
                break
            except urllib.error.HTTPError as exc:
                if exc.code in (429, 500, 503) and attempt < 2:
                    time.sleep(1.5 * (2 ** attempt))
                    continue
                print(f"  Note: Could not query Cloud Monitoring for project '{pid}': HTTP {exc.code}")
                return pid, None
            except urllib.error.URLError as exc:
                if isinstance(exc.reason, ssl.SSLCertVerificationError):
                    print(
                        f"  ERROR: SSL certificate verification failed for project '{pid}'. "
                        "Install CA certificates ('pip install certifi' or run 'Install Certificates.command'), "
                        "or pass '--insecure' to bypass TLS verification."
                    )
                    return pid, None
                print(f"  Note: Could not query Cloud Monitoring for project '{pid}': {exc}")
                return pid, None
            except Exception as exc:
                print(f"  Note: Could not query Cloud Monitoring for project '{pid}': {exc}")
                return pid, None

        if payload is None:
            return pid, None

        for ts in payload.get("timeSeries", []):
            log_name = ts.get("metric", {}).get("labels", {}).get("log", "unknown")
            val = sum(int(pt["value"].get("int64Value", 0)) for pt in ts.get("points", []))
            by_log[log_name] = by_log.get(log_name, 0) + val
            total_7d += val

        page_token = payload.get("nextPageToken", "")
        if not page_token:
            break

    return pid, {
        "total_bytes_7d": total_7d,
        "avg_mib_per_day": round(total_7d / (1024 ** 2) / 7.0, 2),
        "by_log_mib_per_day": {
            k: round(v / (1024 ** 2) / 7.0, 3)
            for k, v in sorted(by_log.items(), key=lambda x: -x[1])
        },
    }


def fetch_7d_logging_metrics(
    projects: list,
    billing_project: str = "",
    insecure: bool = False,
    max_workers: int = 10,
) -> dict:
    """Queries 7-day logging.googleapis.com/byte_count per project concurrently using gcloud token."""
    try:
        env = os.environ.copy()
        if billing_project:
            env["CLOUDSDK_BILLING_QUOTA_PROJECT"] = billing_project
        token = (
            subprocess.check_output(
                ["gcloud", "auth", "print-access-token"],
                env=env,
                stderr=subprocess.DEVNULL,
            )
            .decode("utf-8")
            .strip()
        )
    except Exception as exc:
        print(f"WARNING: Could not obtain gcloud access token for metrics ({exc}). Skipping metrics.")
        return {}

    now = datetime.datetime.now(datetime.timezone.utc)
    start = (now - datetime.timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    end = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    ssl_ctx = _build_ssl_context(insecure=insecure)

    results = {}
    workers = max(1, min(max_workers, len(projects)))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                _query_project_logging_bytes,
                pid,
                token,
                billing_project or pid,
                start,
                end,
                ssl_ctx,
            ): pid
            for pid in projects
        }
        for future in as_completed(futures):
            pid, data = future.result()
            if data is not None:
                results[pid] = data

    return results


def main():
    parser = argparse.ArgumentParser(description="Prepare AI-readable SIEM sizing inventory from CAI exports.")
    parser.add_argument("--resources", default="cai_resource.json", help="Path to cai_resource.json")
    parser.add_argument("--iam", default="cai_iam-policy.json", help="Path to cai_iam-policy.json")
    parser.add_argument("--org-policies", default="cai_org-policy.json", help="Path to cai_org-policy.json")
    parser.add_argument("--out-md", default="gcp_siem_sizing_inventory.md", help="Output Markdown path")
    parser.add_argument("--out-json", default="gcp_siem_sizing_inventory.json", help="Output JSON path")
    parser.add_argument("--with-metrics", action="store_true", help="Query 7-day Cloud Logging byte volume via Cloud Monitoring API")
    parser.add_argument("--billing-project", default="", help="Billing/quota project ID for --with-metrics")
    parser.add_argument("--redact", action="store_true", help="Redact email addresses and IPv4 CIDRs")
    parser.add_argument("--insecure", action="store_true", help="Disable SSL certificate verification for Cloud Monitoring API calls")
    parser.add_argument("--max-table-rows", type=int, default=100, help="Max rows per workload table in Markdown report (0 for unlimited)")
    parser.add_argument("--max-detailed-resources", type=int, default=2000, help="Max items in JSON resources_detailed (0 for unlimited)")
    args = parser.parse_args()

    print("Streaming CAI NDJSON files...")

    # 1. Pass 1 over cai_resource.json: Discover Organization, Folders, and Projects
    org_info = {"name": "organizations/UNKNOWN", "displayName": "Unknown"}
    folder_map = {}
    proj_map = {}
    projects_meta = {}

    for r in iter_ndjson(args.resources, do_redact=args.redact, warn_missing=True):
        at = r.get("asset_type", "")
        if at not in (
            "cloudresourcemanager.googleapis.com/Organization",
            "cloudresourcemanager.googleapis.com/Folder",
            "cloudresourcemanager.googleapis.com/Project",
        ):
            continue
        d = r.get("resource", {}).get("data", {})
        if at == "cloudresourcemanager.googleapis.com/Organization":
            org_info = d
        elif at == "cloudresourcemanager.googleapis.com/Folder":
            fid = r.get("name", "").split("/")[-1]
            folder_map[f"folders/{fid}"] = d.get("displayName", fid)
        elif at == "cloudresourcemanager.googleapis.com/Project":
            pnum = str(d.get("projectNumber", ""))
            pid = d.get("projectId", pnum)
            proj_map[f"projects/{pnum}"] = pid
            proj_map[pnum] = pid
            projects_meta[pid] = {
                "projectId": pid,
                "projectNumber": pnum,
                "name": d.get("name", pid),
                "lifecycleState": d.get("lifecycleState", "UNKNOWN"),
            }

    org_id = org_info.get("name", "organizations/UNKNOWN").split("/")[-1]

    def get_scope(item: dict) -> str:
        for anc in item.get("ancestors", []):
            if anc.startswith("projects/"):
                return proj_map.get(anc, anc)
            if anc.startswith("folders/"):
                return f"folder:{folder_map.get(anc, anc)}"
        return f"org:{org_id}"

    # 2. Pass 2 over cai_resource.json: Aggregate counts, telemetry configs & workloads
    total_resources = 0
    type_counts = Counter()
    scope_counts = defaultdict(Counter)
    enabled_apis = defaultdict(list)

    compute_vms = []
    gke_clusters = []
    serverless_items = []
    database_items = []
    subnets_flow_on = []
    subnets_total = 0
    firewalls = []
    routers_nat = []
    dns_items = []
    lb_backends = []
    armor_policies = []
    log_sinks = []
    compact_resources = []
    compact_resources_omitted = 0

    for r in iter_ndjson(args.resources, do_redact=args.redact, warn_missing=False):
        total_resources += 1
        at = r.get("asset_type", "UNKNOWN")
        scope = get_scope(r)
        type_counts[at] += 1
        scope_counts[scope][at] += 1
        d = r.get("resource", {}).get("data", {})
        loc = r.get("resource", {}).get("location", "global")

        if at == "serviceusage.googleapis.com/Service" and d.get("state") == "ENABLED":
            enabled_apis[scope].append(r.get("name", "").split("/")[-1])

        elif at == "compute.googleapis.com/Instance":
            compute_vms.append({
                "project": scope,
                "name": d.get("name"),
                "status": d.get("status"),
                "machineType": d.get("machineType", "").split("/")[-1],
                "zone": d.get("zone", "").split("/")[-1],
            })

        elif at == "container.googleapis.com/Cluster":
            gke_clusters.append({
                "project": scope,
                "name": d.get("name"),
                "status": d.get("status"),
                "location": loc,
                "currentNodeCount": d.get("currentNodeCount", 0),
                "loggingConfig": d.get("loggingConfig", {}),
            })

        elif at in (
            "run.googleapis.com/Service",
            "cloudfunctions.googleapis.com/Function",
            "cloudfunctions.googleapis.com/CloudFunction",
            "appengine.googleapis.com/Application",
        ):
            serverless_items.append({
                "project": scope,
                "asset_type": at,
                "name": d.get("name") or r.get("name", "").split("/")[-1],
                "location": loc,
            })

        elif at in DATABASE_ASSET_TYPES:
            db_entry = {
                "project": scope,
                "asset_type": at,
                "name": d.get("name") or r.get("name", "").split("/")[-1],
                "location": d.get("region") or loc,
                "state": d.get("state", "UNKNOWN"),
            }
            if at == "sqladmin.googleapis.com/Instance":
                db_entry["databaseVersion"] = d.get("databaseVersion", "")
                flags = d.get("settings", {}).get("databaseFlags", [])
                audit_flags = {
                    fl.get("name"): fl.get("value")
                    for fl in flags
                    if fl.get("name", "").startswith(AUDIT_DB_FLAG_PREFIXES)
                }
                if audit_flags:
                    db_entry["auditFlags"] = audit_flags
            database_items.append(db_entry)

        elif at == "compute.googleapis.com/Subnetwork":
            subnets_total += 1
            lc = d.get("logConfig", {})
            fl_on = bool(d.get("enableFlowLogs") or lc.get("enable"))
            if fl_on:
                subnets_flow_on.append({
                    "project": scope,
                    "name": d.get("name"),
                    "region": loc,
                    "aggregationInterval": lc.get("aggregationInterval", "DEFAULT"),
                    "flowSampling": lc.get("flowSampling", 0.5),
                    "metadata": lc.get("metadata", "INCLUDE_ALL_METADATA"),
                })

        elif at == "compute.googleapis.com/Firewall":
            lc = d.get("logConfig", {})
            firewalls.append({
                "project": scope,
                "name": d.get("name"),
                "direction": d.get("direction"),
                "disabled": d.get("disabled", False),
                "log_enable": bool(lc.get("enable")),
            })

        elif at == "compute.googleapis.com/Router":
            for nat in d.get("nats", []):
                lc = nat.get("logConfig", {})
                routers_nat.append({
                    "project": scope,
                    "router": d.get("name"),
                    "region": loc,
                    "nat_name": nat.get("name"),
                    "log_enable": bool(lc.get("enable")),
                    "log_filter": lc.get("filter", "NONE"),
                })

        elif at in ("dns.googleapis.com/Policy", "dns.googleapis.com/ManagedZone"):
            log_on = bool(d.get("enableLogging") or d.get("cloudLoggingConfig", {}).get("enableLogging"))
            dns_items.append({
                "project": scope,
                "asset_type": at,
                "name": d.get("name", r.get("name", "").split("/")[-1]),
                "log_enable": log_on,
            })

        elif at == "compute.googleapis.com/BackendService":
            lc = d.get("logConfig", {})
            sec_pol = d.get("securityPolicy", "")
            lb_backends.append({
                "project": scope,
                "name": d.get("name") or r.get("name", "").split("/")[-1],
                "loadBalancingScheme": d.get("loadBalancingScheme", "UNKNOWN"),
                "protocol": d.get("protocol", "UNKNOWN"),
                "log_enable": bool(lc.get("enable")),
                "sample_rate": lc.get("sampleRate", 1.0 if lc.get("enable") else 0.0),
                "security_policy": sec_pol.split("/")[-1] if sec_pol else "",
            })

        elif at == "compute.googleapis.com/SecurityPolicy":
            armor_policies.append({
                "project": scope,
                "name": d.get("name") or r.get("name", "").split("/")[-1],
                "rule_count": len(d.get("rules", [])),
                "adaptive_protection": bool(
                    d.get("adaptiveProtectionConfig", {}).get("layer7DdosDefenseConfig", {}).get("enable")
                ),
            })

        elif at == "logging.googleapis.com/LogSink":
            exclusions = [
                {
                    "name": ex.get("name"),
                    "filter": ex.get("filter", ""),
                    "disabled": ex.get("disabled", False),
                }
                for ex in d.get("exclusions", [])
            ]
            log_sinks.append({
                "scope": scope,
                "name": d.get("name"),
                "destination": d.get("destination"),
                "filter": d.get("filter", ""),
                "disabled": d.get("disabled", False),
                "include_children": d.get("includeChildren", False),
                "exclusions": exclusions,
            })

        # Populate compact_resources for JSON output (respecting --max-detailed-resources)
        if at in SUMMARY_ONLY_ASSET_TYPES and at not in (
            "osconfig.googleapis.com/VulnerabilityReport",
            "bigquery.googleapis.com/Table",
        ):
            continue

        if args.max_detailed_resources > 0 and len(compact_resources) >= args.max_detailed_resources:
            compact_resources_omitted += 1
            continue

        if at == "osconfig.googleapis.com/VulnerabilityReport":
            compact_resources.append({
                "name": r.get("name"),
                "asset_type": at,
                "scope": scope,
                "vulnerability_count": len(d.get("vulnerabilities", [])),
            })
        elif at == "bigquery.googleapis.com/Table":
            compact_resources.append({
                "name": r.get("name"),
                "asset_type": at,
                "scope": scope,
                "tableReference": d.get("tableReference"),
                "type": d.get("type"),
                "column_count": len(d.get("schema", {}).get("fields", [])),
            })
        elif at == "compute.googleapis.com/Subnetwork":
            lc = d.get("logConfig", {})
            fl_on = bool(d.get("enableFlowLogs") or lc.get("enable"))
            if fl_on or d.get("name") != "default":
                compact_resources.append({
                    "name": r.get("name"),
                    "asset_type": at,
                    "scope": scope,
                    "location": loc,
                    "enableFlowLogs": fl_on,
                    "logConfig": lc,
                })
        else:
            compact_resources.append({
                "name": r.get("name"),
                "asset_type": at,
                "scope": scope,
                "location": loc,
                "data": sanitize_resource_data(d),
            })

    # 3. Stream IAM Audit Configs & Principals
    total_iam_policies = 0
    audit_configs = []
    principals = set()
    for p in iter_ndjson(args.iam, do_redact=args.redact, warn_missing=True):
        total_iam_policies += 1
        pol = p.get("iam_policy", {})
        for b in pol.get("bindings", []):
            for m in b.get("members", []):
                principals.add(m)
        for ac in pol.get("audit_configs", []):
            log_types = [
                AUDIT_LOG_TYPE_MAP.get(cfg.get("log_type"), str(cfg.get("log_type")))
                for cfg in ac.get("audit_log_configs", [])
            ]
            audit_configs.append({
                "scope": get_scope(p),
                "resource": p.get("name"),
                "service": ac.get("service"),
                "log_types": log_types,
            })

    principal_types = Counter(m.split(":")[0] for m in principals)

    # Stream Org Policies count
    total_org_policies = sum(1 for _ in iter_ndjson(args.org_policies, do_redact=args.redact, warn_missing=True))

    # 4. Optional 7-Day Cloud Monitoring Metrics
    metrics_by_project = {}
    if args.with_metrics and projects_meta:
        active_pids = [
            pid for pid, m in projects_meta.items() if m.get("lifecycleState") == "ACTIVE"
        ]
        print(f"Querying 7-day Cloud Logging byte volume across {len(active_pids)} active project(s)...")
        metrics_by_project = fetch_7d_logging_metrics(
            active_pids,
            billing_project=args.billing_project,
            insecure=args.insecure,
        )

    # 5. Write Compact JSON (with 0600 permissions)
    ai_json = {
        "organization": {
            "organization_id": org_id,
            "display_name": org_info.get("displayName"),
            "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "redacted": args.redact,
        },
        "summary": {
            "total_resources": total_resources,
            "total_resource_types": len(type_counts),
            "total_iam_policies": total_iam_policies,
            "total_unique_iam_principals": len(principals),
            "iam_principals_by_type": dict(principal_types),
            "total_org_policies": total_org_policies,
            "detailed_resources_included": len(compact_resources),
            "detailed_resources_omitted": compact_resources_omitted,
        },
        "projects": list(projects_meta.values()),
        "iam_data_access_audit_configs": audit_configs,
        "log_sinks": log_sinks,
        "vpc_flow_log_subnets": subnets_flow_on,
        "firewall_rules": firewalls,
        "cloud_nat_gateways": routers_nat,
        "dns_logging": dns_items,
        "load_balancer_backends": lb_backends,
        "cloud_armor_policies": armor_policies,
        "compute_instances": compute_vms,
        "gke_clusters": gke_clusters,
        "serverless_resources": serverless_items,
        "database_instances": database_items,
        "measured_cloud_logging_7d": metrics_by_project,
        "asset_counts_by_type": dict(type_counts.most_common()),
        "enabled_apis_by_project": {k: sorted(v) for k, v in enabled_apis.items()},
        "resources_detailed": compact_resources,
    }

    write_secure_file(args.out_json, json.dumps(ai_json, indent=2))

    # 6. Write AI-Ready Markdown Report (with 0600 permissions & escaped cells)
    max_rows = args.max_table_rows
    md = []
    md.append("# GCP Organization Inventory for SIEM Log Ingestion Sizing\n")
    md.append(
        "> **LLM Sizing Prompt:** *Using this GCP Cloud Asset Inventory report, estimate daily and monthly "
        "SIEM log ingestion volume (GB/day and events/sec) broken down by log source (Cloud Audit Logs, "
        "Data Access Logs, VPC Flow Logs, Firewall Logs, Cloud NAT Logs, Cloud DNS Logs, Load Balancer & "
        "Cloud Armor Logs, OS/Endpoint Logs, GKE/Serverless, and Database Logs), and highlight top volume drivers.*\n"
    )

    md.append("## 1. Organization Overview\n")
    md.append("| Metric | Value |")
    md.append("| :--- | :--- |")
    md.append(f"| **Organization ID** | `{md_escape(org_id)}` (`{md_escape(org_info.get('displayName', 'N/A'))}`) |")
    md.append(f"| **Total Assets** | `{total_resources}` across `{len(type_counts)}` asset types |")
    md.append(f"| **Active Projects** | `{len(projects_meta)}` |")
    md.append(f"| **Unique IAM Principals** | `{len(principals)}` (`{md_escape(dict(principal_types))}`) |")
    md.append(f"| **Org Policies** | `{total_org_policies}` |\n")

    md.append("### Projects\n")
    md.append("| Project ID | Project Number | State | Total Assets | Enabled APIs |")
    md.append("| :--- | :--- | :--- | ---: | ---: |")
    sorted_projects = sorted(projects_meta.items())
    shown_projects = sorted_projects[:max_rows] if max_rows > 0 else sorted_projects
    for pid, pmeta in shown_projects:
        tot = sum(scope_counts[pid].values())
        apis = len(enabled_apis.get(pid, []))
        md.append(
            f"| `{md_escape(pid)}` | `{md_escape(pmeta['projectNumber'])}` | "
            f"`{md_escape(pmeta['lifecycleState'])}` | {tot} | {apis} |"
        )
    if max_rows > 0 and len(sorted_projects) > max_rows:
        md.append(f"\n*... and {len(sorted_projects) - max_rows} additional project(s) (see JSON output for full list).*")
    md.append("")

    md.append("## 2. SIEM Log Volume Drivers (Extracted from CAI)\n")
    md.append("### 2.1 IAM Data Access Audit Configs (`audit_configs`)\n")
    if audit_configs:
        md.append("| Scope | Target Service | Enabled Log Types |")
        md.append("| :--- | :--- | :--- |")
        for ac in audit_configs:
            md.append(
                f"| `{md_escape(ac['scope'])}` | `{md_escape(ac['service'])}` | "
                f"`{md_escape(', '.join(ac['log_types']))}` |"
            )
    else:
        md.append("*No custom Data Access `audit_configs` found (only default Admin Activity / System Event logs enabled).*")
    md.append("")

    md.append("### 2.2 Cloud Logging Sinks (`logging.googleapis.com/LogSink`)\n")
    custom_sinks = [s for s in log_sinks if s["name"] not in ("_Default", "_Required")]
    modified_builtin_sinks = [
        s for s in log_sinks
        if s["name"] in ("_Default", "_Required") and (s["disabled"] or s["exclusions"])
    ]
    md.append(
        f"Total Log Sinks: **{len(log_sinks)}** "
        f"(**{len(custom_sinks)}** custom sinks, **{len(log_sinks) - len(custom_sinks)}** default `_Default`/`_Required` sinks).\n"
    )
    if custom_sinks:
        md.append("| Scope | Sink Name | Destination | Disabled | Exclusions | Filter |")
        md.append("| :--- | :--- | :--- | :--- | ---: | :--- |")
        for s in custom_sinks:
            md.append(
                f"| `{md_escape(s['scope'])}` | `{md_escape(s['name'])}` | `{md_escape(s['destination'])}` | "
                f"`{md_escape(s['disabled'])}` | {len(s['exclusions'])} | `{md_escape(s['filter'])}` |"
            )
        md.append("")
    if modified_builtin_sinks:
        md.append("#### Modified or Disabled `_Default` / `_Required` Sinks (Impacts Stored Cloud Logging Volume)\n")
        md.append("| Scope | Sink Name | Disabled | Active Exclusions |")
        md.append("| :--- | :--- | :--- | :--- |")
        for s in modified_builtin_sinks:
            excl_summary = ", ".join(
                f"`{md_escape(ex['name'])}`" for ex in s["exclusions"] if not ex.get("disabled")
            ) or "None"
            md.append(
                f"| `{md_escape(s['scope'])}` | `{md_escape(s['name'])}` | "
                f"`{md_escape(s['disabled'])}` | {excl_summary} |"
            )
        md.append("")

    md.append("### 2.3 Network & Edge Telemetry Settings (VPC Flow, Firewall, Cloud NAT, DNS, Load Balancers, Cloud Armor)\n")
    md.append(f"* **VPC Subnetworks**: **{len(subnets_flow_on)}** with Flow Logs ON out of **{subnets_total}** total subnets.")
    for s in subnets_flow_on:
        md.append(
            f"  * `{md_escape(s['project'])}` / `{md_escape(s['name'])}` (`{md_escape(s['region'])}`): "
            f"interval=`{md_escape(s['aggregationInterval'])}`, sampling=`{md_escape(s['flowSampling'])}`, metadata=`{md_escape(s['metadata'])}`"
        )
    fw_on = [fw for fw in firewalls if fw["log_enable"] and not fw["disabled"]]
    md.append(f"* **VPC Firewall Rules**: **{len(fw_on)}** with logging ON out of **{len(firewalls)}** total rules.")
    for fw in fw_on:
        md.append(f"  * `{md_escape(fw['project'])}` / `{md_escape(fw['name'])}` (`{md_escape(fw['direction'])}`)")
    nat_on = [n for n in routers_nat if n["log_enable"]]
    md.append(f"* **Cloud NAT Gateways**: **{len(nat_on)}** with logging ON out of **{len(routers_nat)}** total NAT gateways.")
    for n in routers_nat:
        md.append(
            f"  * `{md_escape(n['project'])}` / `{md_escape(n['nat_name'])}` (`{md_escape(n['region'])}`): "
            f"logging=`{md_escape(n['log_enable'])}`, filter=`{md_escape(n['log_filter'])}`"
        )
    dns_on = [d for d in dns_items if d["log_enable"]]
    md.append(f"* **Cloud DNS Policies & Managed Zones**: **{len(dns_on)}** with logging ON out of **{len(dns_items)}** total.")
    for d in dns_items:
        md.append(
            f"  * `{md_escape(d['project'])}` / `{md_escape(d['name'])}` (`{md_escape(d['asset_type'])}`): "
            f"logging=`{md_escape(d['log_enable'])}`"
        )
    lb_on = [lb for lb in lb_backends if lb["log_enable"]]
    md.append(f"* **Load Balancer Backend Services**: **{len(lb_on)}** with request logging ON out of **{len(lb_backends)}** total backends.")
    for lb in lb_backends:
        pol_str = f", cloud_armor=`{md_escape(lb['security_policy'])}`" if lb["security_policy"] else ""
        md.append(
            f"  * `{md_escape(lb['project'])}` / `{md_escape(lb['name'])}` (`{md_escape(lb['loadBalancingScheme'])}` / `{md_escape(lb['protocol'])}`): "
            f"logging=`{md_escape(lb['log_enable'])}`, sampleRate=`{md_escape(lb['sample_rate'])}`{pol_str}"
        )
    md.append(f"* **Cloud Armor Security Policies**: **{len(armor_policies)}** total policies.")
    for ap in armor_policies:
        md.append(
            f"  * `{md_escape(ap['project'])}` / `{md_escape(ap['name'])}`: rules=`{md_escape(ap['rule_count'])}`, "
            f"adaptiveProtection=`{md_escape(ap['adaptive_protection'])}`"
        )
    md.append("")

    md.append("## 3. Compute, GKE, Serverless & Database Workloads\n")
    running_vms = [v for v in compute_vms if v["status"] == "RUNNING"]
    md.append(f"### 3.1 Compute Engine VMs ({len(compute_vms)} Total: {len(running_vms)} RUNNING, {len(compute_vms) - len(running_vms)} Non-Running)\n")
    if compute_vms:
        md.append("| Project | Instance Name | Status | Machine Type | Zone |")
        md.append("| :--- | :--- | :--- | :--- | :--- |")
        sorted_vms = sorted(compute_vms, key=lambda x: (x["status"] != "RUNNING", str(x["project"]), str(x["name"])))
        shown_vms = sorted_vms[:max_rows] if max_rows > 0 else sorted_vms
        for v in shown_vms:
            md.append(
                f"| `{md_escape(v['project'])}` | `{md_escape(v['name'])}` | "
                f"`{md_escape(v['status'])}` | `{md_escape(v['machineType'])}` | `{md_escape(v['zone'])}` |"
            )
        if max_rows > 0 and len(sorted_vms) > max_rows:
            md.append(f"\n*... and {len(sorted_vms) - max_rows} additional VM(s) omitted for brevity (see JSON output).*")
    md.append("")

    if gke_clusters:
        total_nodes = sum(int(c.get("currentNodeCount") or 0) for c in gke_clusters)
        md.append(f"### 3.2 GKE Clusters ({len(gke_clusters)} Clusters, {total_nodes} Total Nodes)\n")
        md.append("| Project | Cluster Name | Location | Status | Node Count | Logging Components |")
        md.append("| :--- | :--- | :--- | :--- | ---: | :--- |")
        for c in gke_clusters:
            comps = c.get("loggingConfig", {}).get("componentConfig", {}).get("enableComponents", [])
            comp_str = ", ".join(comps) if comps else "DEFAULT"
            md.append(
                f"| `{md_escape(c['project'])}` | `{md_escape(c['name'])}` | `{md_escape(c['location'])}` | "
                f"`{md_escape(c['status'])}` | {c['currentNodeCount']} | `{md_escape(comp_str)}` |"
            )
        md.append("")

    if serverless_items:
        md.append(f"### 3.3 Serverless Services & Functions ({len(serverless_items)})\n")
        md.append("| Project | Asset Type | Name | Location |")
        md.append("| :--- | :--- | :--- | :--- |")
        shown_sls = serverless_items[:max_rows] if max_rows > 0 else serverless_items
        for s in shown_sls:
            md.append(
                f"| `{md_escape(s['project'])}` | `{md_escape(s['asset_type'])}` | "
                f"`{md_escape(s['name'])}` | `{md_escape(s['location'])}` |"
            )
        if max_rows > 0 and len(serverless_items) > max_rows:
            md.append(f"\n*... and {len(serverless_items) - max_rows} additional serverless resource(s) omitted (see JSON output).*")
        md.append("")

    if database_items:
        md.append(f"### 3.4 Managed Databases ({len(database_items)})\n")
        md.append("| Project | Asset Type | Name | Location | State | Version / Audit Flags |")
        md.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
        shown_dbs = database_items[:max_rows] if max_rows > 0 else database_items
        for db in shown_dbs:
            details = []
            if db.get("databaseVersion"):
                details.append(f"ver=`{md_escape(db['databaseVersion'])}`")
            if db.get("auditFlags"):
                details.append(f"flags=`{md_escape(db['auditFlags'])}`")
            detail_str = ", ".join(details) if details else "N/A"
            md.append(
                f"| `{md_escape(db['project'])}` | `{md_escape(db['asset_type'])}` | `{md_escape(db['name'])}` | "
                f"`{md_escape(db['location'])}` | `{md_escape(db['state'])}` | {detail_str} |"
            )
        if max_rows > 0 and len(database_items) > max_rows:
            md.append(f"\n*... and {len(database_items) - max_rows} additional database resource(s) omitted (see JSON output).*")
        md.append("")

    if metrics_by_project:
        md.append("## 4. Measured 7-Day Cloud Logging Volume (`logging.googleapis.com/byte_count`)\n")
        md.append("| Project ID | Daily Average (MiB/day) | Top Log Streams (MiB/day) |")
        md.append("| :--- | ---: | :--- |")
        grand_mib_day = 0.0
        for pid, m in sorted(metrics_by_project.items(), key=lambda x: -x[1]["avg_mib_per_day"]):
            grand_mib_day += m["avg_mib_per_day"]
            top_streams = ", ".join(
                f"`{md_escape(k)}` ({v} MiB/d)" for k, v in list(m["by_log_mib_per_day"].items())[:5]
            ) or "None"
            md.append(f"| `{md_escape(pid)}` | **{m['avg_mib_per_day']:.2f} MiB/day** | {top_streams} |")
        md.append(f"| **TOTAL** | **{grand_mib_day:.2f} MiB/day** | *(~{grand_mib_day * 30 / 1024:.2f} GiB/month)* |\n")

    md.append("## 5. Complete Asset Count Breakdown by Type\n")
    md.append("| Count | Asset Type |")
    md.append("| ---: | :--- |")
    for at, cnt in type_counts.most_common():
        md.append(f"| {cnt} | `{md_escape(at)}` |")
    md.append("")

    write_secure_file(args.out_md, "\n".join(md))

    md_kb = os.path.getsize(args.out_md) / 1024.0
    json_kb = os.path.getsize(args.out_json) / 1024.0
    print(f"Done! Created AI-ready sizing files (permissions 0600):")
    print(f"  1. {args.out_md} ({md_kb:.1f} KB)")
    print(f"  2. {args.out_json} ({json_kb:.1f} KB)")


if __name__ == "__main__":
    main()
