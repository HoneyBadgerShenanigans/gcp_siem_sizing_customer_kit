# GCP Cloud Asset Inventory Collection Guide (SIEM Log Sizing)

This kit collects a snapshot of your Google Cloud Organization's resource inventory, IAM audit logging configuration, and network telemetry settings, and converts the raw `.ndjson` exports into a lightweight, AI-readable summary (`gcp_siem_sizing_inventory.md` and `gcp_siem_sizing_inventory.json`) for SIEM log ingestion sizing.

---

## 1. Prerequisites

We recommend running these scripts in **Google Cloud Shell** (which already has `gcloud` and `python3` installed).

### Required Information
1. **Organization ID** (`--org`): Your numeric GCP Organization ID (e.g., `123456789012` — find it via `gcloud organizations list`).
2. **Billing / Quota Project ID** (`--project`): Any active project ID in your organization where `cloudasset.googleapis.com` is (or can be) enabled.
3. **Temporary GCS Bucket Name** (`--bucket`): An existing Cloud Storage bucket (or a new bucket name if passing `--create-bucket`).
   * *Note: Cloud Asset Inventory cannot export to buckets configured with Customer-Managed Encryption Keys (CMEK) or an active bucket retention policy.*

### Required IAM Roles
Ensure your authenticated `gcloud` user or service account has:
| Role | Scope | Purpose |
| :--- | :--- | :--- |
| `roles/cloudasset.viewer` | Organization (`organizations/<ORG_ID>`) | Export organization-wide resource, IAM, and org policy inventory |
| `roles/storage.admin` *(or `objectCreator` + `objectViewer`)* | Target GCS Bucket | Write and download the exported `.json` snapshot files |
| `roles/serviceusage.serviceUsageConsumer` | Billing / Quota Project | Use the project's API quota for the export call |
| `roles/monitoring.viewer` *(Optional)* | Organization / Projects | Allows `--with-metrics` to query 7-day `logging.googleapis.com/byte_count` totals |

---

## 2. Step-by-Step Execution

### Step 1: Upload the Kit to Cloud Shell
Upload `1_export_cai.sh` and `2_prepare_siem_sizing_report.py` to your Cloud Shell directory and make the scripts executable:

```bash
chmod +x 1_export_cai.sh 2_prepare_siem_sizing_report.py
```

### Step 2: Run the Cloud Asset Inventory Export
Run `1_export_cai.sh` with your Organization ID, Billing Project ID, and GCS Bucket name (add `--create-bucket` if you want the script to create the bucket for you):

```bash
./1_export_cai.sh \
  --org YOUR_NUMERIC_ORG_ID \
  --project YOUR_BILLING_PROJECT_ID \
  --bucket YOUR_GCS_BUCKET_NAME \
  --create-bucket
```

*What this does:*
1. Enables `cloudasset.googleapis.com` and `storage.googleapis.com` on your billing project.
2. Submits three asynchronous exports (`resource`, `iam-policy`, `org-policy`) to `gs://YOUR_GCS_BUCKET_NAME/`.
3. Automatically polls `gcloud asset operations describe` every 10 seconds until all three exports report `done: true` (and verifies no export errors occurred).
4. Downloads `cai_resource.json`, `cai_iam-policy.json`, and `cai_org-policy.json` into your current directory.

### Step 3: Generate the AI-Ready SIEM Sizing Report
Run `2_prepare_siem_sizing_report.py` to strip out multi-megabyte CVE lists and BigQuery column schemas and produce a clean Markdown and JSON summary:

```bash
python3 2_prepare_siem_sizing_report.py \
  --with-metrics \
  --billing-project YOUR_BILLING_PROJECT_ID
```

> [!TIP]
> **Need to anonymize emails and IP addresses?**
> Add the `--redact` flag to hash all user/group/service-account email addresses and IPv4 CIDR ranges before the report is written:
> ```bash
> python3 2_prepare_siem_sizing_report.py --with-metrics --billing-project YOUR_BILLING_PROJECT_ID --redact
> ```

---

## 3. What to Return

Please return the two generated summary files (and fill out the 4 brief context questions below):
1. **`gcp_siem_sizing_inventory.md`** *(Human- and AI-readable Markdown summary — typically `< 50 KB`)*
2. **`gcp_siem_sizing_inventory.json`** *(Compacted JSON inventory)*

### Quick Context Questionnaire
*(Please include these 4 answers when sending your files, as future plans and external log sources are not captured in Cloud Asset Inventory)*:

1. **Planned vs. Current GCP Telemetry**: Are we sizing solely for the logging flags currently enabled in your GCP environment, or do you plan to enable additional high-volume telemetry during SIEM onboarding (e.g., turning on VPC Flow Logs, HTTP Load Balancer / Cloud Armor request logs, Cloud DNS logging, or `DATA_READ`/`DATA_WRITE` Audit Logs across additional production projects)?
   * *Answer:* 
2. **Endpoint / OS Log Collection**: For your running Compute Engine VMs and GKE nodes, do you plan to collect OS/container logs (Windows Event Logs, Sysmon, Linux `syslog`/`auditd`, EDR) via a direct SIEM forwarder/agent or via Cloud Logging?
   * *Answer:* 
3. **Google Workspace & Identity Providers**: Should the SIEM sizing include Google Workspace audit logs (Workspace Activity, Login, Admin, Groups, Chrome Enterprise) and/or external IdP logs (Okta, Microsoft Entra ID)? If yes, approximately how many active human users are in your directory?
   * *Answer:* 
4. **Expected 12-Month Growth**: What is your approximate expected 12-month growth rate (%) for cloud workloads?
   * *Answer:* 
