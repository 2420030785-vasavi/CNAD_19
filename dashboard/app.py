import json
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

# ---------------------------------------------------------
# Configuration & Constants
# ---------------------------------------------------------
AWS_REGION = "ap-southeast-2"  # STRICTLY Sydney
NSW_GRID_EMISSION_FACTOR = 640  # gCO2e per kWh (NSW Grid, NGA Factors 2025)
PUE = 1.135                     # AWS data center Power Usage Effectiveness
T3_MICRO_MIN_WATTS = 0.74       # Idle watts per vCPU
T3_MICRO_MAX_WATTS = 3.5        # 100% load watts per vCPU
T3_MICRO_VCPUS = 2

COST_ENABLED = False  # Cost Explorer costs $0.01 per request and may be blocked by SCP

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
TF_STATE_PATH = PROJECT_ROOT / "terraform" / "terraform.tfstate"
DB_PATH = BASE_DIR / "watchdog_v2.db"

app = FastAPI(title="AWS Infra Watchdog", version="2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

db_lock = threading.Lock()

# Simple 3-second cache to avoid hitting AWS rate limits on rapid polls
_cache: Dict[str, Any] = {
    "status_data": None,
    "last_fetched": 0.0,
}

# ---------------------------------------------------------
def get_db_connection():
    return sqlite3.connect(DB_PATH, timeout=15.0)

# ---------------------------------------------------------
# Database Initialization
# ---------------------------------------------------------
def init_db():
    with db_lock:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                status TEXT NOT NULL,          -- 'open' or 'resolved'
                severity TEXT NOT NULL,        -- 'critical', 'high', 'medium', 'info'
                summary TEXT NOT NULL,
                explanation TEXT NOT NULL,
                badge TEXT NOT NULL,           -- 'Gemini' or 'Rules'
                created_at TEXT NOT NULL,
                resolved_at TEXT,
                resolution_detail TEXT
            )
        """)
        conn.commit()
        conn.close()

init_db()

# ---------------------------------------------------------
# AWS Clients (Cached & Pooled for Long-Running Stability)
# ---------------------------------------------------------
_boto3_clients: Dict[tuple, Any] = {}

def get_boto3_client(service_name: str, region_name: str = AWS_REGION):
    key = (service_name, region_name)
    if key not in _boto3_clients:
        _boto3_clients[key] = boto3.client(service_name, region_name=region_name)
    return _boto3_clients[key]

# ---------------------------------------------------------
# Terraform State Parser
# ---------------------------------------------------------
def read_terraform_state() -> Dict[str, Any]:
    if not TF_STATE_PATH.exists():
        return {"exists": False, "resources": {}}

    try:
        with open(TF_STATE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        return {"exists": False, "error": str(e), "resources": {}}

    resources = {}
    for res in data.get("resources", []):
        res_type = res.get("type")
        res_name = res.get("name")
        instances = res.get("instances", [])
        if not instances:
            continue
        attrs = instances[0].get("attributes", {})

        if res_type == "aws_security_group" and res_name == "watchdog_sg":
            resources["security_group"] = {
                "id": attrs.get("id"),
                "name": attrs.get("name"),
                "ingress": attrs.get("ingress", []),
                "egress": attrs.get("egress", []),
            }
        elif res_type == "aws_instance" and res_name == "app_server":
            resources["instance"] = {
                "id": attrs.get("id"),
                "instance_type": attrs.get("instance_type", "t3.micro"),
                "state": "running",
            }
        elif res_type == "aws_s3_bucket" and res_name == "data_bucket":
            resources["s3_bucket"] = {
                "bucket": attrs.get("bucket"),
            }

    return {"exists": True, "resources": resources}

# ---------------------------------------------------------
# Gemini AI Analysis with Rule-Based Fallback
# ---------------------------------------------------------
def generate_ai_explanation(drift_summary: str, severity: str) -> tuple[str, str]:
    api_key = os.getenv("GEMINI_API_KEY")

    # If API key is present, try Google Gemini
    if api_key:
        try:
            from google import genai
            client = genai.Client(api_key=api_key)

            models_to_try = ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-1.5-flash"]
            prompt = (
                f"You are an AWS cloud security and GreenOps watchdog. Drift detected:\n"
                f"{drift_summary}\nSeverity: {severity}\n\n"
                f"Respond strictly in under 80 words with 3 plain text bullet sections:\n"
                f"What happened: [1 sentence]\n"
                f"Risk: [1 sentence]\n"
                f"Fix: [2 numbered steps]"
            )

            for model_name in models_to_try:
                try:
                    response = client.models.generate_content(
                        model=model_name,
                        contents=prompt
                    )
                    if response and response.text:
                        return response.text.strip(), "Gemini"
                except Exception:
                    continue
        except Exception:
            pass

    # Built-in deterministic rule-based analysis (badge: Rules)
    if "22" in drift_summary:
        explanation = (
            "What happened: Inbound SSH (port 22) rule was added from 0.0.0.0/0 outside Terraform.\n"
            "Risk: Exposes Linux server to brute-force attacks and unauthorized access from the entire internet.\n"
            "Fix: 1. Click 'Remediate Now' to remove the rule instantly. 2. Run 'terraform apply' to maintain zero-inbound baseline."
        )
    elif "3389" in drift_summary:
        explanation = (
            "What happened: Inbound RDP (port 3389) rule was opened to 0.0.0.0/0.\n"
            "Risk: Allows public scanning and exploitation of remote desktop services.\n"
            "Fix: 1. Revoke the rule via Watchdog dashboard. 2. Lock down CIDR to authorized management subnet."
        )
    elif "Firewall" in drift_summary:
        explanation = (
            "What happened: Unauthorized inbound security group rule detected that is not defined in Terraform state.\n"
            "Risk: Widens attack surface and violates infrastructure-as-code compliance.\n"
            "Fix: 1. Click 'Remediate Now' to revoke unauthorized ports. 2. Synchronize with Terraform."
        )
    else:
        explanation = (
            "What happened: Discrepancy detected between Terraform state and live AWS resources.\n"
            "Risk: Configuration drift leads to unmonitored security holes and operational instability.\n"
            "Fix: 1. Investigate live resource changes. 2. Run 'terraform apply' to restore expected architecture."
        )
    return explanation, "Rules"

# ---------------------------------------------------------
# Incident Lifecycle Management (SQLite)
# ---------------------------------------------------------
def sync_incident(differences: List[Dict[str, Any]], is_empty: bool) -> Optional[Dict[str, Any]]:
    with db_lock:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check for open incident
        cursor.execute("SELECT id, summary, severity FROM incidents WHERE status = 'open' ORDER BY id DESC LIMIT 1")
        open_row = cursor.fetchone()

        # Case 1: Infrastructure destroyed / empty
        if is_empty:
            if open_row:
                now_str = datetime.now(timezone.utc).isoformat()
                cursor.execute(
                    "UPDATE incidents SET status = 'resolved', resolved_at = ?, resolution_detail = ? WHERE id = ?",
                    (now_str, "Infrastructure destroyed or state emptied", open_row[0])
                )
                conn.commit()
            conn.close()
            return None

        # Case 2: No drift (everything in sync)
        if not differences:
            if open_row:
                now_str = datetime.now(timezone.utc).isoformat()
                cursor.execute(
                    "UPDATE incidents SET status = 'resolved', resolved_at = ?, resolution_detail = ? WHERE id = ?",
                    (now_str, "Resolved (reversed manually or via terraform apply)", open_row[0])
                )
                conn.commit()
            conn.close()
            return None

        # Case 3: Drift detected
        # Determine highest severity
        severities = [d.get("severity", "medium") for d in differences]
        current_severity = "critical" if "critical" in severities else ("high" if "high" in severities else "medium")

        # Compose summary text
        primary_diff = differences[0]["message"]
        summary = f"Drift detected because {primary_diff}; Terraform expects: none."

        if not open_row:
            # Create new incident
            explanation, badge = generate_ai_explanation(summary, current_severity)
            now_str = datetime.now(timezone.utc).isoformat()
            cursor.execute(
                """INSERT INTO incidents
                   (status, severity, summary, explanation, badge, created_at, resolved_at, resolution_detail)
                   VALUES ('open', ?, ?, ?, ?, ?, NULL, NULL)""",
                (current_severity, summary, explanation, badge, now_str)
            )
            incident_id = cursor.lastrowid
            conn.commit()
            conn.close()
            return {
                "id": incident_id,
                "status": "open",
                "severity": current_severity,
                "summary": summary,
                "explanation": explanation,
                "badge": badge,
                "created_at": now_str
            }
        else:
            # If summary or severity changed, update incident
            incident_id, old_summary, old_severity = open_row
            if old_summary != summary or old_severity != current_severity:
                explanation, badge = generate_ai_explanation(summary, current_severity)
                cursor.execute(
                    "UPDATE incidents SET severity = ?, summary = ?, explanation = ?, badge = ? WHERE id = ?",
                    (current_severity, summary, explanation, badge, incident_id)
                )
                conn.commit()
            else:
                cursor.execute("SELECT explanation, badge, created_at FROM incidents WHERE id = ?", (incident_id,))
                rec = cursor.fetchone()
                explanation, badge, now_str = rec[0], rec[1], rec[2]

            conn.close()
            return {
                "id": incident_id,
                "status": "open",
                "severity": current_severity,
                "summary": summary,
                "explanation": explanation,
                "badge": badge,
                "created_at": open_row[0]
            }

# ---------------------------------------------------------
# GreenOps Carbon Calculation (CloudWatch EC2)
# ---------------------------------------------------------
def get_greenops_metrics(instance_id: Optional[str]) -> Dict[str, Any]:
    if not instance_id:
        return {
            "available": False,
            "reason": "No instance active",
            "cpu_percent": 0.0,
            "power_watts": 0.0,
            "kwh_per_hour": 0.0,
            "gco2e_per_hour": 0.0,
            "gco2e_per_day": 0.0,
        }

    try:
        cw = get_boto3_client("cloudwatch")
        end_time = datetime.now(timezone.utc)
        start_time = datetime.fromtimestamp(end_time.timestamp() - 3600, tz=timezone.utc)

        response = cw.get_metric_statistics(
            Namespace="AWS/EC2",
            MetricName="CPUUtilization",
            Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
            StartTime=start_time,
            EndTime=end_time,
            Period=300,
            Statistics=["Average"],
        )

        datapoints = response.get("Datapoints", [])
        if not datapoints:
            return {
                "available": False,
                "reason": "Awaiting CloudWatch metrics (5-10m delay for new instances)",
                "cpu_percent": 0.0,
                "power_watts": round(T3_MICRO_VCPUS * T3_MICRO_MIN_WATTS, 2),
                "kwh_per_hour": round((T3_MICRO_VCPUS * T3_MICRO_MIN_WATTS / 1000.0) * PUE, 5),
                "gco2e_per_hour": round(((T3_MICRO_VCPUS * T3_MICRO_MIN_WATTS / 1000.0) * PUE) * NSW_GRID_EMISSION_FACTOR, 3),
                "gco2e_per_day": round((((T3_MICRO_VCPUS * T3_MICRO_MIN_WATTS / 1000.0) * PUE) * NSW_GRID_EMISSION_FACTOR) * 24, 2),
            }

        datapoints.sort(key=lambda x: x["Timestamp"])
        avg_cpu = datapoints[-1]["Average"]

        # Cloud Carbon Footprint formula
        power_w = T3_MICRO_VCPUS * (T3_MICRO_MIN_WATTS + (avg_cpu / 100.0) * (T3_MICRO_MAX_WATTS - T3_MICRO_MIN_WATTS))
        kwh_hour = (power_w / 1000.0) * PUE
        gco2e_hour = kwh_hour * NSW_GRID_EMISSION_FACTOR
        gco2e_day = gco2e_hour * 24.0

        return {
            "available": True,
            "cpu_percent": round(avg_cpu, 2),
            "power_watts": round(power_w, 2),
            "kwh_per_hour": round(kwh_hour, 5),
            "gco2e_per_hour": round(gco2e_hour, 3),
            "gco2e_per_day": round(gco2e_day, 2),
            "history": [round(dp["Average"], 1) for dp in datapoints[-12:]],
        }
    except Exception as e:
        return {
            "available": False,
            "reason": f"CloudWatch unavailable: {str(e)}",
            "cpu_percent": 0.0,
            "power_watts": 0.0,
            "kwh_per_hour": 0.0,
            "gco2e_per_hour": 0.0,
            "gco2e_per_day": 0.0,
        }

# ---------------------------------------------------------
# Core Evaluation Engine (State vs Live AWS)
# ---------------------------------------------------------
def evaluate_infrastructure() -> Dict[str, Any]:
    tf_data = read_terraform_state()

    # Empty State check
    if not tf_data.get("exists") or not tf_data.get("resources"):
        sync_incident([], is_empty=True)
        return {
            "mode": "empty",
            "banner_text": "No infrastructure deployed",
            "status_message": "Terraform state has no active resources.",
            "differences": [],
            "incident": None,
            "live_resources": {},
            "expected_resources": {},
            "greenops": get_greenops_metrics(None),
            "cost": {"enabled": COST_ENABLED, "display": "$0.00 (Free Tier)", "message": "Cost Explorer disabled (zero-cost plan)"},
        }

    expected_resources = tf_data["resources"]
    expected_instance = expected_resources.get("instance")
    expected_sg = expected_resources.get("security_group")
    expected_s3 = expected_resources.get("s3_bucket")

    differences: List[Dict[str, Any]] = []
    live_instance_info: Dict[str, Any] = {}
    live_sg_info: Dict[str, Any] = {}

    ec2 = get_boto3_client("ec2")

    # 1. Compare Security Group
    if expected_sg:
        sg_id = expected_sg.get("id")
        try:
            resp = ec2.describe_security_groups(GroupIds=[sg_id])
            live_sg_list = resp.get("SecurityGroups", [])
            if not live_sg_list:
                differences.append({
                    "resource": f"SecurityGroup/{sg_id}",
                    "severity": "critical",
                    "message": f"Security group {sg_id} not found in AWS",
                })
            else:
                live_sg = live_sg_list[0]
                live_inbound = live_sg.get("IpPermissions", [])
                live_sg_info = {
                    "id": live_sg.get("GroupId"),
                    "name": live_sg.get("GroupName"),
                    "rule_count": len(live_inbound),
                    "rules": live_inbound
                }

                # Expected ingress is []
                for rule in live_inbound:
                    proto = rule.get("IpProtocol", "tcp")
                    from_p = rule.get("FromPort", "all")
                    to_p = rule.get("ToPort", "all")
                    port_str = f"{from_p}" if from_p == to_p else f"{from_p}-{to_p}"
                    if proto == "-1":
                        port_str = "All Traffic"

                    cidrs = [r.get("CidrIp") for r in rule.get("IpRanges", []) if r.get("CidrIp")]
                    v6_cidrs = [r.get("CidrIpv6") for r in rule.get("Ipv6Ranges", []) if r.get("CidrIpv6")]
                    all_ranges = cidrs + v6_cidrs
                    range_str = ", ".join(all_ranges) if all_ranges else "all"

                    is_open_world = "0.0.0.0/0" in range_str or "::/0" in range_str
                    is_mgmt_port = from_p in [22, 3389] or proto == "-1"

                    if is_open_world and is_mgmt_port:
                        severity = "critical"
                    elif is_open_world:
                        severity = "high"
                    else:
                        severity = "medium"

                    differences.append({
                        "resource": f"SecurityGroup/{sg_id}",
                        "severity": severity,
                        "type": "inbound_rule_added",
                        "port": port_str,
                        "protocol": proto.upper(),
                        "source": range_str,
                        "rule_spec": rule,
                        "message": f"an unexpected inbound rule was added to the firewall ({proto.upper()} port {port_str} from {range_str})",
                    })
        except ClientError as ce:
            err_code = ce.response.get("Error", {}).get("Code", "Error")
            err_msg = ce.response.get("Error", {}).get("Message", str(ce))
            differences.append({
                "resource": f"SecurityGroup/{sg_id}",
                "severity": "critical",
                "message": f"Failed to describe Security Group: {err_code} - {err_msg}",
            })

    # 2. Compare EC2 Instance
    if expected_instance:
        inst_id = expected_instance.get("id")
        try:
            resp = ec2.describe_instances(InstanceIds=[inst_id])
            reservations = resp.get("Reservations", [])
            instances = reservations[0].get("Instances", []) if reservations else []
            if not instances:
                differences.append({
                    "resource": f"EC2/{inst_id}",
                    "severity": "critical",
                    "message": f"EC2 instance {inst_id} was deleted or terminated in AWS",
                })
            else:
                live_inst = instances[0]
                inst_state = live_inst.get("State", {}).get("Name", "unknown")
                inst_type = live_inst.get("InstanceType", "")
                pub_ip = live_inst.get("PublicIpAddress", "None")
                az = live_inst.get("Placement", {}).get("AvailabilityZone", AWS_REGION)
                launch_time = live_inst.get("LaunchTime")
                launch_str = launch_time.isoformat() if launch_time else ""

                live_instance_info = {
                    "id": inst_id,
                    "state": inst_state,
                    "type": inst_type,
                    "public_ip": pub_ip,
                    "zone": az,
                    "launch_time": launch_str,
                }

                if inst_state != "running":
                    differences.append({
                        "resource": f"EC2/{inst_id}",
                        "severity": "high",
                        "message": f"EC2 instance {inst_id} is '{inst_state}' (expected: running)",
                    })

                if inst_type != expected_instance.get("instance_type"):
                    differences.append({
                        "resource": f"EC2/{inst_id}",
                        "severity": "high",
                        "message": f"EC2 instance type changed to {inst_type} (expected: {expected_instance.get('instance_type')})",
                    })
        except ClientError as ce:
            err_code = ce.response.get("Error", {}).get("Code", "Error")
            err_msg = ce.response.get("Error", {}).get("Message", str(ce))
            differences.append({
                "resource": f"EC2/{inst_id}",
                "severity": "critical",
                "message": f"Failed to describe EC2: {err_code} - {err_msg}",
            })

    # Determine Overall Mode
    if differences:
        mode = "drift"
        banner_text = "Drift detected"
    else:
        mode = "running"
        banner_text = "Application running"

    incident = sync_incident(differences, is_empty=False)
    greenops = get_greenops_metrics(live_instance_info.get("id"))

    return {
        "mode": mode,
        "banner_text": banner_text,
        "status_message": "All infrastructure matches Terraform state." if mode == "running" else f"{len(differences)} configuration discrepancy detected.",
        "differences": differences,
        "incident": incident,
        "live_resources": {
            "instance": live_instance_info,
            "security_group": live_sg_info,
            "s3_bucket": expected_s3,
        },
        "expected_resources": expected_resources,
        "greenops": greenops,
        "cost": {
            "enabled": COST_ENABLED,
            "display": "$0.00 (Free Tier)",
            "message": "Cost Explorer disabled (preserves zero-cost Free Plan, prevents $0.01 API fee / SCP restriction)."
        }
    }

# ---------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------
@app.get("/api/status")
def get_status():
    now = time.time()
    # Cache for 3 seconds
    if _cache["status_data"] and (now - _cache["last_fetched"]) < 3.0:
        return _cache["status_data"]

    try:
        data = evaluate_infrastructure()
        _cache["status_data"] = data
        _cache["last_fetched"] = now
        return data
    except Exception as e:
        return {
            "mode": "error",
            "banner_text": "System Error",
            "status_message": f"Watchdog encountered an error: {str(e)}",
            "differences": [],
            "incident": None,
            "live_resources": {},
            "expected_resources": {},
            "greenops": get_greenops_metrics(None),
            "cost": {"enabled": False, "display": "N/A", "message": "Error reading cost"},
        }

@app.get("/api/connection")
def get_connection_proof():
    results = []
    account_masked = "Unknown"
    caller_arn = "Unknown"

    # 1. STS GetCallerIdentity
    t0 = time.time()
    try:
        sts = get_boto3_client("sts")
        identity = sts.get_caller_identity()
        ms = round((time.time() - t0) * 1000, 1)
        raw_acct = identity.get("Account", "000000000000")
        account_masked = f"******{raw_acct[-4:]}"
        caller_arn = identity.get("Arn", "Unknown")
        results.append({"call": "sts:GetCallerIdentity", "success": True, "latency_ms": ms})
    except Exception as e:
        ms = round((time.time() - t0) * 1000, 1)
        results.append({"call": "sts:GetCallerIdentity", "success": False, "latency_ms": ms, "error": str(e)})

    # 2. EC2 DescribeSecurityGroups
    t0 = time.time()
    try:
        ec2 = get_boto3_client("ec2")
        ec2.describe_security_groups(MaxResults=5)
        ms = round((time.time() - t0) * 1000, 1)
        results.append({"call": "ec2:DescribeSecurityGroups", "success": True, "latency_ms": ms})
    except Exception as e:
        ms = round((time.time() - t0) * 1000, 1)
        results.append({"call": "ec2:DescribeSecurityGroups", "success": False, "latency_ms": ms, "error": str(e)})

    # 3. CloudWatch ListMetrics
    t0 = time.time()
    try:
        cw = get_boto3_client("cloudwatch")
        cw.list_metrics(Namespace="AWS/EC2", MetricName="CPUUtilization")
        ms = round((time.time() - t0) * 1000, 1)
        results.append({"call": "cloudwatch:ListMetrics", "success": True, "latency_ms": ms})
    except Exception as e:
        ms = round((time.time() - t0) * 1000, 1)
        results.append({"call": "cloudwatch:ListMetrics", "success": False, "latency_ms": ms, "error": str(e)})

    avg_latency = round(sum(r["latency_ms"] for r in results) / len(results), 1) if results else 0

    # Retrieve live status data to pass along server and SG summary
    status_payload = get_status()

    return {
        "connected": any(r["success"] for r in results),
        "region": AWS_REGION,
        "account_id": account_masked,
        "caller_arn": caller_arn,
        "average_latency_ms": avg_latency,
        "api_calls": results,
        "server": status_payload.get("live_resources", {}).get("instance", {}),
        "security_group": status_payload.get("live_resources", {}).get("security_group", {}),
    }

@app.post("/api/remediate")
def remediate_drift():
    status = evaluate_infrastructure()
    differences = status.get("differences", [])
    inbound_diffs = [d for d in differences if d.get("type") == "inbound_rule_added"]

    if not inbound_diffs:
        return {"status": "noop", "message": "No remediable firewall drift detected."}

    ec2 = get_boto3_client("ec2")
    revoked_count = 0
    errors = []

    for diff in inbound_diffs:
        sg_id = diff.get("resource", "").split("/")[-1]
        rule_spec = diff.get("rule_spec")
        if sg_id and rule_spec:
            try:
                ec2.revoke_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions=[rule_spec]
                )
                revoked_count += 1
            except Exception as e:
                errors.append(str(e))

    # Mark open incident as resolved in DB
    with db_lock:
        conn = get_db_connection()
        cursor = conn.cursor()
        now_str = datetime.now(timezone.utc).isoformat()
        cursor.execute(
            "UPDATE incidents SET status = 'resolved', resolved_at = ?, resolution_detail = ? WHERE status = 'open'",
            (now_str, f"Remediated directly from Watchdog dashboard (revoked {revoked_count} rule(s))")
        )
        conn.commit()
        conn.close()

    # Clear cache so next poll sees clean state immediately
    _cache["status_data"] = None

    if errors:
        return {"status": "partial", "revoked": revoked_count, "errors": errors}
    return {"status": "success", "message": f"Successfully revoked {revoked_count} unauthorized inbound rule(s)."}

@app.get("/api/incidents")
def get_incidents():
    with db_lock:
        conn = get_db_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 50")
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows

# Serve static frontend files
app.mount("/", StaticFiles(directory=str(BASE_DIR / "static"), html=True), name="static")
