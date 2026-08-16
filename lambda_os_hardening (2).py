"""
AngelOne AMC — Monthly OS CIS Hardening Report Automation
==========================================================
Triggered by:  Amazon EventBridge (1st of every month, 06:30 IST)
Output:        CSV report — saved to S3 + emailed as attachment
Fix v3:        SSM output saved to S3 directly — eliminates 24KB
               StandardOutputContent limit and PluginName issues.
"""

import boto3
import json
import os
import time
import csv
import io
import datetime
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text      import MIMEText
from email.mime.base      import MIMEBase
from email                import encoders
from botocore.exceptions  import ClientError

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

ACCOUNTS = [
    {"id": "801947417375", "label": "Production",      "role": "arn:aws:iam::801947417375:role/CIS-Hardening-Report-Role"},
    {"id": "203771687516", "label": "Test-Account",    "role":  None},
    {"id": "129321895510", "label": "UAT",             "role": "arn:aws:iam::129321895510:role/CIS-Hardening-Report-Role"},
    {"id": "390725325823", "label": "Network",         "role": "arn:aws:iam::390725325823:role/CIS-Hardening-Report-Role"},
    {"id": "482160608712", "label": "Shared Services", "role": "arn:aws:iam::482160608712:role/CIS-Hardening-Report-Role"},
]

REGION           = os.environ.get("AWS_REGION",       "ap-south-1")
S3_BUCKET        = os.environ.get("S3_BUCKET",        "nusummit-prash-test-bucket")
S3_PREFIX        = os.environ.get("S3_PREFIX",        "os-cis-hardening")
SMTP_SECRET      = os.environ.get("SMTP_SECRET",      "cis-hardening/smtp-credentials")
SSM_DOC_LINUX    = os.environ.get("SSM_DOC_LINUX",    "CIS-Linux-Check")
SSM_DOC_WINDOWS  = os.environ.get("SSM_DOC_WINDOWS",  "CIS-Windows-Check")
SSM_WAIT_SECONDS = int(os.environ.get("SSM_WAIT_SEC", "600"))
SSM_S3_PREFIX    = f"{S3_PREFIX}/ssm-raw-output"   # where SSM writes full output
REPORT_TITLE     = "AngelOne AMC — OS CIS Hardening Report"


# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — Cross-account session
# ─────────────────────────────────────────────────────────────────────────────

def assume_role_session(role_arn=None, session_name="OSCISHardeningReport"):
    if role_arn is None:
        return boto3.Session(region_name=REGION)
    sts   = boto3.client("sts")
    creds = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=session_name,
        DurationSeconds=3600,
    )["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=REGION,
    )


# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — Discover running EC2 instances with SSM agent online
# ─────────────────────────────────────────────────────────────────────────────

def discover_managed_instances(session, account_id, account_label):
    ec2 = session.client("ec2", region_name=REGION)
    ssm = session.client("ssm", region_name=REGION)

    ssm_ids = set()
    for page in ssm.get_paginator("describe_instance_information").paginate(
            Filters=[{"Key": "PingStatus", "Values": ["Online"]}]):
        for info in page["InstanceInformationList"]:
            ssm_ids.add(info["InstanceId"])

    instances = []
    for page in ec2.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}]):
        for res in page["Reservations"]:
            for inst in res["Instances"]:
                iid = inst["InstanceId"]
                if iid not in ssm_ids:
                    continue
                name     = next((t["Value"] for t in inst.get("Tags", [])
                                 if t["Key"] == "Name"), iid)
                platform = inst.get("PlatformDetails",
                                    inst.get("Platform", "Linux/UNIX"))
                os_type  = "windows" if "windows" in platform.lower() else "linux"
                instances.append({
                    "instance_id":   iid,
                    "name":          name,
                    "account_id":    account_id,
                    "account_label": account_label,
                    "platform":      platform,
                    "os_type":       os_type,
                    "instance_type": inst.get("InstanceType", ""),
                    "private_ip":    inst.get("PrivateIpAddress", ""),
                    "az":            inst.get("Placement", {}).get("AvailabilityZone", ""),
                })

    print(f"[INFO]   {account_label}: {len(instances)} SSM-managed instances")
    return instances


# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — Send SSM Run Command and collect results
# ─────────────────────────────────────────────────────────────────────────────

def _read_ssm_output_from_s3(s3_client, cmd_id, iid, step_name):
    """
    SSM writes full stdout to S3 when OutputS3BucketName is set.
    Try multiple key patterns because the format varies by schema version.
    Returns the raw stdout string, or "" if not found.
    """
    candidates = [
        # Schema 2.2 — step name based
        f"{SSM_S3_PREFIX}/{cmd_id}/{iid}/{step_name}/0.{step_name}/stdout",
        # Schema 2.2 — alternative
        f"{SSM_S3_PREFIX}/{cmd_id}/{iid}/{step_name}/stdout",
        # Fallback — action name based
        f"{SSM_S3_PREFIX}/{cmd_id}/{iid}/awsrunShellScript/0.awsrunShellScript/stdout",
        f"{SSM_S3_PREFIX}/{cmd_id}/{iid}/aws:runShellScript/0.aws:runShellScript/stdout",
    ]
    for key in candidates:
        try:
            obj     = s3_client.get_object(Bucket=S3_BUCKET, Key=key)
            content = obj["Body"].read().decode("utf-8")
            if content.strip():
                print(f"[INFO]  S3 output found → {key} ({len(content)} chars)")
                return content
        except Exception:
            continue
    return ""

def _sanitize_json(s: str) -> str:
    """Remove invalid bash escape sequences before JSON parsing.
    Bash scripts embed grep patterns like chmod\|chown in JSON strings.
    \| is not a valid JSON escape — replace with plain |.
    """
    return (s
            .replace('\\|', '|')
            .replace('\\(', '(')
            .replace('\\)', ')')
            .replace('\\!', '!')
            .replace('\\&', '&'))

def run_ssm_checks(session, instances):
    """
    Send SSM Run Command to all instances.
    ─ OutputS3BucketName saves FULL stdout to S3 (no 24KB limit).
    ─ Lambda reads results from S3, with StandardOutputContent as fallback.
    """
    ssm = session.client("ssm", region_name=REGION)
    s3  = boto3.client("s3")          # uses Lambda's own credentials for S3
    results = {}

    linux_ids   = [i["instance_id"] for i in instances if i["os_type"] == "linux"]
    windows_ids = [i["instance_id"] for i in instances if i["os_type"] == "windows"]
    command_ids = {}

    # Map instance → script step name (needed for S3 key lookup)
    plugin_map = {
        **{iid: "RunLinuxCISChecks"   for iid in linux_ids},
        **{iid: "RunWindowsCISChecks" for iid in windows_ids},
    }

    # ── Send Linux command ──────────────────────────────────────────────────
    if linux_ids:
        try:
            resp = ssm.send_command(
                InstanceIds=linux_ids,
                DocumentName=SSM_DOC_LINUX,
                TimeoutSeconds=300,
                Comment="CIS Linux OS Hardening Check",
                OutputS3BucketName=S3_BUCKET,        # ← saves full output to S3
                OutputS3KeyPrefix=SSM_S3_PREFIX,
            )
            command_ids["linux"] = resp["Command"]["CommandId"]
            print(f"[INFO] Linux SSM sent: {command_ids['linux']} "
                  f"→ {len(linux_ids)} instances  (output → s3://{S3_BUCKET}/{SSM_S3_PREFIX}/)")
        except ClientError as e:
            print(f"[ERROR] Linux SSM send failed: {e}")

    # ── Send Windows command ────────────────────────────────────────────────
    if windows_ids:
        try:
            resp = ssm.send_command(
                InstanceIds=windows_ids,
                DocumentName=SSM_DOC_WINDOWS,
                TimeoutSeconds=300,
                Comment="CIS Windows OS Hardening Check",
                OutputS3BucketName=S3_BUCKET,
                OutputS3KeyPrefix=SSM_S3_PREFIX,
            )
            command_ids["windows"] = resp["Command"]["CommandId"]
            print(f"[INFO] Windows SSM sent: {command_ids['windows']} "
                  f"→ {len(windows_ids)} instances")
        except ClientError as e:
            print(f"[ERROR] Windows SSM send failed: {e}")

    if not command_ids:
        return results

    # ── Poll for completion ─────────────────────────────────────────────────
    deadline = time.time() + SSM_WAIT_SECONDS
    pending  = {
        **{iid: command_ids["linux"]   for iid in linux_ids   if "linux"   in command_ids},
        **{iid: command_ids["windows"] for iid in windows_ids if "windows" in command_ids},
    }

    while pending and time.time() < deadline:
        time.sleep(15)
        for iid, cmd_id in list(pending.items()):
            try:
                # Get status — try with PluginName first, fallback without
                plugin_name = plugin_map.get(iid, "RunLinuxCISChecks")
                try:
                    inv = ssm.get_command_invocation(
                        CommandId=cmd_id,
                        InstanceId=iid,
                        PluginName=plugin_name,
                    )
                except ClientError:
                    inv = ssm.get_command_invocation(
                        CommandId=cmd_id,
                        InstanceId=iid,
                    )

                status = inv["StatusDetails"]
                if status not in ("Success", "Failed", "TimedOut", "Cancelled"):
                    continue   # still running

                print(f"[INFO]  {iid} | SSM {status} | reading output...")

                # ── Priority 1: Read full output from S3 (no size limit) ──
                output = _read_ssm_output_from_s3(s3, cmd_id, iid, plugin_name)

                # ── Priority 2: Fallback to StandardOutputContent ──────────
                if not output:
                    output = inv.get("StandardOutputContent", "")
                    print(f"[DEBUG] {iid} | S3 empty, using StandardOutputContent "
                          f"({len(output)} chars)")
                    if output:
                        print(f"[DEBUG] {iid} | preview: {repr(output[:200])}")

                # ── Parse results ───────────────────────────────────────────
                marker = "---RESULTS---"
                idx    = output.find(marker)

                if idx != -1:
                    json_str = output[idx + len(marker):].strip()
                    json_str = _sanitize_json(json_str)
                    try:
                        parsed = json.loads(json_str)
                        parsed["ssm_status"] = status
                        results[iid] = parsed
                        print(f"[INFO]  {iid} | ✅ score={parsed.get('score')} "
                              f"pass={parsed.get('summary',{}).get('pass')} "
                              f"fail={parsed.get('summary',{}).get('fail')} "
                              f"warn={parsed.get('summary',{}).get('warn')}")
                    except json.JSONDecodeError as je:
                        print(f"[ERROR] {iid} | JSON parse failed: {je}")
                        print(f"[ERROR] {iid} | raw[:300]: {json_str[:300]}")
                        results[iid] = {
                            "ssm_status": status,
                            "error": f"JSON parse failed: {je}",
                            "raw":   json_str[:500],
                        }
                else:
                    print(f"[WARN]  {iid} | ---RESULTS--- NOT found")
                    print(f"[WARN]  {iid} | full output: {repr(output[:400])}")
                    results[iid] = {
                        "ssm_status": status,
                        "error": "No results marker found in output",
                        "raw":   output[:500],
                    }

                del pending[iid]

            except ClientError as e:
                if "InvocationDoesNotExist" not in str(e):
                    print(f"[WARN] Poll error {iid}: {e}")

    for iid in pending:
        print(f"[WARN] {iid} | Timed out waiting for SSM")
        results[iid] = {"ssm_status": "Timeout",
                        "error": "Did not complete within SSM_WAIT_SEC"}

    return results


# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 — Merge EC2 metadata with SSM results
# ─────────────────────────────────────────────────────────────────────────────

def merge_results(instances, ssm_results):
    merged = []
    for inst in instances:
        iid    = inst["instance_id"]
        result = ssm_results.get(iid, {
            "ssm_status": "Not reached",
            "error": "Instance not in SSM results",
        })
        score   = result.get("score", 0)
        summary = result.get("summary", {})
        overall = ("pass" if score >= 80 else
                   "warn" if score >= 55 else
                   "fail")
        if result.get("ssm_status") not in ("Success", None):
            overall = "error"
        merged.append({
            **inst,
            "score":      score,
            "overall":    overall,
            "ssm_status": result.get("ssm_status", "Unknown"),
            "os_detail":  result.get("os", inst["platform"]),
            "kernel":     result.get("kernel", ""),
            "benchmark":  result.get("benchmark", "CIS v3.0"),
            "summary":    summary,
            "checks":     result.get("results", []),
            "error":      result.get("error", ""),
        })
    return merged


# ─────────────────────────────────────────────────────────────────────────────
# STEP 5 — Aggregate top findings across fleet
# ─────────────────────────────────────────────────────────────────────────────

def aggregate_os_findings(all_instances):
    fail_map = {}
    for inst in all_instances:
        for check in inst.get("checks", []):
            if check.get("status") not in ("fail", "warn"):
                continue
            cid = check.get("id", "unknown")
            if cid not in fail_map:
                fail_map[cid] = {"check": check, "instances": [], "count": 0}
            fail_map[cid]["instances"].append(inst["name"])
            fail_map[cid]["count"] += 1

    findings = []
    for cid, info in sorted(fail_map.items(),
                            key=lambda x: x[1]["count"], reverse=True)[:12]:
        check = info["check"]
        sev   = ("critical" if check.get("status") == "fail"
                               and check.get("level") == 1 else
                 "high"     if check.get("status") == "fail" else
                 "medium")
        findings.append({
            "severity":  sev,
            "cis":       cid,
            "title":     check.get("title", cid),
            "detail":    check.get("detail", ""),
            "affected":  info["count"],
            "instances": ", ".join(info["instances"][:4])
                         + ("..." if info["count"] > 4 else ""),
        })
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# STEP 6 — Generate CSV report
# ─────────────────────────────────────────────────────────────────────────────

def generate_csv_report(all_instances, findings, month_label):
    buf    = io.StringIO()
    writer = csv.writer(buf)

    now_str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    n_pass  = sum(1 for i in all_instances if i["overall"] == "pass")
    n_warn  = sum(1 for i in all_instances if i["overall"] == "warn")
    n_fail  = sum(1 for i in all_instances if i["overall"] in ("fail","error"))
    scores  = [i["score"] for i in all_instances if i["score"] > 0]
    avg_sc  = round(sum(scores)/len(scores)) if scores else 0

    # Section 1 — Summary
    writer.writerow([REPORT_TITLE])
    writer.writerow([f"Month: {month_label}"])
    writer.writerow([f"Generated: {now_str}"])
    writer.writerow(["Benchmark: CIS Linux / Windows Server Benchmark v3.0"])
    writer.writerow([])
    writer.writerow(["FLEET SUMMARY"])
    writer.writerow(["Total Instances",             len(all_instances)])
    writer.writerow(["Compliant  (score >= 80)",    n_pass])
    writer.writerow(["Warning    (score 55-79)",    n_warn])
    writer.writerow(["Non-Compliant (score < 55)",  n_fail])
    writer.writerow(["Fleet Average CIS Score",     f"{avg_sc}/100"])
    writer.writerow([])

    # Section 2 — Instance Registry
    writer.writerow(["INSTANCE REGISTRY"])
    writer.writerow(["Instance ID","Name","Account","OS","Instance Type",
                     "Private IP","AZ","CIS Score",
                     "Pass","Fail","Warn","Overall Status","SSM Status"])
    for inst in all_instances:
        s = inst.get("summary", {})
        writer.writerow([
            inst["instance_id"], inst["name"], inst["account_label"],
            inst.get("os_detail", inst["platform"]), inst["instance_type"],
            inst["private_ip"], inst["az"], inst["score"],
            s.get("pass",0), s.get("fail",0), s.get("warn",0),
            inst["overall"].upper(), inst.get("ssm_status",""),
        ])
    writer.writerow([])

    # Section 3 — Top Findings
    writer.writerow(["TOP CIS FINDINGS"])
    writer.writerow(["Severity","CIS Control","Finding Title",
                     "Remediation Detail","# Instances Affected",
                     "Affected Instance Names"])
    for f in findings:
        writer.writerow([f["severity"].upper(), f["cis"], f["title"],
                         f["detail"], f["affected"], f["instances"]])
    writer.writerow([])

    # Section 4 — Detailed Findings
    writer.writerow(["DETAILED FINDINGS PER INSTANCE"])
    writer.writerow(["Instance ID","Instance Name","Account",
                     "CIS Control","Title","Status","Level",
                     "Remediation Detail"])
    for inst in all_instances:
        for check in inst.get("checks", []):
            if check.get("status") not in ("fail","warn"):
                continue
            writer.writerow([
                inst["instance_id"], inst["name"], inst["account_label"],
                check.get("id",""), check.get("title",""),
                check.get("status","").upper(),
                f"L{check.get('level','')}",
                check.get("detail",""),
            ])

    return buf.getvalue()


# ─────────────────────────────────────────────────────────────────────────────
# STEP 7 — Save CSV to S3
# ─────────────────────────────────────────────────────────────────────────────

def save_to_s3(csv_content, month_label):
    s3  = boto3.client("s3")
    key = (f"{S3_PREFIX}/{month_label.replace(' ','-')}/"
           f"os_cis_hardening_{month_label.replace(' ','_')}.csv")
    s3.put_object(Bucket=S3_BUCKET, Key=key,
                  Body=csv_content.encode("utf-8"),
                  ContentType="text/csv",
                  ServerSideEncryption="AES256")
    return f"s3://{S3_BUCKET}/{key}"


# ─────────────────────────────────────────────────────────────────────────────
# STEP 8 — Send email with CSV attachment via SMTP
# ─────────────────────────────────────────────────────────────────────────────

def send_email(csv_content, findings, all_instances, month_label, s3_uri):
    sm    = boto3.client("secretsmanager", region_name=REGION)
    creds = json.loads(
        sm.get_secret_value(SecretId=SMTP_SECRET)["SecretString"])

    smtp_host  = creds["smtp_host"]
    smtp_port  = int(creds["smtp_port"])
    smtp_user  = creds["smtp_user"]
    smtp_pass  = creds["smtp_password"]
    email_from = creds["email_from"]
    recipients = [e.strip() for e in creds["email_to"].split(",") if e.strip()]

    critical = sum(1 for f in findings if f["severity"] == "critical")
    high     = sum(1 for f in findings if f["severity"] == "high")
    subject  = (f"[{month_label}] OS CIS Hardening Report — "
                f"{critical} Critical · {high} High findings")

    n_total = len(all_instances)
    n_pass  = sum(1 for i in all_instances if i["overall"] == "pass")
    n_warn  = sum(1 for i in all_instances if i["overall"] == "warn")
    n_fail  = sum(1 for i in all_instances if i["overall"] in ("fail","error"))
    scores  = [i["score"] for i in all_instances if i["score"] > 0]
    avg_sc  = round(sum(scores)/len(scores)) if scores else 0

    top_txt = "\n".join(
        f"  [{f['severity'].upper():8}] {f['cis']:15} "
        f"{f['title']}  ({f['affected']} instance/s)"
        for f in findings[:10]
    ) or "  No findings detected."

    text_body = (
        f"OS CIS Hardening Report — {month_label}\n"
        f"{'='*55}\n\n"
        f"FLEET SUMMARY\n"
        f"  Total Instances     : {n_total}\n"
        f"  Compliant  (>= 80)  : {n_pass}\n"
        f"  Warning   (55-79)   : {n_warn}\n"
        f"  Non-Compliant (< 55): {n_fail}\n"
        f"  Fleet Avg Score     : {avg_sc}/100\n"
        f"  Critical Findings   : {critical}\n"
        f"  High Findings       : {high}\n\n"
        f"TOP FINDINGS\n{top_txt}\n\n"
        f"Full CSV report is attached.\n"
        f"S3 backup: {s3_uri}\n"
    )

    msg = MIMEMultipart("mixed")
    msg["Subject"] = subject
    msg["From"]    = email_from
    msg["To"]      = ", ".join(recipients)
    msg.attach(MIMEText(text_body, "plain", "utf-8"))

    csv_filename = f"os_cis_hardening_{month_label.replace(' ','_')}.csv"
    part = MIMEBase("text", "csv")
    part.set_payload(csv_content.encode("utf-8"))
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", "attachment", filename=csv_filename)
    msg.attach(part)

    ctx = ssl.create_default_context()
    print(f"[INFO] Sending email to: {', '.join(recipients)}")
    if smtp_port == 465:
        with smtplib.SMTP_SSL(smtp_host, smtp_port, context=ctx) as s:
            s.login(smtp_user, smtp_pass)
            s.sendmail(email_from, recipients, msg.as_string())
    else:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as s:
            s.ehlo(); s.starttls(context=ctx); s.ehlo()
            s.login(smtp_user, smtp_pass)
            s.sendmail(email_from, recipients, msg.as_string())
    print(f"[INFO] Email + CSV attachment sent to: {', '.join(recipients)}")


# ─────────────────────────────────────────────────────────────────────────────
# LAMBDA HANDLER
# ─────────────────────────────────────────────────────────────────────────────

def lambda_handler(event, context):
    now         = datetime.datetime.utcnow()
    month_label = now.strftime("%B %Y")
    print(f"[INFO] OS CIS Hardening Report — {month_label}")

    all_instances = []

    for acct in ACCOUNTS:
        print(f"[INFO] Account: {acct['id']} ({acct['label']})")
        try:
            session   = assume_role_session(acct["role"])
            instances = discover_managed_instances(
                session, acct["id"], acct["label"])
            if not instances:
                print("[INFO]   No SSM-managed instances — skipping")
                continue
            ssm_results = run_ssm_checks(session, instances)
            merged      = merge_results(instances, ssm_results)
            all_instances.extend(merged)
        except Exception as e:
            print(f"[ERROR] Account {acct['id']}: {e}")

    print(f"[INFO] Total instances: {len(all_instances)}")
    findings    = aggregate_os_findings(all_instances)
    print(f"[INFO] Total findings:  {len(findings)}")

    csv_content = generate_csv_report(all_instances, findings, month_label)
    s3_uri      = save_to_s3(csv_content, month_label)
    print(f"[INFO] CSV saved → {s3_uri}")

    send_email(csv_content, findings, all_instances, month_label, s3_uri)
    print("[INFO] Email delivered")

    return {
        "statusCode": 200,
        "body": json.dumps({
            "month":     month_label,
            "instances": len(all_instances),
            "findings":  len(findings),
            "s3_uri":    s3_uri,
        }),
    }
