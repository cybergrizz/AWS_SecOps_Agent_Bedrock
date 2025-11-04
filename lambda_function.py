import os, json, time, hmac, hashlib, urllib.parse, urllib.request, boto3, base64

EC2 = boto3.client("ec2")
BR = boto3.client("bedrock-runtime")
MODEL_ID = os.environ.get("BEDROCK_MODEL_ID","us.amazon.nova-micro-v1:0")
INSTANCE_ID        = os.environ["INSTANCE_ID"]
QUARANTINE_SG_ID   = os.environ["QUARANTINE_SG_ID"]
SLACK_WEBHOOK_URL  = os.environ["SLACK_WEBHOOK_URL"]        # Incoming Webhook (for the proposal message)
SLACK_SIGNING_SECRET = os.environ["SLACK_SIGNING_SECRET"]   # For verifying Slack interactive callbacks

# Env
INSTANCE_ID        = os.environ["INSTANCE_ID"]
QUARANTINE_SG_ID   = os.environ["QUARANTINE_SG_ID"]
SLACK_WEBHOOK_URL  = os.environ["SLACK_WEBHOOK_URL"]        # Incoming Webhook (for the proposal message)
SLACK_SIGNING_SECRET = os.environ["SLACK_SIGNING_SECRET"]   # For verifying Slack interactive callbacks




def reason_on_finding(detail: dict) -> str:
    """
    Summarize the GuardDuty finding and justify quarantine vs observe.
    Returns a short analysis for Slack (≤ ~10 lines).
    """
    system = "You are a SecOps co-pilot. Be concise, evidence-based, and risk-aware."
    user = {
        "findingType": detail.get("type"),
        "severity": detail.get("severity"),
        "resource": detail.get("resource", {}),
        "service": detail.get("service", {}),
    }
    resp = BR.converse(
        modelId=MODEL_ID,
        system=[{"text": system}],
        messages=[{"role":"user","content":[{"text":json.dumps(user)}]}],
        inferenceConfig={"maxTokens": 300, "temperature": 0.2}
    )
    out = "".join([c.get("text","") for c in resp["output"]["message"]["content"]])
    return out[:1000]

# --- helpers ---
def log(*args):
    print("[secops]", *args)

def verify_slack(headers, body):
    ts  = headers.get("x-slack-request-timestamp") or headers.get("X-Slack-Request-Timestamp")
    sig = headers.get("x-slack-signature") or headers.get("X-Slack-Signature")
    if not ts or not sig:
        return False
    # Replay protection (5 minutes)
    if abs(time.time() - int(ts)) > 300:
        log("slack timestamp too old")
        return False
    basestring = f"v0:{ts}:{body}".encode("utf-8")
    digest = hmac.new(SLACK_SIGNING_SECRET.encode("utf-8"), basestring, hashlib.sha256).hexdigest()
    expected = f"v0={digest}"
    # constant-time compare
    return len(expected) == len(sig) and not any(x ^ y for x, y in zip(expected.encode(), sig.encode()))

def _http_post_json(url, payload):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type":"application/json"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        body = resp.read().decode()
        return getattr(resp, "status", 200), body

def describe_instance_sgs(instance_id):
    r = EC2.describe_instances(InstanceIds=[instance_id])
    inst = r["Reservations"][0]["Instances"][0]
    return [g["GroupId"] for g in inst.get("SecurityGroups", [])]
    
def _get_primary_eni_id(instance_id):
    r = EC2.describe_instances(InstanceIds=[instance_id])
    ni_list = r["Reservations"][0]["Instances"][0]["NetworkInterfaces"]
    primary = [ni for ni in ni_list if ni.get("Attachment", {}).get("DeviceIndex") == 0][0]
    return primary["NetworkInterfaceId"]

def _get_eni_groups(eni_id):
    r = EC2.describe_network_interfaces(NetworkInterfaceIds=[eni_id])
    return [g["GroupId"] for g in r["NetworkInterfaces"][0]["Groups"]]

def rollback_instance(instance_id):
    # read the original SGs from instance tag we set during quarantine
    r = EC2.describe_instances(InstanceIds=[instance_id])
    inst = r["Reservations"][0]["Instances"][0]
    tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
    orig = tags.get("secops_pre_quarantine_sg", "")
    if not orig:
        raise Exception("no original SGs recorded on instance")
    orig_groups = [g for g in orig.split(",") if g]

    eni_id = _get_primary_eni_id(instance_id)
    EC2.modify_network_interface_attribute(NetworkInterfaceId=eni_id, Groups=orig_groups)
    EC2.create_tags(Resources=[instance_id], Tags=[
        {"Key":"secops_quarantined","Value":"false"},
        {"Key":"secops_rollback_time","Value":str(int(time.time()))}
    ])
    return orig_groups
    
    
def quarantine_instance(instance_id, quarantine_sg):
    eni_id = _get_primary_eni_id(instance_id)
    original = _get_eni_groups(eni_id)
    # swap SGs on the primary ENI to ONLY the quarantine SG
    EC2.modify_network_interface_attribute(NetworkInterfaceId=eni_id, Groups=[quarantine_sg])
    EC2.create_tags(Resources=[instance_id], Tags=[
        {"Key":"secops_pre_quarantine_sg","Value":",".join(original)},
        {"Key":"secops_quarantined","Value":"true"},
        {"Key":"secops_quarantine_time","Value":str(int(time.time()))}
    ])
    return original

def _proposal_blocks(analysis=None):
    header = (
        "*GuardDuty Finding*: UnauthorizedAccess:EC2/SSHBruteForce\n"
        f"*Instance*: `{INSTANCE_ID}`\n"
        f"*Proposed action*: move to quarantine SG `{QUARANTINE_SG_ID}`"
    )
    blocks = [{"type":"section","text":{"type":"mrkdwn","text":header}}]
    if analysis:
        blocks.append({"type":"section","text":{"type":"mrkdwn","text":f"*LLM Analysis*\n{analysis}"}})
    blocks.append({
        "type":"actions","elements":[
            {"type":"button","text":{"type":"plain_text","text":"Approve ✅"},"style":"primary","value":"approve","action_id":"approve_quarantine"},
            {"type":"button","text":{"type":"plain_text","text":"Deny ❌"},"style":"danger","value":"deny","action_id":"deny_quarantine"},
            {"type":"button","text":{"type":"plain_text","text":"Rollback 🔄"},"value":"rollback","action_id":"rollback_quarantine"}
        ]
    })
    return {"text":"SecOps Agent: Quarantine proposal", "blocks": blocks}

# --- lambda entrypoint ---
def handler(event, context):
    headers = event.get("headers") or {}
    sig = headers.get("x-slack-signature") or headers.get("X-Slack-Signature")
    ts  = headers.get("x-slack-request-timestamp") or headers.get("X-Slack-Request-Timestamp")
    is_slack = bool(sig and ts)  # only true if BOTH are present

    raw_body = event.get("body") or ""
    if event.get("isBase64Encoded"):
       raw_body = base64.b64decode(raw_body).decode("utf-8")

    # Slack interactive path (unchanged)...
    if is_slack:
    # --- read the raw body EXACTLY as Slack sent it ---


    # Always initialize to avoid UnboundLocalError
       action_val   = None
       action_id    = None
       response_url = None

    # 1) Verify Slack signature on the raw body (before any parsing)
    if not verify_slack(headers, raw_body):
        # Debug (safe): show ts and a short prefix of the body; do NOT log your secret
        log("invalid slack signature", {"ts": ts, "body_prefix": raw_body[:80]})
        return {"statusCode": 401, "body": "invalid signature"}

    # 2) Handle Slack's ssl_check probe gracefully
    form = urllib.parse.parse_qs(raw_body)
    if form.get("ssl_check", ["0"])[0] == "1":
        return {"statusCode": 200, "body": "ok"}  # Slack just checking SSL

    # 3) Parse interactive payload JSON
    payload_raw = form.get("payload", [None])[0]
    if not payload_raw:
        log("slack_missing_payload")
        return {"statusCode": 400, "body": "missing payload"}
    try:
        payload = json.loads(payload_raw)
    except Exception as e:
        log("slack_bad_payload", str(e))
        return {"statusCode": 400, "body": "bad payload"}

    actions = payload.get("actions") or []
    if actions and isinstance(actions, list):
        first = actions[0] or {}
        action_val = first.get("value")       # "approve" | "rollback" | "deny"
        action_id  = first.get("action_id")   # approve_quarantine | rollback_quarantine | deny_quarantine
        response_url = payload.get("response_url")

    log("slack_action", {"action_id": action_id, "action_val": action_val})

    raw_body = event.get("body") or ""
    if event.get("isBase64Encoded"):
       raw_body = base64.b64decode(raw_body).decode("utf-8")

    if not verify_slack(headers, raw_body):
       return {"statusCode": 401, "body": "invalid signature"}
 
    # Now parse AFTER verifying:
    form = urllib.parse.parse_qs(raw_body)
    payload_raw = form.get("payload", [None])[0]

    # 4) Route actions (approve / rollback / deny)
    if action_val == "approve":
        try:
            original = quarantine_instance(INSTANCE_ID, QUARANTINE_SG_ID)
            msg = {
                "replace_original": True,
                "text": "✅ Quarantine executed",
                "blocks":[
                    {"type":"section","text":{"type":"mrkdwn",
                     "text": f"*Quarantine executed*\nInstance `{INSTANCE_ID}` → SG `{QUARANTINE_SG_ID}`\nPrevious SGs: `{','.join(original)}`"}},
                    {"type":"actions","elements":[
                        {"type":"button","text":{"type":"plain_text","text":"Rollback 🔄"},
                         "value":"rollback","action_id":"rollback_quarantine"}
                    ]}
                ]
            }
            log("quarantined", INSTANCE_ID, "prev_sg", original)
        except Exception as e:
            log("quarantine_failed", str(e))
            msg = {"replace_original": False, "text": f"⚠️ Quarantine failed: {e}"}

    elif action_val == "rollback":
        try:
            restored = rollback_instance(INSTANCE_ID)
            msg = {
                "replace_original": False,
                "text": "🔄 Rollback executed",
                "blocks":[
                    {"type":"section","text":{"type":"mrkdwn",
                     "text": f"*Rollback executed*\nInstance `{INSTANCE_ID}` restored SGs: `{','.join(restored)}`"}}
                ]
            }
            log("rollback_ok", INSTANCE_ID, "restored_sg", restored)
        except Exception as e:
            log("rollback_failed", str(e))
            msg = {"replace_original": False, "text": f"⚠️ Rollback failed: {e}"}

    elif action_val == "deny":
        msg = {"replace_original": True, "text": "❌ Quarantine denied by reviewer."}

    else:
        msg = {"replace_original": False, "text": f"🤔 Unknown action: {action_val or 'none'}"}

    # 5) Update Slack via response_url
    if response_url:
        try: update_via_response_url(response_url, msg)
        except Exception as e: log("response_update_failed", str(e))

    return {"statusCode": 200, "body": "ok"}




    # EventBridge GuardDuty path → craft reasoning
    analysis = None
    if event.get("source") == "aws.guardduty" and event.get("detail"):
        try:
            analysis = reason_on_finding(event["detail"])
        except Exception as e:
            log("reasoning_failed", str(e))

    # Manual/browser call or EventBridge → post proposal
    try:
        status, resp_body = _http_post_json(SLACK_WEBHOOK_URL, _proposal_blocks(analysis))
        if status >= 400:
            return {"statusCode": 502, "body": json.dumps({"error":"webhook_failed","status":status,"body":resp_body})}
        return {"statusCode": 200, "body": json.dumps({"status":"proposal_sent","reasoned":bool(analysis)})}
    except Exception as e:
        log("proposal_exception", str(e))
        return {"statusCode": 500, "body": json.dumps({"error":"proposal_exception","message":str(e)})}
    
    



    # Non-Slack call ? send the proposal to your channel via Incoming Webhook
    try:
        status, body = _http_post_json(SLACK_WEBHOOK_URL, _proposal_blocks())
        log("proposal_post_status", status)
        if status >= 400:
            return {"statusCode": 502, "body": json.dumps({"error":"webhook_failed","status":status,"body":body})},
        return {"statusCode": 200, "body": json.dumps({"status":"proposal_sent"})}
    except Exception as e:
        log("proposal_exception", str(e))
        return {"statusCode": 500, "body": json.dumps({"error":"proposal_exception","message":str(e)})}

