import csv
import io
import json
import re
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional


def _extract_target_info(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Extract Wazuh target information: whether the target is the Wazuh Manager or a Wazuh Agent."""
    agent = entry.get("agent")
    manager = entry.get("manager")

    agent_id = ""
    agent_name = ""
    agent_ip = ""
    manager_name = ""

    if isinstance(agent, dict):
        agent_id = str(agent.get("id") if agent.get("id") is not None else "").strip()
        agent_name = str(agent.get("name") or "").strip()
        agent_ip = str(agent.get("ip") or "").strip()
    elif isinstance(agent, str):
        agent_name = agent.strip()

    if isinstance(manager, dict):
        manager_name = str(manager.get("name") or "").strip()
    elif isinstance(manager, str):
        manager_name = manager.strip()

    if not agent_id:
        agent_id = str(entry.get("agent_id") if entry.get("agent_id") is not None else (entry.get("agentId") or "")).strip()
    if not agent_name:
        agent_name = str(entry.get("agent_name") or entry.get("agentName") or "").strip()
    if not agent_ip:
        agent_ip = str(entry.get("agent_ip") or entry.get("agentIp") or "").strip()
    if not manager_name:
        manager_name = str(entry.get("manager_name") or entry.get("managerName") or "").strip()

    location = str(entry.get("location") or "")
    if not agent_name and "(" in location and ")" in location:
        match = re.search(r"\(([^)]+)\)", location)
        if match:
            agent_name = match.group(1).strip()

    explicit_target = str(
        entry.get("target_type")
        or entry.get("target_role")
        or entry.get("node_type")
        or entry.get("host_type")
        or entry.get("role")
        or ""
    ).lower().strip()

    is_manager_flag = entry.get("is_manager")
    if is_manager_flag is True or str(is_manager_flag).lower() == "true":
        role = "manager"
    elif is_manager_flag is False or str(is_manager_flag).lower() == "false":
        role = "agent"
    elif explicit_target in ["manager", "wazuh-manager", "wazuh_manager", "master"]:
        role = "manager"
    elif explicit_target in ["agent", "wazuh-agent", "wazuh_agent", "endpoint", "node"]:
        role = "agent"
    elif agent_id in ["000", "0"]:
        role = "manager"
    elif agent_name.lower() in ["wazuh-manager", "manager", "master"]:
        role = "manager"
    elif agent_id and agent_id not in ["000", "0"]:
        role = "agent"
    elif agent_name:
        role = "agent"
    elif location.startswith("wazuh-manager"):
        role = "manager"
    elif manager_name and not agent_name and not agent_id:
        role = "manager"
    else:
        role = "unknown"

    target_id = agent_id if agent_id else ("000" if role == "manager" else "")
    target_name = agent_name if agent_name else (manager_name if role == "manager" else ("wazuh-manager" if role == "manager" else ""))

    return {
        "role": role,
        "id": target_id,
        "name": target_name,
        "ip": agent_ip,
    }


def _extract_ip_from_entry(entry: Dict[str, Any]) -> str:
    """Extract source/attacker IP from normalized log entry or Wazuh data fields."""
    data = entry.get("data")
    if isinstance(data, dict):
        candidate = (
            data.get("srcip")
            or data.get("src_ip")
            or data.get("source_ip")
            or data.get("client_ip")
            or data.get("remote_ip")
        )
        if candidate:
            return str(candidate).strip()

    candidate = (
        entry.get("ip")
        or entry.get("src_ip")
        or entry.get("source_ip")
        or entry.get("srcip")
        or entry.get("remote_ip")
        or entry.get("client_ip")
    )
    if candidate:
        return str(candidate).strip()

    # Search in full_log or message for IP
    text = " ".join([str(entry.get("full_log", "")), str(entry.get("message", ""))])
    ip_match = re.search(r"\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})\b", text)
    if ip_match:
        return ip_match.group(1)

    return "unknown"


def _extract_user_from_entry(entry: Dict[str, Any]) -> str:
    """Extract targeted username from normalized log entry or Wazuh data fields."""
    data = entry.get("data")
    if isinstance(data, dict):
        candidate = (
            data.get("srcuser")
            or data.get("dstuser")
            or data.get("user")
            or data.get("username")
            or data.get("target_user")
        )
        if candidate:
            return str(candidate).strip()

    candidate = (
        entry.get("user")
        or entry.get("username")
        or entry.get("user_name")
        or entry.get("srcuser")
        or entry.get("dstuser")
        or entry.get("account")
        or entry.get("Account Name")
    )
    if candidate:
        return str(candidate).strip()

    # Search in full_log for user
    full_log = str(entry.get("full_log", ""))
    match = re.search(r"for\s+(?:invalid\s+user\s+)?([A-Za-z0-9_\-\.\\]+)\s+from", full_log)
    if match:
        return match.group(1).strip()

    return ""


def _extract_path_from_entry(entry: Dict[str, Any]) -> str:
    data = entry.get("data")
    if isinstance(data, dict):
        candidate = data.get("url") or data.get("uri") or data.get("path") or data.get("request")
        if candidate:
            return str(candidate).strip()
    return str(entry.get("path") or entry.get("uri") or entry.get("url") or entry.get("request") or "").strip()


def _extract_user_agent_from_entry(entry: Dict[str, Any]) -> str:
    data = entry.get("data")
    if isinstance(data, dict):
        candidate = data.get("http_user_agent") or data.get("user_agent") or data.get("ua")
        if candidate:
            return str(candidate).lower().strip()
    return str(
        entry.get("user_agent")
        or entry.get("http_user_agent")
        or entry.get("ua")
        or ""
    ).lower().strip()


def _extract_message_from_entry(entry: Dict[str, Any]) -> str:
    rule = entry.get("rule")
    if isinstance(rule, dict) and rule.get("description"):
        return str(rule.get("description")).strip()
    data = entry.get("data")
    if isinstance(data, dict) and data.get("message"):
        return str(data.get("message")).strip()
    return str(entry.get("message") or entry.get("full_log") or entry.get("Command Line") or entry.get("command_line") or "").strip()


def _parse_csv_string(raw_text: str) -> List[Dict[str, Any]]:
    stream = io.StringIO(raw_text)
    reader = csv.DictReader(stream)
    rows: List[Dict[str, Any]] = []

    for row in reader:
        if row is None:
            continue
        normalized = {
            str(key).strip(): (value.strip() if isinstance(value, str) else value)
            for key, value in row.items()
            if key is not None
        }
        if not normalized:
            continue

        candidate_ip = (
            normalized.get("ip")
            or normalized.get("src_ip")
            or normalized.get("source_ip")
            or normalized.get("remote_ip")
            or normalized.get("local_ip")
        )
        if candidate_ip:
            normalized["ip"] = str(candidate_ip)
        elif "Remote IP" in normalized or "Local IP" in normalized:
            normalized["ip"] = str(normalized.get("Remote IP") or normalized.get("Local IP") or "unknown")

        if "event" not in normalized:
            event_value = normalized.get("event_name") or normalized.get("Process Name") or normalized.get("process_name")
            if event_value:
                normalized["event"] = str(event_value)

        if "message" not in normalized:
            message_value = normalized.get("message") or normalized.get("Command Line") or normalized.get("command_line")
            if message_value:
                normalized["message"] = str(message_value)

        rows.append(normalized)

    return rows


def _looks_like_csv(raw_text: str) -> bool:
    if not raw_text:
        return False
    lines = [line.strip() for line in raw_text.splitlines() if line.strip()]
    if len(lines) < 2:
        return False
    first_line = lines[0]
    return "," in first_line and not first_line.strip().startswith("{") and not first_line.strip().startswith("[")


def normalize_log_input(raw_logs: Any) -> List[Dict[str, Any]]:
    """Accept JSON, NDJSON, CSV, or raw text log input and return a normalized list of dicts."""
    if raw_logs is None:
        return []

    if isinstance(raw_logs, dict):
        return [raw_logs]

    if isinstance(raw_logs, list):
        return [entry for entry in raw_logs if isinstance(entry, dict)]

    if not isinstance(raw_logs, str):
        return []

    text = raw_logs.strip()
    if not text:
        return []

    if _looks_like_csv(text):
        return _parse_csv_string(text)

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = None

    if isinstance(parsed, dict):
        return [parsed]
    if isinstance(parsed, list):
        return [entry for entry in parsed if isinstance(entry, dict)]

    normalized: List[Dict[str, Any]] = []
    for line in text.splitlines():
        candidate = line.strip()
        if not candidate:
            continue

        try:
            parsed_line = json.loads(candidate)
        except json.JSONDecodeError:
            parsed_line = None

        if isinstance(parsed_line, dict):
            normalized.append(parsed_line)
            continue

        entry: Dict[str, Any] = {}
        for assignment in re.split(r"\s+(?=[A-Za-z0-9_\-]+=)", candidate):
            if "=" not in assignment:
                continue
            key, value = assignment.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"\'')
            if key:
                entry[key] = value

        if entry:
            normalized.append(entry)

    return normalized


SUSPICIOUS_WEB_PATTERNS = [
    "union select",
    "or '1'='1",
    "or 1=1",
    "sql injection",
    "xp_",
    "sleep(",
    "--",
    "<script",
    "javascript:",
    "../",
    "..\\",
    "cmd=",
    "/etc/passwd",
    "wp-admin",
    "wp-login.php",
    "/.git",
    "/.env",
    "/config.php",
    "/phpmyadmin",
    "pma",
    "xmlrpc.php",
]

SCANNER_USER_AGENT_PATTERNS = [
    "sqlmap",
    "nmap",
    "masscan",
    "dirbuster",
    "nikto",
    "acunetix",
    "havij",
    "whatweb",
]

SENSITIVE_ENDPOINT_PATTERNS = [
    "/admin",
    "/wp-admin",
    "/wp-login.php",
    "/phpmyadmin",
    "/pma",
    "/xmlrpc.php",
    "/.git",
    "/.env",
    "/config.php",
    "/.htaccess",
    "/.well-known",
]

WAZUH_AUTH_RULE_IDS = {
    "5503", "5504", "5710", "5711", "5712", "5716", "5720", "2501", "2502"
}

WAZUH_WEB_ATTACK_RULE_IDS = {
    "30101", "30102", "30103", "30104", "30112", "30115",
    "31101", "31102", "31103", "31104", "31105", "31106", "31164", "31165"
}


def _is_sensitive_endpoint_access(log_entry: Dict[str, Any]) -> bool:
    path = _extract_path_from_entry(log_entry).lower()
    return any(pattern in path for pattern in SENSITIVE_ENDPOINT_PATTERNS)


def _is_known_scanner_activity(log_entry: Dict[str, Any]) -> bool:
    user_agent = _extract_user_agent_from_entry(log_entry)
    if any(signature in user_agent for signature in SCANNER_USER_AGENT_PATTERNS):
        return True

    payload = " ".join(
        [
            _extract_path_from_entry(log_entry),
            _extract_message_from_entry(log_entry),
            str(log_entry.get("query", "")),
            str(log_entry.get("full_log", "")),
        ]
    ).lower()
    return any(signature in payload for signature in SCANNER_USER_AGENT_PATTERNS)


def _is_auth_failure_event(log_entry: Dict[str, Any]) -> bool:
    # Check rule groups and rule id if Wazuh
    rule = log_entry.get("rule")
    if isinstance(rule, dict):
        rule_id = str(rule.get("id", ""))
        if rule_id in WAZUH_AUTH_RULE_IDS:
            return True
        groups = rule.get("groups")
        if isinstance(groups, list):
            group_set = {str(g).lower() for g in groups}
            if group_set & {"authentication_failed", "authentication_failures", "invalid_login", "sshd"}:
                return True
        elif isinstance(groups, str) and any(
            g in groups.lower() for g in ["authentication_failed", "invalid_login"]
        ):
            return True

    event = str(log_entry.get("event", "")).lower()
    if any(name in event for name in ["login_failed", "failed_login", "auth_failure", "authentication_failed", "authentication_failure"]):
        return True

    msg = " ".join([_extract_message_from_entry(log_entry), str(log_entry.get("full_log", ""))]).lower()
    if any(phrase in msg for phrase in ["failed password", "failed login", "invalid user", "authentication failed", "login failed"]):
        return True

    return False


def _is_suspicious_web_activity(log_entry: Dict[str, Any]) -> bool:
    rule = log_entry.get("rule")
    if isinstance(rule, dict):
        rule_id = str(rule.get("id", ""))
        if rule_id in WAZUH_WEB_ATTACK_RULE_IDS:
            return True
        groups = rule.get("groups")
        if isinstance(groups, list):
            group_set = {str(g).lower() for g in groups}
            if group_set & {"sql_injection", "web_scan", "xss", "path_traversal", "attack", "attacks"}:
                return True
        rule_level = rule.get("level")
        if isinstance(rule_level, (int, float)) and rule_level >= 7:
            return True

    path = _extract_path_from_entry(log_entry)
    user_agent = _extract_user_agent_from_entry(log_entry)
    msg = _extract_message_from_entry(log_entry)
    full_log = str(log_entry.get("full_log", ""))
    event = str(log_entry.get("event", "")).lower()

    payload = f"{path} {msg} {full_log} {user_agent} {str(log_entry.get('query', ''))}".lower()

    if not payload.strip():
        return False

    if any(name in event for name in ["blocked", "denied", "rejected"]):
        return True

    status = str(log_entry.get("status") or (log_entry.get("data", {}).get("status") if isinstance(log_entry.get("data"), dict) else "")).strip()
    if status == "403" and _is_sensitive_endpoint_access(log_entry):
        return True

    if _is_sensitive_endpoint_access(log_entry):
        return True

    if _is_known_scanner_activity(log_entry):
        return True

    if any(pattern in payload for pattern in SUSPICIOUS_WEB_PATTERNS):
        return True

    if re.search(r"(union|select|drop|insert|update|delete).*(from|table)", payload):
        return True

    if re.search(r"(?:\b(?:or|and)\s+\d+=\d+|\'.*\'.*\'.*\')", payload):
        return True

    return False


def _build_target_summary(target_role: str, targets: List[Dict[str, Any]]) -> str:
    """Build a concise, human-readable summary of the attack target(s)."""
    if target_role == "manager":
        mgr_names = [t.get("name") or "wazuh-manager" for t in targets if t.get("role") == "manager"]
        mgr_name = mgr_names[0] if mgr_names else "wazuh-manager"
        return f"Wazuh Manager (ID: 000, Name: {mgr_name})"
    elif target_role == "agent":
        agent_strs = [
            f"{t.get('name') or 'agent'} (ID: {t.get('id') or 'N/A'})"
            for t in targets if t.get("role") == "agent"
        ]
        return f"Wazuh Agent(s): {', '.join(agent_strs) if agent_strs else 'Monitored Agent'}"
    elif target_role == "both":
        mgr_part = "Wazuh Manager (ID: 000)"
        agent_strs = [
            f"{t.get('name') or 'agent'} (ID: {t.get('id') or 'N/A'})"
            for t in targets if t.get("role") == "agent"
        ]
        return f"{mgr_part} & Wazuh Agent(s): {', '.join(agent_strs) if agent_strs else 'Monitored Agent'}"
    return "Unknown Target"


def _build_reason(
    ip: str,
    target_role: str,
    target_summary: str,
    failed_logins: List[Dict[str, Any]],
    suspicious_events: List[Dict[str, Any]],
    failed_usernames: List[str],
    sensitive_count: int,
    scanner_count: int,
) -> str:
    reasons: List[str] = []

    # Prefix with explicit Target Role
    if target_role == "manager":
        reasons.append(f"[Target: Wazuh Manager] Attack targeted the central Wazuh Manager ({target_summary}).")
    elif target_role == "agent":
        reasons.append(f"[Target: Wazuh Agent] Attack targeted monitored agent endpoint(s) ({target_summary}).")
    elif target_role == "both":
        reasons.append(f"[Target: Wazuh Manager & Agent] Multi-target attack directed at both the Wazuh Manager and monitored Agent(s) ({target_summary}).")

    if failed_logins:
        reasons.append(f"{len(failed_logins)} failed login attempt(s) were observed from {ip}.")

    if len(failed_usernames) > 1:
        reasons.append(
            f"Multiple usernames were targeted from {ip}: {', '.join(sorted(failed_usernames))}."
        )
    elif len(failed_usernames) == 1:
        reasons.append(f"Targeted username: {failed_usernames[0]}.")

    if suspicious_events:
        top_event = suspicious_events[0]
        path = _extract_path_from_entry(top_event) or "request"
        msg = _extract_message_from_entry(top_event) or "suspicious request"
        if any(token in str(path).lower() for token in ["union", "select", "or '1'='1", "or 1=1", "sql", "script"]):
            reasons.append(f"The request to {path} shows SQL injection or script-related payloads: {msg}.")
        elif str(top_event.get("event", "")).lower() in {"blocked_request", "blocked", "denied", "rejected"}:
            reasons.append(f"The WAF or gateway blocked an anomalous request from {ip}: {msg}.")
        elif _is_sensitive_endpoint_access(top_event):
            reasons.append(f"The request targeted a sensitive endpoint from {ip}: {path}.")
        elif scanner_count:
            reasons.append(
                f"Traffic from {ip} contained known scanning or reconnaissance signatures: {msg}."
            )
        else:
            reasons.append(f"The traffic pattern for {ip} includes anomalous web activity: {msg}.")

    if sensitive_count and not any(_is_sensitive_endpoint_access(entry) for entry in suspicious_events):
        reasons.append(f"{sensitive_count} request(s) targeted sensitive admin or configuration endpoints.")

    if scanner_count and not any(_is_known_scanner_activity(entry) for entry in suspicious_events):
        reasons.append(f"{scanner_count} request(s) included scanner or reconnaissance signatures.")

    return " ".join(reasons)


def correlate_logs(logs: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Correlate security logs and Wazuh alert entries to detect attacks on Manager vs Agent."""
    normalized_logs = normalize_log_input(logs)
    report: Dict[str, Any] = {
        "is_attack_attempt": False,
        "alerts": [],
        "summary": {
            "total_events": 0,
            "analyzed_ips": [],
            "target_ips": [],
            "attack_count": 0,
            "risk_level": "low",
            "manager_attacks": 0,
            "agent_attacks": 0,
            "target_distribution": {
                "manager": 0,
                "agent": 0,
                "both": 0,
                "unknown": 0,
            },
            "affected_agents": [],
            "affected_managers": [],
        },
    }

    if logs is None:
        return report

    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for raw_entry in normalized_logs:
        if not isinstance(raw_entry, dict):
            continue
        entry = dict(raw_entry)
        entry["_ip"] = _extract_ip_from_entry(entry)
        entry["_target"] = _extract_target_info(entry)
        grouped[entry["_ip"]].append(entry)

    report["summary"]["total_events"] = sum(len(items) for items in grouped.values())
    report["summary"]["analyzed_ips"] = sorted(grouped.keys())

    target_ips: List[str] = []
    alerts: List[Dict[str, Any]] = []
    all_affected_agents: set = set()
    all_affected_managers: set = set()

    for ip, entries in grouped.items():
        failed_logins = [entry for entry in entries if _is_auth_failure_event(entry)]
        suspicious_events = [entry for entry in entries if _is_suspicious_web_activity(entry)]
        sensitive_accesses = [entry for entry in entries if _is_sensitive_endpoint_access(entry)]
        scanner_hits = [entry for entry in entries if _is_known_scanner_activity(entry)]
        failed_usernames = sorted({_extract_user_from_entry(entry) for entry in failed_logins if _extract_user_from_entry(entry)})

        if not failed_logins and not suspicious_events and not sensitive_accesses and not scanner_hits:
            continue

        is_attack = False
        if len(failed_logins) >= 2:
            is_attack = True
        if suspicious_events:
            is_attack = True
        if sensitive_accesses:
            is_attack = True
        if scanner_hits:
            is_attack = True
        if len(failed_usernames) >= 2:
            is_attack = True

        if not is_attack:
            continue

        # Determine target role across all events for this IP
        roles_present = {entry["_target"]["role"] for entry in entries}
        has_manager = "manager" in roles_present
        has_agent = "agent" in roles_present

        if has_manager and has_agent:
            target_role = "both"
        elif has_manager:
            target_role = "manager"
        elif has_agent:
            target_role = "agent"
        else:
            target_role = "unknown"

        # Collect unique target objects
        unique_targets_dict: Dict[str, Dict[str, Any]] = {}
        for entry in entries:
            t = entry["_target"]
            key = f"{t.get('role')}:{t.get('id')}:{t.get('name')}"
            if key not in unique_targets_dict and (t.get("role") != "unknown" or len(entries) == 1):
                unique_targets_dict[key] = {
                    "role": t.get("role"),
                    "id": t.get("id"),
                    "name": t.get("name"),
                    "ip": t.get("ip"),
                }

        targets_list = list(unique_targets_dict.values())
        target_summary = _build_target_summary(target_role, targets_list)

        targeted_agent_names = sorted({
            t["name"] or f"Agent-{t['id']}"
            for t in targets_list
            if t["role"] == "agent" and (t.get("name") or t.get("id"))
        })
        targeted_agent_ids = sorted({
            t["id"]
            for t in targets_list
            if t["role"] == "agent" and t.get("id")
        })
        targeted_manager_names = sorted({
            t["name"] or "wazuh-manager"
            for t in targets_list
            if t["role"] == "manager"
        })

        if targeted_agent_names:
            all_affected_agents.update(targeted_agent_names)
        elif targeted_agent_ids:
            all_affected_agents.update(targeted_agent_ids)

        if has_manager:
            all_affected_managers.update(targeted_manager_names or ["wazuh-manager"])

        target_ips.append(ip)
        alert = {
            "ip": ip,
            "target_type": target_role,
            "target_summary": target_summary,
            "targets": targets_list,
            "severity": "high" if suspicious_events or len(failed_logins) >= 2 or sensitive_accesses or scanner_hits or len(failed_usernames) >= 2 else "medium",
            "reason": _build_reason(
                ip,
                target_role,
                target_summary,
                failed_logins,
                suspicious_events,
                failed_usernames,
                len(sensitive_accesses),
                len(scanner_hits),
            ),
            "evidence": {
                "target_type": target_role,
                "is_manager_attack": has_manager,
                "is_agent_attack": has_agent,
                "targeted_agents": targeted_agent_names,
                "targeted_agent_ids": targeted_agent_ids,
                "targeted_managers": targeted_manager_names,
                "failed_login_count": len(failed_logins),
                "suspicious_event_count": len(suspicious_events),
                "sensitive_endpoint_count": len(sensitive_accesses),
                "scanner_signature_count": len(scanner_hits),
                "unique_failed_usernames": failed_usernames,
                "failed_login_examples": [_extract_message_from_entry(entry) for entry in failed_logins[:3]],
                "suspicious_examples": [_extract_path_from_entry(entry) or _extract_message_from_entry(entry) for entry in suspicious_events[:3]],
            },
        }
        alerts.append(alert)

    if alerts:
        report["is_attack_attempt"] = True
        report["alerts"] = alerts
        report["summary"]["attack_count"] = len(alerts)
        report["summary"]["target_ips"] = sorted(target_ips)
        report["summary"]["risk_level"] = "high"

        manager_count = sum(1 for a in alerts if a["target_type"] in ["manager", "both"])
        agent_count = sum(1 for a in alerts if a["target_type"] in ["agent", "both"])
        report["summary"]["manager_attacks"] = manager_count
        report["summary"]["agent_attacks"] = agent_count

        dist = {"manager": 0, "agent": 0, "both": 0, "unknown": 0}
        for a in alerts:
            dist[a["target_type"]] = dist.get(a["target_type"], 0) + 1
        report["summary"]["target_distribution"] = dist
        report["summary"]["affected_agents"] = sorted(all_affected_agents)
        report["summary"]["affected_managers"] = sorted(all_affected_managers)
    else:
        report["summary"]["target_ips"] = []
        report["summary"]["attack_count"] = 0
        report["summary"]["risk_level"] = "low"

    return report


def build_report(logs: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    return correlate_logs(logs)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Correlate security logs and flag likely attack attempts.")
    parser.add_argument("logs_path", help="Path to a JSON file containing log entries.")
    args = parser.parse_args()

    with open(args.logs_path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)

    report = correlate_logs(payload if isinstance(payload, list) else [payload])
    print(json.dumps(report, indent=2))
