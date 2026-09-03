# Wazuh Log Correlation & Attack Detector

A security correlation engine that directly connects to **Wazuh SIEM/XDR** (API and Indexer) to ingest alert logs, correlate attacks by source IP, and detect whether the attack targets the **Wazuh Manager** (ID: 000) or monitored **Wazuh Agents** (ID: 001+).

## Features

- **Live Wazuh SIEM Attachment**: Authenticates with Wazuh REST API (`https://<host>:55000`) and Wazuh Indexer (`https://<host>:9200`) using JWT and Basic authentication.
- **Wazuh Target Identification**: Differentiates between attacks targeting the central **Wazuh Manager** (`agent.id: "000"` / `wazuh-manager`) versus monitored **Wazuh Agents** (`agent.id: "001+"` / named endpoints) or multi-target attacks hitting both.
- **Node & Agent Inventory Discovery**: Automatically discovers connected Wazuh nodes and maps agent IDs to target roles.
- **Real-Time Live Sync**: Pulls live alerts from Wazuh with a single click or CLI command.
- **Multi-Source Ingestion**: Ingests Wazuh `alerts.json`, NDJSON, flat JSON, CSV logs, or raw key-value logs.
- **Interactive Web Dashboard**: Includes live connection status pill, Wazuh settings modal, agent inventory viewer, and PDF report export.

## Configuration (`wazuh_config.json`)

Credentials and endpoints are configured in `wazuh_config.json` or via the web interface:

```json
{
  "host": "https://localhost:55000",
  "indexer_host": "https://localhost:9200",
  "username": "admin",
  "password": "l6ArtMq7XC*XGtK08mwGBCPsWXh?Lgxv",
  "verify_ssl": false,
  "timeout": 10
}
```

## Quick Start

### 1. Start the Live Web Server & UI

```bash
py -m correlation_tool.server
```
Then open `http://localhost:8000` in your browser.

### 2. Test Live Wazuh Connection (CLI)

```bash
# Test authentication and connection to Wazuh API & Indexer
py -m correlation_tool.cli --test-wazuh

# List all discovered Wazuh agents and manager node
py -m correlation_tool.cli --list-agents
```

### 3. Fetch & Correlate Live Wazuh Alerts (CLI)

```bash
# Pull live alerts from Wazuh and print correlation summary
py -m correlation_tool.cli --live --summary

# Save live correlation report to JSON
py -m correlation_tool.cli --live --output live_report.json
```

### 4. Analyze Local File (Offline Mode)

```bash
py -m correlation_tool.cli sample_wazuh_logs.json --summary
```

### 5. Run Automated Tests

```bash
py -m unittest discover tests
```

---

## Wazuh Target Role Determination

| Entity | Wazuh Agent ID / Pattern | Target Role | Description |
| :--- | :--- | :--- | :--- |
| **Wazuh Manager** | `agent.id: "000"` or `name: "wazuh-manager"` or `is_manager: true` | `manager` | Attack is directed at the central Wazuh Manager server |
| **Wazuh Agent** | `agent.id: "001+"` or `name: "<hostname>"` or `location: "(<agent-name>)..."` | `agent` | Attack is directed at a monitored agent endpoint |
| **Multi-Target** | Attacker IP targets both Manager and Agent(s) | `both` | Attacker is targeting both Manager and Agent nodes |

## Example Correlated Output

```json
{
  "is_attack_attempt": true,
  "alerts": [
    {
      "ip": "198.51.100.50",
      "target_type": "manager",
      "target_summary": "Wazuh Manager (ID: 000, Name: wazuh-manager)",
      "targets": [
        {
          "role": "manager",
          "id": "000",
          "name": "wazuh-manager",
          "ip": "192.168.1.10"
        }
      ],
      "severity": "high",
      "reason": "[Target: Wazuh Manager] Attack targeted the central Wazuh Manager (Wazuh Manager (ID: 000, Name: wazuh-manager)). 2 failed login attempt(s) were observed from 198.51.100.50. Multiple usernames were targeted from 198.51.100.50: admin, root.",
      "evidence": {
        "target_type": "manager",
        "is_manager_attack": true,
        "is_agent_attack": false,
        "targeted_agents": [],
        "targeted_agent_ids": [],
        "targeted_managers": ["wazuh-manager"],
        "failed_login_count": 2,
        "suspicious_event_count": 0,
        "unique_failed_usernames": ["admin", "root"]
      }
    }
  ],
  "summary": {
    "total_events": 6,
    "analyzed_ips": ["192.0.2.77", "198.51.100.50", "203.0.113.88"],
    "target_ips": ["192.0.2.77", "198.51.100.50", "203.0.113.88"],
    "attack_count": 3,
    "risk_level": "high",
    "manager_attacks": 1,
    "agent_attacks": 2,
    "target_distribution": {
      "manager": 1,
      "agent": 2,
      "both": 0,
      "unknown": 0
    },
    "affected_agents": ["db-server-02", "web-server-01"],
    "affected_managers": ["wazuh-manager"]
  }
}
```
