import argparse
import json
from pathlib import Path

from correlation_tool.log_correlator import correlate_logs, normalize_log_input
from correlation_tool.wazuh_client import WazuhClient, load_wazuh_config


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Correlate security logs and detect whether attacks target Wazuh Manager or Agent(s)."
    )
    parser.add_argument("logfile", nargs="?", help="Path to a JSON, NDJSON, or CSV file containing log objects.")
    parser.add_argument("--live", action="store_true", help="Connect to live Wazuh SIEM to fetch alerts and correlate in real time.")
    parser.add_argument("--test-wazuh", action="store_true", help="Test connection to Wazuh API and Indexer using configured credentials.")
    parser.add_argument("--list-agents", action="store_true", help="List all discovered Wazuh agents and manager node.")
    parser.add_argument("--server", action="store_true", help="Start the local Wazuh correlation web server.")
    parser.add_argument("--port", type=int, default=8000, help="Port for the local web server (default 8000).")
    parser.add_argument("--host", help="Custom Wazuh API host (e.g. https://localhost:55000).")
    parser.add_argument("--user", help="Custom Wazuh username.")
    parser.add_argument("--password", help="Custom Wazuh password.")
    parser.add_argument("--output", help="Optional report path to save the JSON alert report.")
    parser.add_argument("--summary", action="store_true", help="Print a human-readable summary of Manager vs Agent attack targets.")
    args = parser.parse_args()

    if args.server:
        from correlation_tool.server import run_server
        run_server(args.port)
        return

    if args.test_wazuh:
        cfg = load_wazuh_config()
        client = WazuhClient(
            host=args.host or cfg.get("host", "https://localhost:55000"),
            username=args.user or cfg.get("username", "admin"),
            password=args.password or cfg.get("password", ""),
            verify_ssl=cfg.get("verify_ssl", False),
        )
        print(f"[*] Testing connection to Wazuh API at {client.host} with user '{client.username}'...")
        res = client.test_connection()
        print(json.dumps(res, indent=2))
        return

    if args.list_agents:
        cfg = load_wazuh_config()
        client = WazuhClient(
            host=args.host or cfg.get("host", "https://localhost:55000"),
            username=args.user or cfg.get("username", "admin"),
            password=args.password or cfg.get("password", ""),
            verify_ssl=cfg.get("verify_ssl", False),
        )
        agents = client.get_agents()
        if not agents:
            print("[!] No agents retrieved or failed to authenticate.")
        else:
            print(f"[*] Discovered {len(agents)} Wazuh Node(s):")
            for ag in agents:
                ag_id = ag.get("id", "N/A")
                role = "MANAGER" if str(ag_id) in ["000", "0"] else "AGENT"
                print(f"  - [{role}] ID: {ag_id} | Name: {ag.get('name')} | IP: {ag.get('ip', 'N/A')} | Status: {ag.get('status', 'unknown')}")
        return

    if args.live:
        cfg = load_wazuh_config()
        client = WazuhClient(
            host=args.host or cfg.get("host", "https://localhost:55000"),
            username=args.user or cfg.get("username", "admin"),
            password=args.password or cfg.get("password", ""),
            verify_ssl=cfg.get("verify_ssl", False),
        )
        print(f"[*] Fetching live alerts from Wazuh ({client.host})...")
        report = client.fetch_and_correlate()
    elif args.logfile:
        content = Path(args.logfile).read_text(encoding="utf-8")
        logs = normalize_log_input(content)
        report = correlate_logs(logs)
    else:
        parser.print_help()
        return

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"Report saved to {output_path}")

    if args.summary:
        print("\n=== WAZUH LOG CORRELATION REPORT ===")
        print(f"Total events analyzed: {report['summary']['total_events']}")
        print(f"Total attack alerts: {report['summary']['attack_count']}")
        print(f"Risk level: {report['summary']['risk_level'].upper()}")
        print(f"Attacks targeting Wazuh Manager: {report['summary'].get('manager_attacks', 0)}")
        print(f"Attacks targeting Wazuh Agent(s): {report['summary'].get('agent_attacks', 0)}")
        if report['summary'].get('affected_agents'):
            print(f"Affected Agents: {', '.join(report['summary']['affected_agents'])}")
        if report['summary'].get('affected_managers'):
            print(f"Affected Managers: {', '.join(report['summary']['affected_managers'])}")
        print("\n--- Alerts ---")
        for alert in report.get("alerts", []):
            print(f"[*] Attacker IP: {alert['ip']}")
            print(f"    Target Type: {alert.get('target_type', 'unknown').upper()}")
            print(f"    Target Summary: {alert.get('target_summary', 'N/A')}")
            print(f"    Severity: {alert['severity'].upper()}")
            print(f"    Reason: {alert['reason']}")
            print()
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
