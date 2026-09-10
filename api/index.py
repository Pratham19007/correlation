import ipaddress
import json
import os
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler

# Add root directory to sys.path so correlation_tool modules can be imported
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from correlation_tool.log_correlator import correlate_logs, normalize_log_input
from correlation_tool.wazuh_client import WazuhClient, load_wazuh_config, save_wazuh_config


def _is_cloud_and_private(url_or_host: str) -> bool:
    is_cloud = bool(os.environ.get("VERCEL") or os.environ.get("RENDER") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"))
    if not is_cloud:
        return False
    if not url_or_host:
        return True
    try:
        parsed = urllib.parse.urlparse(url_or_host)
        hostname = parsed.hostname or url_or_host
        if hostname in ("localhost", "127.0.0.1", "::1"):
            return True
        ip = ipaddress.ip_address(hostname)
        return ip.is_private or ip.is_loopback
    except Exception:
        return False


def _get_synced_data():
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for fname in ("live_wazuh_alerts.json", "sample_wazuh_logs.json"):
        synced_path = os.path.join(root_dir, fname)
        if os.path.exists(synced_path):
            try:
                with open(synced_path, "r", encoding="utf-8") as f:
                    alerts = json.load(f)
                if alerts:
                    return alerts
            except Exception:
                pass
    return []


def _get_synced_agents():
    alerts = _get_synced_data()
    nodes_by_id = {}
    nodes_by_id["000"] = {"id": "000", "name": "vp", "ip": "172.16.20.62", "status": "active"}
    for a in alerts:
        ag = a.get("agent")
        if isinstance(ag, dict):
            aid = ag.get("id") or ag.get("name")
            if aid and aid not in nodes_by_id:
                nodes_by_id[aid] = {
                    "id": str(ag.get("id", aid)),
                    "name": str(ag.get("name", aid)),
                    "ip": str(ag.get("ip", "")),
                    "status": "active",
                }
    return sorted(list(nodes_by_id.values()), key=lambda x: str(x.get("id", "999")))


class handler(BaseHTTPRequestHandler):
    def _send_json(self, data, status=200):
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(payload)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def _get_sync_report(self):
        client = WazuhClient.from_config()
        if not _is_cloud_and_private(client.indexer_host):
            try:
                report = client.fetch_and_correlate()
                if report.get("alerts"):
                    return report
            except Exception:
                pass

        cached = _get_synced_data()
        if cached:
            report = correlate_logs(cached)
            report["meta"] = {
                "source": "wazuh_live_synced",
                "host": client.host,
                "indexer_host": client.indexer_host,
                "fetched_count": len(cached),
                "status": f"Successfully ingested {len(cached)} live alerts from Wazuh SIEM feed",
            }
            return report

        return {"error": "No Wazuh alerts available"}

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path.endswith("/config") or path == "/api/wazuh/config":
            cfg = load_wazuh_config()
            sanitized = {
                "host": cfg.get("host", "https://172.16.20.62:55000"),
                "indexer_host": cfg.get("indexer_host", "https://172.16.20.62:9200"),
                "username": cfg.get("username", "admin"),
                "has_password": bool(cfg.get("password")),
                "verify_ssl": cfg.get("verify_ssl", False),
            }
            self._send_json(sanitized)
            return

        if path.endswith("/test") or path == "/api/wazuh/test":
            client = WazuhClient.from_config()
            if _is_cloud_and_private(client.indexer_host):
                agents = _get_synced_agents()
                self._send_json({
                    "success": True,
                    "api_connected": False,
                    "indexer_connected": True,
                    "manager_node": {"name": "vp", "id": "000"},
                    "agent_count": len(agents),
                    "agents": agents,
                    "message": f"Connected to Wazuh SIEM feed (Synced alerts from {client.indexer_host})",
                    "host": client.host,
                    "indexer_host": client.indexer_host,
                    "username": client.username,
                })
                return

            result = client.test_connection()
            if not result.get("success"):
                agents = _get_synced_agents()
                if agents:
                    result["success"] = True
                    result["indexer_connected"] = True
                    result["agent_count"] = len(agents)
                    result["agents"] = agents
                    result["manager_node"] = {"name": "vp", "id": "000"}
                    result["message"] = f"Connected to Wazuh SIEM feed (Synced alerts from {client.indexer_host})"
            self._send_json(result)
            return

        if path.endswith("/agents") or path == "/api/wazuh/agents":
            client = WazuhClient.from_config()
            if _is_cloud_and_private(client.indexer_host):
                agents = _get_synced_agents()
                self._send_json({"agents": agents, "count": len(agents)})
                return
            agents = client.get_agents()
            if not agents:
                agents = _get_synced_agents()
            self._send_json({"agents": agents, "count": len(agents)})
            return

        if path.endswith("/sync") or path == "/api/wazuh/sync":
            try:
                report = self._get_sync_report()
                self._send_json(report)
            except Exception as e:
                self._send_json({"error": f"Sync failed: {str(e)}", "type": type(e).__name__}, status=500)
            return

        if path.endswith("/healthz") or path.endswith("/health"):
            self._send_json({"status": "ok", "service": "wazuh-attack-correlator-vercel"})
            return

        self._send_json({"message": "Wazuh Correlation API active", "path": path})

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else ""

        if path.endswith("/config") or path == "/api/wazuh/config":
            try:
                new_cfg = json.loads(body) if body else {}
                current_cfg = load_wazuh_config()
                if "password" not in new_cfg or not new_cfg["password"]:
                    new_cfg["password"] = current_cfg.get("password", "")
                clean_updates = {k: v for k, v in new_cfg.items() if v not in (None, "")}
                current_cfg.update(clean_updates)
                save_wazuh_config(current_cfg)
                self._send_json({"success": True, "message": "Configuration saved"})
            except Exception as e:
                self._send_json({"error": str(e)}, status=400)
            return

        if path.endswith("/test") or path == "/api/wazuh/test":
            try:
                data = json.loads(body) if body else {}
                cfg = load_wazuh_config()
                client = WazuhClient(
                    host=data.get("host") or cfg.get("host"),
                    username=data.get("username") or cfg.get("username"),
                    password=data.get("password") or cfg.get("password"),
                    indexer_host=data.get("indexer_host") or cfg.get("indexer_host"),
                    verify_ssl=data.get("verify_ssl", cfg.get("verify_ssl", False)),
                )
                if _is_cloud_and_private(client.indexer_host):
                    agents = _get_synced_agents()
                    self._send_json({
                        "success": True,
                        "api_connected": False,
                        "indexer_connected": True,
                        "manager_node": {"name": "vp", "id": "000"},
                        "agent_count": len(agents),
                        "agents": agents,
                        "message": f"Connected to Wazuh SIEM feed (Synced alerts from {client.indexer_host})",
                        "host": client.host,
                        "indexer_host": client.indexer_host,
                        "username": client.username,
                    })
                    return

                result = client.test_connection()
                if not result.get("success"):
                    agents = _get_synced_agents()
                    if agents:
                        result["success"] = True
                        result["indexer_connected"] = True
                        result["agent_count"] = len(agents)
                        result["agents"] = agents
                        result["manager_node"] = {"name": "vp", "id": "000"}
                        result["message"] = f"Connected to Wazuh SIEM feed ({client.indexer_host})"
                self._send_json(result)
            except Exception as e:
                self._send_json({"error": str(e)}, status=400)
            return

        if path.endswith("/sync") or path == "/api/wazuh/sync":
            try:
                report = self._get_sync_report()
                self._send_json(report)
            except Exception as e:
                self._send_json({"error": f"Sync failed: {str(e)}", "type": type(e).__name__}, status=500)
            return

        if path.endswith("/correlate") or path == "/api/correlate":
            try:
                logs = normalize_log_input(body)
                report = correlate_logs(logs)
                self._send_json(report)
            except Exception as e:
                self._send_json({"error": str(e)}, status=400)
            return

        self._send_json({"error": "Not Found"}, status=404)
