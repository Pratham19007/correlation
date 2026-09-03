import json
import os
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler

# Add root directory to sys.path so correlation_tool modules can be imported
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from correlation_tool.log_correlator import correlate_logs, normalize_log_input
from correlation_tool.wazuh_client import WazuhClient, load_wazuh_config, save_wazuh_config


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

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path.endswith("/config") or path == "/api/wazuh/config":
            cfg = load_wazuh_config()
            sanitized = {
                "host": cfg.get("host", "https://localhost:55000"),
                "indexer_host": cfg.get("indexer_host", "https://localhost:9200"),
                "username": cfg.get("username", "admin"),
                "has_password": bool(cfg.get("password")),
                "verify_ssl": cfg.get("verify_ssl", False),
            }
            self._send_json(sanitized)
            return

        if path.endswith("/test") or path == "/api/wazuh/test":
            client = WazuhClient.from_config()
            result = client.test_connection()
            self._send_json(result)
            return

        if path.endswith("/agents") or path == "/api/wazuh/agents":
            client = WazuhClient.from_config()
            agents = client.get_agents()
            self._send_json({"agents": agents, "count": len(agents)})
            return

        if path.endswith("/sync") or path == "/api/wazuh/sync":
            client = WazuhClient.from_config()
            report = client.fetch_and_correlate()
            self._send_json(report)
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
                current_cfg.update(new_cfg)
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
                result = client.test_connection()
                self._send_json(result)
            except Exception as e:
                self._send_json({"error": str(e)}, status=400)
            return

        if path.endswith("/sync") or path == "/api/wazuh/sync":
            try:
                client = WazuhClient.from_config()
                # Try to authenticate first to catch credential errors
                auth_ok, auth_msg = client.authenticate()
                if not auth_ok:
                    self._send_json({"error": f"Authentication failed: {auth_msg}"}, status=401)
                    return
                
                # Fetch alerts and correlate
                report = client.fetch_and_correlate()
                
                # If no alerts found, provide diagnostic info
                if not report.get("alerts"):
                    # Try to get manager info for diagnostics
                    mgr_info = client.get_manager_info()
                    agents = client.get_agents()
                    report["diagnostics"] = {
                        "manager_info": mgr_info,
                        "agent_count": len(agents) if agents else 0,
                        "message": "No alerts found - check Wazuh has recent security events"
                    }
                
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
