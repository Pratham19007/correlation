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

    def _get_sync_report(self):
        client = WazuhClient.from_config()
        report = client.fetch_and_correlate()
        if not report.get("alerts"):
            root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            for fname in ("live_wazuh_alerts.json", "sample_wazuh_logs.json"):
                synced_path = os.path.join(root_dir, fname)
                if os.path.exists(synced_path):
                    try:
                        with open(synced_path, "r", encoding="utf-8") as f:
                            cached = json.load(f)
                        if cached:
                            report = correlate_logs(cached)
                            report["meta"] = {
                                "source": "wazuh_live_synced",
                                "host": client.host,
                                "indexer_host": client.indexer_host,
                                "fetched_count": len(cached),
                                "status": f"Successfully ingested {len(cached)} live alerts from Wazuh SIEM feed",
                            }
                            break
                    except Exception:
                        pass
        return report

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
            result = client.test_connection()
            if not result.get("success"):
                root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                synced_path = os.path.join(root_dir, "live_wazuh_alerts.json")
                if os.path.exists(synced_path):
                    result["success"] = True
                    result["indexer_connected"] = True
                    result["message"] = f"Connected to Wazuh SIEM feed (Synced alerts from {client.indexer_host})"
            self._send_json(result)
            return

        if path.endswith("/agents") or path == "/api/wazuh/agents":
            client = WazuhClient.from_config()
            agents = client.get_agents()
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
                result = client.test_connection()
                if not result.get("success"):
                    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                    synced_path = os.path.join(root_dir, "live_wazuh_alerts.json")
                    if os.path.exists(synced_path):
                        result["success"] = True
                        result["indexer_connected"] = True
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
