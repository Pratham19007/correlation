import http.server
import json
import os
import socketserver
import sys
import urllib.parse
from pathlib import Path
from typing import Any, Dict

# Add project root to Python path for module imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from correlation_tool.log_correlator import correlate_logs, normalize_log_input
from correlation_tool.wazuh_client import WazuhClient, load_wazuh_config, save_wazuh_config

DEFAULT_PORT = int(os.environ.get("PORT", 8000))


class WazuhCorrelationHandler(http.server.SimpleHTTPRequestHandler):
    def _send_json_response(self, data: Any, status: int = 200) -> None:
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(payload)

    def do_OPTIONS(self) -> None:
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path

        if path == "/api/wazuh/config":
            cfg = load_wazuh_config()
            sanitized = {
                "host": cfg.get("host", "https://localhost:55000"),
                "indexer_host": cfg.get("indexer_host", "https://localhost:9200"),
                "username": cfg.get("username", "admin"),
                "has_password": bool(cfg.get("password")),
                "verify_ssl": cfg.get("verify_ssl", False),
            }
            self._send_json_response(sanitized)
            return

        if path == "/api/wazuh/test":
            client = WazuhClient.from_config()
            result = client.test_connection()
            self._send_json_response(result)
            return

        if path == "/api/wazuh/agents":
            client = WazuhClient.from_config()
            agents = client.get_agents()
            self._send_json_response({"agents": agents, "count": len(agents)})
            return

        if path == "/api/wazuh/sync":
            client = WazuhClient.from_config()
            report = client.fetch_and_correlate()
            self._send_json_response(report)
            return

        if path == "/healthz" or path == "/health":
            self._send_json_response({"status": "ok", "service": "wazuh-attack-correlator"})
            return

        # Default static file handling
        super().do_GET()

    def do_POST(self) -> None:
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else ""

        if path == "/api/wazuh/config":
            try:
                new_cfg = json.loads(body) if body else {}
                current_cfg = load_wazuh_config()
                if "password" not in new_cfg or not new_cfg["password"]:
                    new_cfg["password"] = current_cfg.get("password", "")
                current_cfg.update(new_cfg)
                save_wazuh_config(current_cfg)
                self._send_json_response({"success": True, "message": "Configuration saved"})
            except Exception as e:
                self._send_json_response({"error": str(e)}, status=400)
            return

        if path == "/api/wazuh/test":
            try:
                data = json.loads(body) if body else {}
                cfg = load_wazuh_config()
                host = data.get("host") or cfg.get("host")
                username = data.get("username") or cfg.get("username")
                password = data.get("password") or cfg.get("password")
                indexer_host = data.get("indexer_host") or cfg.get("indexer_host")
                verify_ssl = data.get("verify_ssl", cfg.get("verify_ssl", False))

                client = WazuhClient(
                    host=host,
                    username=username,
                    password=password,
                    indexer_host=indexer_host,
                    verify_ssl=verify_ssl,
                )
                result = client.test_connection()
                self._send_json_response(result)
            except Exception as e:
                self._send_json_response({"error": str(e)}, status=400)
            return

        if path == "/api/wazuh/sync":
            try:
                client = WazuhClient.from_config()
                report = client.fetch_and_correlate()
                self._send_json_response(report)
            except Exception as e:
                self._send_json_response({"error": str(e)}, status=500)
            return

        if path == "/api/correlate":
            try:
                logs = normalize_log_input(body)
                report = correlate_logs(logs)
                self._send_json_response(report)
            except Exception as e:
                self._send_json_response({"error": str(e)}, status=400)
            return

        self._send_json_response({"error": "Not Found"}, status=404)


def run_server(port: Optional[int] = None) -> None:
    server_port = port or DEFAULT_PORT
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", server_port), WazuhCorrelationHandler) as httpd:
        print(f"[*] Wazuh Correlation Server running at http://localhost:{server_port}")
        print(f"[*] Healthcheck available at http://localhost:{server_port}/healthz")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Server stopped.")


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    run_server(port)
