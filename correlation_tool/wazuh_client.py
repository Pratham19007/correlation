import base64
import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from correlation_tool.log_correlator import correlate_logs

DEFAULT_CONFIG_PATH = Path("wazuh_config.json")


def load_wazuh_config(config_path: Optional[Path] = None) -> Dict[str, Any]:
    cfg = {
        "host": "https://localhost:55000",
        "indexer_host": "https://localhost:9200",
        "username": "admin",
        "password": "",
        "verify_ssl": False,
        "timeout": 10,
    }

    path = config_path or DEFAULT_CONFIG_PATH
    if path.exists():
        try:
            file_cfg = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(file_cfg, dict):
                cfg.update(file_cfg)
        except Exception:
            pass

    # Override with environment variables if present (useful for Vercel / Render / Cloud)
    if os.environ.get("WAZUH_HOST"):
        cfg["host"] = os.environ["WAZUH_HOST"]
    if os.environ.get("WAZUH_INDEXER_HOST"):
        cfg["indexer_host"] = os.environ["WAZUH_INDEXER_HOST"]
    if os.environ.get("WAZUH_USER") or os.environ.get("WAZUH_USERNAME"):
        cfg["username"] = os.environ.get("WAZUH_USER") or os.environ.get("WAZUH_USERNAME")
    if os.environ.get("WAZUH_PASSWORD"):
        cfg["password"] = os.environ["WAZUH_PASSWORD"]
    if os.environ.get("WAZUH_VERIFY_SSL"):
        cfg["verify_ssl"] = os.environ["WAZUH_VERIFY_SSL"].lower() in ("true", "1", "yes")
    if os.environ.get("WAZUH_TIMEOUT"):
        try:
            cfg["timeout"] = int(os.environ["WAZUH_TIMEOUT"])
        except ValueError:
            pass

    return cfg


def save_wazuh_config(config: Dict[str, Any], config_path: Optional[Path] = None) -> None:
    path = config_path or DEFAULT_CONFIG_PATH
    path.write_text(json.dumps(config, indent=2), encoding="utf-8")


class WazuhClient:
    """Client for connecting to Wazuh REST API (port 55000) and Wazuh Indexer / OpenSearch (port 9200)."""

    def __init__(
        self,
        host: str = "https://localhost:55000",
        username: str = "admin",
        password: str = "",
        indexer_host: Optional[str] = None,
        verify_ssl: bool = False,
        timeout: int = 10,
    ):
        self.host = host.rstrip("/")
        self.indexer_host = (indexer_host or self._derive_indexer_host(self.host)).rstrip("/")
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.token: Optional[str] = None

    @classmethod
    def from_config(cls, config_path: Optional[Path] = None) -> "WazuhClient":
        cfg = load_wazuh_config(config_path)
        return cls(
            host=cfg.get("host", "https://localhost:55000"),
            username=cfg.get("username", "admin"),
            password=cfg.get("password", ""),
            indexer_host=cfg.get("indexer_host"),
            verify_ssl=cfg.get("verify_ssl", False),
            timeout=cfg.get("timeout", 10),
        )

    def _derive_indexer_host(self, host: str) -> str:
        parsed = urllib.parse.urlparse(host)
        hostname = parsed.hostname or "localhost"
        scheme = parsed.scheme or "https"
        return f"{scheme}://{hostname}:9200"

    def _get_ssl_context(self) -> ssl.SSLContext:
        if not self.verify_ssl:
            ctx = ssl._create_unverified_context()
            ctx.check_hostname = False
            return ctx
        return ssl.create_default_context()

    def _make_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Any] = None,
    ) -> Tuple[int, Dict[str, Any]]:
        req_headers = headers or {}
        body = None
        if data is not None:
            if isinstance(data, (dict, list)):
                body = json.dumps(data).encode("utf-8")
                if "Content-Type" not in req_headers:
                    req_headers["Content-Type"] = "application/json"
            elif isinstance(data, bytes):
                body = data
            elif isinstance(data, str):
                body = data.encode("utf-8")

        req = urllib.request.Request(url, data=body, headers=req_headers, method=method)
        ctx = self._get_ssl_context()

        try:
            with urllib.request.urlopen(req, context=ctx, timeout=self.timeout) as resp:
                resp_data = resp.read().decode("utf-8")
                try:
                    return resp.status, json.loads(resp_data)
                except json.JSONDecodeError:
                    return resp.status, {"raw": resp_data}
        except urllib.error.HTTPError as err:
            err_body = err.read().decode("utf-8")
            try:
                parsed_err = json.loads(err_body)
            except json.JSONDecodeError:
                parsed_err = {"error": err_body}
            return err.code, parsed_err
        except Exception as err:
            return 0, {"error": str(err)}

    def authenticate(self) -> Tuple[bool, str]:
        """Authenticate against Wazuh API (/security/user/authenticate) and store JWT token."""
        url = f"{self.host}/security/user/authenticate"
        auth_str = f"{self.username}:{self.password}"
        encoded_auth = base64.b64encode(auth_str.encode("utf-8")).decode("utf-8")
        headers = {
            "Authorization": f"Basic {encoded_auth}",
            "Content-Type": "application/json",
        }

        status, resp = self._make_request(url, method="POST", headers=headers)
        if status == 200 and isinstance(resp, dict):
            data = resp.get("data")
            if isinstance(data, dict) and "token" in data:
                self.token = data["token"]
                return True, "Authenticated successfully with Wazuh API"
            elif isinstance(data, str):
                self.token = data
                return True, "Authenticated successfully with Wazuh API"
            elif "token" in resp:
                self.token = resp["token"]
                return True, "Authenticated successfully with Wazuh API"

        error_msg = resp.get("message") or resp.get("error") or f"HTTP {status}"
        return False, f"Failed to authenticate with Wazuh API: {error_msg}"

    def get_manager_info(self) -> Dict[str, Any]:
        """Fetch Wazuh manager status and system information."""
        if not self.token:
            auth_ok, msg = self.authenticate()
            if not auth_ok:
                return {"error": msg}

        url = f"{self.host}/manager/info"
        headers = {"Authorization": f"Bearer {self.token}"}
        status, resp = self._make_request(url, headers=headers)

        if status == 200 and isinstance(resp, dict):
            return resp.get("data") or resp
        return {"error": resp.get("message") or resp.get("error") or f"HTTP {status}"}

    def get_agents(self) -> List[Dict[str, Any]]:
        """List all Wazuh agents and manager node."""
        if not self.token:
            auth_ok, _ = self.authenticate()
            if not auth_ok:
                return []

        url = f"{self.host}/agents?limit=500"
        headers = {"Authorization": f"Bearer {self.token}"}
        status, resp = self._make_request(url, headers=headers)

        if status == 200 and isinstance(resp, dict):
            data = resp.get("data")
            if isinstance(data, dict):
                items = data.get("affected_items") or data.get("items") or []
                return items
            if isinstance(data, list):
                return data
        return []

    def fetch_alerts_from_indexer(self, limit: int = 500, min_level: int = 3) -> List[Dict[str, Any]]:
        """Query Wazuh Indexer / OpenSearch (port 9200) for alerts."""
        url = f"{self.indexer_host}/wazuh-alerts-*/_search"
        auth_str = f"{self.username}:{self.password}"
        encoded_auth = base64.b64encode(auth_str.encode("utf-8")).decode("utf-8")
        headers = {
            "Authorization": f"Basic {encoded_auth}",
            "Content-Type": "application/json",
        }

        query_payload = {
            "size": limit,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"rule.level": {"gte": min_level}}}
                    ]
                }
            },
        }

        status, resp = self._make_request(url, method="POST", headers=headers, data=query_payload)
        if status == 200 and isinstance(resp, dict):
            hits = resp.get("hits", {}).get("hits", [])
            alerts = [hit.get("_source") for hit in hits if isinstance(hit, dict) and "_source" in hit]
            return alerts
        return []

    def fetch_alerts(self, limit: int = 500, min_level: int = 3) -> List[Dict[str, Any]]:
        """Fetch alerts from Wazuh Indexer or Wazuh API."""
        alerts = self.fetch_alerts_from_indexer(limit=limit, min_level=min_level)
        if alerts:
            return alerts

        # Try Wazuh API alerts endpoint if available
        if not self.token:
            auth_ok, _ = self.authenticate()
            if not auth_ok:
                return []

        url = f"{self.host}/alerts?limit={limit}"
        headers = {"Authorization": f"Bearer {self.token}"}
        status, resp = self._make_request(url, headers=headers)
        if status == 200 and isinstance(resp, dict):
            data = resp.get("data")
            if isinstance(data, dict):
                return data.get("affected_items") or data.get("items") or []
            if isinstance(data, list):
                return data
        return []

    def test_connection(self) -> Dict[str, Any]:
        """Verify connection to Wazuh API and Wazuh Indexer with diagnostics."""
        result: Dict[str, Any] = {
            "success": False,
            "api_connected": False,
            "indexer_connected": False,
            "manager_node": None,
            "agent_count": 0,
            "agents": [],
            "message": "",
            "host": self.host,
            "indexer_host": self.indexer_host,
            "username": self.username,
        }

        # 1. Test Wazuh API
        auth_ok, auth_msg = self.authenticate()
        if auth_ok:
            result["api_connected"] = True
            mgr_info = self.get_manager_info()
            if "error" not in mgr_info:
                result["manager_node"] = mgr_info
            agents = self.get_agents()
            result["agents"] = agents
            result["agent_count"] = len(agents)

        # 2. Test Wazuh Indexer
        try:
            indexer_alerts = self.fetch_alerts_from_indexer(limit=1)
            if indexer_alerts is not None:
                result["indexer_connected"] = True
        except Exception:
            pass

        if result["api_connected"] or result["indexer_connected"]:
            result["success"] = True
            msg_parts = []
            if result["api_connected"]:
                msg_parts.append(f"Connected to Wazuh API at {self.host}")
            if result["indexer_connected"]:
                msg_parts.append(f"Connected to Wazuh Indexer at {self.indexer_host}")
            if result["agent_count"] > 0:
                msg_parts.append(f"{result['agent_count']} agent(s) discovered")
            result["message"] = ". ".join(msg_parts)
        else:
            result["message"] = f"Could not connect to Wazuh: {auth_msg}"

        return result

    def fetch_and_correlate(self, limit: int = 500, min_level: int = 3) -> Dict[str, Any]:
        """Fetch live alerts from Wazuh and run correlation to classify Manager vs Agent attacks."""
        alerts = self.fetch_alerts(limit=limit, min_level=min_level)
        if not alerts:
            return {
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
                    "target_distribution": {"manager": 0, "agent": 0, "both": 0, "unknown": 0},
                    "affected_agents": [],
                    "affected_managers": [],
                },
                "meta": {
                    "source": "wazuh_live",
                    "fetched_count": 0,
                    "status": "No alerts found matching query",
                },
            }

        report = correlate_logs(alerts)
        report["meta"] = {
            "source": "wazuh_live",
            "host": self.host,
            "indexer_host": self.indexer_host,
            "fetched_count": len(alerts),
        }
        return report
