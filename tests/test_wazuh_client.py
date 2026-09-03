import json
import unittest
from unittest.mock import MagicMock, patch

from correlation_tool.wazuh_client import WazuhClient, load_wazuh_config, save_wazuh_config


class WazuhClientTests(unittest.TestCase):
    def setUp(self):
        self.client = WazuhClient(
            host="https://localhost:55000",
            username="admin",
            password="l6ArtMq7XC*XGtK08mwGBCPsWXh?Lgxv",
            verify_ssl=False,
        )

    def test_client_init_and_config_loading(self):
        cfg = load_wazuh_config()
        self.assertEqual(cfg.get("username"), "admin")
        self.assertTrue(bool(cfg.get("password")))

        client = WazuhClient.from_config()
        self.assertEqual(client.username, "admin")
        self.assertEqual(client.host, cfg.get("host", "https://localhost:55000"))

    @patch("correlation_tool.wazuh_client.urllib.request.urlopen")
    def test_authenticate_success(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = json.dumps({
            "data": {"token": "mock-jwt-token-xyz123"}
        }).encode("utf-8")
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        ok, msg = self.client.authenticate()
        self.assertTrue(ok)
        self.assertEqual(self.client.token, "mock-jwt-token-xyz123")
        self.assertIn("Authenticated successfully", msg)

    @patch("correlation_tool.wazuh_client.urllib.request.urlopen")
    def test_get_agents_parsing(self, mock_urlopen):
        self.client.token = "valid-token"

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = json.dumps({
            "data": {
                "affected_items": [
                    {"id": "000", "name": "wazuh-manager", "status": "active", "ip": "192.168.1.2"},
                    {"id": "001", "name": "web-srv-01", "status": "active", "ip": "192.168.1.50"}
                ]
            }
        }).encode("utf-8")
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        agents = self.client.get_agents()
        self.assertEqual(len(agents), 2)
        self.assertEqual(agents[0]["id"], "000")
        self.assertEqual(agents[1]["name"], "web-srv-01")

    @patch.object(WazuhClient, "fetch_alerts")
    def test_fetch_and_correlate_live_alerts(self, mock_fetch):
        mock_fetch.return_value = [
            {
                "timestamp": "2026-08-24T08:15:10Z",
                "agent": {"id": "000", "name": "wazuh-manager"},
                "rule": {"id": "5710", "description": "Failed password for admin"},
                "data": {"srcip": "198.51.100.50", "srcuser": "admin"}
            },
            {
                "timestamp": "2026-08-24T08:15:20Z",
                "agent": {"id": "000", "name": "wazuh-manager"},
                "rule": {"id": "5710", "description": "Failed password for root"},
                "data": {"srcip": "198.51.100.50", "srcuser": "root"}
            }
        ]

        report = self.client.fetch_and_correlate()
        self.assertTrue(report["is_attack_attempt"])
        self.assertEqual(report["summary"]["manager_attacks"], 1)
        self.assertEqual(report["alerts"][0]["target_type"], "manager")
        self.assertEqual(report["meta"]["source"], "wazuh_live")


if __name__ == "__main__":
    unittest.main()
