import unittest

from correlation_tool.log_correlator import correlate_logs, normalize_log_input


class LogCorrelationTests(unittest.TestCase):
    def test_detects_attack_attempt_from_correlated_login_and_web_signals(self):
        logs = [
            {
                "timestamp": "2026-07-31T10:00:00Z",
                "source": "auth",
                "ip": "203.0.113.5",
                "event": "login_failed",
                "user": "admin",
                "message": "Failed login for admin",
            },
            {
                "timestamp": "2026-07-31T10:00:30Z",
                "source": "auth",
                "ip": "203.0.113.5",
                "event": "login_failed",
                "user": "admin",
                "message": "Failed login for admin",
            },
            {
                "timestamp": "2026-07-31T10:01:00Z",
                "source": "web",
                "ip": "203.0.113.5",
                "event": "http_request",
                "status": 200,
                "path": "/search?q=admin' OR '1'='1",
                "message": "SQL injection probe",
            },
            {
                "timestamp": "2026-07-31T10:01:20Z",
                "source": "waf",
                "ip": "203.0.113.5",
                "event": "blocked_request",
                "status": 403,
                "path": "/admin",
                "message": "blocked suspicious request",
            },
        ]

        report = correlate_logs(logs)

        self.assertTrue(report["is_attack_attempt"])
        self.assertGreaterEqual(len(report["alerts"]), 1)
        self.assertTrue(
            any(
                "sql" in alert["reason"].lower() or "failed login" in alert["reason"].lower()
                for alert in report["alerts"]
            )
        )
        self.assertEqual(report["summary"]["target_ips"], ["203.0.113.5"])

    def test_ignores_normal_activity(self):
        logs = [
            {
                "timestamp": "2026-07-31T11:00:00Z",
                "source": "auth",
                "ip": "198.51.100.22",
                "event": "login_success",
                "user": "alice",
                "message": "Successful login",
            },
            {
                "timestamp": "2026-07-31T11:02:00Z",
                "source": "web",
                "ip": "198.51.100.22",
                "event": "http_request",
                "status": 200,
                "path": "/dashboard",
                "message": "Viewed dashboard",
            },
        ]

        report = correlate_logs(logs)

        self.assertFalse(report["is_attack_attempt"])
        self.assertEqual(report["alerts"], [])
        self.assertEqual(report["summary"]["target_ips"], [])

    def test_normalizes_raw_json_log_input(self):
        payload = """[
            {
                "timestamp": "2026-07-31T10:00:00Z",
                "source": "auth",
                "ip": "203.0.113.5",
                "event": "login_failed",
                "user": "admin",
                "message": "Failed login for admin"
            },
            {
                "timestamp": "2026-07-31T10:01:00Z",
                "source": "web",
                "ip": "203.0.113.5",
                "event": "http_request",
                "path": "/search?q=admin' OR '1'='1",
                "message": "SQL injection probe"
            }
        ]"""

        logs = normalize_log_input(payload)

        self.assertIsInstance(logs, list)
        self.assertEqual(len(logs), 2)
        self.assertEqual(logs[0]["ip"], "203.0.113.5")

    def test_detects_scanner_user_agent_and_sensitive_endpoint_access(self):
        logs = [
            {
                "timestamp": "2026-07-31T12:00:00Z",
                "source": "web",
                "ip": "203.0.113.10",
                "event": "http_request",
                "status": 200,
                "path": "/wp-login.php",
                "user_agent": "Mozilla/5.0 (compatible; sqlmap/1.6)",
                "message": "Scanner probe",
            },
        ]

        report = correlate_logs(logs)

        self.assertTrue(report["is_attack_attempt"])
        self.assertEqual(report["summary"]["target_ips"], ["203.0.113.10"])
        self.assertEqual(report["alerts"][0]["evidence"]["sensitive_endpoint_count"], 1)
        self.assertEqual(report["alerts"][0]["evidence"]["scanner_signature_count"], 1)

    def test_detects_multiple_usernames_in_failed_logins(self):
        logs = [
            {
                "timestamp": "2026-07-31T12:01:00Z",
                "source": "auth",
                "ip": "203.0.113.11",
                "event": "login_failed",
                "user": "admin",
                "message": "Failed login for admin",
            },
            {
                "timestamp": "2026-07-31T12:01:30Z",
                "source": "auth",
                "ip": "203.0.113.11",
                "event": "login_failed",
                "user": "root",
                "message": "Failed login for root",
            },
        ]

        report = correlate_logs(logs)

        self.assertTrue(report["is_attack_attempt"])
        self.assertEqual(report["alerts"][0]["evidence"]["unique_failed_usernames"], ["admin", "root"])
        self.assertIn("Multiple usernames were targeted", report["alerts"][0]["reason"])

    def test_normalizes_csv_log_input(self):
        payload = """Event Time,Process Name,Remote IP,Local IP,Command Line
2025-01-26 21:09:46,svchost.exe,65.0.195.250,192.168.226.60,C:\\Windows\\System32\\svchost.exe
2025-01-26 21:09:46,login_failed,203.0.113.5,10.0.0.5,Failed login for admin
"""

        logs = normalize_log_input(payload)

        self.assertIsInstance(logs, list)
        self.assertEqual(len(logs), 2)
        self.assertEqual(logs[1]["ip"], "203.0.113.5")

    def test_wazuh_attack_on_manager_detected(self):
        logs = [
            {
                "timestamp": "2026-08-24T08:15:10.123+0000",
                "rule": {
                    "id": "5710",
                    "level": 5,
                    "description": "sshd: Attempt to login using a non-existent user",
                    "groups": ["syslog", "sshd", "authentication_failed"],
                },
                "agent": {
                    "id": "000",
                    "name": "wazuh-manager",
                    "ip": "192.168.1.10",
                },
                "manager": {
                    "name": "wazuh-manager",
                },
                "data": {
                    "srcip": "198.51.100.50",
                    "srcuser": "root",
                },
                "location": "/var/log/auth.log",
                "full_log": "Aug 24 08:15:10 wazuh-manager sshd[4120]: Failed password for root from 198.51.100.50 port 43212 ssh2",
            },
            {
                "timestamp": "2026-08-24T08:15:25.456+0000",
                "rule": {
                    "id": "5710",
                    "level": 5,
                    "description": "sshd: Attempt to login using a non-existent user",
                    "groups": ["syslog", "sshd", "authentication_failed"],
                },
                "agent": {
                    "id": "000",
                    "name": "wazuh-manager",
                    "ip": "192.168.1.10",
                },
                "manager": {
                    "name": "wazuh-manager",
                },
                "data": {
                    "srcip": "198.51.100.50",
                    "srcuser": "admin",
                },
                "location": "/var/log/auth.log",
                "full_log": "Aug 24 08:15:25 wazuh-manager sshd[4125]: Failed password for invalid user admin from 198.51.100.50 port 43218 ssh2",
            },
        ]

        report = correlate_logs(logs)

        self.assertTrue(report["is_attack_attempt"])
        self.assertEqual(len(report["alerts"]), 1)
        alert = report["alerts"][0]
        self.assertEqual(alert["ip"], "198.51.100.50")
        self.assertEqual(alert["target_type"], "manager")
        self.assertTrue(alert["evidence"]["is_manager_attack"])
        self.assertFalse(alert["evidence"]["is_agent_attack"])
        self.assertIn("Target: Wazuh Manager", alert["reason"])
        self.assertEqual(report["summary"]["manager_attacks"], 1)
        self.assertEqual(report["summary"]["agent_attacks"], 0)

    def test_wazuh_attack_on_agent_detected(self):
        logs = [
            {
                "timestamp": "2026-08-24T08:20:00.100+0000",
                "rule": {
                    "id": "31101",
                    "level": 7,
                    "description": "SQL injection attempt detected in HTTP request",
                    "groups": ["web", "accesslog", "sql_injection", "attack"],
                },
                "agent": {
                    "id": "001",
                    "name": "web-server-01",
                    "ip": "192.168.1.101",
                },
                "manager": {
                    "name": "wazuh-manager",
                },
                "data": {
                    "srcip": "203.0.113.88",
                    "url": "/search?q=admin' OR '1'='1",
                    "http_user_agent": "sqlmap/1.7#stable",
                    "status": "200",
                },
                "location": "(web-server-01) 192.168.1.101->/var/log/nginx/access.log",
                "full_log": "203.0.113.88 - - [24/Aug/2026:08:20:00 +0000] \"GET /search?q=admin' OR '1'='1 HTTP/1.1\" 200 4520 \"-\" \"sqlmap/1.7#stable\"",
            },
        ]

        report = correlate_logs(logs)

        self.assertTrue(report["is_attack_attempt"])
        self.assertEqual(len(report["alerts"]), 1)
        alert = report["alerts"][0]
        self.assertEqual(alert["ip"], "203.0.113.88")
        self.assertEqual(alert["target_type"], "agent")
        self.assertFalse(alert["evidence"]["is_manager_attack"])
        self.assertTrue(alert["evidence"]["is_agent_attack"])
        self.assertIn("web-server-01", alert["evidence"]["targeted_agents"])
        self.assertIn("Target: Wazuh Agent", alert["reason"])
        self.assertEqual(report["summary"]["manager_attacks"], 0)
        self.assertEqual(report["summary"]["agent_attacks"], 1)
        self.assertIn("web-server-01", report["summary"]["affected_agents"])

    def test_wazuh_attack_on_both_manager_and_agent(self):
        logs = [
            {
                "timestamp": "2026-08-24T08:15:10Z",
                "agent": {"id": "000", "name": "wazuh-manager"},
                "ip": "198.51.100.99",
                "event": "login_failed",
                "user": "root",
                "message": "Failed login for root",
            },
            {
                "timestamp": "2026-08-24T08:15:20Z",
                "agent": {"id": "000", "name": "wazuh-manager"},
                "ip": "198.51.100.99",
                "event": "login_failed",
                "user": "admin",
                "message": "Failed login for admin",
            },
            {
                "timestamp": "2026-08-24T08:16:00Z",
                "agent": {"id": "002", "name": "db-server-02"},
                "ip": "198.51.100.99",
                "event": "http_request",
                "path": "/admin/config.php",
                "message": "Sensitive endpoint access",
            },
        ]

        report = correlate_logs(logs)

        self.assertTrue(report["is_attack_attempt"])
        alert = report["alerts"][0]
        self.assertEqual(alert["target_type"], "both")
        self.assertTrue(alert["evidence"]["is_manager_attack"])
        self.assertTrue(alert["evidence"]["is_agent_attack"])
        self.assertIn("db-server-02", alert["evidence"]["targeted_agents"])
        self.assertEqual(report["summary"]["manager_attacks"], 1)
        self.assertEqual(report["summary"]["agent_attacks"], 1)
        self.assertEqual(report["summary"]["target_distribution"]["both"], 1)

    def test_wazuh_location_agent_extraction(self):
        logs = [
            {
                "timestamp": "2026-08-24T08:25:00Z",
                "location": "(custom-agent-node) 10.0.0.22->/var/log/auth.log",
                "data": {"srcip": "203.0.113.77", "srcuser": "user1"},
                "rule": {"id": "5710", "description": "Failed password"},
            },
            {
                "timestamp": "2026-08-24T08:25:10Z",
                "location": "(custom-agent-node) 10.0.0.22->/var/log/auth.log",
                "data": {"srcip": "203.0.113.77", "srcuser": "user2"},
                "rule": {"id": "5710", "description": "Failed password"},
            },
        ]

        report = correlate_logs(logs)

        self.assertTrue(report["is_attack_attempt"])
        alert = report["alerts"][0]
        self.assertEqual(alert["target_type"], "agent")
        self.assertIn("custom-agent-node", alert["evidence"]["targeted_agents"])


if __name__ == "__main__":
    unittest.main()
