#!/usr/bin/env python3
"""
Unit and Integration Test Suite for SquidMan: User IP Pools, Strict ACL Enforcement & Port Mappings
"""

import os
import tempfile
import shutil
import unittest
from starlette.testclient import TestClient

# Set test environment variables before importing server
temp_dir = tempfile.mkdtemp(prefix="squid_test_")
test_conf_file = os.path.join(temp_dir, "squid.conf")
test_users_file = os.path.join(temp_dir, "users.pwd")
test_ips_file = os.path.join(temp_dir, "allowed_ips.txt")
test_outgoing_file = os.path.join(temp_dir, "outgoing_ips.conf")
test_users_meta = os.path.join(temp_dir, "users_meta.json")
test_ips_meta = os.path.join(temp_dir, "ips_meta.json")
test_routing_meta = os.path.join(temp_dir, "routing_meta.json")
test_interfaces_meta = os.path.join(temp_dir, "interfaces_meta.json")
test_ports_meta = os.path.join(temp_dir, "ports_meta.json")
test_env_file = os.path.join(temp_dir, ".env")
test_api_key = "test-secret-key-12345"

with open(test_conf_file, "w") as f:
    f.write("http_port 3128\nvisible_hostname anonymous-proxy-gateway\nhttp_access allow authenticated_users\nhttp_access deny all\n")

os.environ["API_KEY"] = test_api_key
os.environ["SQUID_CONF_PATH"] = test_conf_file
os.environ["SQUID_USERS_PATH"] = test_users_file
os.environ["SQUID_ALLOWED_IPS_PATH"] = test_ips_file
os.environ["SQUID_OUTGOING_IPS_PATH"] = test_outgoing_file
os.environ["ENV_FILE_PATH"] = test_env_file
os.environ["USERS_METADATA_PATH"] = test_users_meta
os.environ["IPS_METADATA_PATH"] = test_ips_meta
os.environ["ROUTING_METADATA_PATH"] = test_routing_meta
os.environ["INTERFACES_METADATA_PATH"] = test_interfaces_meta
os.environ["PORTS_METADATA_PATH"] = test_ports_meta
os.environ["SERVER_PUBLIC_IP"] = "198.51.100.99"
os.environ["PROXY_PORT"] = "3128"

import server
from server import app, ensure_squid_conf_structure, sync_outgoing_ips_conf

class TestSquidManagementPanel(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.headers = {"X-API-Key": test_api_key}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(temp_dir, ignore_errors=True)

    def test_00_get_system_status(self):
        """Test that /api/v1/status returns 200 and valid system/squid metadata."""
        resp = self.client.get("/api/v1/status", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("squid", data)
        self.assertIn("system", data)
        self.assertIn("network", data)
        self.assertIn("is_running", data["squid"])

    def test_01_ensure_squid_conf_structure(self):
        """Test that outgoing_ips.conf is properly placed BEFORE http_access allow authenticated_users."""
        ensure_squid_conf_structure()
        with open(test_conf_file, "r") as f:
            content = f.read()
        
        inc_pos = content.find(test_outgoing_file)
        auth_pos = content.find("http_access allow authenticated_users")
        self.assertNotEqual(inc_pos, -1)
        self.assertNotEqual(auth_pos, -1)
        self.assertLess(inc_pos, auth_pos, "outgoing_ips.conf must be included BEFORE authenticated_users")

    def test_02_preview_and_batch_same_port(self):
        """Test preview and batch addition of IPs with same-port mode."""
        payload = {
            "mode": "cidr",
            "cidr_block": "192.168.80.0/30",
            "start_port": 3150,
            "port_mode": "same"
        }
        resp = self.client.post("/api/v1/network/ips/preview", json=payload, headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["total_ips"], 2)
        self.assertEqual(data["ips"][0]["port"], 3150)
        self.assertEqual(data["ips"][1]["port"], 3150)

        batch_payload = {
            "interface": "eth0",
            "mode": "cidr",
            "cidr_block": "192.168.80.0/30",
            "start_port": 3150,
            "port_mode": "same"
        }
        b_resp = self.client.post("/api/v1/network/ips/batch", json=batch_payload, headers=self.headers)
        self.assertEqual(b_resp.status_code, 200)
        self.assertEqual(b_resp.json()["total_added"], 2)

    def test_03_port_assignment_and_interface_metadata(self):
        """Test updating a secondary IP's port via /api/v1/network/ports."""
        port_payload = {
            "ip": "192.168.80.1",
            "port": 3155
        }
        p_resp = self.client.post("/api/v1/network/ports", json=port_payload, headers=self.headers)
        self.assertEqual(p_resp.status_code, 200)
        
        # Check interfaces list
        if_resp = self.client.get("/api/v1/network/interfaces", headers=self.headers)
        self.assertEqual(if_resp.status_code, 200)
        interfaces = if_resp.json()["interfaces"]
        found_ip = False
        for iface in interfaces:
            for addr in iface["ipv4_addresses"]:
                if addr["ip"] == "192.168.80.1":
                    found_ip = True
                    self.assertEqual(addr["assigned_port"], 3155)
        self.assertTrue(found_ip, "192.168.80.1 should be listed in interfaces with port 3155")

    def test_04_strict_user_pool_acl_enforcement(self):
        """Test that restricted users get STRICT ACLs (allow pool, deny user)."""
        payload = {
            "username": "restricted_user",
            "password": "Password123!",
            "notes": "Restricted to 2 IPs only",
            "ip_access_mode": "custom_list",
            "assigned_ips": ["192.168.80.1", "192.168.80.2"]
        }
        create_resp = self.client.post("/api/v1/users", json=payload, headers=self.headers)
        self.assertEqual(create_resp.status_code, 200)

        with open(test_outgoing_file, "r") as f:
            content = f.read()

        # Verify strict ACL structure
        self.assertIn("acl user_auth_restricted_user proxy_auth restricted_user", content)
        self.assertIn("acl user_pool_ips_restricted_user myip 192.168.80.1 192.168.80.2", content)
        self.assertIn("http_access allow user_auth_restricted_user user_pool_ips_restricted_user", content)
        self.assertIn("http_access deny user_auth_restricted_user", content)

        # Clean up
        self.client.delete("/api/v1/users/restricted_user", headers=self.headers)

    def test_05_proxy_start_and_restart_endpoints(self):
        """Test /api/v1/proxy/start and /api/v1/proxy/restart endpoints."""
        start_resp = self.client.post("/api/v1/proxy/start", headers=self.headers)
        self.assertEqual(start_resp.status_code, 200)

        restart_resp = self.client.post("/api/v1/proxy/restart", headers=self.headers)
        self.assertEqual(restart_resp.status_code, 200)

if __name__ == "__main__":
    unittest.main()
