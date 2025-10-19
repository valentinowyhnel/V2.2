import django
django.setup()

import unittest
from unittest.mock import patch
from xerror.parsing.msf_rpc_handler import MSF_rpc_Hhandler

class TestMsfRpcHandler(unittest.TestCase):

    @patch("pymetasploit3.msfrpc.MsfRpcClient")
    def test_try_exploit(self, mock_rpc_client):
        # Simuler un client RPC Metasploit
        mock_client = mock_rpc_client.return_value
        mock_client.modules.use.return_value.execute.return_value = {"job_id": 1}

        msf_handler = MSF_rpc_Hhandler()
        result = msf_handler.try_exploit(config_id=1, req_job_id=1)
        self.assertEqual(result, {"job_id": 1})

    def test_exploit_sesion_list_parser(self):
        msf_handler = MSF_rpc_Hhandler()
        # Simuler une liste de sessions
        session_list = {"1": {"exploit_uuid": "test_uuid", "target_host": "192.168.1.1", "info": "Session 1 info"}, "2": {"exploit_uuid": "test_uuid", "target_host": "192.168.1.2", "info": "Session 2 info"}}
        result = msf_handler.exploit_sesion_list_parser(uuid="test_uuid", sessoin_list=session_list)
        self.assertIn("1", result)
        self.assertIn("2", result)

if __name__ == "__main__":
    unittest.main()