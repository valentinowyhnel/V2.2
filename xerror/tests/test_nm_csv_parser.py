import unittest
from unittest.mock import mock_open, patch
from xerror.parsing.nm_csv_parser import nmcsvpar, build_html_row

class TestNmCsvParser(unittest.TestCase):

    def test_nmcsvpar(self):
        # Simuler un fichier CSV factice
        mock_csv = "IP,Proto,Port,Service,Service_version,Product\n192.168.1.1,TCP,80,HTTP,1.1,Apache\n"
        with patch("builtins.open", mock_open(read_data=mock_csv)):
            result, host, osname, ip_addr = nmcsvpar("test.csv")
            self.assertIsNotNone(result)
            self.assertEqual(ip_addr, "192.168.1.1")

    def test_build_html_row(self):
        # Fournir un dictionnaire valide
        resul = {
            "proto": ["TCP"],
            "port": ["80"],
            "serv": ["HTTP"],
            "serv_ver": ["1.1"],
            "prod": ["Apache"]
        }
        html_row = build_html_row(resul)
        self.assertIn("<tr>", html_row)
        self.assertIn("</tr>", html_row)
        self.assertIn("<td>TCP</td>", html_row)

if __name__ == "__main__":
    unittest.main()