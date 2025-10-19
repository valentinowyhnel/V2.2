import unittest
from unittest.mock import mock_open, patch
from xml.etree.ElementTree import Element
from xerror.parsing.nm_xml_parser import get_host_data, parse_xml, parse_to_csv, list_ip_addresses, nmxmlparser

class TestNmXmlParser(unittest.TestCase):

    def test_get_host_data(self):
        # Simuler un élément XML
        root = Element("host")
        data = get_host_data(root)
        self.assertIsInstance(data, list)  # Ajuster pour vérifier une liste

    def test_parse_xml(self):
        # Simuler un fichier XML factice
        mock_xml = "<nmaprun><host></host></nmaprun>"
        with patch("builtins.open", mock_open(read_data=mock_xml)):
            data = parse_xml("test.xml")
            self.assertIsInstance(data, list)

    def test_parse_to_csv(self):
        # Simuler des données et un fichier CSV
        data = [{"key": "value"}]
        with patch("builtins.open", mock_open()) as mocked_file:
            parse_to_csv(data, "test.csv")
            mocked_file.assert_called_once_with("test.csv", "w", newline="", encoding="utf-8")

    def test_list_ip_addresses(self):
        # Simuler des données
        data = [{"ip": "192.168.1.1"}]
        ips = list_ip_addresses(data)
        self.assertIn("192.168.1.1", ips)

    def test_nmxmlparser(self):
        # Simuler un fichier XML avec des hôtes "Up"
        mock_xml = """
        <nmaprun>
            <host>
                <status state='up'/>
                <address addr='192.168.1.1'/>
            </host>
        </nmaprun>
        """
        with patch("builtins.open", mock_open(read_data=mock_xml)):
            nmxmlparser("test_repo", "test.csv")

if __name__ == "__main__":
    unittest.main()