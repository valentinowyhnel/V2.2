import csv


class openvas_csv_parse_detail:
    def __init__(self, file):
        self.file = file

        self.CVE_dict = {}
        self.resul = {}
        self.openvas_csv_par()

    def openvas_csv_par(self):
        """
        Parse OpenVAS CSV report into structured dicts.

        result structure:
            self.resul = {
                'ip': ip_addr,
                'host': host,
                'ports': { port: {port detail dict} }
            }
            self.CVE_dict = { port: cve }
        """

        with open(self.file, encoding='utf-8') as fh:
            rd = csv.DictReader(fh, delimiter=',')
            is_first_row = True
            temp_port_dict = {}
            for row in rd:
                if is_first_row:
                    ip_addr = row.get("IP", "")
                    host = row.get("Hostname", "")
                    self.resul['ip'] = ip_addr
                    self.resul['host'] = host
                    self.CVE_dict['ip_addr'] = ip_addr
                    is_first_row = False

                temp_port_detail_dict = {}

                if row.get('IP') == ip_addr:
                    port = row.get('Port', '')
                    cvss = row.get('CVSS', '')
                    proto = row.get('Port Protocol', '')
                    severity = row.get('Severity', '')
                    nvt_name = row.get('NVT Name', '')
                    summary = row.get('Summary', '')
                    cve = row.get('CVEs', '')
                    impact = row.get('Impact', '')

                    if port:
                        if severity != 'Log':
                            temp_port_detail_dict = {
                                'port': port,
                                'proto': proto,
                                'cvss': cvss,
                                'severity': severity,
                                'cve': cve,
                                'nvt_name': nvt_name,
                                'impact': impact,
                                'summary': summary
                            }

                            temp_port_dict[port] = temp_port_detail_dict
                            if cve and cve != 'NOCVE':
                                self.CVE_dict[port] = cve

        self.resul["ports"] = temp_port_dict

    def openvas_cve_dict(self):
        """Return a mapping port -> CVE string (if any)."""
        return self.CVE_dict

    def openvas_result_dict(self):
        """Return full parsed result dict."""
        return self.resul

    def opv_resul_table(self):
        """Return an HTML table fragment and the target IP."""
        rows = []
        for port, details in self.resul.get("ports", {}).items():
            row = f"<tr>"
            row += f"<td>{details.get('port', '')}</td>"
            row += f"<td>{details.get('proto', '')}</td>"
            row += f"<td>{details.get('cvss', '')}</td>"
            row += f"<td>{details.get('cve', '')}</td>"
            row += f"<td>{details.get('severity', '')}</td>"
            row += f"<td>{details.get('nvt_name', '')}</td>"
            row += f"<td>{details.get('impact', '')}</td>"
            row += f"<td>{details.get('summary', '')}</td>"
            row += "</tr>"
            rows.append(row)
        return "".join(rows), self.resul.get('ip', '')

