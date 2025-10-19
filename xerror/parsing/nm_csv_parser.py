import csv


def nmcsvpar(fname):
    file = fname
    ip_addr = ""
    host = ""
    osname = ""
    proto = []
    port = []
    serv = []
    serv_ver = []
    prod = []
    ser_fp = []
    resul = {}

    with open(file, encoding='utf-8') as fh:
        rd = csv.DictReader(fh, delimiter=',')
        first = True
        for row in rd:
            if first:
                # capture header-derived initial values
                keys = list(row.keys())
                osname = row.get("os", "")
                ip_addr = row.get("IP", "")
                host = row.get("Host", "")
                first = False

            if row.get('IP') == ip_addr:
                proto.append(row.get('Proto', ''))
                port.append(row.get('Port', ''))
                serv.append(row.get('Service', ''))
                serv_ver.append(row.get('Service_version', ''))
                prod.append(row.get('Product', ''))
                ser_fp.append(row.get('Service FP', ''))

    resul["host"] = host
    resul["os"] = osname
    resul["proto"] = proto
    resul["port"] = port
    resul["serv"] = serv
    resul["serv_ver"] = serv_ver
    resul["prod"] = prod
    resul["ser_fp"] = ser_fp

    row_html = build_html_row(resul)
    return row_html, host, osname, ip_addr


# Build HTML row
def build_html_row(resul):
    a = len(resul["proto"])
    row_html = ""
    for i in range(a):
        row_html += "<tr>"
        pro = f"<td>{resul['proto'][i]}</td>"
        po = f"<td>{resul['port'][i]}</td>"
        se = f"<td>{resul['serv'][i]}</td>"
        se_v = f"<td>{resul['serv_ver'][i]}</td>"
        prd = f"<td>{resul['prod'][i]}</td>"
        row_html += po + pro + se + se_v + prd + "</tr>"
    return row_html

