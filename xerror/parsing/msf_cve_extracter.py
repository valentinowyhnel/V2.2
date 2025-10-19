class MsfCsvExtract:
    def __init__(self, file):
        self.file = file

        self.temp_lst = []

        self.msf_detail_dict = {}
        self.exploit_detail_dict = {}
        self.auxiliary_detail_dict = {}
        self.post_detail_dict = {}

        self.parse_msf_modules()

    def parse_msf_modules(self):
        with open(self.file, encoding='utf-8') as fp:
            for line in fp:
                self.temp_lst = line.replace(" ", "").split("CVE")

                exploit_name = ""
                for index, item in enumerate(self.temp_lst):
                    if index == 0:
                        exploit_name = item
                    else:
                        cve_id = f"CVE{item.strip()}"
                        self.msf_detail_dict[cve_id] = exploit_name

    def msf_auxiliary_cve(self):
        """Return auxiliary modules mapped to CVEs."""
        self.auxiliary_detail_dict = {
            k: v for k, v in self.msf_detail_dict.items() if v.startswith("auxiliary")
        }
        return self.auxiliary_detail_dict

    def msf_exploit_cve(self):
        """Return exploit modules mapped to CVEs."""
        self.exploit_detail_dict = {
            k: v for k, v in self.msf_detail_dict.items() if v.startswith("exploit")
        }
        return self.exploit_detail_dict

    def msf_post_cve(self):
        """Return post modules mapped to CVEs."""
        self.post_detail_dict = {
            k: v for k, v in self.msf_detail_dict.items() if v.startswith("post")
        }
        return self.post_detail_dict