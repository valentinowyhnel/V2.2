import xmlrpc.client

class CustomMsfRpcClient:
    def __init__(self, username, password, host="127.0.0.1", port=55553):
        self.url = f"http://{username}:{password}@{host}:{port}/api/"
        self.client = xmlrpc.client.ServerProxy(self.url)

    def call(self, method, *args):
        try:
            return getattr(self.client, method)(*args)
        except Exception as e:
            print(f"[Error] RPC call failed: {e}")
            return None

    def list_sessions(self):
        return self.call("session.list")

    def execute_module(self, module_type, module_name, options):
        return self.call(f"module.execute", module_type, module_name, options)

# Exemple d'utilisation :
# client = CustomMsfRpcClient("msf", "password")
# print(client.list_sessions())