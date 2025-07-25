import json
import random
import os
from pypinyin import lazy_pinyin

# "PingConfig": {
# 		"Epoch": 10,
# 		"Count": 3,
# 		"Connections": 1
# 	},
# 	"Use_ipv6": false,
# 	"Mode": {
# 		"Endpoint": "",
# 		"LastSuccTime": "",
# 		"Status": "true",
# 		"Type": "local"
# 	},
# 	"Base": {
# 		"Archive": 10,
# 		"Refresh": 1,
# 		"Timeout": 5
# 	},
# 	"Topology": {
#         "Tline": "1",
#         "Tsound": "",
#         "Tsymbolsize": "70"
#     },

class config:
    def __init__(self):
        self.addr = ""
        self.name = ""
        self.destination = []
        self.controlleraddr = ""
        self.port = 8889
        self.dscp = [0, 16]
        self.PingConfig = {
            "Epoch": 3,
            "Count": 1,
            "Connections": 1
        }
        self.Policies = []
        self.Use_ipv6 = False
        self.Mode = {
            "Endpoint": "",
            "LastSuccTime": "",
            "Status": "true",
            "Type": "local"
        }
        self.Base = {
            "Archive": 10,
            "Refresh": 1,
            "Timeout": 5
        }
        self.Topology = {
            "Tline": "1",
            "Tsound": "",
            "Tsymbolsize": "70"
        }
        self.Network = {}

    def to_json(self):
        return {
            "Addr": self.addr,
            "Name": self.name,
            "Destinations": self.destination,
            "ControllerAddr": self.controlleraddr,
            "Port": self.port,
            "Dscp": self.dscp,
            "PingConfig": self.PingConfig,
            "Policies": self.Policies,
            "UseIpv6": self.Use_ipv6,
            "Mode": self.Mode,
            "Base": self.Base,
            "Topology": self.Topology,
            "Network": self.Network
        }
    

if __name__ == "__main__":
    with open('conf/topo.json', 'r') as f:
        topo = json.load(f)
        topo = topo[0]

    json_dir = "../agent/conf/containers"
    for file_name in os.listdir(json_dir):
        if file_name.endswith(".json") and file_name[0].isdigit():
            os.remove(os.path.join(json_dir, file_name))

    controlleraddr = "10.1." + str(topo["point_num"] + 1) + ".2"
    for i in range(topo["point_num"]):
        hostname = topo["points"][str(i)]["name"]

        addr = {}
        name = {}
        zonemesh = {}
        ping = {}
        topology = {}
        
        selfconfig = config()

        fullmesh = []

        # 遍历每个节点
        for pi in range(topo["point_num"]):
            name[pi] = topo["points"][str(pi)]["name"]
            # 获取节点信息
            if pi == i:
                selfconfig.name = name[pi]
            addr[pi] = "10.1." + str(pi + 1) + ".2"
            # TODO: Ping + destination
            zonemesh[pi] = True
            ping[pi] = []
            topology[pi] = []
            fullmesh.append(addr[pi])
        
        # for pi in range(topo["point_num"]):
        #     ping[pi] = random.sample(fullmesh, min(12, len(fullmesh)))
        #     if pi == i:
        #         selfconfig.destination = ping[pi].copy()
        
        for link in topo["links"]:
            for p in link["points"]:
                for p2 in link["points"]:
                    if p < p2:
                        topology[p].append({
                            "Addr": addr[p2],
                            "Name": name[p2],
                            "Thdavgdelay": "200",
                            "Thdchecksec": "900",
                            "Thdloss": "30",
                            "Thdoccnum": "3"
                        })
                        # topology[p2].append({
                        #     "Addr": addr[p],
                        #     "Name": name[p],
                        #     "Thdavgdelay": "200",
                        #     "Thdchecksec": "900",
                        #     "Thdloss": "30",
                        #     "Thdoccnum": "3"
                        # })

        network = {}
        # 将节点信息添加到字典中
        for pi in range(topo["point_num"]):
            address = addr[pi]
            network[address] = {
                "Name": name[pi],
                "Addr": addr[pi],
                "Zonemesh": zonemesh[pi],
                "Ping": ping[pi],
                "Topology": topology[pi]
            }

        selfconfig.Network = network
        selfconfig.addr = addr[i]
        selfconfig.controlleraddr = controlleraddr
        # name = "".join(lazy_pinyin(hostname)).capitalize()

        out = open(json_dir+f"/point-{str(i+1)}.json", "w")
        json.dump(selfconfig, out, default=lambda o: o.to_json(), indent=4, ensure_ascii=False)