import os
import yaml

yml_file = "docker-compose.yml"

with open(yml_file, "r") as f:
    compose = yaml.safe_load(f)

if __name__ == "__main__":
    sh_dir = "sh"
    for file_name in os.listdir(sh_dir):
        if file_name.endswith(".sh") and (file_name[0].isdigit() or file_name == "Controller.sh" or file_name[0:6] == "point-"):
            os.remove(os.path.join(sh_dir, file_name))
    for index, (service_name, service) in enumerate(compose["services"].items()):
        name = service["container_name"]
        networks = service["networks"]
        if name == "controller":
            continue
        else:
            filename = service_name+".sh"
        with open("sh/"+filename, "w") as sh:
            sh.write("service frr start\n")
            sh.write("vtysh -c 'conf t' -c 'ipv6 forwarding'\n")
            sh.write("vtysh -c 'conf t' -c 'router ospf' -c 'redistribute bgp' -c 'redistribute connected' -c 'redistribute local'\n")
            for network in networks:
                sh.write("vtysh -c 'conf t' -c 'router ospf' -c 'network "+compose["networks"][network]["ipam"]["config"][0]["subnet"]+" area 0'\n")
            
            # output=$(vtysh -c 'show ip ospf neighbor')
            # neighbors=$(echo "$output" | awk 'NR>2')
            # full_count=$(echo "$neighbors" | awk '$4 == "Full"' | wc -l)
            # while [ "$full_count" != {} ]; do
            #     sleep 10
            # done
            sh.write("\noutput=$(vtysh -c 'show ip ospf neighbor')\n")
            sh.write("neighbors=$(echo \"$output\" | awk 'NR>2')\n")
            sh.write("full_count=$(echo \"$neighbors\" | grep 'Full' | wc -l)\n")
            sh.write(f"while [ \"$full_count\" -ne {len(networks)-2} ]; do\n")
            sh.write("    sleep 2\n")
            sh.write("    output=$(vtysh -c 'show ip ospf neighbor')\n")
            sh.write("    neighbors=$(echo \"$output\" | awk 'NR>2')\n")
            # sh.write("    echo \"$neighbors\"\n")
            sh.write("    full_count=$(echo \"$neighbors\" | grep 'Full' | wc -l)\n")
            # sh.write(f"    echo \"Full neighbors: $full_count    Target: {len(networks)-1}\"\n")
            sh.write("done\n\n")

            # sh.write("\noutput=$(vtysh -c 'show ip ospf neighbor')\n")
            # sh.write("neighbor_lines=$(echo \"$output\" | tail -n +2)\n")
            # sh.write("while [ -z \"$neighbor_lines\" ] || echo \"$output\" | grep -qE 'Init|2-Way'; do\n")
            # sh.write("    sleep 5\n")
            # sh.write("    output=$(vtysh -c 'show ip ospf neighbor')\n")
            # sh.write("done\n\n")
            if service_name != "controller":
                # sh.write("vtysh\n")
                # sh.write("show ip route\n")
                # sh.write("vtysh -c 'show ip route'\n")
                # sh.write("ip route\n")
                sh.write("cd /app/agent/http\n")
                i = int(service_name[6:])
                sh.write(f"mv http_service point-{i:03d}\n")
                sh.write(f"./point-{i:03d}\n")