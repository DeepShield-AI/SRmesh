import json
from pypinyin import lazy_pinyin

Print_controller = True
Host = False

if __name__ == "__main__":
    config = open('conf/topo.json', 'r')
    topo = json.load(config)
    topo = topo[0]
    config.close()
    out = open('docker-compose.yml', 'w')

    out.write("version: '3.8'\n\n")

    out.write("services:\n")
    if Print_controller:
        out.write("  controller:\n")
        out.write("    image: frr-go-controller\n")
        out.write("    container_name: controller\n")
        # out.write("    environment:\n")
        out.write("    ports:\n")
        out.write("      - \"50051:50051\"\n")
        out.write("    privileged: true\n")
        out.write("    volumes:\n")
        out.write("      - ./sh:/app/sh\n")
        # healthcheck:
        #   test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
        #   interval: 5s
        #   timeout: 3s
        #   retries: 5
        out.write("    healthcheck:\n")
        out.write("      test: [\"CMD-SHELL\", \"ss -tnlp | grep 50051\"]\n")
        out.write("      interval: 5s\n")
        out.write("      timeout: 600s\n")
        out.write("      retries: 120\n")
        if Host:
            out.write("    network_mode: host\n")
        else:
            out.write("    networks:\n")
            out.write("      selfcontrolbr:\n")
            out.write("        ipv4_address: "+f"10.0.{topo['point_num']+1}.2\n")
            out.write("        ipv6_address: "+f"fc00:0000:{topo['point_num']+1:x}::2\n")
            for pi in range(topo["point_num"]):
                out.write("      controlbr-"+f"{pi}:\n")
        out.write("    command: [\"bash\", \"controller/start.sh\"]\n\n")

    for pi in range(topo["point_num"]):
        out.write("  point-"+f"{pi+1}:\n")
        out.write("    image: frr-go\n")
        name = ''.join(lazy_pinyin(topo["points"][str(pi)]["name"])).capitalize()
        out.write("    container_name: "+f"{name}\n")
        out.write("    environment:\n")
        if (pi+1 < 10):
            out.write("      - PROC_NAME=point-"+f"00{pi+1}\n")
        elif (pi+1 < 100):
            out.write("      - PROC_NAME=point-"+f"0{pi+1}\n")
        elif (pi+1 < 1000):
            out.write("      - PROC_NAME=point-"+f"{pi+1}\n")
        else:
            print("Error: don't support point number > 1000")
            
        out.write("    ports:\n")
        if pi < 10:
            out.write(f"      - \"880{pi}:8889\"\n")
        elif pi < 100:
            out.write(f"      - \"88{pi}:8889\"\n")
        else:
            print("Error: don't support point number > 100")
        out.write("    privileged: true\n")
        out.write("    volumes:\n")
        out.write("      - /lib/modules:/lib/modules:ro\n")
        # out.write("      - /sys/fs/bpf:/sys/fs/bpf\n")
        out.write("      - /usr/src:/usr/src:ro\n")
        out.write("      - /sys/kernel/debug:/sys/kernel/debug\n")
        out.write("      - ./sh:/app/sh\n")
        if Print_controller:
            out.write("    depends_on:\n")
            out.write("      controller:\n")
            out.write("        condition: service_healthy\n")

        if Host:
            out.write("    network_mode: host\n")
        else:
            out.write("    networks:\n")
            out.write("      selfbr-"+f"{pi}:\n")
            out.write("        ipv4_address: "+f"10.1.{pi+1}.2\n")
            out.write("        ipv6_address: "+f"fc00:0001:{pi+1:x}::2\n")
            if Print_controller:
                out.write("      controlbr-"+f"{pi}:\n")
        
            for li in range(topo["link_num"]):
                if pi in topo["links"][li]["points"]:
                    out.write("      br-"+f"{li}:\n")
        
        # out.write(f"    command: [\"./http/http_service\", \"{name}\"]\n")
        out.write(f"    command: [\"bash\", \"/app/agent/start.sh\", \"point-{pi+1}\"]\n")
        out.write("\n")

    if Host == False:
        out.write("networks:\n\n")
        for pi in range(topo["point_num"]):
            out.write("  selfbr-"+f"{pi}:\n")
            out.write("    driver: bridge\n")
            out.write("    enable_ipv6: true\n")
            out.write("    ipam:\n")
            out.write("      config:\n")
            out.write("      - subnet: "+f"10.1.{pi+1}.0/24\n")
            out.write("      - subnet: "+f"fc00:0001:{pi+1:x}::/64\n\n")
        if Print_controller:
            out.write("  selfcontrolbr:\n")
            out.write("    driver: bridge\n")
            out.write("    enable_ipv6: true\n")
            out.write("    ipam:\n")
            out.write("      config:\n")
            out.write("      - subnet: "+f"10.0.{topo['point_num']+1}.0/24\n")
            out.write("      - subnet: "+f"fc00:0000:{topo['point_num']+1:x}::/64\n\n")

        for li in range(topo["link_num"]):
            out.write("  br-"+f"{li}:\n")
            out.write("    driver: bridge\n")
            out.write("    enable_ipv6: true\n")
            out.write("    ipam:\n")
            out.write("      config:\n")
            ip = topo["links"][li]["IP"]
            out.write("      - subnet: "+f"{ip}\n")
            ipv6 = topo["links"][li]["IPv6"]
            out.write("      - subnet: "+f"{ipv6}\n\n")

        if Print_controller:
            for pi in range(topo["point_num"]):
                out.write("  controlbr-"+f"{pi}:\n")
                out.write("    driver: bridge\n")
                out.write("    enable_ipv6: true\n")
                out.write("    ipam:\n")
                out.write("      config:\n")
                out.write("      - subnet: "+f"10.2.{pi+1}.0/24\n")
                out.write("      - subnet: "+f"fc00:0002:{pi+1:x}::/64\n\n")