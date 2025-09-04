#!/bin/bash

# 延迟设置函数
set_link_delay() {
    local container=$1
    local iface=$2
    local delay=${3:-200ms}

    echo "[INFO] Setting delay $delay on $container:$iface"

    # 等待容器启动完成
    sleep 10

    # 验证容器是否存在且在运行
    if ! docker ps --format '{{.Names}}' | grep -q "^${container}$"; then
        echo "[ERROR] Container not found or not running: $container"
        return 1
    fi

    # 验证接口是否存在于容器中
    if ! docker exec "$container" ip link show "$iface" >/dev/null 2>&1; then
        echo "[ERROR] Interface '$iface' not found in container '$container'"
        echo "[DEBUG] Available interfaces in $container:"
        docker exec "$container" ip -br link
        return 1
    fi

    # 在指定的容器接口上应用延迟
    echo "[INFO] Applying delay $delay to all outgoing traffic on $container:$iface"
    docker exec "$container" bash -c "
        tc qdisc del dev $iface root 2>/dev/null || true;
        tc qdisc add dev $iface root netem delay $delay
    "

    # 验证tc设置
    echo "[DEBUG] Verifying tc settings on $container:$iface"
    docker exec "$container" tc qdisc show dev "$iface"
    
    echo "[INFO] Delay configuration completed for $container:$iface"
}

# 清理函数
cleanup() {
    echo ""
    echo "[INFO] Received stop signal..."
    echo "[INFO] Running analysis..."
    # If run with sudo, de-escalate to the original user to run the analysis
    # This ensures the user's python environment (with pandas) is used.
    if [ -n "$SUDO_USER" ]; then
        sudo -u "$SUDO_USER" bash -c "cd $(dirname "$0")/../analyzer && python3 analyzer.py"
    else
        (cd "$(dirname "$0")/../analyzer" && python3 analyzer.py)
    fi
    echo "[INFO] Cleanup completed."
    exit 0
}

# 设置信号处理器
trap cleanup SIGINT SIGTERM

# 解析命令行参数
DELAY_PARAMS=()
echo "[DEBUG] Starting parameter parsing, args: $@"

while [[ $# -gt 0 ]]; do
    echo "[DEBUG] Processing argument: $1"
    case "$1" in
        --delay)
            if [[ $# -lt 3 ]]; then
                echo "[ERROR] Invalid arguments for --delay."
                echo "Usage: $0 --delay <container> <interface> [delay]"
                echo "Example: $0 --delay Wulumuqi eth1 100ms"
                exit 1
            fi
            
            container="$2"
            iface="$3"
            delay_val="${4:-200ms}"
            
            echo "[DEBUG] Parsed delay param: Container=$container, Interface=$iface, Delay=$delay_val"
            DELAY_PARAMS+=("$container $iface $delay_val")
            
            # 检查是否有第4个参数（延迟值）
            if [[ $# -ge 4 && "$4" != --* ]]; then
                shift 4
            else
                shift 3
            fi
            ;;
        *)
            echo "[DEBUG] Skipping unknown argument: $1"
            shift
            ;;
    esac
done

echo "[DEBUG] Finished parsing. Found ${#DELAY_PARAMS[@]} delay configurations."

python3 build_yml.py
python3 containers_sh.py
python3 modify_conf.py

# 清理之前的CSV文件
echo "[INFO] Cleaning up previous CSV files..."
rm -f ../agent/csv/pingLog*.csv

cd ../agent/http
rm -f http_service point-*
sudo go build -o http_service http.go client.go
cd ../..
cd controller/server
sudo go build -o server server.go
# docker build -t frr-go -f Dockerfile.agent ..
# docker build -t frr-go-controller -f Dockerfile.controller ..

cd ../../docker

# 清理项目相关的Docker环境
echo "[INFO] Cleaning up existing project containers and networks..."
docker compose -f docker-compose.yml down --remove-orphans
echo "[INFO] Project cleanup completed"

# 启动容器（在后台）
echo "[INFO] Starting containers..."
docker compose -f docker-compose.yml up -d

# 如果设置了延迟参数，则应用延迟
if [ ${#DELAY_PARAMS[@]} -gt 0 ]; then
    echo "[INFO] Found ${#DELAY_PARAMS[@]} delay configurations to apply."
    for param_set in "${DELAY_PARAMS[@]}"; do
        read -r container iface delay <<< "$param_set"
        echo "[INFO] About to apply delay: Container=$container, Interface=$iface, Delay=$delay"
        set_link_delay "$container" "$iface" "$delay" &
    done
    wait # 等待所有延迟设置完成
    echo "[INFO] All delay configurations have been applied."
else
    echo "[INFO] No --delay parameters found. Skipping delay configuration."
fi

# 显示日志并保持运行
echo "[INFO] System is running. Press Ctrl+C to stop."
docker compose -f docker-compose.yml logs -f