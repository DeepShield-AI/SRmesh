#!/bin/bash

# 查看所有容器的延迟配置
# Usage: ./check_delay.sh

echo "=== 检查所有容器的网络延迟配置 ==="
echo

# 容器列表
containers=("Wulumuqi" "Beihang" "Beida" "Beiyou" "Shenyang" "Haerbin" "Changchun" "Huhehaote" "Beijing" "Dalian" "Lasa" "Yinchuan" "Taiyuan" "Shijiazhuang" "Tianjin" "Xining")

for container in "${containers[@]}"; do
    echo "--- $container ---"
    if docker ps --format "table {{.Names}}" | grep -q "^$container$"; then
        # 检查tc规则
        docker exec $container bash -c "
            echo 'Network interfaces:'
            ip link show | grep -E 'eth[0-9]+' | awk -F: '{gsub(/^ +/, \"\", \$2); print \"  \" \$2}'
            echo 'TC qdisc rules:'
            tc qdisc show | grep netem | awk '{print \"  \" \$0}' || echo '  No netem delay rules found'
        " 2>/dev/null || echo "  Container not accessible"
    else
        echo "  Container not running"
    fi
    echo
done

echo "=== 延迟配置检查完成 ==="
