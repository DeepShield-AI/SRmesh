#!/bin/bash

echo "🔍 Network Delay Analyzer"
echo "========================"

# 检查是否有CSV文件
if [ ! -d "../agent/csv" ] || [ -z "$(ls -A ../agent/csv/*.csv 2>/dev/null)" ]; then
    echo "❌ No CSV files found in ../agent/csv/"
    echo "Please run the network simulation first to generate probe data."
    exit 1
fi

# 检查Python依赖
echo "📦 Checking dependencies..."
python3 -c "import pandas, numpy, networkx" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "❌ Missing required Python packages"
    echo "Please install: pip3 install pandas numpy networkx"
    exit 1
fi

# 运行分析器
echo "🚀 Starting analysis..."
echo ""

# 允许传递瓶颈阈值参数
THRESHOLD=${1:-100}
python3 analyzer.py $THRESHOLD

echo ""
echo "📁 CSV files analyzed from: ../agent/csv/"
echo "📋 Topology loaded from: ../docker/conf/topo.json"
