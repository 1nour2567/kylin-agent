#!/bin/bash
set -e
echo "=== Kylin Agent 部署 ==="

# Config
INSTALL_DIR="/opt/kylin-agent"
PORT=8008

# 1. Python 确认
echo "[1/6] 检查 Python..."
python3 --version || { echo "需要 Python 3.10+"; exit 1; }

# 2. 安装依赖
echo "[2/6] 安装 Python 依赖..."
cd "$INSTALL_DIR"
pip3 install -r requirements.txt 2>&1 | tail -3

# 3. 创建受限用户
echo "[3/6] 创建 kylin-agent 用户..."
if ! id kylin-agent &>/dev/null; then
    sudo useradd -r -s /usr/sbin/nologin kylin-agent
fi

# 4. 写 .env（如果不存在）
if [ ! -f .env ]; then
    echo "[4/6] 创建 .env..."
    cat > .env << 'ENVEOF'
DEEPSEEK_API_KEY=sk-6a36b0751f984ea0bd66b3cef2a05e3d
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-chat
HOST=0.0.0.0
PORT=8008
CORS_ORIGINS=*
AGENT_MODE=live
ENVEOF
else
    echo "[4/6] .env 已存在，跳过"
fi

# 5. 创建数据目录
echo "[5/6] 创建数据目录..."
mkdir -p data/audit data/logs data/baseline

# 6. 启动
echo "[6/6] 启动 Agent (端口 $PORT, 模式 live)..."
cd backend
python3 main.py
