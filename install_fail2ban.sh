#!/usr/bin/env bash
# ============================================================
# Fail2ban 安装与严格封禁策略（阿里云优化版，无邮件）
# 适用：CentOS / Rocky / Alma / Alibaba Cloud Linux
# 用法：sudo bash install_fail2ban.sh
# ============================================================

set -euo pipefail

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GRN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YLW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && error "请使用 root 或 sudo 运行"

# ── 1. 识别系统 ─────────────────────────────────────────────
info "识别系统..."
source /etc/os-release
OS=$ID
VER_ID=${VERSION_ID%%.*}
info "系统: $OS $VER_ID"

# ── 2. 安装 EPEL ────────────────────────────────────────────
info "安装 EPEL..."
if ! rpm -qa | grep -q epel-release; then
    rpm -Uvh --quiet https://dl.fedoraproject.org/pub/epel/epel-release-latest-${VER_ID}.noarch.rpm || warn "EPEL 安装可能失败"
fi

# ── 3. 安装 fail2ban ───────────────────────────────────────
info "安装 fail2ban..."
if command -v dnf >/dev/null 2>&1; then
    dnf install -y fail2ban fail2ban-systemd
else
    yum install -y fail2ban fail2ban-systemd
fi

# ── 4. 确保 firewalld ──────────────────────────────────────
info "配置 firewalld..."
if ! systemctl is-enabled firewalld >/dev/null 2>&1; then
    if command -v dnf >/dev/null; then
        dnf install -y firewalld
    else
        yum install -y firewalld
    fi
    systemctl enable --now firewalld
fi

BACKEND="firewallcmd-ipset"

# ── 5. 写配置 ─────────────────────────────────────────────
info "写入 jail.local..."

cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1

# 封禁策略
bantime = 3600
bantime.increment = true
bantime.factor = 2
bantime.maxtime = 864000

findtime = 600
maxretry = 5

backend = systemd

# ❗ 不使用邮件
action = %(action_)s

# ── SSH 基础防护 ─────────────────
[sshd]
enabled   = true
port      = ssh
filter    = sshd
backend   = systemd
maxretry  = 5
findtime  = 300
bantime   = 3600

# ── SSH 激进防护（防扫描）────────
[sshd-ddos]
enabled   = true
port      = ssh
filter    = sshd-ddos
backend   = systemd
maxretry  = 3
findtime  = 60
bantime   = 86400
EOF

# ── 6. 日志配置 ────────────────────────────────────────────
mkdir -p /var/log/fail2ban

cat > /etc/fail2ban/fail2ban.local <<EOF
[Definition]
loglevel = INFO
logtarget = /var/log/fail2ban/fail2ban.log
EOF

# ── 7. 启动 ───────────────────────────────────────────────
info "启动 fail2ban..."
systemctl daemon-reexec
systemctl enable --now fail2ban

sleep 2

# ── 8. 验证 ───────────────────────────────────────────────
if fail2ban-client ping | grep -q pong; then
    info "fail2ban 运行正常 ✓"
else
    error "fail2ban 启动失败，请检查日志"
fi

# ── 9. 输出 ───────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " Fail2ban 已部署完成"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "查看状态："
echo "  fail2ban-client status"
echo ""
echo "查看 SSH："
echo "  fail2ban-client status sshd"
echo ""
echo "解封 IP："
echo "  fail2ban-client set sshd unbanip <IP>"
echo ""
echo "日志："
echo "  tail -f /var/log/fail2ban/fail2ban.log"
echo ""
echo "⚠️ 建议：把你的公网IP加入 ignoreip 防止误封"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
