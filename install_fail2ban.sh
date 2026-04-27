#!/bin/bash
# ============================================================
#  Fail2ban 安装与严格封禁策略配置脚本
#  适用：CentOS 7 / 8 / Stream
#  作者：sysadmin  用法：sudo bash install_fail2ban.sh
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GRN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YLW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && error "请使用 root 或 sudo 运行"

# ── 1. 检测发行版 ──────────────────────────────────────────
if   [[ -f /etc/centos-release ]]; then OS="centos"
elif [[ -f /etc/redhat-release ]]; then OS="rhel"
else error "不支持的发行版"; fi
VER=$(rpm -E '%{rhel}')
info "检测到 $OS $VER"

# ── 2. 安装 EPEL ───────────────────────────────────────────
info "安装 EPEL 源..."
if [[ "$VER" -eq 7 ]]; then
    yum install -y epel-release
elif [[ "$VER" -ge 8 ]]; then
    dnf install -y epel-release
    dnf config-manager --set-enabled epel 2>/dev/null || true
fi

# ── 3. 安装 fail2ban ───────────────────────────────────────
info "安装 fail2ban..."
if [[ "$VER" -eq 7 ]]; then
    yum install -y fail2ban fail2ban-systemd
else
    dnf install -y fail2ban fail2ban-systemd
fi

# ── 4. 检测防火墙后端 ─────────────────────────────────────
if systemctl is-active --quiet firewalld; then
    BACKEND="firewallcmd-ipset"
    info "检测到 firewalld，使用 firewallcmd-ipset 后端"
else
    BACKEND="iptables-multiport"
    warn "未检测到 firewalld，使用 iptables 后端"
fi

# ── 5. 写入 /etc/fail2ban/jail.local ─────────────────────
info "写入严格封禁策略配置..."
cat > /etc/fail2ban/jail.local << 'JAILEOF'
[DEFAULT]
# 白名单：本机回环 + 内网（按实际修改）
ignoreip = 127.0.0.1/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16

# ── 封禁时长策略（严格递增）──────────────────────────────
# 首次封禁 1 小时，每次被封再乘 2，上限 30 天
bantime         = 3600
bantime.increment = true
bantime.factor  = 2
bantime.maxtime = 2592000
bantime.overalljails = true

# 检测窗口：10 分钟内超过阈值即封禁
findtime  = 600

# 最大失败次数（严格：3 次）
maxretry  = 3

# 后端（由脚本自动替换）
backend   = BACKEND_PLACEHOLDER

# 动作：封禁 + 发送告警邮件（无邮件服务器则用 %(action_)s）
action    = %(action_mwl)s

# 日志编码
encoding  = UTF-8

# ── SSH 防爆破（主要 jail）────────────────────────────────
[sshd]
enabled   = true
port      = ssh
filter    = sshd
logpath   = %(sshd_log)s
backend   = %(sshd_backend)s
maxretry  = 3
findtime  = 300
bantime   = 7200

# ── SSH 反复探测加强版（更长封禁）────────────────────────
[sshd-ddos]
enabled   = true
port      = ssh
filter    = sshd-ddos
logpath   = %(sshd_log)s
maxretry  = 2
findtime  = 60
bantime   = 86400

# ── 端口扫描封禁（需要 portscan filter）──────────────────
[portscan]
enabled   = false
filter    = portscan
logpath   = /var/log/messages
maxretry  = 5
findtime  = 60
bantime   = 86400

# ── Web 服务（可选，nginx 安装后启用）────────────────────
[nginx-http-auth]
enabled  = false
port     = http,https
filter   = nginx-http-auth
logpath  = /var/log/nginx/error.log
maxretry = 3

[nginx-limit-req]
enabled  = false
port     = http,https
filter   = nginx-limit-req
logpath  = /var/log/nginx/error.log
maxretry = 5
findtime = 60
bantime  = 3600
JAILEOF

# 替换后端占位符
sed -i "s/BACKEND_PLACEHOLDER/$BACKEND/" /etc/fail2ban/jail.local

# ── 6. 写入自定义 portscan filter ─────────────────────────
cat > /etc/fail2ban/filter.d/portscan.conf << 'FILTEREOF'
[Definition]
failregex = kernel: .*IN=.* OUT= .* SRC= DPT=(22|23|25|80|110|443|3306|6379|27017)
ignoreregex =
FILTEREOF

# ── 7. 配置 fail2ban 日志 ─────────────────────────────────
mkdir -p /var/log/fail2ban
cat > /etc/fail2ban/fail2ban.local << 'LOGEOF'
[Definition]
loglevel  = INFO
logtarget = /var/log/fail2ban/fail2ban.log
LOGEOF

# ── 8. 启动并设置开机自启 ─────────────────────────────────
info "启动 fail2ban..."
systemctl daemon-reload
systemctl enable --now fail2ban

sleep 3

# ── 9. 验证状态 ───────────────────────────────────────────
info "验证安装..."
if systemctl is-active --quiet fail2ban; then
    info "fail2ban 运行正常 ✓"
    fail2ban-client status
else
    error "fail2ban 启动失败，请检查：journalctl -u fail2ban -n 50"
fi

# ── 10. 打印摘要 ──────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Fail2ban 安装完成 — 封禁策略摘要"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  SSH 最大失败次数 : 3 次 / 5 分钟"
echo "  首次封禁时长     : 2 小时"
echo "  递增封禁上限     : 30 天"
echo "  DDoS 探测封禁    : 2 次 / 60 秒 → 封禁 24 小时"
echo "  防火墙后端       : $BACKEND"
echo "  配置文件         : /etc/fail2ban/jail.local"
echo "  日志文件         : /var/log/fail2ban/fail2ban.log"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  白名单修改：编辑 /etc/fail2ban/jail.local → ignoreip"
echo "  重载配置  ：fail2ban-client reload"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"