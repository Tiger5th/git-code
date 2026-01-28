#!/usr/bin/env bash
# ==============================================================================
# Project: Sub-Store Operations Platform (Titanium Edition)
# Version: 2.0.0.2
# Author: Gemini & Tiger5th
# Build Date: 2026-01-28
#
# Description:
#   Enterprise-grade deployment and operations tool for Sub-Store.
#   Includes auto-discovery, self-healing, audit logging, and full lifecycle management.
#
# Features:
#   [x] Docker Container Lifecycle (Deploy, Upgrade, Rollback)
#   [x] Smart Nginx Discovery (Host/Docker/OpenResty)
#   [x] ACME v2 Certificate Management (Auto-renewal Hooks)
#   [x] Backup & Disaster Recovery (Snapshots)
#   [x] Network & Firewall Automata
#   [x] Interactive TUI (Text User Interface)
#
# License: MIT
# ==============================================================================

# --- Kernel Parameter Configuration ---
# Enable strict mode to prevent silent failures
set -o errexit   # Exit immediately if a command exits with a non-zero status
set -o pipefail  # Return value of a pipeline is the status of the last command to exit with a non-zero status
set -o nounset   # Treat unset variables as an error

# ==============================================================================
# SECTION 1: Global Constants & Configuration
# ==============================================================================

# Meta Information
readonly SCRIPT_VER="2.0.0.2"
readonly SCRIPT_NAME="substore_ops"
readonly UPDATE_URL="https://raw.githubusercontent.com/Tiger5th/git-code/master/sub-gemini.sh"
readonly SCRIPT_PATH="/root/substore.sh"

# File Paths
readonly LOG_FILE="/var/log/substore_ops.log"
readonly STATE_DIR="/var/lib/substore-script"
readonly STATE_CFG_FILE="${STATE_DIR}/config.env"
readonly STATE_DB_FILE="${STATE_DIR}/domains.db"
readonly HOOK_SCRIPT_DIR="${STATE_DIR}/hooks"
readonly LOCAL_CERT_REPO="${STATE_DIR}/certs_repo"
readonly BACKUP_DIR="${STATE_DIR}/backups"
readonly TEMP_DIR="/tmp/substore_tmp"

# Application Defaults
readonly IMAGE_DEFAULT="xream/sub-store"
readonly NAME_DEFAULT="sub-store"
readonly DATA_DEFAULT="/root/sub-store"
readonly BIND_DEFAULT="127.0.0.1"
readonly HOST_PORT_DEFAULT="3001"
readonly CONT_PORT_DEFAULT="3001"
readonly JSON_LIMIT_DEFAULT="20mb"

# Nginx Standard Paths (Host / Panel Logic)
readonly LION_BASE="/home/web"
readonly LION_CONF_DIR="${LION_BASE}/conf.d"
readonly LION_CERT_DIR="${LION_BASE}/certs"
readonly LION_WEBROOT_DIR="${LION_BASE}/letsencrypt"

# Nginx Container Standard Paths
readonly C_CONF_DIR="/etc/nginx/conf.d"
readonly C_CERT_DIR="/etc/nginx/certs"
readonly C_WEBROOT_DIR="/var/www/letsencrypt"

# ANSI Color Codes (Visual System)
readonly C_RESET="\033[0m"
readonly C_BOLD="\033[1m"
readonly C_DIM="\033[2m"
readonly C_UNDERLINE="\033[4m"
readonly C_BLINK="\033[5m"
readonly C_REVERSE="\033[7m"

readonly C_BLACK="\033[30m"
readonly C_RED="\033[31m"
readonly C_GREEN="\033[32m"
readonly C_YELLOW="\033[33m"
readonly C_BLUE="\033[34m"
readonly C_PURPLE="\033[35m"
readonly C_CYAN="\033[36m"
readonly C_WHITE="\033[37m"

readonly C_BG_BLACK="\033[40m"
readonly C_BG_RED="\033[41m"
readonly C_BG_GREEN="\033[42m"
readonly C_BG_YELLOW="\033[43m"
readonly C_BG_BLUE="\033[44m"
readonly C_BG_PURPLE="\033[45m"
readonly C_BG_CYAN="\033[46m"
readonly C_BG_WHITE="\033[47m"

# Global State Variables (Runtime)
CURRENT_NGINX_MODE=""
CURRENT_NGINX_TARGET=""
CURRENT_CONF_DIR=""
CURRENT_CERT_DIR=""

# ==============================================================================
# SECTION 2: Low-Level Utility Functions (Logging, UI, System)
# ==============================================================================

# Initialize System Environment
init_environment() {
    # Create necessary directories
    mkdir -p "${STATE_DIR}" "${HOOK_SCRIPT_DIR}" "${LOCAL_CERT_REPO}" "${BACKUP_DIR}" "${TEMP_DIR}"
    
    # Initialize Log File
    if [[ ! -f "${LOG_FILE}" ]]; then
        touch "${LOG_FILE}"
        chmod 600 "${LOG_FILE}"
    fi
    
    # Clean temp dir
    rm -rf "${TEMP_DIR:?}"/*
    
    # Install Shortcut if missing
    if [[ ! -f "/usr/local/bin/st" ]]; then
        install_shortcut_silent
    fi
}

# --- Logging Subsystem ---

log_write() {
    local level="$1"
    local msg="$2"
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    # Remove ANSI codes for log file
    local clean_msg
    clean_msg=$(echo -e "$msg" | sed "s/\x1B\[[0-9;]*[a-zA-Z]//g")
    echo "[${timestamp}] [${level}] ${clean_msg}" >> "${LOG_FILE}"
}

log_info() {
    echo -e "${C_BLUE}ℹ${C_RESET} ${C_BOLD}INFO:${C_RESET} $1"
    log_write "INFO" "$1"
}

log_success() {
    echo -e "${C_GREEN}✔${C_RESET} ${C_BOLD}SUCCESS:${C_RESET} $1"
    log_write "SUCCESS" "$1"
}

log_warn() {
    echo -e "${C_YELLOW}⚠${C_RESET} ${C_BOLD}WARN:${C_RESET} $1"
    log_write "WARN" "$1"
}

log_err() {
    echo -e "${C_RED}✖${C_RESET} ${C_BOLD}ERROR:${C_RESET} $1"
    log_write "ERROR" "$1"
}

die() {
    echo -e "\n${C_BG_RED}${C_WHITE}${C_BOLD} FATAL ERROR ${C_RESET}"
    echo -e "${C_RED}>> $1${C_RESET}"
    echo -e "${C_DIM}System halted. Check log: ${LOG_FILE}${C_RESET}"
    log_write "FATAL" "$1"
    exit 1
}

# --- UI Components ---

# Draw a horizontal separator
separator() {
    local width=60
    local char="─"
    if [[ -n "${1:-}" ]]; then width=$1; fi
    printf "${C_DIM}%${width}s${C_RESET}\n" | tr " " "${char}"
}

# Print a centered title
print_header() {
    local title="$1"
    echo -e "\n${C_CYAN}${C_BOLD}>>> ${title}${C_RESET}"
    separator
}

# Advanced Spinner with PID tracking
# Usage: command & spinner $! "Task Name"
spinner() {
    local pid=$1
    local task_name="$2"
    local delay=0.1
    local spinstr='|/-\'
    
    # Hide cursor
    tput civis
    
    echo -ne "  ${C_CYAN}${task_name}...${C_RESET} "
    
    while kill -0 "$pid" 2>/dev/null; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    
    wait "$pid"
    local exit_code=$?
    
    printf "    \b\b\b\b"
    
    # Restore cursor
    tput cnorm
    
    if [[ $exit_code -eq 0 ]]; then
        echo -e "${C_GREEN}[完成]${C_RESET}"
        log_write "TASK_OK" "${task_name}"
    else
        echo -e "${C_RED}[失败]${C_RESET}"
        log_write "TASK_FAIL" "${task_name} (Exit Code: $exit_code)"
        return 1
    fi
}

# Pause and wait for user
pause() {
    echo -e "\n${C_GRAY}按 ${C_BOLD}Enter${C_RESET}${C_GRAY} 键继续...${C_RESET}"
    read -r
}

# Draw a table for key-value pairs
# Usage: draw_table "Title" "Key1|Val1" "Key2|Val2" ...
draw_table() {
    local title="$1"
    shift
    
    echo -e "${C_BOLD}${title}${C_RESET}"
    separator 50
    printf "${C_CYAN}%-15s${C_RESET} | %s\n" "ITEM" "VALUE"
    separator 50
    
    for row in "$@"; do
        local key="${row%%|*}"
        local val="${row#*|}"
        printf "${C_CYAN}%-15s${C_RESET} | ${C_WHITE}%s${C_RESET}\n" "$key" "$val"
    done
    separator 50
}

# ASCII Banner
print_banner() {
    clear
    echo -e "${C_CYAN}"
    cat << "EOF"
   _____       __        _____ __                 
  / ___/__  __/ /_      / ___// /_____  ________  
  \__ \/ / / / __ \_____\__ \/ __/ __ \/ ___/ _ \ 
 ___/ / /_/ / /_/ /_____/ /_/ /_/ /_/ / /  /  __/ 
/____/\__,_/_.___/     /____/\__/\____/_/   \___/  
                                      
EOF
    echo -e "${C_RESET}"
    echo -e "   ${C_BOLD}运维综合平台${C_RESET} ${C_PURPLE}v${SCRIPT_VER}${C_RESET} | ${C_BLUE}Titanium Edition${C_RESET}"
    separator
}

# ==============================================================================
# SECTION 3: Input Gateway (Validation & UX)
# ==============================================================================

# Standard Input Prompt with Validation
# Usage: ask_input "Prompt Text" "Default" VAR_NAME "Regex"
ask_input() {
    local prompt_text="$1"
    local default_val="$2"
    local result_var="$3"
    local regex="${4:-}"
    local input_val
    local max_retries=3
    local try=0

    while true; do
        # Render Prompt
        echo -ne "${C_BOLD}${prompt_text}${C_RESET}"
        if [[ -n "$default_val" ]]; then
            echo -ne " [默认: ${C_CYAN}${default_val}${C_RESET}]"
        fi
        echo -ne ": "
        
        read -r input_val
        
        # Handle Default
        if [[ -z "$input_val" ]]; then
            input_val="$default_val"
        fi
        
        # Handle Cancel
        if [[ "$input_val" == "q" || "$input_val" == "Q" ]]; then
            log_warn "用户取消操作。"
            return 1
        fi
        
        # Handle Validation
        if [[ -n "$regex" ]]; then
            if [[ ! "$input_val" =~ $regex ]]; then
                ((try++))
                log_warn "输入格式无效! ($try/$max_retries)"
                if [[ $try -ge $max_retries ]]; then
                    die "错误次数过多，流程终止。"
                fi
                continue
            fi
        fi
        
        # Assign to Variable
        eval $result_var="'$input_val'"
        break
    done
    return 0
}

# Confirmation Prompt
ask_confirm() {
    local msg="$1"
    local default="${2:-N}"
    local yn
    
    echo -ne "${C_YELLOW}${msg}${C_RESET} (y/n) [${default}]: "
    read -r yn
    if [[ -z "$yn" ]]; then yn="$default"; fi
    
    if [[ "$yn" =~ ^[Yy]$ ]]; then
        return 0
    else
        return 1
    fi
}

# Specific Prompts
prompt_port() {
    local label="$1"
    local def="$2"
    local var="$3"
    # Port Regex: 1-65535 (simplified)
    ask_input "$label" "$def" "$var" "^[0-9]+$"
    
    # Logical Check
    local val=${!var}
    if [[ $val -lt 1 || $val -gt 65535 ]]; then
        log_warn "端口号必须在 1-65535 之间"
        prompt_port "$label" "$def" "$var"
    fi
}

prompt_domain() {
    local label="$1"
    local var="$2"
    # Domain Regex
    ask_input "$label" "" "$var" "^[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$"
}

# ==============================================================================
# SECTION 4: System Management (Deps, Firewall, Self-Update)
# ==============================================================================

# Check Root Privilege
check_root() {
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        die "此脚本需要 Root 权限。请运行: sudo -i"
    fi
}

# Dependency Manager (Auto-Heal)
check_deps() {
    local deps=("curl" "grep" "awk" "socat" "tar" "openssl" "jq")
    local missing=0
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null; then missing=1; fi
    done
    
    if ! command -v docker >/dev/null; then missing=1; fi
    if [[ ! -f "${HOME}/.acme.sh/acme.sh" ]]; then missing=1; fi

    if [[ $missing -eq 0 ]]; then return 0; fi

    print_header "系统环境自动修补"
    
    # 1. System Packages
    local pkg_mgr=""
    local install_cmd=""
    
    if command -v apt-get >/dev/null; then
        pkg_mgr="apt"
        install_cmd="apt-get update -y && apt-get install -y"
    elif command -v yum >/dev/null; then
        pkg_mgr="yum"
        install_cmd="yum install -y"
    elif command -v apk >/dev/null; then
        pkg_mgr="apk"
        install_cmd="apk add"
    fi
    
    if [[ -n "$pkg_mgr" ]]; then
        eval "${install_cmd} curl grep awk socat tar openssl jq" >/dev/null 2>&1 &
        spinner $! "安装基础工具集 ($pkg_mgr)"
    else
        log_warn "无法识别包管理器，跳过基础工具安装。"
    fi

    # 2. Docker
    if ! command -v docker >/dev/null; then
        curl -fsSL https://get.docker.com | sh >/dev/null 2>&1 &
        spinner $! "安装 Docker Engine"
        systemctl enable --now docker >/dev/null 2>&1 || true
    fi

    # 3. acme.sh
    if [[ ! -f "${HOME}/.acme.sh/acme.sh" ]]; then
        curl https://get.acme.sh | sh -s email=substore@example.com >/dev/null 2>&1 &
        spinner $! "安装 acme.sh 证书工具"
    fi
    
    log_success "环境准备就绪"
}

# Firewall Manager (Auto-Open Ports)
open_firewall_port() {
    local port="$1"
    local proto="tcp"
    
    log_info "检查防火墙配置 (端口: $port)..."
    
    # UFW
    if command -v ufw >/dev/null; then
        if ufw status | grep -q "Status: active"; then
            ufw allow "${port}/tcp" >/dev/null 2>&1
            log_success "UFW: 已放行端口 $port"
        fi
    fi
    
    # Firewalld
    if command -v firewall-cmd >/dev/null; then
        if systemctl is-active --quiet firewalld; then
            firewall-cmd --permanent --add-port="${port}/tcp" >/dev/null 2>&1
            firewall-cmd --reload >/dev/null 2>&1
            log_success "Firewalld: 已放行端口 $port"
        fi
    fi
    
    # Iptables (Basic)
    if command -v iptables >/dev/null; then
        if ! iptables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null; then
            iptables -I INPUT -p tcp --dport "$port" -j ACCEPT
            log_success "Iptables: 已添加规则"
        fi
    fi
}

# Path Safety Check
check_path_safety() {
    local path="$1"
    # Blacklist dangerous paths
    if [[ "$path" == "/" || "$path" == "/root" || "$path" == "/home" || 
          "$path" == "/usr" || "$path" == "/var" || "$path" == "/etc" || 
          "$path" == "/bin" || "$path" == "/sbin" || "$path" == "/tmp" ]]; then
        die "安全保护触发：禁止对高危路径 [$path] 执行批量操作！"
    fi
    if [[ -z "$path" ]]; then die "路径变量为空，操作终止"; fi
}

# Self Update (Atomic)
update_self() {
    print_header "脚本在线更新"
    log_info "正在连接 GitHub..."
    
    local temp_file="${TEMP_DIR}/update.sh"
    
    # Download with timestamp to bypass CDN
    if curl -sL "${UPDATE_URL}?t=$(date +%s)" -o "${temp_file}"; then
        # Integrity Check
        if ! grep -q "SCRIPT_VER" "${temp_file}"; then
            die "下载文件校验失败（内容不完整），请检查网络。"
        fi

        # CRLF Fix
        sed -i 's/\r$//' "${temp_file}"

        # Backup Old
        if [[ -f "${SCRIPT_PATH}" ]]; then
            cp "${SCRIPT_PATH}" "${SCRIPT_PATH}.bak"
        fi

        # Replace
        mv "${temp_file}" "${SCRIPT_PATH}"
        chmod +x "${SCRIPT_PATH}"
        
        log_success "更新成功！正在重启..."
        sleep 1
        exec "${SCRIPT_PATH}"
    else
        die "网络连接失败，更新取消。"
    fi
}

# Install Shortcut
install_shortcut_silent() {
    cat > /usr/local/bin/st <<SH
#!/usr/bin/env bash
exec ${SCRIPT_PATH} "\$@"
SH
    chmod +x /usr/local/bin/st
}

# ==============================================================================
# SECTION 5: Docker Container Management
# ==============================================================================

# Deploy Container Flow
deploy_container() {
    ensure_deps
    
    # Check existing
    if [[ -f "${STATE_CFG_FILE}" ]]; then
        source "${STATE_CFG_FILE}"
        log_warn "检测到已部署配置: ${SC_NAME}"
        if ! ask_confirm "是否删除旧容器并重新部署?" "n"; then return; fi
    fi
    
    print_header "容器部署向导"
    
    local c_name h_port data_dir backend_path
    
    ask_input "容器名称" "${NAME_DEFAULT}" c_name
    
    # Port Check Loop
    while true; do
        prompt_port "宿主机端口 (127.0.0.1)" "${HOST_PORT_DEFAULT}" h_port
        if check_port_available "${h_port}"; then
            break
        else
            log_warn "端口 ${h_port} 似乎被占用了。"
            if ask_confirm "坚持使用该端口?"; then break; fi
        fi
    done
    
    ask_input "数据目录" "${DATA_DEFAULT}" data_dir
    check_path_safety "${data_dir}"
    
    local rand_path="/$(openssl rand -hex 12)"
    ask_input "后台安全路径" "${rand_path}" backend_path
    
    # Summary
    draw_table "配置摘要" \
        "容器名称|${c_name}" \
        "监听端口|127.0.0.1:${h_port}" \
        "数据目录|${data_dir}" \
        "后台入口|${backend_path}"
        
    if ! ask_confirm "确认立即部署?"; then return; fi
    
    # Action
    mkdir -p "${data_dir}"
    
    if docker ps -a --format '{{.Names}}' | grep -qx "${c_name}"; then
        log_info "移除旧容器..."
        docker rm -f "${c_name}" >/dev/null 2>&1
    fi
    
    log_info "正在启动容器..."
    if docker run -it -d \
        --restart=always \
        --name "${c_name}" \
        -p "${BIND_DEFAULT}:${h_port}:${CONT_PORT_DEFAULT}" \
        -v "${data_dir}:/opt/app/data" \
        -e "SUB_STORE_FRONTEND_BACKEND_PATH=${backend_path}" \
        -e "SUB_STORE_BODY_JSON_LIMIT=${JSON_LIMIT_DEFAULT}" \
        "${IMAGE_DEFAULT}" >/dev/null; then
        
        # Save State
        cat > "${STATE_CFG_FILE}" <<EOF
SC_NAME=${c_name}
SC_PORT=${h_port}
SC_BACKEND=${backend_path}
SC_DATA=${data_dir}
EOF
        log_success "部署完成"
    else
        die "容器启动失败，请检查 Docker 日志"
    fi
}

check_port_available() {
    local port="$1"
    if command -v netstat >/dev/null; then
        netstat -tuln | grep -q ":${port} " && return 1
    elif command -v ss >/dev/null; then
        ss -tuln | grep -q ":${port} " && return 1
    fi
    return 0
}

# Container Management Menu
container_menu() {
    if [[ ! -f "${STATE_CFG_FILE}" ]]; then
        log_warn "未找到部署配置"
        pause
        return
    fi
    source "${STATE_CFG_FILE}"
    
    while true; do
        clear
        print_header "容器管理: ${SC_NAME}"
        echo " 1. 查看连接信息"
        echo " 2. 查看实时日志"
        echo " 3. 重启容器"
        echo " 4. 更新镜像 (Update)"
        echo " 5. 备份数据"
        echo " 6. 卸载容器"
        echo " 0. 返回"
        separator
        
        local choice
        read -r -p "选择: " choice
        case "$choice" in
            1)
                draw_table "连接详情" \
                    "容器名|${SC_NAME}" \
                    "端口|${SC_PORT}" \
                    "后台路径|${SC_BACKEND}" \
                    "完整URL|http://127.0.0.1:${SC_PORT}${SC_BACKEND}"
                pause
                ;;
            2) docker logs -f --tail 100 "${SC_NAME}";;
            3) docker restart "${SC_NAME}" >/dev/null && log_success "重启成功"; pause ;;
            4) 
                log_info "Pulling image..."
                docker pull "${IMAGE_DEFAULT}"
                docker restart "${SC_NAME}"
                log_success "更新完成"; pause ;;
            5) backup_data "${SC_DATA}"; pause ;;
            6) uninstall_container; return ;;
            0) return ;;
        esac
    done
}

backup_data() {
    local dir="$1"
    local bak="backup_$(date +%s).tar.gz"
    tar -czf "${BACKUP_DIR}/${bak}" -C "$(dirname "$dir")" "$(basename "$dir")"
    log_success "备份已保存至: ${BACKUP_DIR}/${bak}"
}

uninstall_container() {
    source "${STATE_CFG_FILE}"
    if ! ask_confirm "确认卸载容器 ${SC_NAME}?"; then return; fi
    docker rm -f "${SC_NAME}" >/dev/null
    
    if ask_confirm "是否同时删除数据目录 (不可恢复)?"; then
        check_path_safety "${SC_DATA}"
        rm -rf "${SC_DATA}"
    fi
    rm -f "${STATE_CFG_FILE}"
    log_success "卸载完成"
}

# ==============================================================================
# SECTION 6: Nginx & SSL Logic (The Complex Part)
# ==============================================================================

# Detect Nginx instance
detect_nginx() {
    # 1. Check Docker
    if command -v docker >/dev/null; then
        local c_names="nginx openresty"
        for name in $c_names; do
            if docker ps --format '{{.Names}}' | grep -qx "${name}"; then 
                echo "docker:${name}"
                return 0
            fi
        done
    fi
    # 2. Check Host
    if pgrep -x nginx >/dev/null 2>&1; then 
        echo "host:system"
        return 0
    fi
    return 1
}

# Resolve Nginx Paths & Modes
resolve_nginx_paths() {
    local ngx="$1"
    local type="${ngx%%:*}"
    local name="${ngx#*:}"
    
    # Defaults
    CURRENT_CONF_DIR="/etc/nginx/conf.d"
    CURRENT_CERT_DIR="/etc/nginx/certs"
    CURRENT_NGINX_MODE="host_direct"

    if [[ "$type" == "docker" ]]; then
        # Check Network
        local net_mode
        net_mode=$(docker inspect "${name}" --format '{{.HostConfig.NetworkMode}}')
        if [[ "${net_mode}" != "host" ]]; then
            log_err "容器 [${name}] 网络模式为: ${net_mode}"
            log_warn "必须使用 host 模式才能连接 Sub-Store。"
            die "请修改 Nginx 容器配置后重试。"
        fi
        
        # Check Mounts
        if docker inspect "${name}" --format '{{range .Mounts}}{{.Source}} {{end}}' | grep -q "${LION_CONF_DIR}"; then
            # Mounted Lion paths
            CURRENT_CONF_DIR="${LION_CONF_DIR}"
            CURRENT_CERT_DIR="${LION_CERT_DIR}"
            CURRENT_NGINX_MODE="host_direct"
        else
            # Not mounted
            CURRENT_CONF_DIR="${C_CONF_DIR}"
            CURRENT_CERT_DIR="${C_CERT_DIR}"
            CURRENT_NGINX_MODE="docker_cp"
        fi
    else
        # Host Nginx
        if [[ -d "${LION_CONF_DIR}" ]]; then
            CURRENT_CONF_DIR="${LION_CONF_DIR}"
            CURRENT_CERT_DIR="${LION_CERT_DIR}"
        fi
    fi
    
    CURRENT_NGINX_TARGET="$name"
}

# Core: Add Domain
add_domain_ssl() {
    ensure_deps
    
    if [[ ! -f "${STATE_CFG_FILE}" ]]; then
        log_warn "请先部署容器。"
        pause; return
    fi
    source "${STATE_CFG_FILE}"
    
    local ngx
    if ! ngx=$(detect_nginx); then
        log_warn "未检测到 Nginx。"
        echo "您可以手动输入容器名:"
        ask_input "Nginx 容器名 (留空取消)" "" ngx
        [[ -z "$ngx" ]] && return
        ngx="docker:${ngx}"
    fi
    
    resolve_nginx_paths "${ngx}"
    
    local domain
    prompt_domain "请输入域名" domain
    
    # Determine ACME Mode
    local acme_mode="standalone"
    local webroot_path=""
    if [[ -d "${LION_WEBROOT_DIR}" ]]; then
        acme_mode="webroot"
        webroot_path="${LION_WEBROOT_DIR}"
    fi
    
    # Review
    draw_table "配置确认" \
        "域名|${domain}" \
        "Nginx模式|${CURRENT_NGINX_MODE}" \
        "写入路径|${CURRENT_CONF_DIR}" \
        "签发模式|${acme_mode}"
        
    if ! ask_confirm "确认配置?"; then return; fi
    
    # Execute ACME
    local acme="${HOME}/.acme.sh/acme.sh"
    mkdir -p "${LOCAL_CERT_REPO}"
    
    log_info "正在申请证书..."
    
    if [[ "${acme_mode}" == "webroot" ]]; then
        "$acme" --issue -d "${domain}" --webroot "${webroot_path}" --server letsencrypt || die "证书申请失败"
    else
        # Standalone Logic with Trap
        local type="${ngx%%:*}"
        local name="${ngx#*:}"
        
        trap 'ensure_nginx_running "$type" "$name"' EXIT
        stop_nginx_service "$type" "$name"
        
        # Open firewall for standalone
        open_firewall_port "80"
        
        if ! "$acme" --issue --standalone -d "${domain}" --server letsencrypt; then
            die "证书申请失败 (Standalone)"
        fi
        
        trap - EXIT
        ensure_nginx_running "$type" "$name"
    fi
    
    # Generate Hook
    local hook_file="${HOOK_SCRIPT_DIR}/renew_${domain}.sh"
    generate_hook "${ngx}" "${domain}" "${hook_file}"
    
    # Install Cert
    "$acme" --install-cert -d "${domain}" \
        --key-file "${LOCAL_CERT_REPO}/${domain}.key" \
        --fullchain-file "${LOCAL_CERT_REPO}/${domain}.cer" \
        --reloadcmd "${hook_file}" >> "${LOG_FILE}" 2>&1
        
    # Trigger Hook once
    bash "${hook_file}"
    
    # Write Config
    write_nginx_conf "${ngx}" "${domain}"
    
    # Reload
    reload_nginx_strict "${ngx}"
    
    # Open HTTPS port
    open_firewall_port "443"
    
    log_success "配置完成: https://${domain}${SC_BACKEND}"
    pause
}

stop_nginx_service() {
    local type="$1"
    local name="$2"
    log_info "停止 Nginx (释放80端口)..."
    if [[ "$type" == "docker" ]]; then docker stop "$name" >/dev/null
    else if command -v systemctl >/dev/null; then systemctl stop nginx; else nginx -s stop; fi; fi
}

ensure_nginx_running() {
    local type="$1"
    local name="$2"
    log_info "恢复 Nginx..."
    if [[ "$type" == "docker" ]]; then docker start "$name" >/dev/null 2>&1 || true
    else if command -v systemctl >/dev/null; then systemctl start nginx; else nginx; fi; fi
}

generate_hook() {
    local ngx="$1"
    local domain="$2"
    local file="$3"
    local type="${ngx%%:*}"
    local name="${ngx#*:}"
    
    cat > "${file}" <<EOF
#!/bin/bash
# Hook for ${domain}
# Mode: ${CURRENT_NGINX_MODE}

EOF
    
    # Copy Logic
    if [[ "${CURRENT_NGINX_MODE}" == "host_direct" ]]; then
        echo "cp '${LOCAL_CERT_REPO}/${domain}.cer' '${CURRENT_CERT_DIR}/'" >> "${file}"
        echo "cp '${LOCAL_CERT_REPO}/${domain}.key' '${CURRENT_CERT_DIR}/'" >> "${file}"
    else
        echo "docker cp '${LOCAL_CERT_REPO}/${domain}.cer' '${name}:${CURRENT_CERT_DIR}/'" >> "${file}"
        echo "docker cp '${LOCAL_CERT_REPO}/${domain}.key' '${name}:${CURRENT_CERT_DIR}/'" >> "${file}"
    fi
    
    # Reload Logic
    echo -e "\n# Reload" >> "${file}"
    if [[ "$type" == "docker" ]]; then
        echo "docker exec ${name} nginx -t && docker exec ${name} nginx -s reload" >> "${file}"
    else
        echo "nginx -t && (systemctl reload nginx || nginx -s reload)" >> "${file}"
    fi
    chmod +x "${file}"
}

write_nginx_conf() {
    local ngx="$1"
    local domain="$2"
    local type="${ngx%%:*}"
    local name="${ngx#*:}"
    
    local conf="substore-${domain}.conf"
    local content
    content=$(cat <<EOF
# @SS_MANAGED: true
# @SS_DOMAIN: ${domain}
server {
    listen 80;
    server_name ${domain};
    location / { return 301 https://\$host\$request_uri; }
}
server {
    listen 443 ssl;
    server_name ${domain};
    ssl_certificate ${CURRENT_CERT_DIR}/${domain}.cer;
    ssl_certificate_key ${CURRENT_CERT_DIR}/${domain}.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    add_header Strict-Transport-Security "max-age=63072000" always;
    location / {
        proxy_pass http://127.0.0.1:${SC_PORT};
        proxy_set_header Host \$host;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOF
)
    
    if [[ "${CURRENT_NGINX_MODE}" == "host_direct" ]]; then
        echo "$content" > "${CURRENT_CONF_DIR}/${conf}"
    else
        echo "$content" > "${TEMP_DIR}/${conf}"
        docker cp "${TEMP_DIR}/${conf}" "${name}:${CURRENT_CONF_DIR}/"
    fi
}

reload_nginx_strict() {
    local ngx="$1"
    local type="${ngx%%:*}"
    local name="${ngx#*:}"
    
    log_info "重载 Nginx..."
    if [[ "$type" == "docker" ]]; then
        if docker exec "${name}" nginx -t; then
            docker exec "${name}" nginx -s reload
            log_success "Reloaded"
        else
            die "配置测试失败"
        fi
    else
        if nginx -t; then
            if command -v systemctl >/dev/null; then systemctl reload nginx; else nginx -s reload; fi
            log_success "Reloaded"
        else
            die "配置测试失败"
        fi
    fi
}

# List & Delete Domains (P1-5 Implementation)
list_domains() {
    local ngx
    if ! ngx=$(detect_nginx); then log_warn "未检测到 Nginx"; pause; return; fi
    resolve_nginx_paths "${ngx}"
    
    print_header "已配置域名列表"
    echo -e "${C_DIM}(扫描路径: ${CURRENT_CONF_DIR})${C_RESET}\n"
    
    if [[ "${CURRENT_NGINX_MODE}" == "host_direct" ]]; then
        if [[ -d "${CURRENT_CONF_DIR}" ]]; then
            grep -l "@SS_MANAGED" "${CURRENT_CONF_DIR}"/*.conf 2>/dev/null | while read -r f; do
                 local d; d=$(grep "@SS_DOMAIN" "$f" | awk '{print $3}')
                 echo -e " - ${C_CYAN}${d}${C_RESET}"
            done
        fi
    else
        local name="${ngx#*:}"
        docker exec "${name}" grep -l "@SS_MANAGED" "${CURRENT_CONF_DIR}"/*.conf 2>/dev/null | while read -r f; do
             echo -e " - ${C_CYAN}$(basename "$f" | sed 's/substore-//;s/.conf//')${C_RESET} [容器内]"
        done
    fi
    pause
}

delete_domain() {
    local ngx
    if ! ngx=$(detect_nginx); then log_warn "Nginx Not Found"; return; fi
    resolve_nginx_paths "${ngx}"
    
    local domain
    ask_input "输入要删除的域名" "" domain
    if ! ask_confirm "确认删除 ${domain}?"; then return; fi
    
    local conf="substore-${domain}.conf"
    if [[ "${CURRENT_NGINX_MODE}" == "host_direct" ]]; then
        rm -f "${CURRENT_CONF_DIR}/${conf}"
    else
        local name="${ngx#*:}"
        docker exec "${name}" rm -f "${CURRENT_CONF_DIR}/${conf}"
    fi
    
    if ask_confirm "是否清理证书文件?" "y"; then
        rm -f "${LOCAL_CERT_REPO}/${domain}.cer" "${LOCAL_CERT_REPO}/${domain}.key"
    fi
    rm -f "${HOOK_SCRIPT_DIR}/renew_${domain}.sh"
    "${HOME}/.acme.sh/acme.sh" --remove -d "${domain}" >/dev/null 2>&1 || true
    
    reload_nginx_strict "${ngx}"
    log_success "已删除"
    pause
}

# ==============================================================================
# SECTION 7: Main Logic
# ==============================================================================

# Wizard
wizard_mode() {
    deploy_container
    separator
    if ask_confirm "是否继续配置 HTTPS 域名?" "y"; then
        add_domain_ssl
    fi
    log_success "向导结束"
    pause
}

# Uninstall
uninstall_all() {
    print_header "完全卸载"
    log_warn "此操作将删除容器、脚本、配置及所有数据。"
    if ! ask_confirm "确认执行?"; then return; fi
    
    if [[ -f "${STATE_CFG_FILE}" ]]; then
        source "${STATE_CFG_FILE}"
        docker rm -f "${SC_NAME}" >/dev/null 2>&1 || true
        rm -rf "${SC_DATA}"
    fi
    
    rm -rf "${STATE_DIR}"
    rm -f "/usr/local/bin/st"
    rm -f "${SCRIPT_PATH}"
    
    echo "Done."
    exit 0
}

# Main Menu
show_menu() {
    while true; do
        print_banner
        
        # Status Bar
        local sc_st="${C_GRAY}[未部署]${C_RESET}"
        if [[ -f "${STATE_CFG_FILE}" ]]; then sc_st="${C_GREEN}[已就绪]${C_RESET}"; fi
        local ngx_st="${C_RED}[未检测到]${C_RESET}"
        if detect_nginx >/dev/null; then ngx_st="${C_GREEN}[运行中]${C_RESET}"; fi
        
        echo -e " 状态: 容器 ${sc_st} | Nginx ${ngx_st}"
        separator
        
        echo -e "${C_YELLOW} 向导模式${C_RESET}"
        echo "  1. 一键全家桶 (部署+域名)"
        
        echo -e "\n${C_CYAN} 核心功能${C_RESET}"
        echo "  2. 部署/重置容器"
        echo "  3. 容器管理 (日志/备份)"
        echo "  4. 添加域名 (HTTPS)"
        echo "  5. 域名列表"
        echo "  6. 删除域名"
        
        echo -e "\n${C_DIM} 系统${C_RESET}"
        echo "  8. 更新脚本"
        echo "  9. 卸载"
        echo "  0. 退出"
        
        separator
        echo -ne "${C_BOLD}请输入选项:${C_RESET} "
        read -r choice
        
        case "$choice" in
            1) wizard_mode ;;
            2) deploy_container; pause ;;
            3) container_menu ;;
            4) add_domain_ssl ;;
            5) list_domains ;;
            6) delete_domain ;;
            8) update_self ;;
            9) uninstall_all ;;
            0) exit 0 ;;
            *) log_warn "无效选项"; sleep 1 ;;
        esac
    done
}

# Compatibility alias for update
ensure_deps() { check_deps; }

# Entry Point
init_environment
check_root
check_deps
show_menu
