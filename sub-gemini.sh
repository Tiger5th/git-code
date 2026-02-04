#!/usr/bin/env bash
# ==============================================================================
# Project: Sub-Store Operations Platform (Titanium Edition)
# Version: 2.0.0.5
# Author: Gemini & Tiger5th
# Build Date: 2026-01-28
#
# Changelog 2.0.0.5 [CRITICAL FIX]:
#   [Fix] P0: Fixed script crash/exit loop caused by 'set -o pipefail'.
#             Ensured grep/ls commands return true even when no files are found.
#             Preventing "grep: exit code 1" from killing the script.
#   [Fix] P1: Added protections for backup listing and domain counting.
# ==============================================================================

# --- Kernel Parameter Configuration ---
set -o errexit   # Exit immediately if a command exits with a non-zero status
set -o pipefail  # Return value of a pipeline is the status of the last command to exit with a non-zero status
set -o nounset   # Treat unset variables as an error

# ==============================================================================
# SECTION 1: Global Constants & Configuration
# ==============================================================================

# Meta Information
readonly SCRIPT_VER="2.0.0.5"
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

# Nginx Standard Paths
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
readonly C_GRAY="\033[90m" 

readonly C_BG_BLACK="\033[40m"
readonly C_BG_RED="\033[41m"
readonly C_BG_GREEN="\033[42m"
readonly C_BG_YELLOW="\033[43m"
readonly C_BG_BLUE="\033[44m"
readonly C_BG_PURPLE="\033[45m"
readonly C_BG_CYAN="\033[46m"
readonly C_BG_WHITE="\033[47m"

# Global State Variables
CURRENT_NGINX_MODE=""
CURRENT_NGINX_TARGET=""
CURRENT_CONF_DIR=""
CURRENT_CERT_DIR=""
CONF_MODE=""

# ==============================================================================
# SECTION 2: Low-Level Utility Functions & Environment Handlers
# ==============================================================================

init_environment() {
    mkdir -p "${STATE_DIR}" "${HOOK_SCRIPT_DIR}" "${LOCAL_CERT_REPO}" "${BACKUP_DIR}" "${TEMP_DIR}"
    if [[ ! -f "${LOG_FILE}" ]]; then
        touch "${LOG_FILE}"
        chmod 600 "${LOG_FILE}"
    fi
    rm -rf "${TEMP_DIR:?}"/*
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

separator() {
    local width=65
    local char="-" 
    if [[ -n "${1:-}" ]]; then width=$1; fi
    printf "${C_DIM}%${width}s${C_RESET}\n" | tr " " "${char}"
}

print_header() {
    local title="$1"
    echo -e "\n${C_CYAN}${C_BOLD}>>> ${title}${C_RESET}"
    separator
}

# Advanced Spinner with TTY detection and graceful degradation
spinner() {
    local pid=$1
    local task_name="$2"
    local delay=0.1
    local spinstr='|/-\'
    
    # SAFEGUARD: Check if we are running in an interactive terminal and have `tput`
    if [[ ! -t 1 ]] || ! command -v tput >/dev/null 2>&1; then
        echo -n "  ${C_CYAN}${task_name}...${C_RESET} "
        wait "$pid"
        local exit_code=$?
        if [[ $exit_code -eq 0 ]]; then
            echo -e "${C_GREEN}[完成]${C_RESET}"
            log_write "TASK_OK" "${task_name}"
            return 0
        else
            echo -e "${C_RED}[失败]${C_RESET}"
            log_write "TASK_FAIL" "${task_name} (Exit Code: $exit_code)"
            return 1
        fi
    fi
    
    # Interactive mode logic
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

pause() {
    echo -e "\n${C_GRAY}按 ${C_BOLD}Enter${C_RESET}${C_GRAY} 键继续...${C_RESET}"
    read -r
}

draw_table() {
    local title="$1"
    shift
    echo -e "${C_BOLD}${title}${C_RESET}"
    separator
    printf "${C_CYAN}%-18s${C_RESET} | %s\n" "项目 (ITEM)" "值 (VALUE)"
    separator
    for row in "$@"; do
        local key="${row%%|*}"
        local val="${row#*|}"
        printf "${C_CYAN}%-18s${C_RESET} | ${C_WHITE}%s${C_RESET}\n" "$key" "$val"
    done
    separator
}

print_banner() {
    clear
    echo -e "${C_CYAN}"
    cat << "EOF"
   _____       __        _____ __                 
  / ___/__  __/ /_      / ___// /_____  ________  
  \__ \/ / / / __ \_____\__ \/ __/ __ \/ ___/ _ \ 
 ___/ / /_/ / /_/ /_____/ /_/ /_/ /_/ / /  /  __/ 
/____/\__,_/_.___/     /____/\__/\____/_/   \___/  
==================================================                                      
EOF
    echo -e "${C_RESET}"
    echo -e "   ${C_BOLD}高级运维综合控制台${C_RESET} ${C_PURPLE}v${SCRIPT_VER}${C_RESET} | ${C_BLUE}Titanium Edition${C_RESET}"
    separator
}

# ==============================================================================
# SECTION 3: Robust Input Gateway (Safe Injection Prevention)
# ==============================================================================

# Highly secure input validation. Replaces eval with printf -v.
ask_input() {
    local prompt_text="$1"
    local default_val="$2"
    local result_var="$3"
    local regex="${4:-}"
    local input_val
    local max_retries=3
    local try=0

    while true; do
        echo -ne "${C_BOLD}${prompt_text}${C_RESET}"
        if [[ -n "$default_val" ]]; then
            echo -ne " [默认: ${C_CYAN}${default_val}${C_RESET}]"
        fi
        echo -ne ": "
        read -r input_val
        
        if [[ -z "$input_val" ]]; then input_val="$default_val"; fi
        
        # Unified cancellation logic (q/Q)
        if [[ "$input_val" == "q" || "$input_val" == "Q" ]]; then
            log_warn "用户已取消当前操作。"
            return 1
        fi
        
        # Regex validation if provided
        if [[ -n "$regex" ]]; then
            if [[ ! "$input_val" =~ $regex ]]; then
                ((try++))
                log_warn "输入格式无效! ($try/$max_retries) - 请重试或输入 'q' 取消。"
                if [[ $try -ge $max_retries ]]; then die "错误次数过多，流程安全终止。"; fi
                continue
            fi
        fi
        
        # P0 FIX: Safe variable assignment using printf (avoids eval injection)
        printf -v "$result_var" "%s" "$input_val"
        break
    done
    return 0
}

ask_confirm() {
    local msg="$1"
    local default="${2:-N}"
    local yn
    echo -ne "${C_YELLOW}${msg}${C_RESET} (y/n/q) [${default}]: "
    read -r yn
    if [[ -z "$yn" ]]; then yn="$default"; fi
    # Treat 'q' as negative/cancel
    if [[ "$yn" =~ ^[Qq]$ ]]; then return 1; fi 
    if [[ "$yn" =~ ^[Yy]$ ]]; then return 0; else return 1; fi
}

prompt_port() {
    local label="$1"
    local def="$2"
    local var="$3"
    ask_input "$label" "$def" "$var" "^[0-9]+$" || return 1
    local val=${!var}
    if [[ $val -lt 1 || $val -gt 65535 ]]; then
        log_warn "端口号必须在 1-65535 之间，请重新输入。"
        prompt_port "$label" "$def" "$var"
    fi
}

prompt_domain() {
    local label="$1"
    local var="$2"
    ask_input "$label" "" "$var" "^[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$"
}

# ==============================================================================
# SECTION 4: System Management & Diagnostics
# ==============================================================================

check_root() {
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then die "脚本需要 Root 权限运行。"; fi
}

check_deps() {
    local deps=("curl" "grep" "awk" "socat" "tar" "openssl" "jq")
    local missing=0
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null; then missing=1; fi
    done
    if ! command -v docker >/dev/null; then missing=1; fi
    if [[ ! -f "${HOME}/.acme.sh/acme.sh" ]]; then missing=1; fi

    if [[ $missing -eq 0 ]]; then return 0; fi

    print_header "系统环境自动修补 (检测到缺失依赖)"
    local install_cmd=""
    if command -v apt-get >/dev/null; then install_cmd="DEBIAN_FRONTEND=noninteractive apt-get update -y && apt-get install -y"
    elif command -v yum >/dev/null; then install_cmd="yum install -y"
    elif command -v apk >/dev/null; then install_cmd="apk add"
    fi
    
    if [[ -n "$install_cmd" ]]; then
        eval "${install_cmd} curl grep awk socat tar openssl jq" >/dev/null 2>&1 &
        spinner $! "安装基础系统工具包"
    fi

    if ! command -v docker >/dev/null; then
        curl -fsSL https://get.docker.com | sh >/dev/null 2>&1 &
        spinner $! "安装 Docker Engine"
        systemctl enable --now docker >/dev/null 2>&1 || true
    fi

    if [[ ! -f "${HOME}/.acme.sh/acme.sh" ]]; then
        curl https://get.acme.sh | sh -s email=substore@example.com >/dev/null 2>&1 &
        spinner $! "安装 ACME.sh 证书管理工具"
    fi
    log_success "所有依赖环境已准备就绪"
}

open_firewall_port() {
    local port="$1"
    log_info "检查防火墙配置 (端口: $port)..."
    if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
        ufw allow "${port}/tcp" >/dev/null 2>&1
    fi
    if command -v firewall-cmd >/dev/null && systemctl is-active --quiet firewalld; then
        firewall-cmd --permanent --add-port="${port}/tcp" >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
    fi
    if command -v iptables >/dev/null; then
        if ! iptables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null; then
            iptables -I INPUT -p tcp --dport "$port" -j ACCEPT
        fi
    fi
}

check_path_safety() {
    local path="$1"
    if [[ "$path" == "/" || "$path" == "/root" || "$path" == "/home" || 
          "$path" == "/usr" || "$path" == "/var" || "$path" == "/etc" || 
          "$path" == "/bin" || "$path" == "/tmp" ]]; then
        die "系统安全保护：禁止操作宿主机高危路径 [$path]"
    fi
    if [[ -z "$path" ]]; then die "路径变量为空，已拦截。"; fi
}

update_self() {
    print_header "脚本在线更新"
    log_info "正在连接 GitHub 获取最新版本..."
    local temp_file="${TEMP_DIR}/update.sh"
    
    if curl -sL "${UPDATE_URL}?t=$(date +%s)" -o "${temp_file}"; then
        if ! grep -q "SCRIPT_VER" "${temp_file}"; then die "下载校验失败，文件不完整。"; fi
        sed -i 's/\r$//' "${temp_file}"
        if [[ -f "${SCRIPT_PATH}" ]]; then cp "${SCRIPT_PATH}" "${SCRIPT_PATH}.bak"; fi
        mv "${temp_file}" "${SCRIPT_PATH}"
        chmod +x "${SCRIPT_PATH}"
        log_success "更新成功！准备重启脚本..."
        sleep 1
        exec "${SCRIPT_PATH}"
    else
        die "更新下载失败，请检查网络连接。"
    fi
}

install_shortcut_silent() {
    cat > /usr/local/bin/st <<SH
#!/usr/bin/env bash
exec ${SCRIPT_PATH} "\$@"
SH
    chmod +x /usr/local/bin/st
}

run_system_diagnostics() {
    print_header "宿主机资源诊断"
    
    # 1. CPU/Load
    local load
    load=$(uptime | awk -F'[a-z]:' '{ print $2 }' | xargs)
    
    # 2. Memory
    local mem_total mem_used mem_pct
    mem_total=$(free -m | awk '/^Mem:/ {print $2}')
    mem_used=$(free -m | awk '/^Mem:/ {print $3}')
    mem_pct=$(awk "BEGIN {printf \"%.1f\", ($mem_used/$mem_total)*100}")
    
    # 3. Disk Space (Root)
    local disk_avail disk_pct
    disk_avail=$(df -h / | awk 'NR==2 {print $4}')
    disk_pct=$(df -h / | awk 'NR==2 {print $5}')
    
    # 4. Docker Service
    local docker_st="Not Running"
    if systemctl is-active --quiet docker; then docker_st="${C_GREEN}Active${C_RESET}"; fi
    
    draw_table "系统快照" \
        "负载情况 (Load)|${load}" \
        "内存使用 (Mem)|${mem_used}MB / ${mem_total}MB (${mem_pct}%)" \
        "磁盘剩余 (Disk)|${disk_avail} (已用: ${disk_pct})" \
        "Docker 服务|${docker_st}"
    pause
}

# ==============================================================================
# SECTION 5: Docker Container Management & Backup Matrix
# ==============================================================================

deploy_container() {
    check_deps
    if [[ -f "${STATE_CFG_FILE}" ]]; then
        source "${STATE_CFG_FILE}"
        log_warn "系统检测到已存在的实例配置: ${SC_NAME}"
        if ! ask_confirm "是否确认删除旧容器并重新部署? (此操作不会删除数据)" "n"; then return; fi
    fi
    
    print_header "Sub-Store 实例部署向导"
    local c_name h_port data_dir backend_path
    ask_input "请输入容器名称" "${NAME_DEFAULT}" c_name || return
    
    while true; do
        prompt_port "请输入宿主机映射端口 (仅绑 127.0.0.1)" "${HOST_PORT_DEFAULT}" h_port || return
        if check_port_available "${h_port}"; then break; else
            log_warn "端口 ${h_port} 已被占用。"
            if ask_confirm "坚持使用该端口强制部署?"; then break; fi
        fi
    done
    
    ask_input "请输入数据持久化目录" "${DATA_DEFAULT}" data_dir || return
    check_path_safety "${data_dir}"
    local rand_path="/$(openssl rand -hex 12)"
    ask_input "请输入前端访问安全路径" "${rand_path}" backend_path || return
    
    draw_table "部署配置确认" \
        "容器名称|${c_name}" \
        "监听端口|127.0.0.1:${h_port}" \
        "数据目录|${data_dir}" \
        "安全入口|${backend_path}"
    if ! ask_confirm "参数无误，确认立即启动部署?"; then return; fi
    
    mkdir -p "${data_dir}"
    if docker ps -a --format '{{.Names}}' | grep -qx "${c_name}"; then
        log_warn "移除旧容器: ${c_name}"
        docker rm -f "${c_name}" >/dev/null 2>&1
    fi
    
    log_info "正在启动 Docker 容器..."
    if docker run -it -d --restart=always --name "${c_name}" \
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
        log_success "容器部署完成并已启动。"
    else
        die "容器启动失败，请检查 Docker 日志。"
    fi
}

check_port_available() {
    local port="$1"
    if command -v netstat >/dev/null; then netstat -tuln | grep -q ":${port} " && return 1;
    elif command -v ss >/dev/null; then ss -tuln | grep -q ":${port} " && return 1; fi
    return 0
}

container_menu() {
    if [[ ! -f "${STATE_CFG_FILE}" ]]; then log_warn "未部署实例，请先执行部署。"; pause; return; fi
    source "${STATE_CFG_FILE}"
    while true; do
        clear
        print_header "容器运维管理: ${SC_NAME}"
        echo " 1. 查看连接信息 (URL/Port)"
        echo " 2. 实时查看容器日志 (按 Ctrl+C 退出)"
        echo " 3. 重启容器实例"
        echo " 4. 更新程序镜像 (Pull & Recreate)"
        echo " 5. 进入高级备份中枢"
        echo " 6. 完全卸载当前实例"
        echo -e "\n ${C_DIM}0. 返回上一级 / q=退出${C_RESET}"
        separator
        local choice
        read -r -p "请输入选项: " choice
        case "$choice" in
            1) draw_table "连接详情" "容器名|${SC_NAME}" "内部端口|${SC_PORT}" "后台路径|${SC_BACKEND}" "本地访问|http://127.0.0.1:${SC_PORT}${SC_BACKEND}"; pause ;;
            2) 
               echo -e "\n${C_BG_YELLOW}${C_BLACK} >>> 按 Ctrl+C 停止查看日志并返回此菜单 <<< ${C_RESET}\n"
               docker logs -f --tail 100 "${SC_NAME}" || true
               ;;
            3) 
               docker restart "${SC_NAME}" >/dev/null && log_success "重启成功。"
               pause ;;
            4) 
               log_info "Pulling latest image: ${IMAGE_DEFAULT}..."
               docker pull "${IMAGE_DEFAULT}"
               docker rm -f "${SC_NAME}" >/dev/null 2>&1
               # Relaunch using saved state
               docker run -it -d --restart=always --name "${SC_NAME}" \
                    -p "${BIND_DEFAULT}:${SC_PORT}:${CONT_PORT_DEFAULT}" \
                    -v "${SC_DATA}:/opt/app/data" \
                    -e "SUB_STORE_FRONTEND_BACKEND_PATH=${SC_BACKEND}" \
                    -e "SUB_STORE_BODY_JSON_LIMIT=${JSON_LIMIT_DEFAULT}" \
                    "${IMAGE_DEFAULT}" >/dev/null
               log_success "镜像升级完毕。"
               pause ;;
            5) backup_management_menu ;;
            6) uninstall_container; return ;;
            0|q|Q) return ;;
        esac
    done
}

backup_management_menu() {
    source "${STATE_CFG_FILE}"
    while true; do
        clear
        print_header "数据备份与灾难恢复中心"
        echo " 当前数据路径: ${SC_DATA}"
        echo " 备份存储路径: ${BACKUP_DIR}"
        separator
        echo " 1. 创建即时快照 (Snapshot)"
        echo " 2. 列出所有可用备份"
        echo " 3. 从备份恢复数据 (Restore)"
        echo " 4. 清理旧备份"
        echo -e "\n ${C_DIM}0. 返回上一级 / q=退出${C_RESET}"
        separator
        local b_choice
        read -r -p "请输入选项: " b_choice
        case "$b_choice" in
            1) backup_data "${SC_DATA}"; pause ;;
            2) 
               echo -e "\n${C_BOLD}可用备份列表:${C_RESET}"
               # FIX: grep || true to prevent pipefail crash if empty
               ls -lh "${BACKUP_DIR}" | grep "tar.gz" || echo "暂无备份文件。"
               pause ;;
            3) restore_data "${SC_DATA}"; pause ;;
            4) 
               if ask_confirm "将清空所有历史备份，确认?"; then rm -f "${BACKUP_DIR}"/*.tar.gz; log_success "已清空。"; fi
               pause ;;
            0|q|Q) return ;;
        esac
    done
}

backup_data() {
    local dir="$1"
    local bak="ss_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
    log_info "正在打包数据目录..."
    if tar -czf "${BACKUP_DIR}/${bak}" -C "$(dirname "$dir")" "$(basename "$dir")"; then
        log_success "备份创建成功: ${BACKUP_DIR}/${bak}"
    else
        log_err "备份失败。"
    fi
}

restore_data() {
    local target_dir="$1"
    local backups=()
    for f in "${BACKUP_DIR}"/*.tar.gz; do
        [[ -e "$f" ]] && backups+=("$(basename "$f")")
    done
    
    if [[ ${#backups[@]} -eq 0 ]]; then log_warn "没有找到任何备份。"; return; fi
    
    echo "选择要恢复的备份:"
    for i in "${!backups[@]}"; do
        echo " [$i] ${backups[$i]}"
    done
    local sel
    ask_input "请输入序号 (0-$((${#backups[@]}-1)))" "" sel "^[0-9]+$" || return
    if [[ $sel -ge 0 && $sel -lt ${#backups[@]} ]]; then
        local sel_file="${BACKUP_DIR}/${backups[$sel]}"
        if ask_confirm "警告: 此操作将覆盖现有数据并重启容器，是否继续?"; then
            docker stop "${SC_NAME}" >/dev/null
            rm -rf "${target_dir:?}"/*
            tar -xzf "${sel_file}" -C "$(dirname "$target_dir")"
            docker start "${SC_NAME}" >/dev/null
            log_success "恢复完成并重启容器。"
        fi
    else
        log_err "无效的序号。"
    fi
}

uninstall_container() {
    source "${STATE_CFG_FILE}"
    if ! ask_confirm "确认卸载容器 ${SC_NAME}? (不可逆)"; then return; fi
    docker rm -f "${SC_NAME}" >/dev/null
    if ask_confirm "是否同时删除挂载的数据目录 ${SC_DATA}? (选 y 彻底清空)"; then 
        check_path_safety "${SC_DATA}"; 
        rm -rf "${SC_DATA}"; 
    fi
    rm -f "${STATE_CFG_FILE}"
    log_success "卸载完成。"
}

# ==============================================================================
# SECTION 6: Nginx & SSL Mastery (High Robustness)
# ==============================================================================

detect_nginx() {
    if command -v docker >/dev/null; then
        local c_names="nginx openresty"
        for name in $c_names; do
            # FIX: grep logic in if condition is safe, but explicit checks are better
            if docker ps --format '{{.Names}}' | grep -qx "${name}"; then echo "docker:${name}"; return 0; fi
        done
    fi
    if pgrep -x nginx >/dev/null 2>&1; then echo "host:system"; return 0; fi
    return 1
}

resolve_nginx_paths() {
    local ngx="$1"
    local type="${ngx%%:*}"
    local name="${ngx#*:}"
    
    CURRENT_CONF_DIR="/etc/nginx/conf.d"
    CURRENT_CERT_DIR="/etc/nginx/certs"
    CONF_MODE="host_direct"

    if [[ "$type" == "docker" ]]; then
        local net_mode
        net_mode=$(docker inspect "${name}" --format '{{.HostConfig.NetworkMode}}')
        if [[ "${net_mode}" != "host" ]]; then die "Nginx 容器必须使用 Host 网络模式才能反代本地端口!"; fi
        
        # FIX: pipefail might kill script if grep fails here. Use || true logic inside $() or check exit code
        if docker inspect "${name}" --format '{{range .Mounts}}{{.Source}} {{end}}' | grep -q "${LION_CONF_DIR}"; then
            CURRENT_CONF_DIR="${LION_CONF_DIR}"
            CURRENT_CERT_DIR="${LION_CERT_DIR}"
            CONF_MODE="host_direct"
        else
            CURRENT_CONF_DIR="${C_CONF_DIR}"
            CURRENT_CERT_DIR="${C_CERT_DIR}"
            CONF_MODE="docker_cp"
        fi
    else
        if [[ -d "${LION_CONF_DIR}" ]]; then
            CURRENT_CONF_DIR="${LION_CONF_DIR}"
            CURRENT_CERT_DIR="${LION_CERT_DIR}"
        fi
    fi
    CURRENT_NGINX_TARGET="$name"
}

add_domain_ssl() {
    check_deps
    if [[ ! -f "${STATE_CFG_FILE}" ]]; then log_warn "未找到 Sub-Store 部署信息，请先部署容器。"; pause; return; fi
    source "${STATE_CFG_FILE}"
    
    local ngx ngx_name
    if ! ngx=$(detect_nginx); then
        log_warn "未自动检测到 Nginx"
        while true; do
            ask_input "请手动输入 Nginx 容器名 (输入 q 取消)" "" ngx_name || return
            # P1 FIX: Validate manual container name existence
            if docker ps --format '{{.Names}}' | grep -qx "$ngx_name"; then
                ngx="docker:$ngx_name"
                break
            else
                log_warn "错误: 在 Docker 中未找到名为 '${ngx_name}' 的容器，请检查拼写或重新输入。"
            fi
        done
    fi
    resolve_nginx_paths "${ngx}"
    
    local domain
    prompt_domain "请输入要绑定的域名" domain || return
    
    local acme_mode="standalone"
    local webroot_path=""
    if [[ -d "${LION_WEBROOT_DIR}" ]]; then
        acme_mode="webroot"
        webroot_path="${LION_WEBROOT_DIR}"
    fi
    
    draw_table "SSL 域名配置摘要" "域名|${domain}" "Nginx模式|${CONF_MODE}" "写入路径|${CURRENT_CONF_DIR}" "签发模式|${acme_mode}"
    if ! ask_confirm "确认开始申请证书及写入配置?"; then return; fi
    
    local acme="${HOME}/.acme.sh/acme.sh"
    local acme_home="${ACME_HOME:-${HOME}/.acme.sh}"
    if [[ -f "${HOME}/.acme.sh/account.conf" ]]; then
        local conf_home
        conf_home=$(grep -E '^(LE_WORKING_DIR|DEFAULT_HOME|LE_CONFIG_HOME)=' "${HOME}/.acme.sh/account.conf" \
            | tail -n 1 | cut -d= -f2- | tr -d '"')
        if [[ -n "${conf_home}" ]]; then acme_home="${conf_home}"; fi
    fi
    mkdir -p "${LOCAL_CERT_REPO}"
    log_info "正在向 Let's Encrypt 申请证书 (可能需要1-2分钟)..."

    # Handle existing domain key (RSA/ECC) to avoid acme.sh hard-fail
    local domain_key="${acme_home}/${domain}/${domain}.key"
    local domain_key_ecc="${acme_home}/${domain}_ecc/${domain}.key"
    local acme_key_flag=""
    if [[ -f "${domain_key}" || -f "${domain_key_ecc}" ]]; then
        if ask_confirm "检测到已存在域名密钥，是否覆盖? (选 y 重新生成)" "n"; then
            acme_key_flag="--force"
        else
            if "${acme}" --help 2>/dev/null | grep -q -- "--reuse-key"; then
                acme_key_flag="--reuse-key"
                log_info "将复用已有密钥继续申请。"
            else
                log_warn "当前 acme.sh 版本不支持 --reuse-key。为安全起见已取消操作。"
                return
            fi
        fi
    fi
    
    if [[ "${acme_mode}" == "webroot" ]]; then
        "$acme" --issue -d "${domain}" --webroot "${webroot_path}" --server letsencrypt ${acme_key_flag} || die "证书申请失败 (Webroot)"
    else
        local type="${ngx%%:*}"
        local name="${ngx#*:}"
        trap 'ensure_nginx_running "$type" "$name"' EXIT
        stop_nginx_service "$type" "$name"
        open_firewall_port "80"
        if ! "$acme" --issue --standalone -d "${domain}" --server letsencrypt ${acme_key_flag}; then die "证书申请失败 (Standalone)"; fi
        trap - EXIT
        ensure_nginx_running "$type" "$name"
    fi
    
    # Generate Reload Hook
    local hook_file="${HOOK_SCRIPT_DIR}/renew_${domain}.sh"
    generate_hook "${ngx}" "${domain}" "${hook_file}"
    
    # Install cert via acme.sh to local repo
    "$acme" --install-cert -d "${domain}" \
        --key-file "${LOCAL_CERT_REPO}/${domain}.key" \
        --fullchain-file "${LOCAL_CERT_REPO}/${domain}.cer" \
        --reloadcmd "${hook_file}" >> "${LOG_FILE}" 2>&1
    
    # Trigger initial hook to copy to Nginx
    bash "${hook_file}"
    
    # Write configuration and reload
    write_nginx_conf "${ngx}" "${domain}"
    reload_nginx_strict "${ngx}"
    open_firewall_port "443"
    
    log_success "SSL 配置圆满完成! 访问地址: https://${domain}${SC_BACKEND}"
    pause
}

stop_nginx_service() {
    local type="$1"
    local name="$2"
    if [[ "$type" == "docker" ]]; then docker stop "$name" >/dev/null
    else if command -v systemctl >/dev/null; then systemctl stop nginx; else nginx -s stop; fi; fi
}

ensure_nginx_running() {
    local type="$1"
    local name="$2"
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
# Hook for ${domain} - Auto Managed by Sub-Store Script
EOF
    if [[ "${CONF_MODE}" == "host_direct" ]]; then
        echo "cp '${LOCAL_CERT_REPO}/${domain}.cer' '${CURRENT_CERT_DIR}/'" >> "${file}"
        echo "cp '${LOCAL_CERT_REPO}/${domain}.key' '${CURRENT_CERT_DIR}/'" >> "${file}"
    else
        echo "docker cp '${LOCAL_CERT_REPO}/${domain}.cer' '${name}:${CURRENT_CERT_DIR}/'" >> "${file}"
        echo "docker cp '${LOCAL_CERT_REPO}/${domain}.key' '${name}:${CURRENT_CERT_DIR}/'" >> "${file}"
    fi
    
    echo -e "\n# Reload Routine" >> "${file}"
    if [[ "$type" == "docker" ]]; then
        echo "docker exec ${name} nginx -t && docker exec ${name} nginx -s reload" >> "${file}"
    else
        echo "nginx -t && (systemctl reload nginx || nginx -s reload)" >> "${file}"
    fi
    chmod +x "${file}"
}

# P1 FIX: Enhanced Nginx configuration with missing WebSocket/Proxy Headers
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
# Generate Date: $(date "+%Y-%m-%d %H:%M:%S")

server {
    listen 80;
    server_name ${domain};
    location / { return 301 https://\$host\$request_uri; }
}

server {
    listen 443 ssl http2;
    server_name ${domain};
    
    ssl_certificate ${CURRENT_CERT_DIR}/${domain}.cer;
    ssl_certificate_key ${CURRENT_CERT_DIR}/${domain}.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    add_header Strict-Transport-Security "max-age=63072000" always;
    
    location / {
        proxy_pass http://127.0.0.1:${SC_PORT};
        
        # P1 FIX: Enhanced Proxy Headers for WebSockets and App Correctness
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Real-IP \$remote_addr;
        
        # Prevent timeouts on long ops
        proxy_read_timeout 300;
        proxy_send_timeout 300;
    }
}
EOF
)
    if [[ "${CONF_MODE}" == "host_direct" ]]; then
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
    log_info "测试配置并重载 Nginx..."
    if [[ "$type" == "docker" ]]; then
        if docker exec "${name}" nginx -t; then 
            docker exec "${name}" nginx -s reload; 
            log_success "Reloaded successfully."
        else 
            die "Nginx 配置测试失败，操作回滚或中断。"
        fi
    else
        if nginx -t; then 
            if command -v systemctl >/dev/null; then systemctl reload nginx; else nginx -s reload; fi; 
            log_success "Reloaded successfully."
        else 
            die "Nginx 配置测试失败，操作回滚或中断。"
        fi
    fi
}

list_domains() {
    local ngx count=0
    if ! ngx=$(detect_nginx); then log_warn "未检测到 Nginx，无法列出。"; pause; return; fi
    resolve_nginx_paths "${ngx}"
    print_header "已纳管的 HTTPS 域名列表"
    
    # FIX: Ensure pipelined grep doesn't trigger errexit if no files found
    if [[ "${CONF_MODE}" == "host_direct" ]]; then
        if [[ -d "${CURRENT_CONF_DIR}" ]]; then
            while IFS= read -r f; do
                 [[ -z "$f" ]] && continue
                 local d; d=$(grep "@SS_DOMAIN" "$f" | awk '{print $3}')
                 echo -e " - ${C_GREEN}${d}${C_RESET} [路径: $f]"
                 ((count++))
            done < <(grep -l "@SS_MANAGED" "${CURRENT_CONF_DIR}"/*.conf 2>/dev/null || true)
        fi
    else
        local name="${ngx#*:}"
        while IFS= read -r f; do
             [[ -z "$f" ]] && continue
             echo -e " - ${C_GREEN}$(basename "$f" | sed 's/substore-//;s/.conf//')${C_RESET} [容器内映射]"
             ((count++))
        done < <(docker exec "${name}" grep -l "@SS_MANAGED" "${CURRENT_CONF_DIR}"/*.conf 2>/dev/null || true)
    fi
    
    if [[ $count -eq 0 ]]; then echo -e " ${C_DIM}(暂无通过脚本配置的域名)${C_RESET}"; fi
    pause
}

delete_domain() {
    local ngx domain conf clean_lvl
    if ! ngx=$(detect_nginx); then log_warn "Nginx Not Found"; pause; return; fi
    resolve_nginx_paths "${ngx}"
    
    ask_input "请输入要删除的域名 (输入 q 取消)" "" domain || return
    if ! ask_confirm "高危操作：确认从 Nginx 配置中删除域名 ${domain}?"; then return; fi
    
    conf="substore-${domain}.conf"
    local type="${ngx%%:*}"
    local name="${ngx#*:}"

    # 1. Remove Nginx Config
    if [[ "${CONF_MODE}" == "host_direct" ]]; then
        rm -f "${CURRENT_CONF_DIR}/${conf}"
    else
        docker exec "${name}" rm -f "${CURRENT_CONF_DIR}/${conf}"
    fi

    # 2. P1 FIX: Comprehensive Certificate Cleanup
    echo -e "\n${C_BOLD}请选择证书文件清理级别:${C_RESET}"
    echo " 1) 仅清理本地库缓存 (推荐，安全)"
    echo " 2) 同时清理 Nginx 目标配置目录中的文件 (深度清理)"
    echo " 3) 保留证书文件 (仅删除反代配置)"
    ask_input "选择清理模式" "1" clean_lvl "^[1-3]$" || return

    local acme_home="${ACME_HOME:-${HOME}/.acme.sh}"
    if [[ -f "${HOME}/.acme.sh/account.conf" ]]; then
        local conf_home
        conf_home=$(grep -E '^(LE_WORKING_DIR|DEFAULT_HOME|LE_CONFIG_HOME)=' "${HOME}/.acme.sh/account.conf" \
            | tail -n 1 | cut -d= -f2- | tr -d '"')
        if [[ -n "${conf_home}" ]]; then acme_home="${conf_home}"; fi
    fi

    case "$clean_lvl" in
        1)
            rm -f "${LOCAL_CERT_REPO}/${domain}.cer" "${LOCAL_CERT_REPO}/${domain}.key"
            ;;
        2)
            rm -f "${LOCAL_CERT_REPO}/${domain}.cer" "${LOCAL_CERT_REPO}/${domain}.key"
            if [[ "${CONF_MODE}" == "host_direct" ]]; then
                rm -f "${CURRENT_CERT_DIR}/${domain}.cer" "${CURRENT_CERT_DIR}/${domain}.key"
            else
                docker exec "${name}" rm -f "${CURRENT_CERT_DIR}/${domain}.cer" "${CURRENT_CERT_DIR}/${domain}.key"
            fi
            # Also remove acme.sh domain key to avoid reuse/overwrite prompt
            rm -rf "${acme_home}/${domain}" "${acme_home}/${domain}_ecc"
            ;;
        3)
            log_info "保留证书文件不变。"
            ;;
    esac

    # 3. ACME.sh Cleanup
    rm -f "${HOOK_SCRIPT_DIR}/renew_${domain}.sh"
    "${HOME}/.acme.sh/acme.sh" --remove -d "${domain}" >/dev/null 2>&1 || true
    
    # 4. Reload
    reload_nginx_strict "${ngx}"
    log_success "域名 ${domain} 已从系统中移除。"
    pause
}

# ==============================================================================
# SECTION 7: Advanced TUI Sub-menus & Routing
# ==============================================================================

# UX FIX: Group Domain Options
domain_management_menu() {
    while true; do
        clear
        print_header "Nginx 与域名管理控制台"
        echo " 1. 添加新的 HTTPS 域名配置 (自动申请 SSL)"
        echo " 2. 查看当前已配置域名列表"
        echo " 3. 删除指定域名配置"
        echo -e "\n ${C_DIM}0. 返回主菜单 / q=退出${C_RESET}"
        separator
        local choice
        read -r -p "请输入选项: " choice
        case "$choice" in
            1) add_domain_ssl ;;
            2) list_domains ;;
            3) delete_domain ;;
            0|q|Q) return ;;
        esac
    done
}

wizard_mode() {
    deploy_container
    separator
    if ask_confirm "第一阶段完成。是否立即进入第二阶段: 配置 HTTPS 域名?" "y"; then add_domain_ssl; fi
    log_success "全家桶向导执行结束。"
    pause
}

uninstall_all() {
    print_header "完全清理程序"
    if ! ask_confirm "警告: 此操作将删除脚本创建的所有容器、挂载目录及配置文件。确认执行? (y/q)"; then return; fi
    if [[ -f "${STATE_CFG_FILE}" ]]; then
        source "${STATE_CFG_FILE}"
        docker rm -f "${SC_NAME}" >/dev/null 2>&1 || true
        rm -rf "${SC_DATA}"
    fi
    rm -rf "${STATE_DIR}" "/usr/local/bin/st" "${SCRIPT_PATH}"
    echo -e "${C_GREEN}所有资源清理完毕，感谢您的使用。${C_RESET}"
    exit 0
}

# UX FIX: Enhanced Main Menu Status Bar
get_status_metrics() {
    # 1. Container Status
    SC_STATUS="${C_GRAY}[未部署]${C_RESET}"
    SC_PORT_LBL="N/A"
    SC_PATH_LBL="N/A"
    if [[ -f "${STATE_CFG_FILE}" ]]; then
        source "${STATE_CFG_FILE}"
        if docker ps --format '{{.Names}}' | grep -qx "${SC_NAME}"; then
            SC_STATUS="${C_GREEN}[运行中]${C_RESET}"
            SC_PORT_LBL="${SC_PORT}"
            SC_PATH_LBL="${SC_BACKEND}"
        else
            SC_STATUS="${C_RED}[已停止/异常]${C_RESET}"
        fi
    fi

    # 2. Nginx Status
    NGX_STATUS="${C_RED}[未检测到]${C_RESET}"
    DOM_COUNT=0
    local ngx
    # detect_nginx handles exit codes internally, so it's safe here
    if ngx=$(detect_nginx); then 
        NGX_STATUS="${C_GREEN}[已连接]${C_RESET}" 
        resolve_nginx_paths "$ngx"
        
        # FIX: The pipefail killer. We must ensure grep failure doesn't crash the script.
        # Logic: If grep finds nothing, it returns 1. 
        # With pipefail, the whole pipe returns 1. 
        # With errexit, script dies.
        # Fix: (grep ... || true)
        if [[ "${CONF_MODE}" == "host_direct" ]]; then
            DOM_COUNT=$(grep -l "@SS_MANAGED" "${CURRENT_CONF_DIR}"/*.conf 2>/dev/null | wc -l || true)
        else
            local name="${ngx#*:}"
            DOM_COUNT=$(docker exec "${name}" grep -l "@SS_MANAGED" "${CURRENT_CONF_DIR}"/*.conf 2>/dev/null | wc -l || true)
        fi
    fi
}

show_menu() {
    while true; do
        get_status_metrics
        print_banner
        # Enhanced Status Bar
        echo -e " ${C_BOLD}系统状态${C_RESET} | 容器: ${SC_STATUS} | Nginx: ${NGX_STATUS}"
        echo -e " ${C_BOLD}配置指标${C_RESET} | 端口: ${C_CYAN}${SC_PORT_LBL}${C_RESET} | 后台路径: ${C_CYAN}${SC_PATH_LBL}${C_RESET} | 纳管域名: ${C_YELLOW}${DOM_COUNT} 个${C_RESET}"
        separator
        
        echo -e "${C_YELLOW} 快捷向导${C_RESET}"
        echo "  1. 一键全家桶向导 (部署容器 + 域名绑定)"
        
        echo -e "\n${C_CYAN} 功能模块${C_RESET}"
        echo "  2. 部署 / 重新部署容器实例"
        echo "  3. 容器运维管理 (日志/升级/备份)"
        echo "  4. Nginx 与域名管理台 (HTTPS/反代)"
        
        echo -e "\n${C_DIM} 系统工具${C_RESET}"
        echo "  7. 宿主机资源诊断"
        echo "  8. 更新脚本 (自更新)"
        echo "  9. 完全卸载所有资产"
        echo "  0. 退出 (Exit)"
        separator
        
        local choice
        read -r -p "请输入选项: " choice
        case "$choice" in
            1) wizard_mode ;;
            2) deploy_container; pause ;;
            3) container_menu ;;
            4) domain_management_menu ;;
            7) run_system_diagnostics ;;
            8) update_self ;;
            9) uninstall_all ;;
            0|q|Q) 
               echo -e "${C_GREEN}已退出。您可以使用快捷命令 'st' 随时呼出本菜单。${C_RESET}"
               exit 0 ;;
            *) log_warn "无效选项，请重试。"; sleep 1 ;;
        esac
    done
}

# ==============================================================================
# SECTION 8: Execution Entry Point
# ==============================================================================

ensure_deps() { check_deps; }

init_environment
check_root
check_deps
show_menu
