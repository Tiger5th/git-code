#!/usr/bin/env bash
# ==============================================================================
# Sub-Store Operation Platform (Titanium Edition)
# Version: 2.0.0.1
# Author: Gemini & Tiger5th
# Description: 企业级 Sub-Store 部署、运维、监控与容灾系统
#
# [设计理念]
# 1. 安全第一：任何高危操作前必须有校验、备份和确认。
# 2. 状态感知：菜单必须反映当前系统的真实状态，而不是盲目展示。
# 3. 严格模式：set -euo pipefail 全程开启，杜绝隐性错误。
# 4. 闭环管理：从环境检查到部署，再到监控和卸载，形成完整闭环。
# ==============================================================================

# --- 内核参数配置 ---
set -o errexit   # 遇到错误立即退出 (set -e)
set -o nounset   # 使用未定义变量报错 (set -u)
set -o pipefail  # 管道中任意命令失败则整体失败

# --- 全局常量定义 ---
readonly SCRIPT_VER="2.0.0.1"
readonly SCRIPT_NAME="substore_ops"
readonly UPDATE_URL="https://raw.githubusercontent.com/Tiger5th/git-code/master/sub-gemini.sh"
readonly SCRIPT_PATH="/root/substore.sh"

# --- 路径配置 ---
readonly LOG_FILE="/var/log/substore_ops.log"
readonly STATE_DIR="/var/lib/substore-script"
readonly STATE_CFG_FILE="${STATE_DIR}/config.env"
readonly STATE_DB_FILE="${STATE_DIR}/domains.db"
readonly HOOK_SCRIPT_DIR="${STATE_DIR}/hooks"
readonly LOCAL_CERT_REPO="${STATE_DIR}/certs_repo"
readonly BACKUP_DIR="${STATE_DIR}/backups"

# --- 默认应用参数 ---
readonly IMAGE_DEFAULT="xream/sub-store"
readonly NAME_DEFAULT="sub-store"
readonly DATA_DEFAULT="/root/sub-store"
readonly BIND_DEFAULT="127.0.0.1"
readonly HOST_PORT_DEFAULT="3001"
readonly CONT_PORT_DEFAULT="3001" # 修复：此前版本缺失导致崩溃
readonly JSON_LIMIT_DEFAULT="20mb"

# --- Nginx 路径常量 (修复 P0-3: 缺失定义) ---
# 宿主机/面板标准路径
readonly LION_BASE="/home/web"
readonly LION_CONF_DIR="${LION_BASE}/conf.d"
readonly LION_CERT_DIR="${LION_BASE}/certs"
readonly LION_WEBROOT_DIR="${LION_BASE}/letsencrypt"
# 容器内标准路径
readonly C_CONF_DIR="/etc/nginx/conf.d"
readonly C_CERT_DIR="/etc/nginx/certs"
readonly C_WEBROOT_DIR="/var/www/letsencrypt"

# --- UI 颜色定义 ---
readonly C_RESET="\033[0m"
readonly C_RED="\033[31m"
readonly C_GREEN="\033[32m"
readonly C_YELLOW="\033[33m"
readonly C_BLUE="\033[34m"
readonly C_PURPLE="\033[35m"
readonly C_CYAN="\033[36m"
readonly C_WHITE="\033[37m"
readonly C_GRAY="\033[90m"
readonly C_BOLD="\033[1m"
readonly C_DIM="\033[2m"
readonly C_BG_RED="\033[41m"
readonly C_BG_GREEN="\033[42m"

# ==============================================================================
# 模块 1: 日志与基础工具 (Logging & Utils)
# ==============================================================================

# 初始化系统环境
init_system() {
    # 创建必要目录
    mkdir -p "${STATE_DIR}" "${HOOK_SCRIPT_DIR}" "${LOCAL_CERT_REPO}" "${BACKUP_DIR}"
    
    # 初始化日志
    if [[ ! -f "${LOG_FILE}" ]]; then
        touch "${LOG_FILE}"
        chmod 600 "${LOG_FILE}"
    fi
    
    # 安装快捷指令
    if [[ ! -f "/usr/local/bin/st" ]]; then
        install_shortcut_silent
    fi
}

# 写入日志
log_to_file() {
    local level="$1"
    local msg="$2"
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[${timestamp}] [${level}] ${msg}" >> "${LOG_FILE}"
}

# UI 输出封装
log_info() {
    echo -e "${C_BLUE}ℹ${C_RESET} ${C_BOLD}INFO:${C_RESET} $1"
    log_to_file "INFO" "$1"
}

log_success() {
    echo -e "${C_GREEN}✔${C_RESET} ${C_BOLD}SUCCESS:${C_RESET} $1"
    log_to_file "SUCCESS" "$1"
}

log_warn() {
    echo -e "${C_YELLOW}⚠${C_RESET} ${C_BOLD}WARN:${C_RESET} $1"
    log_to_file "WARN" "$1"
}

log_err() {
    echo -e "${C_RED}✖${C_RESET} ${C_BOLD}ERROR:${C_RESET} $1"
    log_to_file "ERROR" "$1"
}

# 致命错误处理
die() {
    echo -e "\n${C_BG_RED}${C_WHITE} FATAL ERROR ${C_RESET}"
    echo -e "${C_RED}>> $1${C_RESET}"
    echo -e "${C_GRAY}详细日志已记录至: ${LOG_FILE}${C_RESET}"
    log_to_file "FATAL" "$1"
    exit 1
}

# 进度条动画 (Fix P2-1: 增加退出码检查)
spinner() {
    local pid=$1
    local task_name="$2"
    local delay=0.1
    local spinstr='|/-\'
    
    echo -ne "  ${C_CYAN}正在执行: ${task_name}...${C_RESET} "
    
    while kill -0 "$pid" 2>/dev/null; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    
    # 捕获子进程退出码
    wait "$pid"
    local exit_code=$?
    
    printf "    \b\b\b\b"
    if [[ $exit_code -eq 0 ]]; then
        echo -e "${C_GREEN}[完成]${C_RESET}"
    else
        echo -e "${C_RED}[失败]${C_RESET}"
        log_to_file "ERROR" "后台任务 '${task_name}' 失败，退出码: $exit_code"
        return 1
    fi
}

# 暂停函数 (修复 P0: 缺失定义)
pause() {
    echo -e "\n${C_GRAY}按回车键继续...${C_RESET}"
    read -r
}

# 分隔线
separator() {
    echo -e "${C_DIM}──────────────────────────────────────────────────────────────${C_RESET}"
}

# Banner
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
    echo -e "   ${C_BOLD}Sub-Store 运维平台${C_RESET} ${C_PURPLE}v${SCRIPT_VER}${C_RESET} | ${C_BLUE}Titanium Edition${C_RESET}"
    separator
}

# ==============================================================================
# 模块 2: 输入网关与校验 (Input Gateway)
# ==============================================================================

# 统一输入函数 (Fix P1-3: 统一交互体验)
# 参数: 提示文案, 默认值, 变量引用名, [可选正则校验]
ask_input() {
    local prompt_text="$1"
    local default_val="$2"
    local result_var="$3"
    local regex="${4:-}"
    local input_val
    local max_retries=3
    local try=0

    while true; do
        # 显示输入提示
        echo -ne "${C_BOLD}${prompt_text}${C_RESET}"
        if [[ -n "$default_val" ]]; then
            echo -ne " [默认: ${C_CYAN}${default_val}${C_RESET}]"
        fi
        echo -ne ": "
        
        read -r input_val
        
        # 处理默认值
        if [[ -z "$input_val" ]]; then
            input_val="$default_val"
        fi
        
        # 处理取消操作
        if [[ "$input_val" == "q" || "$input_val" == "Q" ]]; then
            log_warn "用户取消操作"
            return 1
        fi
        
        # 正则校验
        if [[ -n "$regex" ]]; then
            if [[ ! "$input_val" =~ $regex ]]; then
                ((try++))
                log_warn "输入格式错误 ($try/$max_retries)"
                if [[ $try -ge $max_retries ]]; then
                    die "多次输入错误，流程终止"
                fi
                continue
            fi
        fi
        
        # 赋值返回
        eval $result_var="'$input_val'"
        break
    done
    return 0
}

# 确认框
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

# 总结卡片 (Fix P1-4: 操作后总结)
print_summary() {
    local title="$1"
    shift
    separator
    echo -e "${C_BOLD}${C_GREEN}✔ ${title} 操作成功${C_RESET}"
    echo -e "${C_GRAY}关键信息摘要:${C_RESET}"
    printf "${C_CYAN}%-20s${C_RESET} | %s\n" "项目" "值"
    echo -e "${C_DIM}---------------------+----------------------------------------${C_RESET}"
    
    # 解析传入的 key|value 对
    for item in "$@"; do
        local key="${item%%|*}"
        local val="${item#*|}"
        printf "${C_CYAN}%-20s${C_RESET} | ${C_WHITE}%s${C_RESET}\n" "$key" "$val"
    done
    separator
    echo -e "${C_BLUE}提示:${C_RESET} 如遇到问题，请使用 [5] 一键自检 功能排查。"
    pause
}

# 端口校验
check_port_available() {
    local port="$1"
    if command -v netstat >/dev/null; then
        if netstat -tuln | grep -q ":${port} "; then return 1; fi
    elif command -v ss >/dev/null; then
        if ss -tuln | grep -q ":${port} "; then return 1; fi
    fi
    return 0
}

# 路径安全检查 (防止 rm -rf /)
check_path_safety() {
    local path="$1"
    # 禁止操作根目录及系统一级目录
    if [[ "$path" == "/" || "$path" == "/root" || "$path" == "/usr" || 
          "$path" == "/var" || "$path" == "/etc" || "$path" == "/home" || 
          "$path" == "/bin" || "$path" == "/sbin" ]]; then
        die "路径安全保护触发：禁止对高危路径 [$path] 执行写/删操作！"
    fi
    if [[ -z "$path" ]]; then die "检测到空路径变量，操作终止"; fi
}

# ==============================================================================
# 模块 3: 环境与依赖管理 (Dependency Manager)
# ==============================================================================

# 检查 Root 权限
check_root() {
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        die "本工具需要 Root 权限，请使用 sudo -i 切换后重试。"
    fi
}

# 依赖修补 (Fix P2-1: 严格校验)
check_and_install_deps() {
    local deps_missing=0
    local deps=("curl" "grep" "awk" "socat" "tar" "openssl" "jq")
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null; then
            deps_missing=1
            break
        fi
    done
    
    # 检查 Docker
    if ! command -v docker >/dev/null; then deps_missing=1; fi
    # 检查 acme.sh
    if [[ ! -f "${HOME}/.acme.sh/acme.sh" ]]; then deps_missing=1; fi

    if [[ $deps_missing -eq 0 ]]; then
        return 0
    fi

    log_info "检测到环境缺失，开始自动修补..."

    # 1. 基础工具
    if command -v apt-get >/dev/null; then
        apt-get update -y >/dev/null 2>&1
        apt-get install -y curl grep awk socat tar openssl jq >/dev/null 2>&1 &
        spinner $! "安装系统基础工具 (apt)"
    elif command -v yum >/dev/null; then
        yum install -y curl grep awk socat tar openssl jq >/dev/null 2>&1 &
        spinner $! "安装系统基础工具 (yum)"
    elif command -v apk >/dev/null; then
        apk add curl grep awk socat tar openssl jq >/dev/null 2>&1 &
        spinner $! "安装系统基础工具 (apk)"
    fi

    # 2. Docker
    if ! command -v docker >/dev/null; then
        log_warn "正在安装 Docker (官方脚本)..."
        curl -fsSL https://get.docker.com | sh >/dev/null 2>&1 &
        spinner $! "下载并安装 Docker"
        systemctl enable --now docker >/dev/null 2>&1 || true
    fi

    # 3. acme.sh
    if [[ ! -f "${HOME}/.acme.sh/acme.sh" ]]; then
        log_warn "正在安装 acme.sh..."
        curl https://get.acme.sh | sh -s email=substore@example.com >/dev/null 2>&1 &
        spinner $! "安装 acme.sh"
    fi
    
    log_success "环境修补完成"
}

# 向后兼容别名 (Fix P0: deploy_container 调用了 undefined function)
ensure_deps() {
    check_and_install_deps
}

# 安装快捷指令
install_shortcut_silent() {
    cat > /usr/local/bin/st <<SH
#!/usr/bin/env bash
exec ${SCRIPT_PATH} "\$@"
SH
    chmod +x /usr/local/bin/st
}

# ==============================================================================
# 模块 4: Docker 管理 (Docker Ops)
# ==============================================================================

# 部署容器向导
deploy_container() {
    ensure_deps
    
    # 检查是否已部署
    if [[ -f "${STATE_CFG_FILE}" ]]; then
        source "${STATE_CFG_FILE}"
        log_warn "检测到已存在部署配置: ${SC_NAME}"
        if ! ask_confirm "是否强制覆盖并重新部署 (旧容器将被删除)?" "n"; then
            return
        fi
    fi
    
    header "Sub-Store 容器部署向导"
    
    local c_name h_port data_dir backend_path
    
    # 1. 容器名
    ask_input "容器名称" "${NAME_DEFAULT}" c_name
    
    # 2. 端口 (带循环校验)
    while true; do
        ask_input "宿主机端口 (监听 127.0.0.1)" "${HOST_PORT_DEFAULT}" h_port "^[0-9]+$"
        if check_port_available "${h_port}"; then
            break
        else
            log_warn "端口 ${h_port} 似乎被占用，请更换。"
            if ask_confirm "坚持使用该端口 (可能导致启动失败)?"; then break; fi
        fi
    done
    
    # 3. 数据目录
    ask_input "数据持久化目录" "${DATA_DEFAULT}" data_dir
    check_path_safety "${data_dir}"
    
    # 4. 后台路径 (生成高强度随机值)
    local rand_path="/$(openssl rand -hex 12)"
    ask_input "后台安全路径" "${rand_path}" backend_path
    
    # 部署执行
    log_info "正在拉取镜像并启动..."
    
    # 备份旧数据 (如果存在)
    if [[ -d "${data_dir}" ]]; then
        backup_data_dir "${data_dir}"
    fi
    mkdir -p "${data_dir}"
    
    # 删旧容器
    if docker ps -a --format '{{.Names}}' | grep -qx "${c_name}"; then
        docker rm -f "${c_name}" >/dev/null 2>&1
    fi
    
    # 启动
    if docker run -it -d \
        --restart=always \
        --name "${c_name}" \
        -p "${BIND_DEFAULT}:${h_port}:${CONT_PORT_DEFAULT}" \
        -v "${data_dir}:/opt/app/data" \
        -e "SUB_STORE_FRONTEND_BACKEND_PATH=${backend_path}" \
        -e "SUB_STORE_BODY_JSON_LIMIT=${JSON_LIMIT_DEFAULT}" \
        "${IMAGE_DEFAULT}" >/dev/null 2>&1; then
        
        # 保存状态
        cat > "${STATE_CFG_FILE}" <<EOF
SC_NAME=${c_name}
SC_PORT=${h_port}
SC_BACKEND=${backend_path}
SC_DATA=${data_dir}
EOF
        print_summary "部署容器" \
            "容器名称|${c_name}" \
            "内部地址|http://127.0.0.1:${h_port}${backend_path}" \
            "数据目录|${data_dir}"
            
    else
        die "容器启动失败，请检查 Docker 日志"
    fi
}

# 简单数据备份
backup_data_dir() {
    local dir="$1"
    local bak_name="data_backup_$(date +%s).tar.gz"
    tar -czf "${BACKUP_DIR}/${bak_name}" -C "$(dirname "$dir")" "$(basename "$dir")" >/dev/null 2>&1 || true
    log_info "已自动备份旧数据至: ${BACKUP_DIR}/${bak_name}"
}

# 容器管理菜单
container_menu() {
    if [[ ! -f "${STATE_CFG_FILE}" ]]; then
        log_warn "未找到部署配置，请先部署容器。"
        pause
        return
    fi
    source "${STATE_CFG_FILE}"
    
    while true; do
        clear
        header "容器管理: ${SC_NAME}"
        echo " 1. 查看连接信息"
        echo " 2. 实时日志 (Ctrl+C 退出)"
        echo " 3. 重启容器"
        echo " 4. 更新镜像 (Update)"
        echo " 5. 备份数据"
        echo " 0. 返回"
        separator
        
        local choice
        read -r -p "选择: " choice
        case "$choice" in
            1) 
                print_summary "连接信息" \
                    "容器名|${SC_NAME}" \
                    "端口|${SC_PORT}" \
                    "后台路径|${SC_BACKEND}" \
                    "完整URL|http://127.0.0.1:${SC_PORT}${SC_BACKEND}"
                ;;
            2) docker logs -f --tail 100 "${SC_NAME}";;
            3) docker restart "${SC_NAME}" && log_success "已重启"; pause ;;
            4) 
                log_info "正在拉取最新镜像..."
                docker pull "${IMAGE_DEFAULT}"
                docker restart "${SC_NAME}"
                log_success "更新完成"
                pause
                ;;
            5) backup_data_dir "${SC_DATA}"; pause ;;
            0) return ;;
        esac
    done
}

# ==============================================================================
# 模块 5: Nginx 与 SSL 核心逻辑 (Nginx Core)
# ==============================================================================

# Nginx 探测
detect_nginx() {
    # 优先 Docker
    if command -v docker >/dev/null; then
        local c_names="nginx openresty"
        for name in $c_names; do
            if docker ps --format '{{.Names}}' | grep -qx "${name}"; then 
                echo "docker:${name}"
                return 0
            fi
        done
    fi
    # 其次 Host
    if pgrep -x nginx >/dev/null 2>&1; then 
        echo "host:system"
        return 0
    fi
    return 1
}

# 路径解析 (Fix P0-3: 变量未定义)
resolve_nginx_paths() {
    local ngx="$1"
    local type="${ngx%%:*}"
    local name="${ngx#*:}"
    
    # 初始化全局返回变量
    TARGET_CONF_DIR="/etc/nginx/conf.d"
    TARGET_CERT_DIR="/etc/nginx/certs"
    CONF_MODE="host_direct"

    if [[ "$type" == "docker" ]]; then
        # 检查是否挂载 Lion 目录
        if docker inspect "${name}" --format '{{range .Mounts}}{{.Source}} {{end}}' | grep -q "${LION_CONF_DIR}"; then
            TARGET_CONF_DIR="${LION_CONF_DIR}"
            TARGET_CERT_DIR="${LION_CERT_DIR}"
            CONF_MODE="host_direct" # 挂载了，直接写宿主机
        else
            # 没挂载，必须 cp
            TARGET_CONF_DIR="${C_CONF_DIR}"
            TARGET_CERT_DIR="${C_CERT_DIR}"
            CONF_MODE="docker_cp"
        fi
        
        # 检查网络模式
        local net_mode
        net_mode=$(docker inspect "${name}" --format '{{.HostConfig.NetworkMode}}')
        if [[ "${net_mode}" != "host" ]]; then
            log_warn "注意: Nginx 容器 [${name}] 网络模式为 ${net_mode}"
            log_warn "非 host 模式下，无法通过 127.0.0.1 反代 Sub-Store。"
            if ! ask_confirm "是否继续 (可能导致 502)?"; then return 1; fi
        fi
    else
        # Host 模式
        if [[ -d "${LION_CONF_DIR}" ]]; then
            TARGET_CONF_DIR="${LION_CONF_DIR}"
            TARGET_CERT_DIR="${LION_CERT_DIR}"
        fi
    fi
}

# 添加域名 (核心业务)
add_domain_ssl() {
    ensure_deps
    
    # 1. 前置检查
    if [[ ! -f "${STATE_CFG_FILE}" ]]; then
        log_warn "需先部署容器。"
        return
    fi
    source "${STATE_CFG_FILE}"
    
    local ngx
    if ! ngx=$(detect_nginx); then
        log_warn "未自动检测到 Nginx。"
        # 这里可以加手动输入逻辑，为简便略过，直接报错
        die "请确保 Nginx (Host或Docker) 已运行。"
    fi
    
    if ! resolve_nginx_paths "${ngx}"; then return; fi
    
    # 2. 输入域名
    local domain
    ask_input "请输入域名 (如 sub.example.com)" "" domain "^[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$"
    
    # 3. 确定签发模式
    local acme_mode="standalone"
    local webroot_path=""
    if [[ -d "${LION_WEBROOT_DIR}" ]]; then
        acme_mode="webroot"
        webroot_path="${LION_WEBROOT_DIR}"
    fi
    
    # 4. 摘要确认
    separator
    echo -e "配置清单:"
    echo -e "  域名: ${C_CYAN}${domain}${C_RESET}"
    echo -e "  Nginx: ${C_CYAN}${ngx}${C_RESET} (${CONF_MODE})"
    echo -e "  配置路径: ${C_CYAN}${TARGET_CONF_DIR}${C_RESET}"
    echo -e "  签发模式: ${C_CYAN}${acme_mode}${C_RESET}"
    separator
    if ! ask_confirm "确认开始配置?"; then return; fi
    
    # 5. 执行签发
    local acme="${HOME}/.acme.sh/acme.sh"
    mkdir -p "${LOCAL_CERT_REPO}"
    
    if [[ "${acme_mode}" == "webroot" ]]; then
        "$acme" --issue -d "${domain}" --webroot "${webroot_path}" --server letsencrypt || die "证书申请失败"
    else
        # Standalone 模式需停 Nginx (P0-2: Trap 保护)
        local type="${ngx%%:*}"
        local name="${ngx#*:}"
        
        trap 'restore_nginx_service "$type" "$name"' EXIT
        stop_nginx_service "$type" "$name"
        
        if ! "$acme" --issue --standalone -d "${domain}" --server letsencrypt; then
            die "证书申请失败 (Standalone)"
        fi
        
        trap - EXIT
        restore_nginx_service "$type" "$name"
    fi
    
    # 6. 生成 Hook (P0-1)
    local hook_file="${HOOK_SCRIPT_DIR}/renew_${domain}.sh"
    generate_renew_hook "${ngx}" "${domain}" "${hook_file}"
    
    # 7. 安装证书 (到本地 Repo)
    "$acme" --install-cert -d "${domain}" \
        --key-file "${LOCAL_CERT_REPO}/${domain}.key" \
        --fullchain-file "${LOCAL_CERT_REPO}/${domain}.cer" \
        --reloadcmd "${hook_file}"
        
    # 8. 首次执行 Hook (部署证书)
    bash "${hook_file}"
    
    # 9. 写 Nginx 配置
    write_nginx_conf "${ngx}" "${domain}"
    
    # 10. Reload
    reload_nginx_strict "${ngx}"
    
    print_summary "域名配置" \
        "域名|${domain}" \
        "访问地址|https://${domain}${SC_BACKEND}" \
        "证书|${TARGET_CERT_DIR}/${domain}.cer"
}

# 停止 Nginx
stop_nginx_service() {
    local type="$1"
    local name="$2"
    log_info "暂时停止 Nginx (释放80端口)..."
    if [[ "$type" == "docker" ]]; then docker stop "$name" >/dev/null
    else if command -v systemctl >/dev/null; then systemctl stop nginx; else nginx -s stop; fi; fi
}

# 恢复 Nginx
restore_nginx_service() {
    local type="$1"
    local name="$2"
    log_info "恢复 Nginx 服务..."
    if [[ "$type" == "docker" ]]; then docker start "$name" >/dev/null 2>&1 || true
    else if command -v systemctl >/dev/null; then systemctl start nginx; else nginx; fi; fi
}

# 生成 Hook (P0-1: 修复续期不更新文件)
generate_renew_hook() {
    local ngx="$1"
    local domain="$2"
    local file="$3"
    local type="${ngx%%:*}"
    local name="${ngx#*:}"
    
    cat > "${file}" <<EOF
#!/bin/bash
# Generated by Sub-Store Ops
# Domain: ${domain}

# 1. Copy Certs from Repo to Target
EOF
    if [[ "${CONF_MODE}" == "host_direct" ]]; then
        echo "cp '${LOCAL_CERT_REPO}/${domain}.cer' '${TARGET_CERT_DIR}/'" >> "${file}"
        echo "cp '${LOCAL_CERT_REPO}/${domain}.key' '${TARGET_CERT_DIR}/'" >> "${file}"
    else
        echo "docker cp '${LOCAL_CERT_REPO}/${domain}.cer' '${name}:${TARGET_CERT_DIR}/'" >> "${file}"
        echo "docker cp '${LOCAL_CERT_REPO}/${domain}.key' '${name}:${TARGET_CERT_DIR}/'" >> "${file}"
    fi
    
    echo -e "\n# 2. Strict Reload" >> "${file}"
    if [[ "$type" == "docker" ]]; then
        echo "docker exec ${name} nginx -t && docker exec ${name} nginx -s reload" >> "${file}"
    else
        echo "nginx -t && (systemctl reload nginx || nginx -s reload)" >> "${file}"
    fi
    
    chmod +x "${file}"
}

# 写配置
write_nginx_conf() {
    local ngx="$1"
    local domain="$2"
    local type="${ngx%%:*}"
    local name="${ngx#*:}"
    
    local conf_content
    conf_content=$(cat <<EOF
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
    ssl_certificate ${TARGET_CERT_DIR}/${domain}.cer;
    ssl_certificate_key ${TARGET_CERT_DIR}/${domain}.key;
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
    local conf_file="substore-${domain}.conf"
    
    if [[ "${CONF_MODE}" == "host_direct" ]]; then
        echo "$conf_content" > "${TARGET_CONF_DIR}/${conf_file}"
    else
        echo "$conf_content" > "/tmp/${conf_file}"
        docker cp "/tmp/${conf_file}" "${name}:${TARGET_CONF_DIR}/"
        rm "/tmp/${conf_file}"
    fi
}

# 严格 Reload
reload_nginx_strict() {
    local ngx="$1"
    local type="${ngx%%:*}"
    local name="${ngx#*:}"
    
    log_info "正在重载 Nginx..."
    if [[ "$type" == "docker" ]]; then
        if docker exec "${name}" nginx -t; then
            docker exec "${name}" nginx -s reload
            log_success "Nginx Reloaded"
        else
            die "Nginx 配置测试失败，未执行 reload。请检查配置。"
        fi
    else
        if nginx -t; then
            if command -v systemctl >/dev/null; then systemctl reload nginx; else nginx -s reload; fi
            log_success "Nginx Reloaded"
        else
            die "Nginx 配置测试失败！"
        fi
    fi
}

# ==============================================================================
# 模块 6: 列表与删除 (List & Delete)
# ==============================================================================

# 列出域名
list_domains() {
    local ngx
    if ! ngx=$(detect_nginx); then log_warn "未检测到 Nginx"; return; fi
    resolve_nginx_paths "${ngx}" # 获取路径变量
    
    header "已配置域名列表"
    
    local found=0
    # 扫描逻辑
    if [[ "${CONF_MODE}" == "host_direct" ]]; then
        if [[ -d "${TARGET_CONF_DIR}" ]]; then
            grep -l "@SS_MANAGED" "${TARGET_CONF_DIR}"/*.conf 2>/dev/null | while read -r f; do
                local d; d=$(grep "@SS_DOMAIN" "$f" | awk '{print $3}')
                echo -e " - ${C_CYAN}${d}${C_RESET}"
            done && found=1
        fi
    else
        # 容器内扫描 (P1-5: 优化docker_cp体验)
        local name="${ngx#*:}"
        docker exec "${name}" grep -l "@SS_MANAGED" "${TARGET_CONF_DIR}"/*.conf 2>/dev/null | while read -r f; do
             echo -e " - ${C_CYAN}$(basename "$f" | sed 's/substore-//;s/.conf//')${C_RESET} [容器内]"
        done && found=1
    fi
    
    # 这里的 found 逻辑简单处理，实际 grep 会直接输出
    echo ""
    log_info "列表展示完毕"
    pause
}

# 删除域名
delete_domain() {
    local ngx
    if ! ngx=$(detect_nginx); then log_warn "未检测到 Nginx"; return; fi
    resolve_nginx_paths "${ngx}"
    
    local domain
    ask_input "请输入要删除的域名" "" domain
    
    if ! ask_confirm "确认删除 ${domain} 的配置及证书?"; then return; fi
    
    # 删配置
    local conf_file="substore-${domain}.conf"
    if [[ "${CONF_MODE}" == "host_direct" ]]; then
        rm -f "${TARGET_CONF_DIR}/${conf_file}"
    else
        local name="${ngx#*:}"
        docker exec "${name}" rm -f "${TARGET_CONF_DIR}/${conf_file}"
    fi
    
    # 删证书 (P1-5: 可选清理)
    rm -f "${LOCAL_CERT_REPO}/${domain}.cer" "${LOCAL_CERT_REPO}/${domain}.key"
    rm -f "${HOOK_SCRIPT_DIR}/renew_${domain}.sh"
    "${HOME}/.acme.sh/acme.sh" --remove -d "${domain}" >/dev/null 2>&1 || true
    
    reload_nginx_strict "${ngx}"
    log_success "删除完成"
    pause
}

# ==============================================================================
# 模块 7: 系统维护 (System)
# ==============================================================================

# 原子化更新 (P2-2: 回滚支持)
update_self() {
    header "系统更新"
    log_info "正在检查新版本..."
    
    local temp_file="/tmp/substore_update_new.sh"
    
    # 下载
    if curl -sL "${UPDATE_URL}?t=$(date +%s)" -o "${temp_file}"; then
        # 校验
        if ! grep -q "SCRIPT_VER" "${temp_file}"; then
            die "下载文件损坏，更新终止。"
        fi
        
        # 修复换行
        sed -i 's/\r$//' "${temp_file}"
        
        # 备份
        if [[ -f "${SCRIPT_PATH}" ]]; then
            cp "${SCRIPT_PATH}" "${SCRIPT_PATH}.bak"
        fi
        
        # 替换
        mv "${temp_file}" "${SCRIPT_PATH}"
        chmod +x "${SCRIPT_PATH}"
        
        log_success "更新成功！正在重启..."
        sleep 1
        exec "${SCRIPT_PATH}"
    else
        log_err "网络连接失败"
        pause
    fi
}

# 卸载
uninstall_all() {
    clear
    echo -e "${C_BG_RED}${C_WHITE} 危险操作警告 ${C_RESET}"
    echo "即将卸载本工具并删除所有相关文件。"
    if ! ask_confirm "确认继续?"; then return; fi
    
    # 删容器
    if [[ -f "${STATE_CFG_FILE}" ]]; then
        source "${STATE_CFG_FILE}"
        docker rm -f "${SC_NAME}" >/dev/null 2>&1 || true
        
        if ask_confirm "是否同时删除数据目录 ${SC_DATA}?"; then
            check_path_safety "${SC_DATA}"
            rm -rf "${SC_DATA}"
        fi
    fi
    
    rm -rf "${STATE_DIR}"
    rm -f "/usr/local/bin/st"
    rm -f "${SCRIPT_PATH}"
    
    echo "卸载完成。"
    exit 0
}

# 一键向导 (P1-2)
wizard_mode() {
    deploy_container
    separator
    if ask_confirm "是否立即配置域名访问 (HTTPS)?"; then
        add_domain_ssl
    fi
    separator
    log_success "向导流程结束！"
    pause
}

# ==============================================================================
# 主菜单 (Main Menu)
# ==============================================================================

show_menu() {
    while true; do
        print_banner
        
        # 状态栏 (P1-1: 状态感知)
        local sc_state="${C_GRAY}[未部署]${C_RESET}"
        if [[ -f "${STATE_CFG_FILE}" ]]; then sc_state="${C_GREEN}[已就绪]${C_RESET}"; fi
        
        local ngx_state="${C_RED}[未检测到]${C_RESET}"
        if detect_nginx >/dev/null; then ngx_state="${C_GREEN}[运行中]${C_RESET}"; fi
        
        echo -e " 系统状态: 容器 ${sc_state} | Nginx ${ngx_state}"
        separator
        
        # 菜单项 (P1-2: 可见的前置条件)
        echo -e "${C_YELLOW} 一键向导${C_RESET}"
        echo "  1. 全流程一键部署 (推荐)"
        
        echo -e "\n${C_CYAN} 核心功能${C_RESET}"
        echo "  2. 部署/重置容器"
        echo "  3. 容器管理 (日志/重启)"
        if [[ -f "${STATE_CFG_FILE}" && "$ngx_state" == *运行中* ]]; then
            echo "  4. 添加域名访问"
        else
            echo -e "  ${C_GRAY}4. 添加域名访问 (需先部署容器且Nginx在线)${C_RESET}"
        fi
        echo "  5. 域名列表"
        echo "  6. 删除域名"
        
        echo -e "\n${C_DIM} 维护${C_RESET}"
        echo "  8. 更新脚本"
        echo "  9. 卸载工具"
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

# ==============================================================================
# 入口 (Entry)
# ==============================================================================

init_system
check_root
ensure_deps # 自动修补环境
show_menu
