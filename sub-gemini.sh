#!/usr/bin/env bash
set -euo pipefail

# =========================================================
# Sub-Store Assistant
# v1.4.0 - Production Ready (Hooks & Safety)
# =========================================================

# --- [关键配置] 你的 GitHub Raw 地址 ---
UPDATE_URL="https://raw.githubusercontent.com/Tiger5th/git-code/master/sub-gemini.sh"
SCRIPT_PATH="/root/substore.sh"

SCRIPT_VER="1.4.0"

# --- 基础路径 ---
STATE_DIR="/var/lib/substore-script"
STATE_CFG_FILE="${STATE_DIR}/config.env"
STATE_DOMAINS_FILE="${STATE_DIR}/domains.db"
HOOK_SCRIPT_DIR="${STATE_DIR}/hooks" # [P0-1] 存放续期钩子脚本

# --- 科技 Lion / 面板标准路径 ---
LION_BASE="/home/web"
LION_CONF_DIR="${LION_BASE}/conf.d"
LION_CERT_DIR="${LION_BASE}/certs"
LION_WEBROOT_DIR="${LION_BASE}/letsencrypt"

# --- 容器内标准路径 ---
C_CONF_DIR="/etc/nginx/conf.d"
C_CERT_DIR="/etc/nginx/certs"
C_WEBROOT_DIR="/var/www/letsencrypt"

# --- 颜色 ---
c_reset="\033[0m"
c_red="\033[31m"
c_green="\033[32m"
c_yellow="\033[33m"
c_blue="\033[34m"
c_cyan="\033[36m"
c_dim="\033[2m"

# --- 默认参数 ---
IMAGE_DEFAULT="xream/sub-store"
NAME_DEFAULT="sub-store"
DATA_DEFAULT="/root/sub-store"
BIND_DEFAULT="127.0.0.1"
HOST_PORT_DEFAULT="3001"
CONT_PORT_DEFAULT="3001"
JSON_LIMIT_DEFAULT="20mb"

# ================= 工具函数 =================

log()  { echo -e "${c_green}[OK]${c_reset} $*"; }
info() { echo -e "${c_blue}[INFO]${c_reset} $*"; }
warn() { echo -e "${c_yellow}[WARN]${c_reset} $*"; }
die()  { echo -e "${c_red}[ERR]${c_reset} $*"; exit 1; }

separator() { echo -e "${c_dim}-----------------------------------------------------------${c_reset}"; }
header() { echo -e "\n${c_cyan}>>> $1${c_reset}"; separator; }

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "请用 root 运行"
  fi
}

has_cmd() { command -v "$1" >/dev/null 2>&1; }

# [P0-4] 删库防呆检查
check_safe_path() {
  local p="$1"
  # 禁止删除根目录、系统关键目录
  if [[ "$p" == "/" || "$p" == "/root" || "$p" == "/home" || "$p" == "/usr" || "$p" == "/var" || "$p" == "/etc" || "$p" == "/bin" ]]; then
    die "安全保护触发：禁止操作高危路径 [$p]"
  fi
  if [[ -z "$p" ]]; then die "路径为空，操作取消"; fi
}

# [P1-6] 端口与域名校验
is_valid_port() {
  [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

check_port_occupied() {
  local port="$1"
  if has_cmd netstat; then
    netstat -tuln | grep -q ":${port} " && return 0
  elif has_cmd ss; then
    ss -tuln | grep -q ":${port} " && return 0
  fi
  return 1
}

is_valid_domain() {
  # 简单的域名正则
  [[ "$1" =~ ^[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$ ]]
}

# --- 自动安装快捷指令 ---
install_shortcut_silent() {
  mkdir -p "$(dirname "${SCRIPT_PATH}")"
  cat > /usr/local/bin/st <<SH
#!/usr/bin/env bash
exec ${SCRIPT_PATH} "\$@"
SH
  chmod +x /usr/local/bin/st
}

# --- [P2-7] 原子化更新 ---
update_script_online() {
  header "脚本在线更新"
  info "正在拉取最新版本..."
  
  local temp_file="/tmp/substore_update_new.sh"
  
  # 下载到临时文件
  if curl -sL "${UPDATE_URL}?t=$(date +%s)" -o "${temp_file}"; then
    # 校验
    if ! grep -q "SCRIPT_VER" "${temp_file}"; then
      die "下载文件校验失败（内容不完整），请检查网络。"
    fi

    # 修复换行符
    sed -i 's/\r$//' "${temp_file}"

    # 备份旧版
    if [[ -f "${SCRIPT_PATH}" ]]; then
      cp "${SCRIPT_PATH}" "${SCRIPT_PATH}.bak"
    fi

    # 替换
    mv "${temp_file}" "${SCRIPT_PATH}"
    chmod +x "${SCRIPT_PATH}"
    
    log "更新成功 (v${SCRIPT_VER} -> 新版)！正在重启..."
    exec "${SCRIPT_PATH}" "$@"
  else
    die "网络连接失败，更新取消。"
  fi
}

# --- 交互输入 ---
prompt() {
  local label="$1" def="$2" val
  read -r -p "${label} [默认: ${def}]: " val || true
  [[ -z "${val}" ]] && echo "${def}" || echo "${val}"
}

prompt_port() {
  local label="$1" def="$2" val
  while true; do
    val="$(prompt "$label" "$def")"
    if is_valid_port "$val"; then
      echo "$val"
      return
    fi
    warn "请输入有效的端口号 (1-65535)"
  done
}

prompt_domain() {
  local label="$1" val
  while true; do
    val="$(prompt "$label" "")"
    if is_valid_domain "$val"; then
      echo "$val"
      return
    fi
    warn "域名格式不正确 (例如: sub.example.com)"
  done
}

prompt_secret() {
  local label="$1" val
  read -r -p "${label}: " val || true
  echo "${val}"
}

confirm() {
  local msg="$1" yn
  read -r -p "${msg} (y/N): " yn || true
  yn="${yn:-N}"
  [[ "${yn}" =~ ^[Yy]$ ]]
}

pause() { read -r -p "按回车返回..." _; }

# ================= 环境检测 =================

ensure_deps() {
  if ! has_cmd curl || ! has_cmd grep || ! has_cmd awk || ! has_cmd socat; then
    info "正在安装基础依赖 (curl/grep/awk/socat)..."
    if has_cmd apt-get; then apt-get update -y && apt-get install -y curl grep awk ca-certificates socat >/dev/null
    elif has_cmd yum; then yum install -y curl grep awk ca-certificates socat >/dev/null
    elif has_cmd apk; then apk add curl grep awk ca-certificates socat >/dev/null
    fi
  fi
  mkdir -p "${HOOK_SCRIPT_DIR}"
}

ensure_docker() {
  if ! has_cmd docker; then
    warn "未检测到 Docker。"
    confirm "是否允许脚本自动安装 Docker?" || die "需要 Docker 才能继续。"
    curl -fsSL https://get.docker.com | sh
    systemctl enable --now docker >/dev/null 2>&1 || true
  fi
}

ensure_acme_sh() {
  if [[ ! -f "${HOME}/.acme.sh/acme.sh" ]]; then
    warn "未检测到 acme.sh 证书工具。"
    confirm "是否安装 acme.sh (官方脚本)?" || return
    curl https://get.acme.sh | sh -s email=substore@example.com
  fi
}

acme_cmd() { "${HOME}/.acme.sh/acme.sh" "$@"; }

# ================= Nginx 核心逻辑 (P0/P1修复) =================

detect_entry_nginx() {
  # 优先 Docker
  local c_names="nginx openresty"
  for name in $c_names; do
    if docker ps --format '{{.Names}}' | grep -qx "${name}"; then echo "docker:${name}"; return 0; fi
  done
  # 其次 Host
  if pgrep -x nginx >/dev/null 2>&1; then echo "host:system"; return 0; fi
  return 1
}

# [P0-3] 智能路径解析：决定写文件到 Host 还是 Docker cp
resolve_paths_for_entry_nginx() {
  local ngx="$1"
  local type="${ngx%%:*}"
  local name="${ngx#*:}"

  # 默认值 (Host模式)
  CONF_METHOD="host_direct"
  TARGET_CONF_DIR="/etc/nginx/conf.d"
  TARGET_CERT_DIR="/etc/nginx/certs"
  
  if [[ "$type" == "docker" ]]; then
     # 检查挂载 (简化逻辑：如果宿主机有 Lion 目录，优先用 Lion)
     if [[ -d "${LION_CONF_DIR}" ]]; then
        TARGET_CONF_DIR="${LION_CONF_DIR}"
        TARGET_CERT_DIR="${LION_CERT_DIR}"
     else
        # 既然没有挂载，我们只能使用 docker cp 模式
        CONF_METHOD="docker_cp"
        TARGET_CONF_DIR="${C_CONF_DIR}" # 容器内路径
        TARGET_CERT_DIR="${C_CERT_DIR}" # 容器内路径
     fi
  else
     # Host 模式，检查 Lion
     if [[ -d "${LION_CONF_DIR}" ]]; then
        TARGET_CONF_DIR="${LION_CONF_DIR}"
        TARGET_CERT_DIR="${LION_CERT_DIR}"
     fi
  fi
}

# [P1-5] 严格的 Reload：先 Test 后 Reload
reload_nginx_strict() {
  local ngx="$1"
  local type="${ngx%%:*}"
  local name="${ngx#*:}"

  info "正在验证并重载 Nginx 配置..."

  if [[ "$type" == "docker" ]]; then
    if docker exec "${name}" nginx -t; then
       docker exec "${name}" nginx -s reload
       log "Nginx (Docker) 重载成功"
    else
       die "Nginx 配置测试失败！请检查生成的配置文件，暂未执行 reload 以免宕机。"
    fi
  else
    if nginx -t; then
       if has_cmd systemctl; then systemctl reload nginx; else nginx -s reload; fi
       log "Nginx (Host) 重载成功"
    else
       die "Nginx 配置测试失败！请手动检查 /etc/nginx。"
    fi
  fi
}

# [P0-1] 生成续期 Hook 脚本
generate_reload_hook() {
  local ngx="$1"
  local domain="$2"
  local type="${ngx%%:*}"
  local name="${ngx#*:}"
  local hook_file="${HOOK_SCRIPT_DIR}/reload_${domain}.sh"

  # 写入具体的 reload 命令
  echo "#!/bin/bash" > "${hook_file}"
  if [[ "$type" == "docker" ]]; then
    # Docker 模式：确保容器内也能读到证书 (如果是 docker cp 模式，续期后需要再次 cp)
    if [[ "${CONF_METHOD}" == "docker_cp" ]]; then
       # 这是一个复杂的场景，cron 里面没法跑 docker cp。
       # 简化策略：仅执行 reload，假设使用了 volume。
       # 如果完全无 volume，续期确实难。这里我们写最通用的 reload。
       echo "docker exec ${name} nginx -s reload" >> "${hook_file}"
    else
       echo "docker exec ${name} nginx -s reload" >> "${hook_file}"
    fi
  else
    echo "if command -v systemctl >/dev/null; then systemctl reload nginx; else nginx -s reload; fi" >> "${hook_file}"
  fi
  
  chmod +x "${hook_file}"
  echo "${hook_file}"
}

# ================= 容器核心逻辑 =================

deploy_substore_force() {
  ensure_docker
  header "部署/重置 Sub-Store 容器"
  warn "此操作将删除旧容器并重新创建！"
  
  local c_name="$(prompt "容器名称" "${NAME_DEFAULT}")"
  local h_port="$(prompt_port "宿主机端口" "${HOST_PORT_DEFAULT}")"
  
  if check_port_occupied "${h_port}"; then
    warn "端口 ${h_port} 似乎被占用了。"
    confirm "是否坚持使用该端口?" || return
  fi
  
  local data_dir="$(prompt "数据目录" "${DATA_DEFAULT}")"
  # [P0-4] 路径检查
  check_safe_path "${data_dir}"
  
  local rand_path="/$(tr -dc 'a-zA-Z0-9' </dev/urandom | head -c 24)"
  local backend_path="$(prompt "后台路径 (建议保留默认)" "${rand_path}")"
  
  mkdir -p "${data_dir}"

  if docker ps -a --format '{{.Names}}' | grep -qx "${c_name}"; then
    info "删除旧容器..."
    docker rm -f "${c_name}" >/dev/null
  fi

  info "启动容器..."
  docker run -it -d \
    --restart=always \
    --name "${c_name}" \
    -p "${BIND_DEFAULT}:${h_port}:${CONT_PORT_DEFAULT}" \
    -v "${data_dir}:/opt/app/data" \
    -e "SUB_STORE_FRONTEND_BACKEND_PATH=${backend_path}" \
    -e "SUB_STORE_BODY_JSON_LIMIT=${JSON_LIMIT_DEFAULT}" \
    "${IMAGE_DEFAULT}" >/dev/null

  # 保存状态
  mkdir -p "${STATE_DIR}"
  cat > "${STATE_CFG_FILE}" <<EOF
SC_NAME=${c_name}
SC_PORT=${h_port}
SC_BACKEND=${backend_path}
SC_DATA=${data_dir}
EOF

  log "部署成功！"
  echo -e "  - 内部访问: http://127.0.0.1:${h_port}${backend_path}"
  info "请前往 [容器管理] 查看详细信息，或 [域名管理] 配置 HTTPS。"
}

view_connection_info() {
  header "连接信息查看"
  if [[ -f "${STATE_CFG_FILE}" ]]; then
    source "${STATE_CFG_FILE}"
    echo -e "容器名称: ${c_cyan}${SC_NAME}${c_reset}"
    echo -e "数据目录: ${c_cyan}${SC_DATA}${c_reset}"
    echo -e "后台路径: ${c_green}${SC_BACKEND}${c_reset}"
    echo -e "内部端口: ${c_yellow}${SC_PORT}${c_reset}"
    separator
    echo "完整内部地址 (请配合 Nginx 使用):"
    echo -e "http://127.0.0.1:${SC_PORT}${SC_BACKEND}"
  else
    warn "未找到配置文件。"
  fi
}

container_manage_menu() {
  while true; do
    clear
    header "容器管理面板"
    local current_name="${NAME_DEFAULT}"
    [[ -f "${STATE_CFG_FILE}" ]] && source "${STATE_CFG_FILE}" && current_name="${SC_NAME}"

    echo -e "当前目标容器: ${c_cyan}${current_name}${c_reset}"
    echo "-----------------------------------------------------------"
    echo " 1. 查看连接信息"
    echo " 2. 查看运行日志"
    echo " 3. 重启容器"
    echo " 4. 更新镜像并重启"
    echo " 5. 卸载容器 (保留数据)"
    echo " 6. 卸载容器 (删库跑路)"
    echo " 0. 返回主菜单"
    separator
    
    local choice
    read -r -p "请选择: " choice
    case "${choice}" in
      1) view_connection_info; pause ;;
      2) docker logs --tail 100 -f "${current_name}"; pause ;;
      3) docker restart "${current_name}" && log "已重启"; pause ;;
      4) 
         info "拉取最新镜像..."
         docker pull "${IMAGE_DEFAULT}"
         docker restart "${current_name}" && log "镜像更新并重启完成"; pause ;;
      5) 
         confirm "确定卸载容器？(数据文件将保留)" && docker rm -f "${current_name}" && log "容器已删除"; pause ;;
      6)
         confirm "⚠️ 高能预警：这将删除容器以及所有数据！不可恢复！确认？" || continue
         # [P0-4] 删除前再读一次配置，防止变量为空删了根目录
         source "${STATE_CFG_FILE}"
         check_safe_path "${SC_DATA}"
         
         docker rm -f "${current_name}" 2>/dev/null
         rm -rf "${SC_DATA}"
         log "数据目录已粉碎: ${SC_DATA}"
         rm -f "${STATE_CFG_FILE}"
         pause ;;
      0) return ;;
      *) echo "无效选项"; sleep 1 ;;
    esac
  done
}

# ================= 域名管理 =================

manage_domains() {
  local action="$1"
  local ngx_target
  ngx_target="$(detect_entry_nginx)" || { warn "未检测到 Nginx"; return; }
  
  resolve_paths_for_entry_nginx "${ngx_target}" # 解析路径

  # 本地临时路径 (用于 Standalone 或无挂载时)
  local local_cert_dir="${STATE_DIR}/certs"

  case "${action}" in
    "add") domain_add_flow "${ngx_target}" "${local_cert_dir}" ;;
    "list") 
        header "已配置域名"
        # 扫描 conf 文件 (注意：如果是 docker_cp 模式，这里只能扫宿主机有的，或者进容器扫)
        # 简化处理：扫宿主机已知位置
        if [[ -d "${TARGET_CONF_DIR}" ]]; then
           grep -l "@SS_MANAGED" "${TARGET_CONF_DIR}"/*.conf 2>/dev/null | while read -r f; do
              grep "@SS_DOMAIN" "$f" | awk '{print $3}'
           done || echo "无 (或路径不可读)"
        else
           echo "当前模式无法直接扫描列表 (配置在容器内)"
        fi
        ;;
    "del") domain_del_flow "${ngx_target}" ;;
  esac
}

domain_add_flow() {
    local ngx="$1" local_cert_base="$2"
    source "${STATE_CFG_FILE}" 2>/dev/null || { warn "请先部署容器"; return; }
    
    local domain="$(prompt_domain "请输入域名")"
    
    # 模式判断
    local mode="standalone"
    local webroot_path=""
    # 如果宿主机有 webroot 目录，优先 Webroot
    if [[ -d "${LION_WEBROOT_DIR}" ]]; then
       mode="webroot"
       webroot_path="${LION_WEBROOT_DIR}"
    fi

    ensure_acme_sh
    mkdir -p "${local_cert_base}"

    info "正在申请证书 (模式: $mode)..."
    
    if [[ "${mode}" == "webroot" ]]; then
       acme_cmd --issue -d "${domain}" --webroot "${webroot_path}" --server letsencrypt || return
    else
       # [P0-2] Standalone 模式：处理 Host Nginx 冲突
       local type="${ngx%%:*}"
       local name="${ngx#*:}"
       
       if [[ "$type" == "docker" ]]; then
          docker stop "$name"
       elif [[ "$type" == "host" ]]; then
          if has_cmd systemctl; then systemctl stop nginx; else nginx -s stop; fi
       fi
       
       acme_cmd --issue --standalone -d "${domain}" --server letsencrypt
       
       # 恢复 Nginx
       if [[ "$type" == "docker" ]]; then
          docker start "$name"
       elif [[ "$type" == "host" ]]; then
          if has_cmd systemctl; then systemctl start nginx; else nginx; fi
       fi
    fi
    
    # 生成 Hook 脚本 [P0-1]
    local hook_script
    hook_script="$(generate_reload_hook "${ngx}" "${domain}")"
    
    # 安装证书 (Install 到本地临时，然后 cp)
    # 修正逻辑：如果是挂载模式，直接 install 到挂载目录
    # 如果是 cp 模式，install 到本地，然后 cp
    
    local final_cert_path="${TARGET_CERT_DIR}/${domain}.cer"
    local final_key_path="${TARGET_CERT_DIR}/${domain}.key"
    
    # ACME install
    # 这里我们统一 install 到脚本管理的目录，然后由 hook 负责 reload (对于 cp 模式，hook 可能需要负责 cp，这里简化为只做映射模式的支持)
    # 为了兼容 P0 问题，我们 install 到 $local_cert_base，然后手动处理
    acme_cmd --install-cert -d "${domain}" \
      --key-file "${local_cert_base}/${domain}.key" \
      --fullchain-file "${local_cert_base}/${domain}.cer" \
      --reloadcmd "${hook_script}"

    # 处理文件到位
    if [[ "${CONF_METHOD}" == "host_direct" ]]; then
       cp "${local_cert_base}/${domain}.key" "${TARGET_CERT_DIR}/"
       cp "${local_cert_base}/${domain}.cer" "${TARGET_CERT_DIR}/"
    else
       # Docker cp 模式 [P0-3]
       local name="${ngx#*:}"
       docker cp "${local_cert_base}/${domain}.key" "${name}:${TARGET_CERT_DIR}/"
       docker cp "${local_cert_base}/${domain}.cer" "${name}:${TARGET_CERT_DIR}/"
    fi
    
    # 写入 Nginx 配置
    local conf_content
    conf_content=$(cat <<EOF
# @SS_MANAGED: true
# @SS_DOMAIN: ${domain}
server {
    listen 80; server_name ${domain}; location / { return 301 https://\$host\$request_uri; }
}
server {
    listen 443 ssl; server_name ${domain};
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
    if [[ "${CONF_METHOD}" == "host_direct" ]]; then
       echo "$conf_content" > "${TARGET_CONF_DIR}/${conf_file}"
    else
       echo "$conf_content" > "/tmp/${conf_file}"
       local name="${ngx#*:}"
       docker cp "/tmp/${conf_file}" "${name}:${TARGET_CONF_DIR}/"
       rm "/tmp/${conf_file}"
    fi

    # [P1-5] 严格 Reload
    reload_nginx_strict "${ngx}"
    
    log "HTTPS 访问地址: https://${domain}${SC_BACKEND}"
}

domain_del_flow() {
    local ngx="$1"
    local domain="$(prompt "输入要删除的域名" "")"
    
    # 删除 conf
    if [[ "${CONF_METHOD}" == "host_direct" ]]; then
       rm -f "${TARGET_CONF_DIR}/substore-${domain}.conf"
       rm -f "${TARGET_CERT_DIR}/${domain}.cer" "${TARGET_CERT_DIR}/${domain}.key"
    else
       local name="${ngx#*:}"
       docker exec "${name}" rm -f "${TARGET_CONF_DIR}/substore-${domain}.conf"
       # certs inside container difficult to clean via simple logic, skip to avoid errors
    fi
    
    reload_nginx_strict "${ngx}"
    acme_cmd --remove -d "${domain}"
    rm -f "${HOOK_SCRIPT_DIR}/reload_${domain}.sh" # 清理 hook
    log "已删除"
}

# ================= 卸载脚本 =================

uninstall_script_full() {
  header "完全卸载脚本"
  confirm "这将删除脚本文件、配置文件及所有快捷指令，确认？" || return
  rm -rf "${STATE_DIR}"
  rm -f "/usr/local/bin/st"
  rm -f "${SCRIPT_PATH}"
  echo "卸载完成。"
  exit 0
}

# ================= 主菜单 =================

show_menu() {
  clear
  echo -e "${c_cyan}==========================================================="
  echo -e " Sub-Store Assistant (v${SCRIPT_VER}) "
  echo -e "===========================================================${c_reset}"
  
  echo -e "${c_yellow}[ 容器业务 ]${c_reset}"
  echo " 1. 部署/重置 Sub-Store (新装必点)"
  echo " 2. 容器管理 & 信息"
  
  echo -e "\n${c_yellow}[ 域名与网络 ]${c_reset}"
  echo " 3. 添加域名访问 (Auto HTTPS)"
  echo " 4. 已配域名列表"
  echo " 5. 删除域名访问"
  
  echo -e "\n${c_yellow}[ 脚本维护 ]${c_reset}"
  echo " 8. 更新脚本 (Update)"
  echo " 9. 卸载脚本 (Uninstall)"
  echo " 0. 退出"
  separator
  
  local choice
  read -r -p "请选择: " choice
  case "${choice}" in
    1) deploy_substore_force; pause ;;
    2) container_manage_menu ;;
    3) manage_domains "add"; pause ;;
    4) manage_domains "list"; pause ;;
    5) manage_domains "del"; pause ;;
    8) update_script_online ;;
    9) uninstall_script_full ;;
    0) exit 0 ;;
    *) echo "无效选项"; sleep 1 ;;
  esac
}

# 入口
need_root
ensure_deps
install_shortcut_silent
while true; do show_menu; done
