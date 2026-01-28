#!/usr/bin/env bash
set -euo pipefail

# =========================================================
# Sub-Store Assistant
# v1.6.0 - Robustness & UX Visibility
# =========================================================

# --- [关键配置] 你的 GitHub Raw 地址 ---
UPDATE_URL="https://raw.githubusercontent.com/Tiger5th/git-code/master/sub-gemini.sh"
SCRIPT_PATH="/root/substore.sh"

SCRIPT_VER="1.6.0"

# --- 基础路径 ---
STATE_DIR="/var/lib/substore-script"
STATE_CFG_FILE="${STATE_DIR}/config.env"
HOOK_SCRIPT_DIR="${STATE_DIR}/hooks"
LOCAL_CERT_REPO="${STATE_DIR}/certs_repo"

# --- 科技 Lion / 面板标准路径 ---
LION_BASE="/home/web"
LION_CONF_DIR="${LION_BASE}/conf.d"
LION_CERT_DIR="${LION_BASE}/certs"
LION_WEBROOT_DIR="${LION_BASE}/letsencrypt"

# --- 容器内标准路径 ---
C_CONF_DIR="/etc/nginx/conf.d"
C_CERT_DIR="/etc/nginx/certs"

# --- 颜色 ---
c_reset="\033[0m"
c_red="\033[31m"
c_green="\033[32m"
c_yellow="\033[33m"
c_blue="\033[34m"
c_cyan="\033[36m"
c_dim="\033[2m"
c_bold="\033[1m"

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
header() { echo -e "\n${c_cyan}${c_bold}>>> $1${c_reset}"; separator; }

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "请用 root 运行"
  fi
}

has_cmd() { command -v "$1" >/dev/null 2>&1; }

check_safe_path() {
  local p="$1"
  if [[ "$p" == "/" || "$p" == "/root" || "$p" == "/home" || "$p" == "/usr" || "$p" == "/var" || "$p" == "/etc" || "$p" == "/bin" ]]; then
    die "安全保护触发：禁止操作高危路径 [$p]"
  fi
  if [[ -z "$p" ]]; then die "路径为空，操作取消"; fi
}

is_valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }

check_port_occupied() {
  local port="$1"
  if has_cmd netstat; then netstat -tuln | grep -q ":${port} " && return 0;
  elif has_cmd ss; then ss -tuln | grep -q ":${port} " && return 0; fi
  return 1
}

is_valid_domain() { [[ "$1" =~ ^[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$ ]]; }

install_shortcut_silent() {
  mkdir -p "$(dirname "${SCRIPT_PATH}")"
  cat > /usr/local/bin/st <<SH
#!/usr/bin/env bash
exec ${SCRIPT_PATH} "\$@"
SH
  chmod +x /usr/local/bin/st
}

update_script_online() {
  header "脚本在线更新"
  info "正在拉取最新版本..."
  local temp_file="/tmp/substore_update_new.sh"
  if curl -sL "${UPDATE_URL}?t=$(date +%s)" -o "${temp_file}"; then
    if ! grep -q "SCRIPT_VER" "${temp_file}"; then die "下载校验失败，请检查网络。"; fi
    sed -i 's/\r$//' "${temp_file}"
    [[ -f "${SCRIPT_PATH}" ]] && cp "${SCRIPT_PATH}" "${SCRIPT_PATH}.bak"
    mv "${temp_file}" "${SCRIPT_PATH}"
    chmod +x "${SCRIPT_PATH}"
    log "更新成功 (v${SCRIPT_VER} -> 新版)！正在重启..."
    exec "${SCRIPT_PATH}" "$@"
  else
    die "网络连接失败，更新取消。"
  fi
}

# --- 交互优化 ---
prompt() {
  local label="$1" def="$2" val
  read -r -p "${c_bold}${label}${c_reset} [默认: ${def}]: " val || true
  [[ -z "${val}" ]] && echo "${def}" || echo "${val}"
}

prompt_port() {
  local label="$1" def="$2" val
  while true; do
    val="$(prompt "$label" "$def")"
    if is_valid_port "$val"; then echo "$val"; return; fi
    warn "请输入有效的端口号 (1-65535)"
  done
}

prompt_domain() {
  local label="$1" val
  while true; do
    val="$(prompt "$label" "")"
    if is_valid_domain "$val"; then echo "$val"; return; fi
    warn "域名格式不正确 (例如: sub.example.com)"
  done
}

confirm() {
  local msg="$1" yn
  read -r -p "${c_yellow}${msg}${c_reset} (y/N): " yn || true
  yn="${yn:-N}"
  [[ "${yn}" =~ ^[Yy]$ ]]
}

pause() { read -r -p "按回车返回..." _; }

# ================= 环境检测 =================

ensure_deps() {
  if ! has_cmd curl || ! has_cmd grep || ! has_cmd awk || ! has_cmd socat; then
    info "正在安装基础依赖..."
    if has_cmd apt-get; then apt-get update -y && apt-get install -y curl grep awk ca-certificates socat >/dev/null
    elif has_cmd yum; then yum install -y curl grep awk ca-certificates socat >/dev/null
    elif has_cmd apk; then apk add curl grep awk ca-certificates socat >/dev/null
    fi
  fi
  mkdir -p "${HOOK_SCRIPT_DIR}" "${LOCAL_CERT_REPO}"
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
    confirm "是否安装 acme.sh?" || return
    curl https://get.acme.sh | sh -s email=substore@example.com
  fi
}

acme_cmd() { "${HOME}/.acme.sh/acme.sh" "$@"; }

# ================= Nginx 核心逻辑 =================

detect_entry_nginx() {
  # 优先 Docker
  if has_cmd docker; then
    local c_names="nginx openresty"
    for name in $c_names; do
      if docker ps --format '{{.Names}}' | grep -qx "${name}"; then echo "docker:${name}"; return 0; fi
    done
  fi
  # 其次 Host
  if pgrep -x nginx >/dev/null 2>&1; then echo "host:system"; return 0; fi
  return 1
}

# 兜底：手动指定 Nginx
force_nginx_detection() {
  local ngx
  if ngx=$(detect_entry_nginx); then
    echo "$ngx"
  else
    warn "未自动检测到 Nginx (nginx/openresty)。"
    echo "请手动指定："
    echo "  输入容器名 (例如: my-nginx)"
    echo "  或者输入 'host' (使用宿主机 Nginx)"
    local input="$(prompt "Nginx入口" "")"
    if [[ "$input" == "host" ]]; then
       echo "host:system"
    elif [[ -n "$input" ]]; then
       if docker ps --format '{{.Names}}' | grep -qx "${input}"; then
         echo "docker:${input}"
       else
         die "找不到名为 [${input}] 的容器。"
       fi
    else
       die "未指定 Nginx，无法继续。"
    fi
  fi
}

check_docker_nginx_network() {
  local ngx_name="$1"
  local net_mode
  net_mode=$(docker inspect "${ngx_name}" --format '{{.HostConfig.NetworkMode}}')
  if [[ "${net_mode}" != "host" ]]; then
    warn "Nginx 容器 [${ngx_name}] 网络模式为: ${net_mode}"
    die "必须使用 host 网络模式，否则无法反代 127.0.0.1。"
  fi
}

# 智能路径解析 (含 Mount 检测)
resolve_paths_for_entry_nginx() {
  local ngx="$1"
  local type="${ngx%%:*}"
  local name="${ngx#*:}"

  CONF_METHOD="host_direct"
  TARGET_CONF_DIR="/etc/nginx/conf.d"
  TARGET_CERT_DIR="/etc/nginx/certs"
  
  if [[ "$type" == "docker" ]]; then
     check_docker_nginx_network "${name}"
     
     # 检测是否真正挂载了 Lion 目录
     # 简化逻辑：检查 Mounts 中是否有 Source=/home/web/conf.d
     if docker inspect "${name}" --format '{{range .Mounts}}{{.Source}} {{end}}' | grep -q "${LION_CONF_DIR}"; then
        TARGET_CONF_DIR="${LION_CONF_DIR}"
        TARGET_CERT_DIR="${LION_CERT_DIR}"
     else
        # 没挂载 -> 强制 docker cp
        CONF_METHOD="docker_cp"
        TARGET_CONF_DIR="${C_CONF_DIR}"
        TARGET_CERT_DIR="${C_CERT_DIR}"
     fi
  else
     if [[ -d "${LION_CONF_DIR}" ]]; then
        TARGET_CONF_DIR="${LION_CONF_DIR}"
        TARGET_CERT_DIR="${LION_CERT_DIR}"
     fi
  fi
}

generate_renewal_hook() {
  local ngx="$1"
  local domain="$2"
  local type="${ngx%%:*}"
  local name="${ngx#*:}"
  local hook_file="${HOOK_SCRIPT_DIR}/renew_${domain}.sh"
  local cert_file="${domain}.cer"
  local key_file="${domain}.key"

  echo "#!/bin/bash" > "${hook_file}"
  
  # 1. 复制逻辑
  if [[ "${CONF_METHOD}" == "host_direct" ]]; then
     echo "cp '${LOCAL_CERT_REPO}/${cert_file}' '${TARGET_CERT_DIR}/'" >> "${hook_file}"
     echo "cp '${LOCAL_CERT_REPO}/${key_file}' '${TARGET_CERT_DIR}/'" >> "${hook_file}"
  else
     echo "docker cp '${LOCAL_CERT_REPO}/${cert_file}' '${name}:${TARGET_CERT_DIR}/'" >> "${hook_file}"
     echo "docker cp '${LOCAL_CERT_REPO}/${key_file}' '${name}:${TARGET_CERT_DIR}/'" >> "${hook_file}"
  fi
  
  # 2. Reload 逻辑 (带 -t 检测)
  if [[ "$type" == "docker" ]]; then
    echo "if docker exec ${name} nginx -t; then docker exec ${name} nginx -s reload; fi" >> "${hook_file}"
  else
    echo "if nginx -t; then if command -v systemctl >/dev/null; then systemctl reload nginx; else nginx -s reload; fi; fi" >> "${hook_file}"
  fi
  
  chmod +x "${hook_file}"
  echo "${hook_file}"
}

reload_nginx_strict() {
  local ngx="$1"
  local type="${ngx%%:*}"
  local name="${ngx#*:}"
  info "正在验证配置并重载 Nginx..."

  if [[ "$type" == "docker" ]]; then
    if docker exec "${name}" nginx -t; then
       docker exec "${name}" nginx -s reload
       log "Nginx 重载成功"
    else
       die "Nginx 配置测试失败！暂未执行 reload。"
    fi
  else
    if nginx -t; then
       if has_cmd systemctl; then systemctl reload nginx; else nginx -s reload; fi
       log "Nginx 重载成功"
    else
       die "Nginx 配置测试失败！"
    fi
  fi
}

ensure_nginx_restore() {
  local type="$1"
  local name="$2"
  info "恢复 Nginx 服务..."
  if [[ "$type" == "docker" ]]; then docker start "$name" >/dev/null 2>&1 || true
  else if has_cmd systemctl; then systemctl start nginx; else nginx; fi; fi
}

# ================= 业务流程 =================

deploy_substore_flow() {
  ensure_docker
  header "部署/重置 Sub-Store 容器"
  echo -e "此操作将${c_red}删除旧容器${c_reset}并重新创建。数据目录保留。"
  
  local c_name="$(prompt "容器名称" "${NAME_DEFAULT}")"
  local h_port="$(prompt_port "宿主机端口 (127.0.0.1)" "${HOST_PORT_DEFAULT}")"
  if check_port_occupied "${h_port}"; then
    warn "端口 ${h_port} 似乎被占用。"
    confirm "是否坚持使用?" || return
  fi
  local data_dir="$(prompt "数据目录" "${DATA_DEFAULT}")"
  check_safe_path "${data_dir}"
  local rand_path="/$(tr -dc 'a-zA-Z0-9' </dev/urandom | head -c 24)"
  local backend_path="$(prompt "后台安全路径" "${rand_path}")"
  
  separator
  echo -e "配置摘要:"
  echo -e "  容器名: ${c_cyan}${c_name}${c_reset}"
  echo -e "  端口: ${c_cyan}127.0.0.1:${h_port}${c_reset}"
  echo -e "  数据: ${c_cyan}${data_dir}${c_reset}"
  separator
  confirm "确认部署?" || return

  mkdir -p "${data_dir}"
  if docker ps -a --format '{{.Names}}' | grep -qx "${c_name}"; then
    info "删除旧容器..."
    docker rm -f "${c_name}" >/dev/null
  fi
  info "启动容器..."
  docker run -it -d --restart=always --name "${c_name}" \
    -p "${BIND_DEFAULT}:${h_port}:${CONT_PORT_DEFAULT}" \
    -v "${data_dir}:/opt/app/data" \
    -e "SUB_STORE_FRONTEND_BACKEND_PATH=${backend_path}" \
    -e "SUB_STORE_BODY_JSON_LIMIT=${JSON_LIMIT_DEFAULT}" \
    "${IMAGE_DEFAULT}" >/dev/null

  mkdir -p "${STATE_DIR}"
  cat > "${STATE_CFG_FILE}" <<EOF
SC_NAME=${c_name}
SC_PORT=${h_port}
SC_BACKEND=${backend_path}
SC_DATA=${data_dir}
EOF
  log "部署成功！"
}

view_connection_info() {
  header "连接信息"
  if [[ -f "${STATE_CFG_FILE}" ]]; then
    source "${STATE_CFG_FILE}"
    echo -e "  容器: ${c_cyan}${SC_NAME}${c_reset}"
    echo -e "  数据: ${c_cyan}${SC_DATA}${c_reset}"
    echo -e "  后台: ${c_green}${SC_BACKEND}${c_reset}"
    echo -e "  端口: ${c_yellow}${SC_PORT}${c_reset}"
    echo -e "  完整: http://127.0.0.1:${SC_PORT}${SC_BACKEND}"
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
    echo -e "目标容器: ${c_cyan}${current_name}${c_reset}"
    separator
    echo " 1. 查看连接信息"
    echo " 2. 查看日志"
    echo " 3. 重启容器"
    echo " 4. 更新镜像"
    echo " 5. 卸载容器 (保留数据)"
    echo " 6. 卸载容器 (删库)"
    echo " 0. 返回"
    separator
    local choice
    read -r -p "请选择: " choice
    case "${choice}" in
      1) view_connection_info; pause ;;
      2) docker logs --tail 100 -f "${current_name}"; pause ;;
      3) docker restart "${current_name}" && log "已重启"; pause ;;
      4) info "Pulling..."; docker pull "${IMAGE_DEFAULT}"; docker restart "${current_name}"; log "Done"; pause ;;
      5) confirm "卸载容器?" && docker rm -f "${current_name}" && log "Done"; pause ;;
      6) confirm "⚠️ 删除数据和容器?" || continue; source "${STATE_CFG_FILE}"; check_safe_path "${SC_DATA}"; docker rm -f "${current_name}" 2>/dev/null; rm -rf "${SC_DATA}"; rm -f "${STATE_CFG_FILE}"; log "Done"; pause ;;
      0) return ;;
      *) echo "无效选项"; sleep 1 ;;
    esac
  done
}

manage_domains() {
  local action="$1"
  local ngx_target
  ngx_target="$(force_nginx_detection)" || return # 使用手动指定兜底

  resolve_paths_for_entry_nginx "${ngx_target}"

  case "${action}" in
    "add") domain_add_flow "${ngx_target}" ;;
    "list") 
        header "已配置域名"
        if [[ -d "${TARGET_CONF_DIR}" ]]; then
           grep -l "@SS_MANAGED" "${TARGET_CONF_DIR}"/*.conf 2>/dev/null | while read -r f; do
              grep "@SS_DOMAIN" "$f" | awk '{print $3}'
           done || echo "无"
        else
           # 容器内扫描
           local type="${ngx_target%%:*}"
           local name="${ngx_target#*:}"
           if [[ "$type" == "docker" ]]; then
              docker exec "${name}" grep -l "@SS_MANAGED" "${TARGET_CONF_DIR}"/*.conf 2>/dev/null | while read -r f; do
                 echo "[容器内] $(basename $f)"
              done || echo "无"
           fi
        fi
        ;;
    "del") domain_del_flow "${ngx_target}" ;;
  esac
}

domain_add_flow() {
    local ngx="$1"
    source "${STATE_CFG_FILE}" 2>/dev/null || { warn "请先部署容器"; return; }
    
    local domain="$(prompt_domain "请输入域名")"
    
    local mode="standalone"
    local webroot_path=""
    if [[ -d "${LION_WEBROOT_DIR}" ]]; then
       mode="webroot"
       webroot_path="${LION_WEBROOT_DIR}"
    fi

    separator
    echo -e "配置摘要:"
    echo -e "  域名: ${c_cyan}${domain}${c_reset}"
    echo -e "  写入模式: ${c_cyan}${CONF_METHOD}${c_reset} (Target: ${TARGET_CONF_DIR})"
    echo -e "  签发模式: ${c_cyan}${mode}${c_reset}"
    separator
    confirm "确认配置?" || return

    ensure_acme_sh
    info "申请证书..."
    
    if [[ "${mode}" == "webroot" ]]; then
       acme_cmd --issue -d "${domain}" --webroot "${webroot_path}" --server letsencrypt || return
    else
       local type="${ngx%%:*}"
       local name="${ngx#*:}"
       trap 'ensure_nginx_restore "$type" "$name"' EXIT
       if [[ "$type" == "docker" ]]; then docker stop "$name"; elif [[ "$type" == "host" ]]; then if has_cmd systemctl; then systemctl stop nginx; else nginx -s stop; fi; fi
       if ! acme_cmd --issue --standalone -d "${domain}" --server letsencrypt; then die "签发失败"; fi
       trap - EXIT
       ensure_nginx_restore "$type" "$name"
    fi
    
    local hook_script
    hook_script="$(generate_renewal_hook "${ngx}" "${domain}")"
    
    acme_cmd --install-cert -d "${domain}" \
      --key-file "${LOCAL_CERT_REPO}/${domain}.key" \
      --fullchain-file "${LOCAL_CERT_REPO}/${domain}.cer" \
      --reloadcmd "${hook_script}"

    bash "${hook_script}"
    
    local conf_content
    conf_content=$(cat <<EOF
# @SS_MANAGED: true
# @SS_DOMAIN: ${domain}
server { listen 80; server_name ${domain}; location / { return 301 https://\$host\$request_uri; } }
server {
    listen 443 ssl; server_name ${domain};
    ssl_certificate ${TARGET_CERT_DIR}/${domain}.cer;
    ssl_certificate_key ${TARGET_CERT_DIR}/${domain}.key;
    ssl_protocols TLSv1.2 TLSv1.3; ssl_ciphers HIGH:!aNULL:!MD5;
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

    reload_nginx_strict "${ngx}"
    log "完成! 访问: https://${domain}${SC_BACKEND}"
}

domain_del_flow() {
    local ngx="$1"
    local domain="$(prompt "输入要删除的域名" "")"
    
    if [[ "${CONF_METHOD}" == "host_direct" ]]; then
       rm -f "${TARGET_CONF_DIR}/substore-${domain}.conf"
    else
       local name="${ngx#*:}"
       docker exec "${name}" rm -f "${TARGET_CONF_DIR}/substore-${domain}.conf"
    fi
    
    reload_nginx_strict "${ngx}"
    acme_cmd --remove -d "${domain}"
    rm -f "${HOOK_SCRIPT_DIR}/renew_${domain}.sh"
    
    # 清理证书询问
    if confirm "是否清理证书文件?"; then
       rm -f "${LOCAL_CERT_REPO}/${domain}.cer" "${LOCAL_CERT_REPO}/${domain}.key"
       log "证书已清理"
    fi
    log "删除完成"
}

uninstall_script_full() {
  header "完全卸载"
  confirm "删除脚本、配置及 st 指令?" || return
  rm -rf "${STATE_DIR}"
  rm -f "/usr/local/bin/st"
  rm -f "${SCRIPT_PATH}"
  echo "卸载完成。"
  exit 0
}

show_menu() {
  clear
  echo -e "${c_cyan}==========================================================="
  echo -e " Sub-Store Assistant (v${SCRIPT_VER}) "
  echo -e "===========================================================${c_reset}"
  
  local sc_status="${c_red}未部署${c_reset}"
  [[ -f "${STATE_CFG_FILE}" ]] && sc_status="${c_green}已部署${c_reset}"
  local ngx_status
  if ngx=$(detect_entry_nginx); then ngx_status="${c_green}${ngx}${c_reset}"; else ngx_status="${c_yellow}未检测到${c_reset}"; fi
  
  echo -e " 容器: ${sc_status} | Nginx: ${ngx_status}"
  separator
  
  echo -e "${c_yellow}[ 核心功能 ]${c_reset}"
  echo " 1. 部署/重置容器"
  echo " 2. 容器管理面板"
  echo " 3. 添加域名访问 (Auto HTTPS)"
  echo " 4. 已配域名列表"
  echo " 5. 删除域名访问"
  
  echo -e "\n${c_yellow}[ 脚本维护 ]${c_reset}"
  echo " 8. 更新脚本"
  echo " 9. 卸载脚本"
  echo " 0. 退出"
  separator
  
  local choice
  read -r -p "请选择: " choice
  case "${choice}" in
    1) deploy_substore_flow; pause ;;
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

need_root
ensure_deps
install_shortcut_silent
while true; do show_menu; done
