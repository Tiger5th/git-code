#!/usr/bin/env bash
set -euo pipefail

# =========================================================
# Sub-Store Assistant (GitHub Hosted Version)
# v1.2.1 - Self-Install & Lion Compatible
# =========================================================

# --- [关键配置] 你的 GitHub Raw 地址 ---
# (请确保这个地址是准确的，脚本会用它来自我更新)
UPDATE_URL="https://raw.githubusercontent.com/Tiger5th/git-code/refs/heads/master/sub-gemini.sh"
SCRIPT_PATH="/root/substore.sh"

# ================= 自我安装/更新逻辑 =================
install_self() {
  # 如果当前脚本不是在 /root/substore.sh 运行的（比如 curl | bash 管道运行）
  # 或者文件不存在，则进行下载安装
  if [[ "${0}" != "${SCRIPT_PATH}" ]] || [[ ! -f "${SCRIPT_PATH}" ]]; then
    echo -e "\033[36m>>> 检测到管道运行或非本地路径，正在安装/更新到 ${SCRIPT_PATH} ...\033[0m"
    
    # 检测 curl
    if ! command -v curl >/dev/null 2>&1; then
      if command -v apt-get >/dev/null 2>&1; then apt-get update && apt-get install -y curl; \
      elif command -v yum >/dev/null 2>&1; then yum install -y curl; \
      elif command -v apk >/dev/null 2>&1; then apk add curl; fi
    fi

    # 下载自身
    if curl -sL "${UPDATE_URL}" -o "${SCRIPT_PATH}"; then
      chmod +x "${SCRIPT_PATH}"
      echo -e "\033[32m>>> 安装成功，正在启动...\033[0m"
      exec "${SCRIPT_PATH}" "$@"
      exit 0
    else
      echo -e "\033[31m>>> 下载失败，请检查 GitHub 地址或网络连接。\033[0m"
      exit 1
    fi
  fi
}

# 执行自安装检查
install_self "$@"

# ================= 以下是核心逻辑 =================

SCRIPT_VER="1.2.1"

# --- 基础路径 ---
STATE_DIR="/var/lib/substore-script"
STATE_CFG_FILE="${STATE_DIR}/config.env"
STATE_DOMAINS_FILE="${STATE_DIR}/domains.db"
HOOK_SCRIPT_DIR="${STATE_DIR}/hooks"

# --- 科技 Lion / 面板标准路径 ---
LION_BASE="/home/web"
LION_CONF_DIR="${LION_BASE}/conf.d"
LION_CERT_DIR="${LION_BASE}/certs"
LION_WEBROOT_DIR="${LION_BASE}/letsencrypt"

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

# --- 自动安装快捷指令 ---
install_shortcut_silent() {
  if [[ ! -f /usr/local/bin/st ]]; then
    cat > /usr/local/bin/st <<SH
#!/usr/bin/env bash
exec ${SCRIPT_PATH} "\$@"
SH
    chmod +x /usr/local/bin/st
    log "快捷指令 'st' 已自动安装，下次直接输入 st 即可启动。"
  fi
}

# --- 交互输入 ---
prompt() {
  local label="$1" def="$2" val
  read -r -p "${label} [默认: ${def}]: " val || true
  [[ -z "${val}" ]] && echo "${def}" || echo "${val}"
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

pause() { read -r -p "按回车返回菜单..." _; }

# ================= 环境检测 =================

ensure_deps() {
  if ! has_cmd curl || ! has_cmd grep || ! has_cmd awk || ! has_cmd socat; then
    info "补全系统依赖 (curl/grep/awk/socat)..."
    if has_cmd apt-get; then
      apt-get update -y && apt-get install -y curl grep awk ca-certificates socat >/dev/null
    elif has_cmd yum; then
      yum install -y curl grep awk ca-certificates socat >/dev/null
    elif has_cmd apk; then
      apk add curl grep awk ca-certificates socat >/dev/null
    else
      warn "无法安装依赖，请手动安装 socat 后重试"
    fi
  fi
}

ensure_docker() {
  if ! has_cmd docker; then
    warn "未检测到 Docker，正在安装..."
    curl -fsSL https://get.docker.com | sh
    systemctl enable --now docker >/dev/null 2>&1 || true
  fi
  docker info >/dev/null 2>&1 || die "Docker 未正常运行"
}

ensure_acme_sh() {
  if [[ ! -f "${HOME}/.acme.sh/acme.sh" ]]; then
    info "安装 acme.sh..."
    curl https://get.acme.sh | sh -s email=substore@example.com
  fi
}

acme_cmd() {
  "${HOME}/.acme.sh/acme.sh" "$@"
}

# ================= Nginx 探测与控制 =================

detect_entry_nginx() {
  # 1. 优先 Docker Nginx
  local c_names="nginx openresty"
  for name in $c_names; do
    if docker ps --format '{{.Names}}' | grep -qx "${name}"; then
      echo "docker:${name}"
      return 0
    fi
  done
  # 2. 宿主机 Nginx
  if pgrep -x nginx >/dev/null 2>&1; then
    echo "host:system"
    return 0
  fi
  return 1
}

reload_nginx() {
  local target="$1" # type:name
  local type="${target%%:*}"
  local name="${target#*:}"

  info "正在无损重载 Nginx 配置..."
  
  if [[ "${type}" == "docker" ]]; then
    if ! docker exec "${name}" nginx -s reload; then
      warn "Reload 失败，尝试测试配置..."
      docker exec "${name}" nginx -t || die "Nginx 配置有误，请手动检查！"
    fi
  else
    if has_cmd systemctl; then
      systemctl reload nginx || nginx -s reload
    else
      nginx -s reload
    fi
  fi
  log "Nginx 重载完成 (业务未中断)"
}

# ================= 部署 Sub-Store =================

deploy_substore() {
  ensure_docker
  header "部署 Sub-Store 容器"
  
  echo "说明：此步骤将启动核心服务。建议仅监听 127.0.0.1，依靠 Nginx 提供公网访问。"
  separator

  local c_name="$(prompt "容器名称" "${NAME_DEFAULT}")"
  local h_port="$(prompt "宿主机端口" "${HOST_PORT_DEFAULT}")"
  local data_dir="$(prompt "数据目录" "${DATA_DEFAULT}")"
  
  # 后台路径生成
  local rand_path="/$(tr -dc 'a-z0-9' </dev/urandom | head -c 8)"
  local backend_path="$(prompt "后台路径 (防爆破)" "${rand_path}")"
  
  mkdir -p "${data_dir}"

  if docker ps -a --format '{{.Names}}' | grep -qx "${c_name}"; then
    warn "检测到容器 ${c_name} 已存在，将被删除重制。"
    docker rm -f "${c_name}" >/dev/null
  fi

  info "拉取镜像并启动..."
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
  echo -e "  - 内部地址: http://127.0.0.1:${h_port}${backend_path}"
  echo -e "  - 数据目录: ${data_dir}"
  info "请继续执行 [3] 添加域名访问，以开启 HTTPS。"
}

# ================= 域名管理 (核心优化) =================

manage_domains() {
  local action="$1"
  local ngx_target
  ngx_target="$(detect_entry_nginx)" || die "未检测到 Nginx (Docker/宿主机)，无法配置域名。"

  local conf_base="/etc/nginx/conf.d"
  local cert_base="/etc/nginx/certs"
  local webroot_path=""
  local env_type="Standard"

  # 智能探测科技Lion环境
  if [[ -d "${LION_WEBROOT_DIR}" ]]; then
    env_type="Lion/Panel"
    webroot_path="${LION_WEBROOT_DIR}"
    conf_base="${LION_CONF_DIR}"
    cert_base="${LION_CERT_DIR}"
  else
    # 非标准环境，创建临时存放点
    cert_base="${STATE_DIR}/certs"
  fi

  case "${action}" in
    "add") domain_add_flow "${ngx_target}" "${conf_base}" "${cert_base}" "${webroot_path}" "${env_type}" ;;
    "list") domain_list_flow "${conf_base}" ;;
    "del") domain_del_flow "${ngx_target}" "${conf_base}" "${cert_base}" ;;
  esac
}

domain_add_flow() {
  local ngx="$1" conf_dir="$2" cert_dir="$3" webroot="$4" env="$5"
  
  header "添加域名访问 (Auto HTTPS)"
  echo -e "环境识别: ${c_cyan}${env}${c_reset}"
  echo "说明：脚本将自动为域名申请证书并配置反向代理。"
  separator

  # 读取配置
  source "${STATE_CFG_FILE}" 2>/dev/null || true
  local upstream_port="${SC_PORT:-3001}"
  
  local domain="$(prompt "请输入域名 (如 sub.example.com)" "")"
  [[ -z "${domain}" ]] && die "域名不能为空"

  # 模式选择逻辑
  local mode="webroot"
  local cf_key=""
  local cf_email=""

  if [[ -n "${webroot}" ]]; then
    info "策略: 使用 [Webroot] 模式 (利用现有目录验证，无损零停机)"
  else
    warn "未检测到面板环境，Webroot 模式不可用。"
    echo "请选择验证模式："
    echo "1) Cloudflare API (推荐，需 Token，最稳健)"
    echo "2) Standalone (需暂停 Nginx 30秒，会导致断网)"
    local ch="$(prompt "选择" "1")"
    if [[ "${ch}" == "1" ]]; then
      mode="dns_cf"
      cf_email="$(prompt_secret "输入 Cloudflare Email")"
      cf_key="$(prompt_secret "输入 Cloudflare Global API Key")"
    else
      mode="standalone"
    fi
  fi

  confirm "即将为 [${domain}] 申请证书并配置 HTTPS，确认？" || return

  ensure_acme_sh
  mkdir -p "${cert_dir}"
  
  # 2. 申请证书
  if [[ "${mode}" == "webroot" ]]; then
    acme_cmd --issue -d "${domain}" --webroot "${webroot}" --server letsencrypt \
      || die "证书申请失败！请检查域名解析是否正确。"
  elif [[ "${mode}" == "dns_cf" ]]; then
    export CF_Key="${cf_key}"
    export CF_Email="${cf_email}"
    acme_cmd --issue --dns dns_cf -d "${domain}" --server letsencrypt \
      || die "证书申请失败！请检查 Token。"
  else
    # Standalone
    warn "停止 Nginx..."
    local type="${ngx%%:*}"
    local name="${ngx#*:}"
    [[ "$type" == "docker" ]] && docker stop "$name" || systemctl stop nginx
    acme_cmd --issue --standalone -d "${domain}" --server letsencrypt
    [[ "$type" == "docker" ]] && docker start "$name" || systemctl start nginx
  fi

  # 3. 安装证书
  local cert_file="${cert_dir}/${domain}.cer"
  local key_file="${cert_dir}/${domain}.key"
  
  acme_cmd --install-cert -d "${domain}" \
    --key-file       "${key_file}"  \
    --fullchain-file "${cert_file}" \
    --reloadcmd      "true" # 稍后统一 reload

  # 4. 写入最终 Nginx 配置
  local conf_file="${conf_dir}/substore-${domain}.conf"
  cat > "${conf_file}" <<EOF
# ==========================================
# @SS_MANAGED: true
# @SS_DOMAIN: ${domain}
# ==========================================

server {
    listen 80;
    server_name ${domain};
    location / { return 301 https://\$host\$request_uri; }
}

server {
    listen 443 ssl;
    server_name ${domain};

    ssl_certificate ${cert_file};
    ssl_certificate_key ${key_file};

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    add_header Strict-Transport-Security "max-age=63072000" always;

    location / {
        proxy_pass http://127.0.0.1:${upstream_port};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOF

  reload_nginx "${ngx}"
  
  log "域名添加成功！"
  echo -e "访问地址: ${c_green}https://${domain}${SC_BACKEND:-}${c_reset}"
}

domain_list_flow() {
  local conf_dir="$1"
  header "已配置域名列表"
  grep -l "@SS_MANAGED" "${conf_dir}"/*.conf 2>/dev/null | while read -r f; do
    local d="$(grep "@SS_DOMAIN" "$f" | awk '{print $3}')"
    echo "- ${d}"
  done || echo "暂无记录"
}

domain_del_flow() {
  local ngx="$1" conf_dir="$2" cert_dir="$3"
  header "删除域名访问"
  local domain="$(prompt "请输入要删除的域名" "")"
  [[ -z "${domain}" ]] && return

  local conf="${conf_dir}/substore-${domain}.conf"
  if [[ -f "${conf}" ]]; then
    rm "${conf}"
    reload_nginx "${ngx}"
    rm -f "${cert_dir}/${domain}.cer" "${cert_dir}/${domain}.key"
    acme_cmd --remove -d "${domain}" >/dev/null 2>&1 || true
    log "域名 ${domain} 已删除。"
  else
    warn "找不到该域名的配置文件。"
  fi
}

# ================= 卸载功能 =================

uninstall_script() {
  header "卸载脚本及清理数据"
  warn "危险操作！这将删除："
  echo "1. 本脚本及 st 快捷指令"
  echo "2. 由脚本生成的 Nginx 配置文件"
  echo "3. Sub-Store 容器"
  echo "4. Sub-Store 数据目录 (可选)"
  separator
  
  confirm "确定要开始卸载吗？" || return
  
  # 1. 删除 Nginx 配置
  local ngx
  ngx="$(detect_entry_nginx || true)"
  if [[ -n "${ngx}" ]]; then
    local conf_base="/etc/nginx/conf.d"
    [[ -d "${LION_CONF_DIR}" ]] && conf_base="${LION_CONF_DIR}"
    
    info "清理 Nginx 配置..."
    rm -f "${conf_base}/substore-"*.conf
    reload_nginx "${ngx}"
  fi
  
  # 2. 删除容器
  source "${STATE_CFG_FILE}" 2>/dev/null || true
  if [[ -n "${SC_NAME:-}" ]]; then
    info "删除容器 ${SC_NAME}..."
    docker rm -f "${SC_NAME}" >/dev/null 2>&1 || true
  fi
  
  # 3. 删除数据 (询问)
  if [[ -n "${SC_DATA:-}" && -d "${SC_DATA}" ]]; then
    if confirm "是否同时删除数据目录 ${SC_DATA}？"; then
      rm -rf "${SC_DATA}"
      log "数据目录已删除"
    else
      log "数据目录已保留"
    fi
  fi
  
  # 4. 删除自身
  info "删除脚本及状态文件..."
  rm -rf "${STATE_DIR}"
  rm -f "/usr/local/bin/st"
  rm -f "${SCRIPT_PATH}"
  
  log "卸载完成，再见！"
  exit 0
}

# ================= 主菜单 =================

show_menu() {
  clear
  echo -e "${c_cyan}==========================================================="
  echo -e " Sub-Store Assistant (v${SCRIPT_VER}) ${c_reset}"
  echo -e "${c_cyan}===========================================================${c_reset}"
  
  # 状态栏
  local ngx_status
  ngx_status="$(detect_entry_nginx || echo "未运行")"
  echo -e " Nginx: ${c_green}${ngx_status}${c_reset} | acme.sh: $(has_cmd acme.sh && echo "${c_green}OK${c_reset}" || echo "${c_yellow}未安装${c_reset}")"
  separator
  
  echo -e "${c_yellow}[ 核心功能 ]${c_reset}"
  echo " 1. 部署/重置 Sub-Store 容器"
  echo " 2. 添加域名访问 (Auto HTTPS)"
  echo " 3. 管理已配域名 (列表/删除)"
  
  echo -e "\n${c_yellow}[ 维护与工具 ]${c_reset}"
  echo " 4. 强制刷新证书 (测试续签)"
  echo " 5. 卸载脚本 (含数据清理)"
  
  echo -e "\n 0. 退出"
  separator
  
  local choice
  read -r -p "请选择: " choice
  case "${choice}" in
    1) deploy_substore; pause ;;
    2) manage_domains "add"; pause ;;
    3) manage_domains "list"; echo; manage_domains "del"; pause ;;
    4) need_root; ensure_acme_sh; info "强制执行续签测试..."; acme_cmd --cron --force; pause ;;
    5) uninstall_script ;;
    0) exit 0 ;;
    *) echo "无效选项"; sleep 1 ;;
  esac
}

# 入口
need_root
ensure_deps
install_shortcut_silent
install_self "$@"
while true; do show_menu; done
