# Sub-Store Operations Platform (Titanium Edition)

一个面向 **Sub-Store（Docker）部署 + 运维 + HTTPS 域名反代** 的交互式控制台脚本。

> 当前脚本版本：`2.0.0.5`（Build: 2026-01-28）  
> 默认镜像：`xream/sub-store`  
> 默认仅绑定本地回环：`127.0.0.1:3001`（由脚本交互可改）:contentReference[oaicite:1]{index=1}

---

## 功能概览

- **一键全家桶向导**：部署容器 + 绑定 HTTPS 域名（反代）
- **容器运维管理**
  - 查看连接信息（端口/后台路径/本地访问 URL）
  - 实时日志（`docker logs -f`）
  - 重启实例
  - 拉取最新镜像并重建容器（升级）
  - 备份 / 恢复（快照 tar.gz）
  - 卸载当前实例（保留/删除数据按脚本逻辑）
- **Nginx 与域名管理台（HTTPS/反代）**
  - 自动检测 Nginx（宿主机 nginx 或 Docker nginx/openresty）
  - 申请证书（acme.sh + Let’s Encrypt）
  - 自动生成续期 hook（续期后复制证书并 reload）
  - 写入反代配置并严格 reload（先 `nginx -t`）
- **系统工具**
  - 宿主机资源诊断
  - 脚本自更新
  - 完全卸载所有资产

---

## 系统要求

- Linux / x86_64 或 arm64
- Root 权限（脚本会写系统目录、管理 Docker、修改防火墙、签发证书）
- 网络可访问 GitHub（下载脚本/更新/依赖安装）与 Let’s Encrypt（签发证书）
- 需要可用的 80/443 入站（签发 HTTPS/对外访问时）

脚本启用严格模式：`errexit / pipefail / nounset`（遇到异常会更早失败并写日志）。:contentReference[oaicite:2]{index=2}

---

## 安装与运行（推荐方式）

> 这是交互式脚本，推荐让 **stdin 保持为终端**。

### 方式 A：process substitution（推荐）
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Tiger5th/git-code/refs/heads/master/sub-gemini.sh)
```

### 方式 B：下载到本地再执行（更稳）

```bash
curl -fsSL https://raw.githubusercontent.com/Tiger5th/git-code/refs/heads/master/sub-gemini.sh -o /root/substore.sh
chmod +x /root/substore.sh
/root/substore.sh
```

> 不建议：`curl ... | bash`  
> 因为脚本需要 `read` 读取用户输入，而 pipe 模式下 stdin 常常被脚本内容占用，导致交互失败（表现为菜单出现后立刻退回 shell）。

---

## 快速开始

1. 运行脚本进入主菜单
2. 选择：

   * `1`：一键全家桶向导（推荐新手）
   * 或 `2`：仅部署容器
3. 若需要域名访问（HTTPS）：

   * 选择 `4`：进入 **Nginx 与域名管理台**
   * 按提示输入域名并确认
4. 完成后，脚本会输出可访问地址，例如：

   * `https://your.domain/<后台路径>`

---

## Nginx / HTTPS 说明

### Nginx 探测逻辑

* 优先探测 Docker 中容器名为 `nginx` 或 `openresty`
* 否则探测宿主机 `nginx` 进程
* 若自动探测失败，脚本允许手动输入 Nginx 容器名（并校验容器是否存在）

### Docker Nginx 的限制

* 若你使用 Docker Nginx 做入口，脚本要求该 Nginx 容器必须是 **host 网络模式**，否则无法反代到宿主机 `127.0.0.1:PORT`（脚本会直接终止并提示原因）。

### 证书签发模式（自动选择）

* 若检测到 Webroot 目录（常见于面板环境），优先使用 `--webroot`
* 否则使用 `--standalone`（会短暂停止 Nginx 占用 80 端口，并自动放行 80）

### 续期机制

* 脚本会生成按域名粒度的续期 hook：

  * 将 acme.sh 续期后的证书复制到 Nginx 证书目录
  * `nginx -t` 通过后再 reload（严格重载）
* 首次签发后会立即执行一次 hook，确保 Nginx 引用的证书文件已就位。

---

## 备份与恢复

* 备份文件默认存放在：

  * `/var/lib/substore-script/backups/` ([GitHub][1])
* 备份格式：

  * `ss_backup_YYYYMMDD_HHMMSS.tar.gz`
* 恢复会：

  1. 停止 Sub-Store 容器
  2. 清空数据目录
  3. 解压备份覆盖
  4. 启动容器

> 建议在低峰期执行恢复操作。

---

## 重要路径与文件

脚本默认使用以下路径（可在脚本常量中查看/调整）：([GitHub][1])

* 脚本本体：`/root/substore.sh`
* 日志：`/var/log/substore_ops.log`
* 状态目录：`/var/lib/substore-script/`

  * 配置：`config.env`
  * hooks：`hooks/`
  * 本地证书仓库：`certs_repo/`
  * 备份：`backups/`
  * 临时目录：`/tmp/substore_tmp/`

Nginx 常见路径：

* 面板环境（Lion）：`/home/web/conf.d`、`/home/web/certs`、`/home/web/letsencrypt`
* 容器内：`/etc/nginx/conf.d`、`/etc/nginx/certs`

---

## 更新与卸载

### 自更新

菜单 `8`：脚本会从 GitHub 下载最新版本并覆盖 `/root/substore.sh`，并自动重启脚本。

### 完全卸载

菜单 `9`：删除脚本创建的容器、数据目录与状态目录（高风险操作，请确认后执行）。

---

## 常见问题（FAQ）

### 1) 菜单一闪而过/输入选项无效

请使用：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Tiger5th/git-code/refs/heads/master/sub-gemini.sh)
```

避免 `curl | bash` 的交互输入问题。

### 2) HTTPS 申请失败

常见原因：

* 域名未解析到当前服务器公网 IP
* 80/443 端口未放行（安全组/防火墙）
* Nginx 占用 80 且 standalone 模式无法临停（或缺少权限）
* 查看日志：`/var/log/substore_ops.log`

### 3) 反代后 502

* 如果入口 Nginx 在 Docker 内，请确认它是 **host 网络**
* `nginx -t` 检查配置是否有效
* 确认 Sub-Store 容器运行且本地端口可访问：`curl -I http://127.0.0.1:<端口><后台路径>`

---

## 安全提示

* 后台路径属于“隐藏入口”类保护措施，仍建议配合：

  * 强密码/鉴权
  * 限制来源 IP（如仅允许自己 IP 段访问）
* 证书与配置会写入系统目录，请确保服务器只有可信用户拥有 root 权限。
* 建议定期备份 `/var/lib/substore-script/` 与数据目录。

---

## 免责声明

本脚本会执行：安装依赖、管理 Docker、修改防火墙、停止/启动 Nginx、签发证书、写入 Nginx 配置等操作。请在了解风险的前提下使用，并建议先在测试环境验证。

---

如果你希望 README 更“面向用户”（比如加截图、运行演示、菜单项说明更细、以及“面板环境 vs 纯净 Linux vs Docker Nginx”三套场景的差异），我也可以在你这份基础上再扩一版（内容会更长但更易懂）。
::contentReference[oaicite:5]{index=5}

[1]: https://raw.githubusercontent.com/Tiger5th/git-code/refs/heads/master/sub-gemini.sh "raw.githubusercontent.com"
