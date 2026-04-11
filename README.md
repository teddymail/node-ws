# Node-ws (Docker Space)

基于 Node.js + WebSocket 的 VLESS/Trojan/SS 订阅代理服务，可运行在 Hugging Face Docker Space。

这个版本已做精简：
- 移除 Cloudflare Workers/KV 依赖逻辑
- 移除 Telegram 通知相关能力
- 保留核心能力：订阅输出、WS 代理、SNI 隐藏字段、自定义优选 IP、后台管理页

## 核心路由

- `/sub` 或自定义订阅路径：输出 Base64 订阅
- `/login`：后台登录
- `/admin`：后台管理
- `/<WSPATH>`：WebSocket 入口（默认从 UUID 前 8 位生成）

## 环境变量

| 变量名 | 是否必须 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `PORT` | 否 | `7860` | 监听端口（Hugging Face Docker Space 推荐） |
| `UUID` | 否 | `5efabea4-f6d4-91fd-b8f0-17e004c89c60` | 用户 UUID |
| `DOMAIN` | 否 | `tunnel.tjhome.top` | 有域名时默认启用 TLS 链接参数 |
| `WSPATH` | 否 | UUID 前 8 位 | WS 路径（不带前导 `/`） |
| `SUB_PATH` | 否 | `sub` | 订阅路径 token |
| `NAME` | 否 | 空 | 节点名前缀 |
| `SNI` | 否 | `DOMAIN` | 订阅链接中的 SNI（用于隐藏/伪装） |
| `HOST_HEADER` | 否 | `DOMAIN` | 订阅链接中的 WS Host 头 |
| `ADMIN`/`PASSWORD` | 否 | `CHANGE_ME_ADMIN_PASSWORD` | 后台登录密码 |
| `ADMIN_SECRET`/`KEY` | 否 | `CHANGE_ME_ADMIN_SECRET` | 登录会话签名密钥 |

## GitHub Secrets 自动注入

已支持通过 GitHub Actions 构建镜像时自动注入变量。请在仓库 `Settings -> Secrets and variables -> Actions` 中添加：

- `ADMIN`
- `ADMIN_SECRET`
- `UUID`
- `DOMAIN`
- `SNI`
- `HOST_HEADER`
- `SUB_PATH`
- `WSPATH`

这些值会在 workflow 构建镜像时作为 `build-args` 注入并写入容器环境变量。
建议不要在仓库文件里保存真实密码，`config.json` 保持占位值即可。

## 优选 IP

在后台 `ADD.txt` 中配置，每行一个：

```text
1.2.3.4:443#HK-1
5.6.7.8:8443#JP-2
example.com:443#SG-Domain
```

- 格式：`host:port#备注`
- `#备注` 可选
- 留空时自动回退到当前服务地址

## 本地运行

```bash
npm ci
npm start
```

## Docker 运行

```bash
docker build -t node-ws:local .
docker run --rm -p 7860:7860 -e PORT=7860 node-ws:local
```

## Hugging Face Docker Space

1. 新建 Space，选择 `Docker`。
2. 推送本仓库代码。
3. 在 Space Variables 中按需配置上表环境变量。
4. 启动后访问：
   - `https://<space-url>/login`
   - `https://<space-url>/admin`
   - `https://<space-url>/sub`

## License

GPL-3.0
