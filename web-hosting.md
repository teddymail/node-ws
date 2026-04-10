## Hugging Face Docker Space 部署指南

## 1) 新建 Space

- 在 Hugging Face 新建 Space，SDK 选择 `Docker`。
- 将本仓库推送到该 Space 对应仓库。

## 2) 设置 Variables（可选）

推荐至少设置：

- `UUID`
- `ADMIN`
- `ADMIN_SECRET`
- `SUB_PATH`
- `WSPATH`
- `DOMAIN`（如果你有自己的域名）
- `SNI`、`HOST_HEADER`（用于 SNI/Host 伪装）

默认端口为 `7860`，无需手动改启动命令。

## 3) 等待构建完成

本项目 `Dockerfile` 会自动：

- 安装依赖
- 启动 `npm start`
- 监听 `PORT=7860`

## 4) 访问与校验

- 后台登录页：`https://<space-url>/login`
- 后台管理页：`https://<space-url>/admin`
- 订阅地址：`https://<space-url>/<SUB_PATH>`（默认 `/sub`）
- WebSocket 路径：`/<WSPATH>`

## 5) 优选 IP 配置

在后台 `ADD.txt` 中按行填写：

```text
1.2.3.4:443#HK
5.6.7.8:8443#JP
example.com:443#SG
```

保存后重新拉取订阅即可生效。

