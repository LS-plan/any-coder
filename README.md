# any-coder（Phase A/B 持续实现中）

面向**单机 Win10 + Tailscale**场景的远程开发工作台后端（MVP）。

## 当前已实现能力

- 全局密码门禁登录（单密码）
- 会话 token 签发与过期校验
- 登录失败锁定策略（5 次失败锁 5 分钟；10 次失败锁 30 分钟）
- 工作区文件 API（目录树、读文件、写文件）
- 目录编辑 API（新建目录、移动/重命名、删除文件/目录）
- Git 基础 API（status、diff）
- 终端基础 API（创建终端、输入、读取输出、关闭终端）

---

## 快速启动

### 1) 生成密码哈希

```bash
npm run hash-password -- <你的登录密码>
```

会输出：

```txt
APP_PASSWORD_HASH=<salt:hash>
```

### 2) 启动服务

```bash
export APP_PASSWORD_HASH='<上一步输出的值>'
export WORKSPACE_ROOT='/workspace/any-coder'   # 改成你的项目根目录
npm run server
```

默认监听：`0.0.0.0:8080`

---

## 接口清单

### 健康检查

- `GET /health`

### 鉴权

- `POST /api/auth/login`
  - body: `{ "password": "..." }`
- `GET /api/auth/session`

### 工作区（需要 Bearer Token）

- `GET /api/workspace/tree?path=.`
- `GET /api/workspace/file?path=README.md`
- `PUT /api/workspace/file?path=notes/todo.txt`
  - body: `{ "content": "..." }`
- `POST /api/workspace/mkdir?path=notes`
- `POST /api/workspace/move`
  - body: `{ "from": "old/path", "to": "new/path" }`
- `DELETE /api/workspace/node?path=notes/todo.txt`

### Git（需要 Bearer Token）

- `GET /api/git/status`
- `GET /api/git/diff`
- `GET /api/git/diff?path=README.md`

### 终端（需要 Bearer Token）

- `POST /api/terminal/create`
  - body: `{ "shell": "bash", "cwd": "." }`（可选）
- `POST /api/terminal/:id/input`
  - body: `{ "input": "ls\n" }`
- `GET /api/terminal/:id/output?from=0`
- `POST /api/terminal/:id/close`

---

## 终端 API 说明（当前阶段）

- 终端会话保存在服务进程内存中（重启服务后丢失）。
- 输出通过轮询 `output` 接口读取（后续可升级 WebSocket 推送）。
- 默认 shell：
  - Linux 容器环境：`bash`
  - Windows 目标环境建议后续配置 `powershell.exe`

---

## 开发脚本

```bash
npm run server
npm run hash-password -- <password>
npm run check
```

---

## 安全与限制

- 密码仅校验哈希（scrypt，`salt:hash`）。
- `WORKSPACE_ROOT` 路径沙箱限制，禁止越界访问。
- `apps/server/data/sessions.json` 为运行时会话存储，已 `.gitignore`。
- 当前还未实现 HTTPS、CSRF 防护、命令白名单、细粒度审计（后续阶段补齐）。
