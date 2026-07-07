# 用户管理系统 — 安全漏洞分析报告

> 目标：http://192.168.119.128:5000/  
> 技术栈：Flask（Python）  
> 分析日期：2026-07-07

---

## 目录

1. [漏洞概述](#1-漏洞概述)
2. [漏洞详情](#2-漏洞详情)
3. [修复方案](#3-修复方案)
4. [修复后验证](#4-修复后验证)

---

## 1. 漏洞概述

| 编号 | 漏洞名称 | 严重程度 |
|------|----------|----------|
| ① | Secret Key 硬编码 → Session 伪造 | 🔴 致命 |
| ② | 默认管理员账号密码泄露（HTML 注释） | 🔴 致命 |
| ③ | 密码明文存储与明文比对 | 🔴 严重 |
| ④ | Debug 模式开启 | 🟠 高危 |
| ⑤ | 监听 0.0.0.0 全网络接口 | 🟠 高危 |
| ⑥ | Session Cookie 缺少安全标志 | 🟠 高危 |
| ⑦ | 无登录频率限制（暴力破解） | 🟡 中危 |
| ⑧ | 无注册 / 密码重置功能 | 🟡 中危 |

---

## 2. 漏洞详情

### ① Secret Key 硬编码 → Session 伪造

**位置：** `app.py` 第 4 行

```python
app.secret_key = "dev-key-2025"
```

**风险分析：**
Flask 使用 `secret_key` 对 session cookie 进行 HMAC 签名。密钥硬编码意味着任何人拿到源码（或通过 debug 错误页面泄露的源码片段）即可：

1. 解码 session 内容（当前仅存储 `{"username":"admin"}`）
2. 用同样密钥伪造任意用户的 session cookie
3. 无需密码，直接以管理员身份登录

**验证截图：**
```bash
# Session cookie 解码结果
Payload: {"username":"admin"}
Timestamp: 2026-07-07 04:09:23
```

---

### ② 默认管理员账号密码泄露

**位置：** `templates/login.html` 第 1 行

```html
<!-- 调试信息 - 默认管理员账号 用户名: admin 密码: admin123 -->
```

**风险分析：**
该注释在 `login.html` 渲染后的 HTML 源码中可见。任何访问登录页的用户均可通过「查看网页源代码」获取管理员凭证。

---

### ③ 密码明文存储与明文比对

**位置：** `app.py` 第 7、14 行（存储），第 29 行（比对）

```python
# 存储
"password": "admin123",   # 明文

# 比对
if user and user["password"] == password:   # 字符串直接比较
```

**风险分析：**
- 源码一旦泄漏，所有用户密码直接暴露
- 用户信息页面（`index.html`）直接渲染 `{{ user.password }}`，登录后可见密码
- 用户常跨平台复用密码，可导致撞库攻击

---

### ④ Debug 模式开启

**位置：** `app.py` 最后一行

```python
app.run(debug=True, host="0.0.0.0", port=5000)
```

**风险分析：**
- `debug=True` 启用 Werkzeug 调试器
- 程序异常时会显示完整 traceback，包含文件路径、变量值和源码片段
- 在部分配置下可能通过 `/console` 路径远程执行代码（RCE）

---

### ⑤ 监听 0.0.0.0

```python
host="0.0.0.0"
```

**风险分析：**
应用绑定所有网络接口，内网任何设备均可访问。生产环境应只监听 `127.0.0.1` 并通过反向代理（Nginx）对外暴露。

---

### ⑥ Session Cookie 缺少安全标志

**原始响应头：**
```
Set-Cookie: session=xxx; HttpOnly; Path=/
```

**问题清单：**
| 属性 | 缺失 | 风险 |
|------|------|------|
| `Secure` | ❌ | HTTP 明文传输时可被中间人窃取 |
| `SameSite` | ❌ | 无 CSRF 防护 |
| 过期时间 | ❌ | session 永不过期 |

---

### ⑦ 无登录频率限制

**风险分析：**
登录接口无任何限速机制：
- 无 IP 频率限制
- 无账号锁定策略
- 无验证码

攻击者可利用弱密码字典对已知用户名（`admin`、`alice`）进行无限次暴力破解。

---

### ⑧ 无注册 / 密码重置功能

**风险分析：**
- 用户无法自行注册账号
- 无忘记密码或重置密码流程
- 用户信息仅能通过修改源码增减

---

## 3. 修复方案

### 修复 ①：密钥管理

```python
import os
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(32).hex())
```

- 优先从环境变量读取密钥
- 无环境变量时使用 `os.urandom(32)` 生成随机密钥

### 修复 ②：移除调试注释

删除 `templates/login.html` 中的：
```html
<!-- 调试信息 - 默认管理员账号 用户名: admin 密码: admin123 -->
```

### 修复 ③：密码加密存储与安全比对

```python
from werkzeug.security import generate_password_hash, check_password_hash

# 存储（加密）
"password": generate_password_hash("admin123"),

# 比对（安全）
if user and check_password_hash(user["password"], password):
```

同时修改 `templates/index.html`，移除密码显示行。

### 修复 ④：关闭 Debug 模式

```python
app.run(host="0.0.0.0", port=5000)   # debug 默认 False
```

### 修复 ⑤：限制监听地址（生产环境）

```python
# 开发：仅本地访问
app.run(host="127.0.0.1", port=5000)

# 或通过 Nginx 反向代理 + internal network binding
```

### 修复 ⑥：配置安全的 Cookie

```python
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',     # 防 CSRF
    PERMANENT_SESSION_LIFETIME=3600,   # 1 小时过期
)
```

### 修复 ⑦：添加登录频率限制

```python
# pip install flask-limiter
from flask_limiter import Limiter

limiter = Limiter(app, key_func=lambda: request.remote_addr)

@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    ...
```

### 修复 ⑧：添加注册与密码重置流程

建议实现：
1. 用户注册接口（带邮箱验证）
2. 忘记密码接口（发送重置链接）
3. 密码强度校验

---

## 4. 修复后验证

### 4.1 登录页 — 注释已移除

```bash
curl -s http://192.168.119.128:5000/login | grep "调试信息"
# ✅ 无输出，注释已移除
```

### 4.2 正常登录 — 功能正常

```bash
curl -s -X POST http://192.168.119.128:5000/login \
  -d "username=admin&password=admin123"
# ✅ 返回 "欢迎回来，admin！"
```

### 4.3 错误密码 — 返回错误

```bash
curl -s -X POST http://192.168.119.128:5000/login \
  -d "username=admin&password=wrongpass"
# ✅ 返回 "用户名或密码错误"
```

### 4.4 用户信息页 — 不再显示密码

- 密码字段（`{{ user.password }}`）已从 `index.html` 模板中删除
- `app.py` 登录逻辑中已过滤密码字段：
  ```python
  user_display = {k: v for k, v in user.items() if k != "password"}
  ```

### 4.5 Cookie 安全配置

```bash
# 修复前
Set-Cookie: session=xxx; HttpOnly; Path=/

# 修复后
Set-Cookie: session=xxx; HttpOnly; Path=/; SameSite=Lax
```

---

## 附录：修改文件清单

| 文件 | 修改内容 |
|------|----------|
| `app.py` | 密钥管理、密码加密、关闭 Debug、Cookie 配置 |
| `templates/login.html` | 删除调试注释 |
| `templates/index.html` | 删除密码显示行 |

> 原始文件备份：`app.py.bak`
