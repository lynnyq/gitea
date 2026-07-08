# Gitea 自定义 SSO 登录技术文档

## 目录

- [1. 概述](#1-概述)
- [2. 架构设计](#2-架构设计)
- [3. SSO 登录流程](#3-sso-登录流程)
- [4. 密码加密方式](#4-密码加密方式)
- [5. 后端实现](#5-后端实现)
- [6. 前端实现](#6-前端实现)
- [7. 配置说明](#7-配置说明)
- [8. 接口定义](#8-接口定义)
- [9. 安全机制汇总](#9-安全机制汇总)
- [10. 故障排查](#10-故障排查)

---

## 1. 概述

本项目基于 **Gitea** 进行二次开发，新增了自定义 **SSO（Single Sign-On）单点登录** 功能。系统支持两种登录方式：

| 登录方式 | 说明 | 标识 |
|---------|------|------|
| **本地登录** | 使用 Gitea 内建用户数据库 + argon2 密码哈希认证 | `LoginSource = 0` |
| **SSO 登录** | 通过企业统一认证服务验证身份 | `LoginSource = -2` |

此外，Gitea 原生还支持 LDAP、SMTP、PAM、OAuth2、SSPI 等外部认证源（`LoginSource > 0`，对应 `login_source` 表中的记录）。

### 核心特性

- SSO 登录页面与本地登录页面通过 Tab 切换，支持 `?mode=sso` 参数强制 SSO 模式
- SSO 用户通过 `LoginSource = -2` 特殊标记，与本地用户和外部认证源用户区分
- SSO 登录成功后自动创建或更新本地用户记录
- 密码在传输至 SSO 服务前使用 **RSA PKCS#1 v1.5** 加密
- 本地密码使用 **argon2** 存储（Gitea 默认算法）
- SSO 用户拒绝本地密码校验，避免负 ID 传入 `auth.GetSourceByID`

---

## 2. 架构设计

### 2.1 系统架构

```
┌──────────────┐      ┌──────────────────┐      ┌──────────────┐
│   用户浏览器   │─────▶│   Gitea 后端      │─────▶│  SSO 认证服务  │
│  (HTML 表单)  │◀─────│  (chi 框架)       │◀─────│              │
└──────────────┘      └────────┬─────────┘      └──────────────┘
                               │
                               ▼
                      ┌──────────────────┐
                      │   数据库          │
                      │ (xorm / MySQL等) │
                      └──────────────────┘
```

### 2.2 核心组件

| 组件 | 文件位置 | 职责 |
|------|---------|------|
| SSO 加密与调用 | `modules/auth/sso/sso.go` | RSA 加密密码、POST 到 SSO 服务、解析响应 |
| SSO 单元测试 | `modules/auth/sso/sso_test.go` | 加密/响应解析的单元测试 |
| SSO 配置定义 | `modules/setting/sso.go` | `SSOConfig` 结构体与 `loadSSOFrom` 加载器 |
| SSO 配置测试 | `modules/setting/sso_test.go` | 配置加载的单元测试 |
| SSO 登录处理 | `routers/web/auth/sso.go` | 用户查找/创建/同步、`signInSSO` 主流程 |
| 登录路由入口 | `routers/web/auth/auth.go` | `SignIn`/`SignInPost`，区分 SSO 与本地模式 |
| 本地登录拦截 | `services/auth/signin.go` | SSO 用户拒绝本地密码校验 |
| 用户模型 | `models/user/user.go` | `LoginSourceSSO` 常量与 `IsSSO()` 方法 |
| 登录模板 | `templates/user/auth/signin_inner.tmpl` | SSO/本地 Tab 切换与表单渲染 |
| 安装向导 | `routers/install/install.go` | 安装时写入 SSO 默认配置（禁用） |
| 示例配置 | `custom/conf/app.example.ini` | `[sso]` 段配置示例与说明 |
| 国际化 | `options/locale/locale_*.json` | SSO 登录相关文案 |

---

## 3. SSO 登录流程

### 3.1 完整流程

```
用户访问 /user/login
       │
       ▼
  SSO 已启用？ ─── 否 ──▶ 显示本地登录表单
       │
      是
       │
       ▼
  显示登录页（SSO Tab + 本地 Tab）
  ?mode=sso 时默认激活 SSO Tab
       │
       ▼
  用户提交 SSO 表单（POST /user/login?mode=sso）
       │
       ▼
  SignInPost() 检测 IsSSOMode
       │
       ▼
  signInSSO()
       │
       ▼
  sso.Authenticate()
  (RSA PKCS1v15 加密密码 → POST 到 SSO 服务)
       │
       ▼
  解析 SSO 响应
  code == SuccessCode ? ─── 否 ──▶ 返回 auth.sso_login_failed 错误
       │
      是
       ▼
  查找本地用户（按 loginName）
       │
       ├── 已存在 ──▶ syncSSOUser()（更新 FullName、强制 LoginSource=-2）
       │
       └── 不存在 ──▶ createSSOUser()（AutoCreateUser=true 时创建，LoginSource=-2）
       │
       ▼
  handleSignIn()
  (设置 Session/Cookie，跳转首页)
```

### 3.2 流程说明

1. **入口判断**：登录页根据 `setting.SSO.Enabled` 和 `?mode=sso` 参数决定显示哪个 Tab。当 SSO 启用且 `EnablePasswordSignInForm=false` 时，仅显示 SSO 表单。
2. **密码加密**：使用 SSO RSA 公钥对明文密码进行 PKCS#1 v1.5 加密，输出 Hex 编码字符串。
3. **SSO 验证**：将加密后的密码以 JSON 格式 POST 到 SSO 服务进行验证。
4. **响应校验**：SSO 返回 `code == SuccessCode`（默认 `"3000"`）且 `content` 非空时视为认证成功。
5. **用户同步**：已存在用户调用 `syncSSOUser` 更新信息并标记为 SSO 用户；新用户调用 `createSSOUser` 自动创建。
6. **会话建立**：由 `handleSignIn` 完成 Session/Cookie 设置并重定向。

---

## 4. 密码加密方式

### 4.1 SSO 密码传输加密（RSA）

SSO 登录时，密码在发送到 SSO 服务之前，使用 **RSA PKCS#1 v1.5** 算法进行加密。

#### 算法参数

| 参数 | 值 |
|------|-----|
| 算法 | RSA PKCS#1 v1.5 |
| 公钥格式 | 支持 Base64 编码 和 PEM 格式 |
| 公钥标准 | 支持 PKCS#1（`MIGf...` 开头）和 PKIX 两种格式 |
| 输出编码 | 十六进制（Hex）字符串 |
| 随机数源 | `crypto/rand` |
| 兼容性 | JSEncrypt（前端）、Python `Crypto.PublicKey.RSA + PKCS1_v1_5` |

> **注意**：PKCS#1 v1.5 已被 Go 1.26 标记为弃用（SA1019），但因 SSO 服务端使用 JSEncrypt / PyCryptodome 的 `PKCS1_v1_5` 解密，不支持 OAEP，故此处保留并通过 `//nolint:staticcheck` 显式抑制告警。

#### 核心代码

**文件**: `modules/auth/sso/sso.go`

```go
func EncryptPassword(publicKey, password string) (string, error) {
    keyBytes, err := parsePublicKey(publicKey)
    if err != nil {
        return "", err
    }
    rsaPub, err := parseRSAKey(keyBytes)
    if err != nil {
        return "", err
    }
    // PKCS#1 v1.5 is intentionally required here: the SSO service decrypts with
    // JSEncrypt / Python PyCryptodome's PKCS1_v1_5, which do not support OAEP.
    //nolint:staticcheck // SA1019: deprecated RSA encryption required for SSO server compatibility
    encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPub, []byte(password))
    if err != nil {
        return "", fmt.Errorf("rsa encrypt: %w", err)
    }
    return hex.EncodeToString(encrypted), nil
}
```

#### 公钥解析流程

```
公钥字符串
   │
   ├─ 以 "-----BEGIN" 开头？ ──▶ PEM 解码 ──▶ DER 字节
   │
   └─ 否 ──▶ Base64 解码 ──▶ DER 字节
                               │
                               ▼
                        parseRSAKey()
                               │
                               ├─ 尝试 PKCS#1（x509.ParsePKCS1PublicKey）
                               │
                               └─ 失败则尝试 PKIX（x509.ParsePKIXPublicKey）
                                  并断言为 *rsa.PublicKey
```

### 4.2 本地密码存储加密

本地用户的密码使用 Gitea 默认的 **argon2** 算法进行哈希存储（由 `modules/auth/password/hash` 包统一管理，算法通过 `user.passwd_hash_algo` 字段配置，默认 `argon2`）。SSO 用户不存储本地密码（`passwd` 字段为空），永远通过 SSO 服务认证。

---

## 5. 后端实现

### 5.1 路由定义

Gitea 原生的 `/user/login` 路由同时承载本地登录与 SSO 登录，通过 `?mode=sso` 区分：

| 路由 | 方法 | 处理函数 | 说明 |
|------|------|---------|------|
| `/user/login` | GET | `auth.SignIn` | 登录页面（根据 SSO 配置与 `mode` 参数渲染对应 Tab） |
| `/user/login` | POST | `auth.SignInPost` | 登录提交（`?mode=sso` 走 SSO 流程，否则走本地密码） |

### 5.2 SSO 登录处理函数

**文件**: `routers/web/auth/sso.go`

`signInSSO(ctx, loginName, password)` 主流程：

1. 校验 `setting.SSO.Enabled` 与入参非空
2. 调用 `sso.Authenticate(ctx, loginName, password)` 加密密码并请求 SSO 服务
3. 校验响应 `Success(SuccessCode)`
4. 按 `loginName` 查找本地用户 `user_model.GetIndividualUserByName`
5. 用户存在 → `syncSSOUser`；不存在 → `createSSOUser`（受 `AutoCreateUser` 控制）
6. 返回 user 交给 `handleSignIn` 建立会话

#### createSSOUser

创建新用户，关键字段：

- `LoginSource = user_model.LoginSourceSSO`（-2）
- `LoginType = 0`（本地类型，避免触发外部源查找）
- `IsActive = true`（通过 `CreateUserOverwriteOptions` 设置）
- `Passwd` 留空（SSO 用户不走本地密码校验）
- 邮箱为空时回退为 `<loginName>@sso.local`
- 显示名优先取 `content.UserName`，其次 `content.IDCardName`
- 记录 `Meta.InitialIP` 与 `Meta.InitialUserAgent` 用于审计

#### syncSSOUser

更新已存在用户：

- 通过 `user_service.UpdateUser` 更新 `FullName`（仅当 SSO 返回了非空值）
- 若 `LoginSource != LoginSourceSSO`，强制改回 `-2`（防止管理员误改后走错流程）

### 5.3 本地登录拦截

**文件**: `services/auth/signin.go`

`UserSignIn` 在查到本地用户后、调用 `auth.GetSourceByID` 之前，增加 SSO 用户拦截：

```go
if hasUser {
    // SSO users are not bound to a `login_source` row. They must go
    // through the dedicated SSO login flow; refuse local password
    // authentication here so we never reach `auth.GetSourceByID`
    // with a negative id.
    if user.IsSSO() {
        return nil, nil, user_model.ErrUserNotExist{Name: username}
    }
    source, err := auth.GetSourceByID(ctx, user.LoginSource)
    ...
}
```

这避免了负数 `LoginSource` 传入 `GetSourceByID` 导致的查询错误。

### 5.4 配置加载

**文件**: `modules/setting/sso.go`

`loadSSOFrom(rootCfg)` 在 `loadCommonSettingsFrom` 中被调用（见 `modules/setting/setting.go`），从 `[sso]` 段读取配置。启用时强制校验 `URL` 与 `PUBLIC_KEY` 非空，否则 `log.Fatal`。

### 5.5 安装向导默认值

**文件**: `routers/install/install.go`

`SubmitInstall` 在生成 `app.ini` 时写入 SSO 默认配置（`ENABLED=false`），确保安装后 SSO 默认关闭，运维人员需手动启用。

---

## 6. 前端实现

**文件**: `templates/user/auth/signin_inner.tmpl`

登录页面通过以下模板变量控制 Tab 与表单显示：

| 变量 | 含义 |
|------|------|
| `.SSOEnabled` | SSO 是否启用（`setting.SSO.Enabled`） |
| `.SSOMode` | 当前是否为 SSO 模式（`?mode=sso` 或 SSO-only） |
| `.SSOOnly` | 是否仅 SSO 可用（SSO 启用且本地表单禁用） |
| `.EnablePasswordSignInForm` | 本地密码表单是否启用 |

#### 渲染逻辑

- **SSO + 本地都启用**：渲染顶部 Tab 切换栏，`SSOMode` 决定激活哪个 Tab
- **仅 SSO**（`EnablePasswordSignInForm=false`）：隐藏本地表单，仅显示 SSO 表单
- **仅本地**（`SSOEnabled=false`）：保持 Gitea 原生行为
- SSO 表单 `action` 指向 `{{.SignInLink}}?mode=sso`，POST 时由 `SignInPost` 的 `IsSSOMode` 分支处理
- 外部认证方法（OAuth2/OpenID/SSPI）在 SSO 模式下隐藏，避免界面混乱

#### 相关 locale key

| key | en-US | zh-CN |
|-----|-------|-------|
| `auth.sso_login_tab` | SSO Sign In | SSO 登录 |
| `auth.sso_login_title` | Sign in via SSO | 通过 SSO 登录 |
| `auth.sso_login_submit` | Sign in with SSO | 使用 SSO 登录 |
| `auth.sso_login_failed` | SSO authentication failed, please try again | SSO 认证失败，请重试 |

---

## 7. 配置说明

### 7.1 SSO 配置

**文件**: `custom/conf/app.ini`（示例见 `custom/conf/app.example.ini`）

```ini
[sso]
; 是否启用 SSO 登录，默认 false
ENABLED = false
; SSO 服务认证 URL，Gitea 会 POST JSON {"loginName":"...","password":"<RSA-encrypted-hex>"} 到此处。必填。
URL =
; RSA 公钥，用于加密密码后发送到 SSO 服务。支持 Base64 编码的 PKCS#1/PKIX 或 PEM 格式。
; 对应私钥需部署在 SSO 服务端。ENABLED=true 时必填。
PUBLIC_KEY =
; 请求超时秒数，默认 10
TIMEOUT = 10
; SSO 响应中表示成功的 code 值，默认 "3000"
SUCCESS_CODE = 3000
; 首次 SSO 登录时是否自动创建本地用户（LoginSource=-2）。false 时仅允许已存在用户通过 SSO 登录。默认 true。
AUTO_CREATE_USER = true
```

### 7.2 启用步骤

1. 编辑 `custom/conf/app.ini`，添加 `[sso]` 段
2. 设置 `ENABLED = true`
3. 填写 `URL`（SSO 服务认证端点）
4. 填写 `PUBLIC_KEY`（SSO 服务的 RSA 公钥）
5. 按需调整 `TIMEOUT`、`SUCCESS_CODE`、`AUTO_CREATE_USER`
6. 重启 Gitea

---

## 8. 接口定义

### 8.1 Gitea 登录接口（前端 → Gitea）

- **URL**: `POST /user/login?mode=sso`
- **Content-Type**: `application/x-www-form-urlencoded`

**请求参数**:

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `user_name` | string | 是 | 用户名 |
| `password` | string | 是 | 明文密码（Gitea 后端 RSA 加密后转发） |
| `_csrf` | string | 是 | CSRF Token |
| `remember` | string | 否 | 是否记住登录 |

**成功响应**: 302 重定向到首页

**失败响应**: 渲染登录页面并显示 `auth.sso_login_failed` 错误提示

### 8.2 SSO 服务接口（Gitea → SSO 服务）

Gitea 后端调用的外部 SSO 服务接口：

- **URL**: `POST {setting.SSO.URL}`
- **Content-Type**: `application/json`

**请求体**:

```json
{
  "loginName": "zhangsan",
  "password": "rsa_encrypted_hex_string"
}
```

**响应体**:

```json
{
  "code": "3000",
  "message": "认证成功",
  "content": {
    "id": 1001,
    "loginName": "zhangsan",
    "userName": "张三",
    "idCardName": "张三",
    "mobileNo": "13800138000",
    "email": "zhangsan@example.com",
    "deptNo": "DEV001",
    "workId": "E1001",
    "gender": "male",
    "officePhone": "010-88888888"
  }
}
```

**状态码说明**:

| SSO Code | 说明 |
|----------|------|
| `SuccessCode`（默认 `"3000"`） | 认证成功，且 `content` 非空 |
| 其他 | 认证失败，具体错误看 `message` 字段 |

---

## 9. 安全机制汇总

| 安全特性 | 实现方式 |
|---------|---------|
| **密码传输加密** | SSO 登录使用 RSA 公钥加密密码后再发送（PKCS#1 v1.5） |
| **密码存储安全** | 本地用户使用 argon2 哈希存储；SSO 用户不存本地密码 |
| **CSRF 保护** | 复用 Gitea 原生 CSRF 中间件，表单需携带 `_csrf` Token |
| **SSO 用户隔离** | `LoginSource = -2` 特殊标记，本地登录流程显式拒绝 SSO 用户 |
| **负 ID 防御** | `services/auth/signin.go` 在 `GetSourceByID` 前拦截 SSO 用户 |
| **配置校验** | 启用 SSO 时强制校验 `URL` 与 `PUBLIC_KEY` 非空，否则 `log.Fatal` |
| **审计日志** | SSO 认证失败、自动创建用户均记录 `log.Warn`/`log.Trace`，含用户名与来源 IP |
| **自动创建可控** | `AUTO_CREATE_USER` 开关控制是否首次自动建号，防止未授权用户涌入 |

---

## 10. 故障排查

### 10.1 SSO 登录失败

| 现象 | 可能原因 | 排查步骤 |
|------|---------|---------|
| 页面不显示 SSO Tab | `SSO.ENABLED = false` | 检查 `custom/conf/app.ini` 中 `[sso]` 配置 |
| 密码加密失败 | 公钥格式不正确 | 确认公钥为 Base64 或 PEM 格式，支持 PKCS#1/PKIX |
| SSO 服务调用失败 | 网络不通或服务宕机 | 检查 `SSO.URL` 配置与网络连通性，查看 Gitea 日志 `call sso service` |
| 认证失败 `code != SuccessCode` | 用户名/密码错误或 `SUCCESS_CODE` 配置不匹配 | 检查 SSO 服务日志，确认 `SUCCESS_CODE` 与 SSO 实际返回的 code 一致 |
| 用户创建失败 | 数据库写入错误或用户名冲突 | 检查数据库连接与 `user` 表唯一约束 |
| SSO 用户被本地登录拒绝 | 预期行为 | SSO 用户必须走 `?mode=sso`，本地登录会返回 `ErrUserNotExist` |

### 10.2 日志排查

SSO 登录相关日志关键字（`log.Warn`/`log.Trace`）：

```
SSO authentication request failed for <user> from <ip>: <err>
SSO authentication rejected for <user>: code=<code> message=<msg>
Failed SSO authentication attempt for <user> from <ip>: <err>
SSO auto-created user: <name>
```

---

## 附录：相关文件索引

| 分类 | 文件路径 |
|------|---------|
| **SSO 加密与调用** | `modules/auth/sso/sso.go` |
| **SSO 单元测试** | `modules/auth/sso/sso_test.go` |
| **SSO 配置定义** | `modules/setting/sso.go` |
| **SSO 配置测试** | `modules/setting/sso_test.go` |
| **SSO 登录处理** | `routers/web/auth/sso.go` |
| **登录路由入口** | `routers/web/auth/auth.go` |
| **登录路由测试** | `routers/web/auth/auth_test.go` |
| **本地登录拦截** | `services/auth/signin.go` |
| **用户模型** | `models/user/user.go` |
| **登录模板** | `templates/user/auth/signin_inner.tmpl` |
| **安装向导** | `routers/install/install.go` |
| **示例配置** | `custom/conf/app.example.ini` |
| **国际化** | `options/locale/locale_en-US.json`、`options/locale/locale_zh-CN.json` |
