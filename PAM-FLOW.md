# PAM 认证全流程详解

> 以本模块 `pam_hkpac` 在 UOS/deepin 图形登录中的实际运行为例。
> 文中所有"手册原文"引自本机 Linux-PAM 1.3.2.8 的 man 页；
> 所有"实测"来自本机复现；代码引用给出文件与行号。

---

## 目录

- [1. 三个角色](#1-三个角色)
- [2. 配置从哪来：/etc/pam.d 的读取规则](#2-配置从哪来etcpamd-的读取规则)
- [3. 配置文件的语法](#3-配置文件的语法)
- [4. 校验过程：一次 pam_authenticate 的完整时序](#4-校验过程一次-pam_authenticate-的完整时序)
- [5. conversation：模块与应用之间的唯一通道](#5-conversation模块与应用之间的唯一通道)
- [6. PAM_AUTHTOK：栈内模块间传递令牌的机制](#6-pam_authtok栈内模块间传递令牌的机制)
- [7. 落到本系统：UOS 图形登录的完整链路](#7-落到本系统uos-图形登录的完整链路)
- [8. 为什么模块的位置决定成败](#8-为什么模块的位置决定成败)
- [9. pam_hkpac 自身的代码级流程](#9-pam_hkpac-自身的代码级流程)
- [10. 配置是怎么被"生成"的：pam-auth-update](#10-配置是怎么被生成的pam-auth-update)
- [11. 调试手段](#11-调试手段)
- [12. 附录：本机实测数据](#12-附录本机实测数据)

---

## 1. 三个角色

| 角色 | 在本系统里是谁 | 职责 |
|---|---|---|
| **应用**（PAM-aware application） | lightdm 的 session-child 进程 | 调用 `pam_*` API，提供 conversation 回调 |
| **PAM 库**（libpam） | `/lib/x86_64-linux-gnu/libpam.so.0` | 读配置、解析模块栈、调度模块、维护栈状态 |
| **PAM 模块**（PAM） | `pam_hkpac.so`、`pam_deepin_authentication.so`、`pam_unix.so` … | 被 libpam `dlopen` 进来，实现 `pam_sm_*` 函数 |

模块本身**不知道**自己在栈里的位置，也**不知道**别的模块做了什么 —— 它们只通过 libpam 提供的
**PAM item**（如 `PAM_AUTHTOK`）和 **conversation** 间接通信。

---

## 2. 配置从哪来：/etc/pam.d 的读取规则

### 2.1 查找顺序

`pam_start(service_name, ...)` 是整件事的起点。手册原文（`man pam_start`）：

> The service_name argument specifies the name of the service to apply and will be stored as
> `PAM_SERVICE` item in the new context. The policy for the service will be read from the file
> **`/etc/pam.d/service_name`** or, if that file does not exist, from **`/etc/pam.conf`**.

`man pam.conf` 补充了目录优先于单文件的规则：

> Alternatively, this may be the contents of the **`/etc/pam.d/`** directory.
> **The presence of this directory will cause Linux-PAM to ignore `/etc/pam.conf`.**

所以实际顺序是：

```
1. /etc/pam.d/<service>        ← 存在就用它（本机所有服务都走这里）
2. /etc/pam.conf               ← 仅当 /etc/pam.d/<service> 不存在
   （/etc/pam.d 目录只要存在，/etc/pam.conf 就被完全忽略）
```

> **本机特有**：`strings /lib/x86_64-linux-gnu/libpam.so.0` 里还出现了
> `/usr/lib/pam.d/%s` 和 `/usr/lib/pam.d` —— 这是发行版补丁加的第二查找目录。
> 本机该目录**不存在**（`ls /usr/lib/pam.d` → No such file or directory），所以不起作用；
> 但换机器时值得留意。

`service_name` 就是文件名，**必须小写**。本系统里：

```
lightdm      图形登录（本模块插在这里）
dde-lock     锁屏解锁
sudo su sshd login polkit-1 cups samba ppp atd cron chfn chsh other …
```

另有保留服务名 **`other`**：当某个服务没有自己的配置文件时，用 `other` 兜底。

### 2.2 模块文件（module-path）怎么解析

`man pam.conf`：

> module-path is either the full filename of the PAM to be used by the application
> (it **begins with a `/`**), or a **relative pathname from the default module location:
> `/lib/security/` or `/lib64/security/`**, depending on the architecture.

本机（Debian 多架构）实际搜索路径实测为：

```
/lib/security
/lib/x86_64-linux-gnu/security      ← 本模块安装在这里
```

所以配置里写 `pam_hkpac.so`（相对名）会被解析成
`/lib/x86_64-linux-gnu/security/pam_hkpac.so`；写 `/tmp/xx/pam_hkpac.so`（绝对路径）则直接加载。
**调试时用绝对路径可以不安装就测试。**

---

## 3. 配置文件的语法

`/etc/pam.d/` 下每个文件由若干行组成（`man pam.conf`）：

```
type    control    module-path    module-arguments
```

（`/etc/pam.conf` 多一个开头的 `service` 字段；`/etc/pam.d/` 里没有，服务名就是文件名。）

### 3.1 `type` —— 管理组，共四类

| type | 用途 | 对应 API |
|---|---|---|
| `auth` | 认证身份 + 授予凭据 | `pam_authenticate` / `pam_setcred` |
| `account` | 非认证的账户管理（时段、资源、是否允许登录） | `pam_acct_mgmt` |
| `password` | 更新认证令牌（改密） | `pam_chauthtok` |
| `session` | 会话前后要做的事（挂载、日志、keyring） | `pam_open_session` / `pam_close_session` |

**`-` 前缀**（如 `-auth`）表示：模块文件不存在时**不要写系统日志**。手册原文：

> If the type value ... is prepended with a `-` character the PAM library will not log to the
> system log if it is not possible to load the module because it is missing in the system.

本机 `/etc/pam.d/lightdm` 里的 `-auth optional pam_deepin_keyring.so` 就是这个用法。

### 3.2 `control` —— 决定"模块返回这个码时，栈怎么走"

两种写法。

**（A）简单关键字**（手册原文）：

| 关键字 | 语义（引手册） |
|---|---|
| `required` | 失败**最终**导致 PAM 返回失败，但**仍会执行完栈里其余模块** |
| `requisite` | 同 required，但**一旦失败立即返回**给应用/上层栈；返回值取**第一个**失败的 required/requisite 模块 |
| `sufficient` | 若成功**且此前没有 required 失败**，**立即返回成功**，不再执行后续模块；若失败则被忽略，继续执行 |
| `optional` | 只有它是该 service+type 里**唯一**的模块时，成败才重要 |
| `include` | 把指定文件里**该 type 的所有行**包含进来 |
| `substack` | 同 include，但见下方差异 |

**（B）方括号 `[value=action ...]`** —— 对**每个返回码**单独指定动作：

```
[success=ok new_authtok_reqd=ok ignore=ignore default=die]
```

`valueN` 取 PAM 返回码名（`success`、`auth_err`、`user_unknown`、`ignore`、`abort`、`conv_err`…），
`default` 表示"未显式列出的所有码"。`actionN` 的语义（手册原文）：

| action | 语义 |
|---|---|
| `ignore` | 该模块的返回码**不参与**最终结果 |
| `bad` | 视为失败；若是栈中第一个失败，其状态码成为整个栈的状态码 |
| `die` | 等同 `bad`，**并立即终止模块栈**返回给应用 |
| `ok` | 该返回码**直接参与**最终结果：若此前状态是成功，用它的码覆盖 |
| `done` | 等同 `ok`，**并立即终止模块栈**返回 |
| `N`（整数） | 等同 `ok`，**并跳过后面 N 个模块**（N=0 不允许） |
| `reset` | 清空栈状态记忆，从下一个模块重新开始 |

四个关键字其实是 `[...]` 的简写（手册给出的等价式）：

```
required    [success=ok new_authtok_reqd=ok ignore=ignore default=bad]
requisite   [success=ok new_authtok_reqd=ok ignore=ignore default=die]
sufficient  [success=done new_authtok_reqd=done default=ignore]
optional    [success=ok new_authtok_reqd=ok default=ignore]
```

> **本机 `common-auth` 里 deepin 那一行长这样**：
> ```
> auth [success=4 auth_err=done new_authtok_reqd=ok ignore=ignore default=die] pam_deepin_authentication.so …
> ```
> 读法：成功 → 记成功并**跳过后面 4 个模块**；`auth_err` → 立即返回；`ignore` 类 → 不计入；
> **其他任何码 → `die`（立即失败）**。最后那条 `default=die` 很关键：它让"意外返回码"直接判失败，
> 不会静默放过。

### 3.3 `include` vs `substack` —— 本模块的位置就是靠这个成立的

手册原文：

> `substack` — include all lines of given type from the configuration file specified as an argument
> to this control. **This differs from `include` in that evaluation of the `done` and `die` actions in
> a substack does not cause skipping the rest of the complete module stack, but only of the substack.
> Jumps in a substack also can not make evaluation jump out of it, and the whole substack is counted
> as one module when the jump is done in a parent stack.** The `reset` action will reset the state of
> a module stack to the state it was in as of beginning of the substack evaluation.

三句话逐条对应到我们的场景：

1. **`die` 只终止 substack，不终止整个栈** —— 所以 `common-auth` 里 `pam_deny.so` 判死，只结束 `common-auth`，父栈 `lightdm` 仍继续往下走；
2. **substack 内的跳转跳不出 substack** —— 所以 `common-auth` 里 deepin 的 `success=4` 只在 `common-auth` **内部**跳，**不会跳过父栈后面的模块**；
3. **整个 substack 在父栈里算作"一个模块"** —— 所以父栈 `lightdm` 里 `substack common-auth` 之后的那一行，会在 substack 整体返回后**正常被执行**。

**第 2、3 条正是 `pam_hkpac` 能放在 `lightdm` 里 `substack common-auth` 之后的原因。**

---

## 4. 校验过程：一次 pam_authenticate 的完整时序

### 4.1 应用侧的调用序列

一个规范的应用（lightdm 就是这样）按顺序调用：

```
pam_start(service, user, &conv, &pamh)   ← 建立事务、读配置、建栈
   │
   ├─ pam_authenticate(pamh, flags)      ← 走 auth 栈：验证"你是你"
   ├─ pam_acct_mgmt(pamh, flags)         ← 走 account 栈：账户是否可用
   ├─ pam_setcred(pamh, flags)           ← 走 auth 栈的凭据授予部分
   ├─ pam_open_session(pamh, flags)      ← 走 session 栈：建会话
   │      … 用户使用服务 …
   ├─ pam_close_session(pamh, flags)     ← 走 session 栈：收尾
   └─ pam_end(pamh, status)              ← 释放事务
```

`pam_chauthtok()`（改密）走 `password` 栈，与登录流程并列、独立触发。

**每一步都只处理自己那个 type 的行**。`pam_authenticate` 完全不看 `session` 行。

### 4.2 `pam_authenticate` 内部发生了什么

手册原文（`man pam_authenticate`）：

> The `pam_authenticate` function is used to authenticate the user. The user is required to provide
> an authentication token depending upon the authentication service, usually this is a password,
> but could also be a finger print.

展开成流程：

```
pam_authenticate(pamh, flags)
  └─ _pam_dispatch(pamh, flags, PAM_AUTHENTICATE)
       ├─ 取 auth 栈（按 /etc/pam.d/<service> 里 auth 行的顺序，substack 就地展开）
       ├─ 逐行：dlopen 模块 → 调 pam_sm_authenticate(pamh, flags, argc, argv)
       │        ↑ argc/argv 就是配置行里 module-arguments 拆出来的
       ├─ 每个返回值按该行的 control 映射成 action（ignore/bad/die/ok/done/N/reset）
       └─ 维护栈状态：
             · 记录"是否已有 required 失败"和"第一个失败的返回码"
             · sufficient 成功且无先前失败 → 立即 PAM_SUCCESS 返回
             · die/done → 立即返回
             · N → 跳过 N 行
       结束时：有 required 失败 → 返回第一个失败的码；否则 PAM_SUCCESS
```

返回值语义（手册 `RETURN VALUES`）：`PAM_SUCCESS` / `PAM_AUTH_ERR` / `PAM_USER_UNKNOWN` /
`PAM_MAXTRIES` / `PAM_AUTHINFO_UNAVAIL` / `PAM_CRED_INSUFFICIENT` / `PAM_ABORT` 等。

**模块侧**的契约是 `pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)`
—— 注意 `argc/argv`：这就是为什么配置里可以写 `pam_hkpac.so key_name=ACpass debug log=/tmp/x.log`，
模块在 `pam_sm_authenticate` 里自己解析 `argv`。

### 4.3 一次完整的 auth 栈执行（以本机 `lightdm` 为例）

```
/etc/pam.d/lightdm:
  auth  requisite                          pam_nologin.so
  auth  [success=1 new_authtok_reqd=done default=ignore] pam_succeed_if.so user ingroup nopasswdlogin
  auth  substack                           common-auth          ← 就地展开
  auth  optional                           pam_hkpac.so key_name=ACpass   ← 本模块
  auth  required                           pam_permit.so
```

`common-auth` 展开后：

```
  auth  [success=4 auth_err=done … default=die]  pam_deepin_authentication.so …
  auth  [success=3 default=ignore]               pam_fprintd.so …
  auth  [success=2 default=ignore]               pam_unix.so nullok_secure try_first_pass
  auth  [success=1 default=ignore]               pam_udcp.so try_first_pass
  auth  requisite                                pam_deny.so
  auth  required                                 pam_permit.so
```

deepin 成功时 `success=4` 的跳转：跳过 fprintd、unix、udcp、deny 共 4 个 → 落到 `pam_permit.so`
→ 成功。**substack 整体返回成功** → 父栈继续 → `pam_hkpac.so` 执行（读令牌）→ `pam_permit.so` → 成功。

---

## 5. conversation：模块与应用之间的唯一通道

模块**不能**自己弹窗、读键盘。它要跟用户交互，只能调用应用注册的回调。手册原文（`man pam_conv`）：

> The PAM library uses an application-defined callback to allow a direct communication between a
> loaded module and the application. This callback is specified by the `struct pam_conv` passed to
> `pam_start(3)` at the start of the transaction.

```c
struct pam_message  { int msg_style; const char *msg; };
struct pam_response { char *resp; int resp_retcode; };

struct pam_conv {
    int (*conv)(int num_msg, const struct pam_message **msg,
                struct pam_response **resp, void *appdata_ptr);
    void *appdata_ptr;
};
```

`msg_style` 四种（手册原文）：

| 值 | 含义 |
|---|---|
| `PAM_PROMPT_ECHO_OFF` | 取一个字符串，**不回显**（密码） |
| `PAM_PROMPT_ECHO_ON` | 取一个字符串，回显（用户名） |
| `PAM_ERROR_MSG` | 显示错误信息 |
| `PAM_TEXT_INFO` | 显示提示文本 |

**模块怎么触发一次 prompt**：调用 `pam_get_authtok()`（令牌未设时它会经 conversation 发
`PAM_PROMPT_ECHO_OFF`），或直接取 `PAM_CONV` item 后自己调 `conv()`。

> `pam_deepin_authentication.so` 走的是后者。见
> `deepin-authentication/misc/pam-module/auth/pam.c` 的 `send_msg()`：
> ```c
> ret = pam_get_item(ud->pamh, PAM_CONV, (const void **)&pconv);
> ret = pconv->conv(1, &pmsg_ptr, &presp, pconv->appdata_ptr);   // style = PAM_PROMPT_ECHO_OFF
> ```
> 它在**子线程** `run_request_pw()` 里发起，然后把响应当成 `"路径;token"` 解析。

**关键约束**：conversation 是**一次问答**语义 —— 一个 prompt 等一个 response。应用端决定
"什么时候回答、回答几次"。**图形登录的应用端（dde-session-shell）在整次认证里只回答一次**
（见第 7 节）。这直接决定了模块**不能**随便多 prompt 一次。

---

## 6. PAM_AUTHTOK：栈内模块间传递令牌的机制

手册原文（`man pam_get_item`）：

> `PAM_AUTHTOK` — The authentication token (often a password). **This token should be ignored by all
> module functions besides `pam_sm_authenticate(3)` and `pam_sm_chauthtok(3)`. In the former function
> it is used to pass the most recent authentication token from one stacked module to another.**
> It contains the currently active authentication token.

这句话就是 `pam_hkpac` 的**设计依据**：

- `pam_deepin_authentication.so` 在认证成功时调用
  `pam_set_item(pamh, PAM_AUTHTOK, ud->auth_tok)`（`pam.c` 的 `run_request_pw()` 与 `bus_signal_cb()`），
  把明文写进这个 item；
- `pam_hkpac.so` 在**它之后**运行，用 `pam_get_item(pamh, PAM_AUTHTOK, &pass)` **只读**取出；
- 标准做法里，下游模块用 `try_first_pass` 参数去复用上游设好的令牌（本机 `pam_unix.so nullok_secure try_first_pass`
  就是这个用法）。

item 存在 `pam_handle_t` 里，**整个事务共享**，所以跨模块、跨 substack 都能读到。取值时拿到的是
**指向内部数据的指针**，手册明确要求 **不要 free、不要改写**。

> 由此推出一条纪律：**`PAM_AUTHTOK` 是"共享状态"，谁都能改，改了会影响到后面所有模块。**
> 所以 `pam_hkpac` 只读不写 —— 不 prompt（避免把 prompt 结果写回该 item）、不 set_item。

---

## 7. 落到本系统：UOS 图形登录的完整链路

### 7.1 谁在调 PAM

```
lightdm 主进程
  └─ 为每次登录 fork 出 session-child
       └─ 调 pam_start("lightdm", user, &conv, &pamh)
            └─ conv 回调 → 通过 lightdm 的 socket 发给 greeter
```

`service_name` = `"lightdm"` → 读 `/etc/pam.d/lightdm`。

### 7.2 greeter 的委托认证：**整个流程只 respond 一次**

`dde-session-shell` 的 greeter **不是**传统 PAM 应用。它把真正的认证委托给
deepin-authentication 的守护进程，PAM 只是最后一环：

```
dde-session-shell/src/lightdm-deepin-greeter/greeterworker.cpp

  :657  showPrompt(text, type)
            → 只是 m_model->updateAuthState(AT_PAM, AS_Prompt, text)
            → 只显示界面，**不 respond**

  :749  onAuthFinished()
            → m_greeter->respond( AuthSessionPath(m_account) + ";" + m_password )
            ↑ 唯一的 respond 点，由 SFAWidget::sendAuthFinished() 触发

dde-session-shell/src/session-widgets/sfa_widget.cpp
  :1231 onLightdmPamStartChanged()  /  :842 checkAuthResult()
            → 条件是 type == AT_All && state == AS_Success
            → 即"域管认证已经报成功"才发
  :1235 sendAuthFinished() → emit authFinished()
```

**结论：一次登录，PAM conversation 只会被回答一次，回答的内容是 `"<会话路径>;<明文密码>"`。**

### 7.3 deepin 模块如何用这次回答

`deepin-authentication/misc/pam-module/auth/pam.c`：

```c
static void *run_request_pw(void *user_data)          // 子线程
{
    rep = send_msg(ud, ud->prompt, PAM_PROMPT_ECHO_OFF);   // ← 等那唯一一次回答
    if (rep) {
        if (split_data(rep->resp, &path, &tok) == 0) {     // 拆 "路径;token"
            dbus_method_getResult(ud, path, &res);         // 拿委托认证的结果
            …
            ud->auth_tok = strdup(tok);
            pam_set_item(ud->pamh, PAM_AUTHTOK, ud->auth_tok);   // ← 明文进 PAM_AUTHTOK
            ud->res = PAM_SUCCESS;
        }
        …
    }
}
```

于是链路闭合：

```
用户输入密码
   → greeter 把 token 发给 deepin-authentication 守护进程做真正的校验
   → 校验成功 → onAuthFinished → respond("路径;明文密码")
   → pam_deepin_authentication.so 收到 → 拆出明文 → pam_set_item(PAM_AUTHTOK, 明文) → PAM_SUCCESS
   → substack common-auth 整体成功返回
   → pam_hkpac.so 运行 → 只读 PAM_AUTHTOK → 写入用户 keyring
   → pam_permit.so → 认证通过 → lightdm startSessionSync → 进入桌面
```

---

## 8. 为什么模块的位置决定成败

`common-auth` 里每个认证模块都以 `[success=end …]` 结尾（`/usr/share/pam-configs/*` 里写的是
`end`，被 `pam-auth-update` 改写成数字 `success=N`）。这造成**两种位置都堵死**：

| 位置 | 结果 | 原因 |
|---|---|---|
| `common-auth` 内、deepin **之前** | ❌ **登录失败** | 模块若 prompt，会**抢走那唯一一次 respond**；deepin 的 `send_msg()` 永远等不到回答 → 认证失败。而"抢到"的模块恰好拿到了明文，于是表现为"看起来在工作，但进不了桌面" |
| `common-auth` 内、deepin **之后** | ❌ **拿不到密码** | deepin 的 `success=end` 成功后**直接跳到栈尾**，后面的模块根本不执行 |
| **`lightdm` 里 `substack common-auth` 之后** | ✅ **正确** | substack 的跳转跳不出自己（第 3.3 节）；整体返回后父栈继续，本模块被正常执行；此时 `PAM_AUTHTOK` 已由 deepin 写好 |

对应到实际配置：

```pam
# /etc/pam.d/lightdm
auth      requisite pam_nologin.so
auth      [success=1 new_authtok_reqd=done default=ignore] pam_succeed_if.so user ingroup nopasswdlogin
auth      substack common-auth
auth      optional pam_hkpac.so key_name=ACpass      # ← 就插在这里
auth      required pam_permit.so
```

---

## 9. pam_hkpac 自身的代码级流程

### 9.1 `pam_sm_authenticate()` 逐段

```c
PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    /* 1) 解析配置参数：key_name=… / debug / log=… */
    for (i = 0; i < argc; i++) { … }

    /* 2) 取用户名（PAM_USER item），后续要按它 setuid 写 keyring */
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || !user || !*user)
        goto out;

    /* 3) 只读认证令牌 —— 绝不 prompt、绝不改写 */
    if (pam_get_item(pamh, PAM_AUTHTOK, (const void **)&pass) != PAM_SUCCESS
        || !pass || !*pass)
        goto out;                       /* 上游没写令牌就静默跳过，不影响登录 */

    /* 4) 兼容 delegated 格式：仅当以 '/' 开头时才按 "路径;token" 拆 */
    payload = pass;
    semi = strchr(pass, ';');
    if (semi && semi != pass && pass[0] == '/')
        payload = semi + 1;

    /* 5) 写入用户 keyring */
    rc = store_to_user_keyring(user, key_name, payload, strlen(payload));

out:
    return PAM_IGNORE;                  /* 纯副作用，绝不影响认证结论 */
}
```

要点：

- **不调用 `pam_get_authtok()`** —— 它在令牌未设时会主动 prompt，会破坏第 7.2 节的"唯一一次 respond"；
- **不改写 `PAM_AUTHTOK`** —— 它是共享状态（第 6 节），改了会污染下游；
- **恒返回 `PAM_IGNORE`** —— 由 `optional` 语义（第 3.2 节）决定它不参与最终结果；
- `pam_sm_setcred()` 直接返回 `PAM_SUCCESS`（本模块不授予任何凭据）。

### 9.2 keyring 写入：为什么必须 fork + setuid

`@u`（用户 keyring）是**按 UID** 的。模块运行在 lightdm 的 session-child 里（root），
所以要写进**目标用户**的 `@u`，必须切到该用户身份：

```c
pid_t pid = fork();
if (pid == 0) {
    setgroups(0, NULL); setgid(pw->pw_gid); setuid(pw->pw_uid);   /* 变成目标用户 */

    /* 四步走，缺一不可 */
    keyctl(KEYCTL_JOIN_SESSION_KEYRING, "hkpac");                  /* 1. 进会话 keyring（进程即 possessor） */
    k = add_key("user", key_name, payload, len, KEY_SPEC_SESSION_KEYRING);  /* 2. 在 @s 里建 key */
    keyctl(KEYCTL_SETPERM, k, KEY_POS_ALL | KEY_USR_ALL);          /* 3. 授权（此时才有资格改权限） */
    keyctl(KEYCTL_LINK, k, KEY_SPEC_USER_KEYRING);                 /* 4. link 进 @u */
    _exit(0);
}
```

**为什么不能一步 `add_key(..., KEY_SPEC_USER_KEYRING)`**（实测，见第 12 节）：

| 做法 | 权限位 | 属主能读吗 |
|---|---|---|
| 直接建在 `@u` | `3f010000`（possessor 全权、**user 只有 view**） | ❌ Permission denied |
| 我们的四步 | `3f3f0000`（possessor + user 全权） | ✅ 可读 |

原因：调用进程**不是 possessor** 时只有 `user` 权限生效，而 `user` 默认只有 `view`（无 read）；
且此时连 `SETPERM` 都会被拒（没有 setattr 权限）。所以必须先"进会话 keyring 当 possessor → 建 key
→ 授权 → 再 link 出去"。

> 补充：**删除 key 不需要 key 上的任何权限位** —— `unlink` 要的是**对 keyring 的 write 权限**。
> 属主对自己的 `@u` 永远有 write，所以两种权限位都删得掉（第 12 节实测）。

---

## 10. 配置是怎么被"生成"的：pam-auth-update

`/etc/pam.d/common-auth` 顶部写着 "managed by pam-auth-update by default"。它的输入是
`/usr/share/pam-configs/*`，每个 profile 形如：

```
Name: Deepin Authentication
Default: yes
Priority: 1024                 ← 决定在栈里的先后（大的在前）
Auth-Type: Primary
Auth:
	[success=end auth_err=done new_authtok_reqd=ok ignore=ignore default=die] pam_deepin_authentication.so …
```

本机 profile 的优先级（实测）：

```
deepin-authentication  1024
fprintd.amd64           260
unix                    256
udcp-iam                200
systemd / mkhomedir / gnome-keyring   0
```

**两个必须知道的行为**：

1. **`success=end` 会被改写成数字**。profile 里写的是 `end`，生成到 `common-auth` 里变成
   `success=4`（因为栈里还有 4 个 Primary 模块要跳过）。所以**手工删模块行后必须重跑
   `pam-auth-update`**，否则跳转数对不上。
2. **本机 `libpam-runtime` 没有 dpkg trigger**，`pam-auth-update` 必须由包自己的
   maintainer script 调用（本包的 `postinst`/`prerm` 就是这么做的）。

**为什么本模块不走这条路**：见第 8 节 —— `common-auth` 里无论放前放后都不成立。

---

## 11. 调试手段

```bash
# 1) 看配置实际长什么样（含 pam-auth-update 生成的结果）
grep -n '^auth' /etc/pam.d/common-auth
grep -n -B1 -A2 pam_hkpac /etc/pam.d/lightdm

# 2) 认证日志（模块的 pam_syslog 与内核/lightdm 的错误都在这）
journalctl -b | grep -iE 'pam_hkpac|pam_deepin_authentication|authentication failure'

# 3) 让本模块输出调试日志（改 lightdm 里那一行，加 debug log=…）
#    auth optional pam_hkpac.so key_name=ACpass debug log=/tmp/pam_hkpac.log
#    日志只打元信息（长度/是否有分号/掩码预览），不打完整密码

# 4) 看 PAM 栈在做什么：插入 pam_debug.so（会把每次调用与返回打到 syslog）
#    auth optional pam_debug.so

# 5) 不安装就测试模块：配置里用绝对路径
#    auth optional /tmp/test/pam_hkpac.so key_name=ACpass debug log=/tmp/x.log

# 6) 看/读/删用户 keyring 里的键（注意必须显式写 @u）
keyctl show @u
serial=$(keyctl search @u user ACpass)
keyctl pipe   "$serial"          # 读明文
keyctl unlink "$serial" @u       # 删：不带 @u 默认操作 @s，会输出 "0 links removed" 且退出码 0
```

---

## 12. 附录：本机实测数据

### 12.1 key 权限位对比

```
$ keyctl show @u
Keyring
 762436975 --alswrv  11670 65534  keyring: _uid.11670
 156780252 --alswrv  11670 11670   \_ user: ACpass
```

`--alswrv` 中 `alswrv` = 属主列的 `setattr,link,search,write,read,view` 全有
→ 权限位 `3f3f0000`，即本模块的 `SETPERM` 生效。

### 12.2 读取与删除（两种建 key 方式）

| 建 key 方式 | 权限位 | 属主读 | 属主 `unlink … @u` |
|---|---|---|---|
| 旧做法（直接 `add_key` 到 `@u`） | `3f010000` | ❌ Permission denied | ✅ OK |
| 本模块（`@s` + SETPERM + link） | `3f3f0000` | ✅ 明文 | ✅ OK |

### 12.3 `keyctl unlink` 的默认 keyring

```
$ keyctl unlink <serial>        # 不指定 keyring
0 links removed                 # ← 退出码 0，但什么都没删（键在 @u，默认操作 @s）

$ keyctl unlink <serial> @u     # 显式指定
（删除成功）

# 对照：把键放进 @s 再不带 keyring 删
$ keyctl unlink <serial>
1 links removed                 # ← 默认确实是 @s
```

### 12.4 超时（可选加固）

`KEYCTL_SET_TIMEOUT` 对 `user` 类型 key 有效（`/proc/keys` 的 expiry 列显示 `1m`），
可让明文即使没被 `start.sh` 删掉也会自动过期。

```
246563f0 I--Q---     2   1m 3f3f0000 14457 14457 user      ACpass: 10
                        ↑ expiry
```

---

## 附：关键结论速查

1. `pam_start("lightdm", …)` → 读 **`/etc/pam.d/lightdm`**（`/etc/pam.d` 存在则忽略 `/etc/pam.conf`）。
2. 配置行格式 `type control module-path module-arguments`；模块相对名从 `/lib/<triplet>/security/` 解析。
3. `pam_authenticate` 按 **auth** 栈逐行 `dlopen` + 调 `pam_sm_authenticate`，按 control 决定跳转与最终结果。
4. **`substack` 内的跳转跳不出去，整体算作父栈里的一个模块** —— 本模块的位置靠这条成立。
5. **`PAM_AUTHTOK` 是栈内模块间传递令牌的标准机制**，也是本模块的取值来源；它是共享状态，**只读不写**。
6. **图形登录全程只 respond 一次** —— 所以本模块**绝不 prompt**。
7. keyring 写入必须 **fork + setuid 到目标用户**，并按"`@s` 建 → `SETPERM` → link `@u`"四步走，否则属主读不出来。
8. 读/删 `@u` 的键**必须显式写 `@u`**；不带 keyring 时 `keyctl unlink` 默认操作 `@s`，会**静默不删**（退出码 0）。
