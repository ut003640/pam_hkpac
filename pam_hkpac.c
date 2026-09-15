/*
 * pam_hkpac.so — 独立极简 PAM 模块（不依赖 deepin-authentication）
 *
 * 用途：认证阶段拿到用户密码，写入该用户 @u keyring（键名默认 ACpass），
 *       供后续 SSO 使用。本模块不做认证，返回 PAM_IGNORE，真正的认证由
 *       栈里后续的 pam_deepin_authentication.so 完成。
 *
 * 编译：
 *   gcc -shared -fPIC -O2 -fstack-protector-strong \
 *       -o pam_hkpac.so pam_hkpac.c -lpam
 *
 * 安装：
 *   install -m 644 pam_hkpac.so /usr/lib/x86_64-linux-gnu/security/
 *
 * 配置（/etc/pam.d/lightdm 的 auth 段，放在 auth substack common-auth 之前）：
 *   auth    optional    pam_hkpac.so key_name=ACpass debug log=/tmp/pam_hkpac.log
 *
 * 参数：
 *   key_name=NAME   写入 @u 的键名，默认 ACpass
 *   debug           打开调试日志
 *   log=FILE        调试日志同时写入该文件（需配合 debug）
 *
 * 注意：debug 只打元信息（长度/格式/掩码预览，不打完整密码），排查完请去掉 debug。
 *
 * 已知代价：
 *   1. 本模块会 prompt 一次拿密码，后面的 pam_deepin_authentication.so 不支持
 *      try_first_pass，可能再 prompt 一次（用户可能输两次密码）。
 *   2. 密码会以 user 类型 key 短暂存进 @u，同 UID + root 可读。
 */

#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>

#ifndef KEY_SPEC_USER_KEYRING
#define KEY_SPEC_USER_KEYRING (-4)
#endif
#ifndef KEY_SPEC_SESSION_KEYRING
#define KEY_SPEC_SESSION_KEYRING (-3)
#endif
#ifndef KEYCTL_JOIN_SESSION_KEYRING
#define KEYCTL_JOIN_SESSION_KEYRING 1
#endif
#ifndef KEYCTL_LINK
#define KEYCTL_LINK 8
#endif

/* key 权限位（与 <keyutils.h> 一致，这里不依赖 keyutils） */
#define KEY_POS_VIEW    0x01000000UL
#define KEY_POS_READ    0x02000000UL
#define KEY_POS_WRITE   0x04000000UL
#define KEY_POS_SEARCH  0x08000000UL
#define KEY_POS_LINK    0x10000000UL
#define KEY_POS_SETATTR 0x20000000UL
#define KEY_POS_ALL     0x3f000000UL
#define KEY_USR_VIEW    0x00010000UL
#define KEY_USR_READ    0x00020000UL
#define KEY_USR_WRITE   0x00040000UL
#define KEY_USR_SEARCH  0x00080000UL
#define KEY_USR_LINK    0x00100000UL
#define KEY_USR_SETATTR 0x00200000UL
#define KEY_USR_ALL     0x003f0000UL

#ifndef KEYCTL_SETPERM
#define KEYCTL_SETPERM  5
#endif

#define DEFAULT_KEY_NAME "ACpass"

static FILE *g_logfp = NULL;

/* 调试日志：同时写 syslog 和（可选）文件 */
static void dlog(pam_handle_t *pamh, const char *fmt, ...)
{
    char buf[256];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    pam_syslog(pamh, LOG_INFO, "hkpac: %s", buf);
    if (g_logfp) {
        fprintf(g_logfp, "hkpac: %s\n", buf);
        fflush(g_logfp);
    }
}

/* 打印响应元信息（不打完整密码） */
static void log_resp(pam_handle_t *pamh, const char *tag, const char *s)
{
    size_t len = s ? strlen(s) : 0;
    int printable = (len > 0);
    char preview[40] = {0};
    size_t i;

    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20 || c > 0x7e) {
            printable = 0;
            break;
        }
    }

    /* 掩码预览：只露首尾各几个字符，足以区分明文/base64/二进制 */
    if (len == 0)
        snprintf(preview, sizeof(preview), "(empty)");
    else if (len <= 4)
        snprintf(preview, sizeof(preview), "****");
    else if (len <= 12)
        snprintf(preview, sizeof(preview), "%.2s****%.2s", s, s + len - 2);
    else
        snprintf(preview, sizeof(preview), "%.4s******%.4s", s, s + len - 4);

    dlog(pamh, "[%s] len=%zu has_semicolon=%d printable=%d preview='%s'",
         tag, len, (s && strchr(s, ';')) ? 1 : 0, printable, preview);
}

/* 以目标用户身份把 payload 写入其 @u 用户 keyring */
static int
store_to_user_keyring(const char *username, const char *key_name,
                      const char *payload, size_t len)
{
    struct passwd *pw = getpwnam(username);
    if (!pw)
        return -1;

    pid_t pid = fork();
    if (pid < 0)
        return -1;

    if (pid == 0) {
        if (setgroups(0, NULL) != 0) _exit(127);
        if (setgid(pw->pw_gid) != 0)  _exit(127);
        if (setuid(pw->pw_uid) != 0)  _exit(127);

        /*
         * 关键：add_key 建在 @u 里的 key，调用进程不是 possessor，只有 user 权限
         * 生效，而 user 默认只有 view（无 read）——属主自己都读不出来，且改不了权限。
         * 所以：
         *   1) 先进会话 keyring，在里面建 key（进程即 possessor）
         *   2) SETPERM 授权（此时才允许改）
         *   3) 再 link 进 @u（会话结束后仍留在用户 keyring，供 SSO 读取）
         */
        syscall(SYS_keyctl, KEYCTL_JOIN_SESSION_KEYRING, "hkpac");

        long k = syscall(SYS_add_key, "user", key_name,
                         payload, len, KEY_SPEC_SESSION_KEYRING);
        if (k < 0)
            _exit(127);

        if (syscall(SYS_keyctl, KEYCTL_SETPERM, k,
                    (unsigned long)(KEY_POS_ALL | KEY_USR_ALL)) < 0)
            _exit(127);

        if (syscall(SYS_keyctl, KEYCTL_LINK, k, KEY_SPEC_USER_KEYRING) < 0)
            _exit(127);

        _exit(0);
    }

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR)
            return -1;
    }
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)flags;
    const char *user = NULL;
    const char *pass = NULL;
    const char *key_name = DEFAULT_KEY_NAME;
    const char *log_file = NULL;
    const char *payload = NULL;
    const char *semi = NULL;
    int debug = 0;
    int i;
    int rc;

    for (i = 0; i < argc; i++) {
        if (strncmp(argv[i], "key_name=", 9) == 0)
            key_name = argv[i] + 9;
        else if (strncmp(argv[i], "log=", 4) == 0)
            log_file = argv[i] + 4;
        else if (strcmp(argv[i], "debug") == 0)
            debug = 1;
    }

    if (debug && log_file)
        g_logfp = fopen(log_file, "a");

    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || !user || !*user)
        goto out;

    /* 拿密码：PAM_AUTHTOK 已设则复用，否则经 conversation 提示 */
    if (pam_get_authtok(pamh, PAM_AUTHTOK, &pass, NULL) != PAM_SUCCESS || !pass || !*pass)
        goto out;

    if (debug) {
        dlog(pamh, "user='%s'", user);
        log_resp(pamh, "raw", pass);
    }

    /*
     * UOS 上 greeter 可能回吐 "会话路径;token"（delegated 格式）。
     * 仅当前半段确实是路径（以 '/' 开头）时才拆取 token，避免误拆含 ';' 的密码。
     */
    payload = pass;
    semi = strchr(pass, ';');
    if (semi && semi != pass && pass[0] == '/') {
        payload = semi + 1;
        if (debug)
            log_resp(pamh, "token", payload);
    }

    if (!*payload) {
        if (debug)
            dlog(pamh, "payload is empty, skip");
        goto out;
    }

    rc = store_to_user_keyring(user, key_name, payload, strlen(payload));
    if (debug)
        dlog(pamh, "write @u key '%s' for user '%s': %s",
             key_name, user, rc == 0 ? "ok" : "FAILED");

out:
    if (g_logfp) {
        fclose(g_logfp);
        g_logfp = NULL;
    }
    /* 纯副作用，不影响认证结论 */
    return PAM_IGNORE;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}
