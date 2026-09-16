pam_hkpac
==========

PAM 模块：认证成功后，把上游认证模块写在 PAM_AUTHTOK 里的明文密码
写入该用户 keyring（键名默认 ACpass），供后续 SSO（如 proxy 认证）复用，
避免用户二次输入。

本模块不做认证、不发起 PAM 对话（不 prompt）、不修改任何 PAM 令牌，
只读 PAM_AUTHTOK，返回 PAM_IGNORE，真正的认证仍由
pam_deepin_authentication.so 完成。

构建
----
    make

安装（手工）
------------
    sudo make install

Debian 打包
-----------
    dpkg-buildpackage -b -us -uc
    # 或
    debuild -b -us -uc

配置
----
必须放在 /etc/pam.d/lightdm 里，且紧随 `auth substack common-auth` 之后：

    auth      substack common-auth
    auth      optional pam_hkpac.so key_name=ACpass
    auth      required pam_permit.so

不能放进 common-auth：放 pam_deepin_authentication.so 之前，本模块若 prompt
会抢走图形登录唯一的那次 conversation 应答，导致 deepin 的 prompt 等不到
回答、登录失败；放它之后，它用的 [success=end ...] 会直接跳到栈尾跳过本模块。
详见 DELIVERY.txt 第三节。

装包时无需手工配置：维护者脚本会自动插入/摘除该行。

注意：add_key 直接建在 @u 里的 key 默认不含属主 read，本模块采用
"会话 keyring 建 key -> SETPERM 授权 -> link 进 @u" 的方式保证可读。

详细说明（实现原理、安全代价、验证与回滚、维护边界）见 DELIVERY.txt。
