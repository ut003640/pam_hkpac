pam_hkpac
==========

PAM 模块：在认证阶段把用户的明文密码写入该用户 keyring（键名默认 ACpass），
供后续 SSO（如 proxy 认证）复用，避免用户二次输入。

本模块不做认证，返回 PAM_IGNORE，真正的认证仍由后续模块
（如 common-auth 里的 pam_deepin_authentication.so）完成。

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
在 /etc/pam.d/<service>（如 lightdm）的 auth 段、认证模块之前新增一行：

    auth    optional    pam_hkpac.so key_name=ACpass

注意：add_key 直接建在 @u 里的 key 默认不含属主 read，本模块采用
"会话 keyring 建 key -> SETPERM 授权 -> link 进 @u" 的方式保证可读。

详细说明（实现原理、安全代价、验证与回滚、维护边界）见 DELIVERY.txt。
