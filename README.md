# hstc-campus-sso-login

韩师校园网无头登录。没有浏览器、没有桌面客户端也能认证上网。

仓库里两个脚本：`campus-sso-login.sh`（Linux / macOS）和 `campus-sso-login.ps1`（Windows）。

```bash
git clone https://github.com/SII56/hstc-campus-sso-login.git
cd hstc-campus-sso-login
```

## Windows

直接运行包装器就行（它会自动绕过 PowerShell 的脚本执行限制，不改系统设置、不需要管理员）：

```
campus-sso-login.cmd
```

不带参数就是登录（已在线会跳过）。想要菜单就加 `-Menu`：

```
campus-sso-login.cmd -Menu             # 菜单
campus-sso-login.cmd -Check            # 只看在不在线
campus-sso-login.cmd -Sms 138xxxxxxxx  # 短信登录（验证码发到手机）
campus-sso-login.cmd -DryRun           # 走完整条链路，但不提交密码
campus-sso-login.cmd -Logout           # 注销
campus-sso-login.cmd -Force            # 忽略在线状态，强制认证
campus-sso-login.cmd -Help             # 列出全部选项
```

会提示输入学号和密码（密码不回显）。

> 直接调 `.ps1` 的话会被执行策略拦住，需要自己加参数：
> `powershell -ExecutionPolicy Bypass -File .\campus-sso-login.ps1`

需要 Windows 10 1803 以上（要用系统自带的 `curl.exe`）和 PowerShell 5.1 以上。

不想每次输密码，就在脚本同目录建一个 `campus.conf.ps1`：

```powershell
$CAMPUS_USER = "202412345678"
$CAMPUS_PASS = "your-password"
```

## Linux / macOS
先添加权限
```bash
chmod +x campus-sso-login.sh
```
输入执行
```bash
./campus-sso-login.sh
```
会提示输入学号和密码（密码不回显）。其它参数：
```bash
# 菜单
./campus-sso-login.sh --menu
# 只看在不在线
./campus-sso-login.sh --check
./campus-sso-login.sh --sms 138xxxxxxxx   # 短信登录（验证码会发到你手机）
# 走完整条链路，但不提交密码
./campus-sso-login.sh --dry-run
# 注销
./campus-sso-login.sh --logout
# 忽略在线状态，强制认证
./campus-sso-login.sh --force
```

## 账号密码

```bash
cp campus.conf.example campus.conf
chmod 600 campus.conf
vi campus.conf
```

不写也行，会在终端里提示输入。

> 只有 CAS 真的要你填登录表单时才会问密码。如果 CAS 已经认得这台机器（IP 级 SSO），
> 它会直接发 ticket，全程不需要密码。

**脚本不保存任何密码**：密码只在这个进程的内存里，从 stdin 交给 curl，
不会出现在 `ps` 的命令行里；`cookies.txt`（可能含 CAS 会话 cookie）退出时自动删除，
工作目录权限 700。

## 出问题看这里

日志：`/tmp/campus-sso-login.log`
现场文件：`/tmp/campus-sso/`（Windows 是 `%TEMP%\campus-sso\`）

| 文件 | 看什么 |
|---|---|
| `cas-login.html` | CAS 返回的页面，确认有没有 `execution` |
| `post.html` | 提交密码后 CAS 的回复，密码错会写在这里 |

## 注意

- `campus.conf` 里是明文密码，权限设成 `600`，别提交到仓库。
- 脚本只做登录/注销，不改任何网络配置。

## License

CC0-1.0，见 [LICENSE](LICENSE)。
