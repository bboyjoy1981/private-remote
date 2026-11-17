# PrivateRemote

**两台 Windows 电脑之间，简单、干净的远程桌面试用项目。**

不用看广告，也没有付费解锁画质的设计。当前版本提供远程桌面与双向文件传输；局域网可连接，外网可通过 Tailscale 连接，欢迎体验、阅读源码和反馈问题。

> **项目状态：开源试用版。** 画面目前采用 JPEG 传输，提供 720p、900p 和清晰档（原画最高 4K）；实际清晰度和速度取决于双方电脑与网络。外网使用需两端安装并连接 Tailscale；内置公网中继、自动部署与正式发行尚未完成。

![朋友圈宣传图](poster-wechat.png)

## 已实现

- Windows 桌面客户端，支持设备配对和本机确认权限。
- 局域网连接，以及通过 Tailscale 在外网连接、屏幕查看与输入控制。
- 双向文件传输，接收端自行选择保存位置。
- 设备身份签名、证书固定校验、加密传输与文件完整性校验。
- 不含广告模块，也没有画质付费限制。

## 快速开始

需要 Windows 和 .NET 10 SDK。源码构建还需要 `libdatachannel` 原生依赖；构建方式见 [开发说明](docs/user-guide.md) 与 [原生依赖脚本](scripts/build-native-from-archives.ps1)。

```powershell
dotnet restore src/PrivateRemote.Client/PrivateRemote.Client.csproj --configfile NuGet.Config
dotnet run --project src/PrivateRemote.Client/PrivateRemote.Client.csproj --no-restore
```

两台电脑的配对与连接步骤见 [局域网连接说明](docs/局域网试用说明.md) 和 [外网连接说明](docs/外网连接说明.md)。**不要公开分享配对文件、连接配置或令牌。**

## 项目结构

| 路径 | 内容 |
| --- | --- |
| `src/PrivateRemote.Client` | Windows 客户端界面与桌面会话 |
| `src/PrivateRemote.Protocol` | 身份、配对和会话协议 |
| `src/PrivateRemote.Transport` | 信令与 WebRTC 传输 |
| `src/PrivateRemote.Transfer` | 文件传输 |
| `src/PrivateRemote.Relay` | 信令服务 |
| `tests` | 自动化测试与桌面探针 |
| `docs` | 使用说明、架构与开发记录 |

## 当前限制

- 面向两台自有 Windows 电脑；外网连接目前依赖 Tailscale。
- 锁屏、登录界面和 UAC 安全桌面不支持远程控制。
- 公网中继、自动证书轮换、正式安装包与签名发布尚未完成。
- 不同网络和机器上的画面质量、延迟取决于环境；“免费高清”表示软件没有付费画质门槛，不是画质或性能保证。

## 开发与许可

运行测试：

```powershell
dotnet run --project tests/PrivateRemote.Tests/PrivateRemote.Tests.csproj --no-restore
```

项目源码采用 [MIT 许可证](LICENSE)。原生依赖及 .NET 运行时有各自的许可证；制作分发包时请保留相应声明。欢迎通过 Issue 反馈双机实测结果。
