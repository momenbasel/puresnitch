<p align="center">
  <img src="../screenshot.png" alt="PureSnitch — 适用于 macOS 的开源应用防火墙" width="800">
</p>

<p align="center">
  <a href="../README.md">English</a> |
  <a href="README.ar.md">العربية</a> |
  <a href="README.es.md">Español</a> |
  <a href="README.ja.md">日本語</a> |
  <b>简体中文</b> |
  <a href="README.zh-Hant.md">繁體中文</a>
</p>

<h1 align="center">PureSnitch</h1>

<p align="center">
  <b>看清你的 Mac 在与谁通信，阻止你不信任的连接。</b><br>
  适用于 macOS 的开源应用防火墙。无订阅、无遥测、无升级推销。
</p>

## 安装

```bash
brew trust momenbasel/puresnitch
brew install --cask momenbasel/puresnitch/puresnitch
```

或从 [Releases](https://github.com/momenbasel/puresnitch/releases/latest) 下载签名并公证的 `.dmg`，然后将 PureSnitch 拖入 `/Applications`。

## 为什么需要它

Little Snitch 是 macOS 应用防火墙的黄金标准，但它是付费商业软件。LuLu 免费且在每进程内核层面表现优秀，但规则管理器较为简陋，没有世界地图、流量图表或内置黑名单库。macOS 自带防火墙只阻止入站连接 — 对出站流量毫无作用。

PureSnitch 是第四种选择:

- **与 Little Snitch 6 相同的界面模式** — 菜单栏、世界地图、规则管理器、连接弹窗。
- **MIT 协议开源** — 阅读源码、复刻、审计皆可。
- **无遥测** — 没有分析 SDK，没有崩溃报告外发。
- **作为原生 Mac 应用构建** — 纯 SwiftUI，并非跨平台移植。
- **采用 Developer ID 签名并经 Apple 公证** — 没有"无法验证开发者"提示。

## 功能

- 网络监视器显示活动连接和每进程带宽汇总；当前版本不包含实时地理定位或每连接字节统计
- 用于搜索、启用、停用和删除已存规则的规则浏览器；v0.2.1 只能从 DNS 代理警报创建新的持久规则
- 内置 DNS over HTTPS，可指向 Cloudflare / Quad9 / Google 或任意 DoH 端点
- 实验性环回 DNS 代理，仅供手动配置的客户端使用，不会修改 macOS 的 DNS 设置
- 通过 1Hosts、OISD、StevenBlack、HaGeZi 实现的域名阻断，仅适用于手动配置为使用实验性 DNS 代理的客户端
- 通过 `pfctl` 锚点实现内核级 IP / CIDR / 端口阻断
- 配置文件 (default / home / public-wifi / lockdown) 仅作为组织标签保存；当前版本只执行 default，其他配置文件无法激活，也未实现随网络自动切换

## 完整英文 README

[README.md](../README.md)
