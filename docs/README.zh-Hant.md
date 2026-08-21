<p align="center">
  <img src="../screenshot.png" alt="PureSnitch — macOS 開源應用程式防火牆" width="800">
</p>

<p align="center">
  <a href="../README.md">English</a> |
  <a href="README.ar.md">العربية</a> |
  <a href="README.es.md">Español</a> |
  <a href="README.ja.md">日本語</a> |
  <a href="README.zh-Hans.md">简体中文</a> |
  <b>繁體中文</b>
</p>

<h1 align="center">PureSnitch</h1>

<p align="center">
  <b>看清你的 Mac 正在與誰通訊，阻擋你不信任的連線。</b><br>
  適用於 macOS 的開源應用程式防火牆。無訂閱、無遙測、無升級推銷。
</p>

## 安裝

```bash
brew trust momenbasel/puresnitch
brew install --cask momenbasel/puresnitch/puresnitch
```

或從 [Releases](https://github.com/momenbasel/puresnitch/releases/latest) 下載簽署並公證的 `.dmg`，然後將 PureSnitch 拖入 `/Applications`。

## 為什麼需要

Little Snitch 是 macOS 應用程式防火牆的黃金標準，但它是付費商業軟體。LuLu 免費且在每行程核心層級表現優秀，但規則管理器較為簡樸，沒有世界地圖、流量圖表或內建黑名單庫。macOS 內建防火牆僅阻擋入站連線 — 對出站流量毫無作用。

PureSnitch 提供第四種選擇:

- **與 Little Snitch 6 相同的介面模式** — 選單列、世界地圖、規則管理器、連線提示。
- **MIT 授權的開源專案** — 閱讀、分叉、稽核皆可。
- **無遙測** — 沒有分析 SDK，沒有當機回報外送。
- **以原生 Mac 應用程式打造** — 純 SwiftUI，並非跨平台移植。
- **採用 Developer ID 簽署並經 Apple 公證** — 不會出現「無法驗證開發者」警告。

## 功能

- 網路監視器顯示活動連線與每行程頻寬彙總；目前版本不包含即時地理定位或每連線位元組統計
- 用於搜尋、啟用、停用與刪除已儲存規則的規則瀏覽器；v0.2.1 只能從 DNS 代理警示建立新的永久規則
- 內建 DNS over HTTPS,可指向 Cloudflare / Quad9 / Google 或任意 DoH 端點
- 實驗性迴路 DNS 代理，僅供手動設定的客戶端使用，不會修改 macOS 的 DNS 設定
- 透過 1Hosts、OISD、StevenBlack、HaGeZi 實作的網域封鎖，僅適用於手動設定為使用實驗性 DNS 代理的客戶端
- 透過 `pfctl` 錨點實作核心層級 IP / CIDR / 連接埠封鎖
- 設定檔 (default / home / public-wifi / lockdown) 僅作為整理標籤儲存；目前版本只套用 default，其他設定檔無法啟用，也尚未實作隨網路自動切換

## 完整英文 README

[README.md](../README.md)
