<p align="center">
  <img src="../screenshot.png" alt="PureSnitch — firewall de aplicaciones para macOS de código abierto" width="800">
</p>

<p align="center">
  <a href="../README.md">English</a> |
  <a href="README.ar.md">العربية</a> |
  <b>Español</b> |
  <a href="README.ja.md">日本語</a>  |
  <a href="README.zh-Hans.md">简体中文</a> |
  <a href="README.zh-Hant.md">繁體中文</a>
</p>

<h1 align="center">PureSnitch</h1>

<p align="center">
  <b>Mira con quién habla tu Mac. Bloquea lo que no te gusta.</b><br>
  Firewall de aplicaciones de código abierto para macOS. Sin suscripción, sin telemetría, sin pop-ups de upselling.
</p>

## Instalar

```bash
brew trust momenbasel/puresnitch
brew install --cask momenbasel/puresnitch/puresnitch
```

O descarga el `.dmg` firmado y notarizado desde [Releases](https://github.com/momenbasel/puresnitch/releases/latest) y arrastra PureSnitch a `/Applications`.

## Por qué existe

Little Snitch es el estándar de oro para firewalls de aplicaciones en macOS, pero es software comercial de pago. LuLu es gratis y excelente a nivel de proceso, pero el administrador de reglas es austero y no tiene mapa mundial ni gráfico de tráfico ni biblioteca de blocklists. El firewall integrado de macOS solo bloquea entrada — no hace nada con el tráfico saliente.

PureSnitch es la cuarta opción:

- **Misma interfaz que Little Snitch 6** — barra de menú, mapa mundial, gestor de reglas, alertas de conexión.
- **Código abierto bajo MIT** — léelo, fórkalo, audítalo.
- **Sin telemetría.** Sin SDKs de analítica, sin reportes de fallos.
- **Construido como una app nativa de Mac** — SwiftUI puro, no un puerto de otra plataforma.
- **Firmado con Developer ID y notarizado por Apple** — sin avisos de "desarrollador no verificado".

## Qué hace

- Monitor de conexiones activas y ancho de banda agregado por proceso; esta versión no incluye geolocalización en vivo ni bytes por conexión
- Navegador de reglas almacenadas con búsqueda, activación, desactivación y borrado; en v0.2.1 las reglas persistentes nuevas solo se crean desde alertas del proxy DNS
- DNS sobre HTTPS a Cloudflare, Quad9, Google o cualquier endpoint DoH
- Proxy DNS experimental en loopback; solo sirve a clientes configurados manualmente y no cambia el DNS de macOS
- Bloqueo por dominio mediante 1Hosts, OISD, StevenBlack y HaGeZi, solo para clientes configurados manualmente para usar el proxy DNS experimental
- Bloqueo por IP, CIDR y puerto a nivel kernel mediante el ancla `pfctl`
- Los perfiles (default, home, public-wifi, lockdown) se guardan solo como etiquetas organizativas; esta versión aplica únicamente default y los demás no se pueden activar. El cambio automático por red no está implementado

## README completo en inglés

[README.md](../README.md)
