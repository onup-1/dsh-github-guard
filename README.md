# dsh-github-guard

Keeps `github.com` reachable from DSH when the resolver hands out blackholed GitHub edge
addresses.

The plugin watches for GitHub traffic, probes the candidate edges over TCP + TLS, picks the
fastest one that actually completes a handshake, and asks a small SYSTEM helper to rewrite
the `hosts` pins. When you are not using GitHub nothing is probed at all.

## Why two halves

Writing `C:\Windows\System32\drivers\etc\hosts` requires an elevated token; a DSH plugin
runs as the logged-on user. So the work is split:

| half | runs as | job |
| --- | --- | --- |
| `index.mjs` (this plugin) | the DSH host process | detect GitHub traffic, probe candidates, decide the edge |
| `native\dsh-github-guard.exe serve` | SYSTEM (scheduled task) | rewrite the hosts pins on request, flush DNS |

The helper only listens on `127.0.0.1:8898` and only accepts requests carrying the token in
`C:\ProgramData\DSHGuard\token.txt`, so an unprivileged process cannot repoint GitHub.

The TLS probing lives in Node on purpose: DSH's Windows sandbox lowers every sandboxed
child process to Low integrity, and Schannel cannot create client credentials at that level
(`SEC_E_NO_CREDENTIALS`), while OpenSSL inside the DSH runtime is unaffected.

## Install

1. Install the plugin bundle into the DSH profile (from the DSH workspace root):

   ```
   plugin_manager install_bundle  target=<absolute path to this directory>
   ```

2. Install the privileged helper once, elevated:

   ```
   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\install-helper.ps1
   ```

   It copies the helper to `C:\ProgramData\DSHGuard\`, creates the token, registers the
   `DSH-GitHubGuardHelper` task (SYSTEM, at startup + at logon), starts it and verifies that
   it answers.

## Status

```
GET  http://127.0.0.1:<dsh port>/github-guard          # status JSON
POST http://127.0.0.1:<dsh port>/github-guard          # {"action":"refresh"} -> probe now
```

The status payload reports the detector pid, the last detected traffic, the last pin, the
scan duration, helper health and a small log ring.

## Behaviour

- On activation: one probe (`startup`), then the detector watches the TCP table.
- A detected connection to a known GitHub edge triggers at most one refresh per minute, and
  the plugin stays quiet for 30 s afterwards so its own probe connections do not re-trigger it.
- A failed pin (helper down, no reachable edge) is reported in the status payload instead of
  breaking anything; the previous pin stays in place.

## Uninstall

```
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\uninstall-helper.ps1 [-Purge]
```

Unregisters the task, stops the helper and removes the `github.com` / `www.github.com` /
`gist.github.com` pins from `hosts` (they go back to DNS). `-Purge` also deletes
`C:\ProgramData\DSHGuard\`.

## Build

```
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\build-native.ps1
```

The helper is plain C# 5 compiled with the .NET Framework compiler that ships with Windows;
no SDK needed. Candidate edges are a static list because DNS answers for `github.com` are
untrustworthy exactly in the networks this is meant for.

---

## 中文说明

这个插件用于在「DNS 返回的 GitHub 边缘 IP 被墙、可用 IP 几分钟就轮换」的网络里保持
`github.com` 可用。它只在你真正访问 GitHub 时才探测，平时完全静止。

- 插件本体（`index.mjs`）跟随 DSH 启动，负责监听流量、探测候选 IP、决定用哪个；
- 真正的 writes 由 `native\dsh-github-guard.exe serve` 以 SYSTEM 身份执行，只接受带
  `C:\ProgramData\DSHGuard\token.txt` 里令牌的请求，仅监听 `127.0.0.1:8898`。

安装：先装插件包，再以管理员运行 `scripts\install-helper.ps1`（一次性，之后不再弹 UAC）。
状态：`GET /github-guard`；立即刷新：`POST /github-guard` 带 `{"action":"refresh"}`。
卸载：以管理员运行 `scripts\uninstall-helper.ps1`。

MIT.
