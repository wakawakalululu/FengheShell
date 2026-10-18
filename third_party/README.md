# third_party / 第三方源码快照

这里放的是**只读的上游参考实现**，不参与 FengheShell 的构建。

## rssh

- 上游：<https://github.com/shihuili1218/rssh>
- 快照：`49a126f`（与上游 main 一致；仓库里只保留工作树，未保留其 git 历史）
- 作用：AI 运维 Copilot 范式的参考实现，需要继续移植逻辑时对照这里看。
  真正被编译进 FengheShell 的是 `crates/ai-copilot/` —— sanitize / redact /
  shell / llm 等模块都是从这里移植过去的。
- 注意：不要把它接到 FengheShell 的构建里。`Cargo.toml` 的 workspace 成员
  只有 `crates/ai-copilot`。

## vendor（在仓库根目录，不在 third_party 下）

`/vendor` 是被 `[patch.crates-io]` 打过补丁的 Slint 上游 crate
（`i-slint-core` / `i-slint-compiler` / `i-slint-backend-winit`）。它们**参与构建**，
改动说明见 `/vendor/EDITOR_PATCH.md`。
