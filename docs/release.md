# 发版 / Release

**简体中文** | [English](#english)

使用发布脚本，让 Git tag 指向的提交本身就已经包含匹配的 Cargo 版本号。

```powershell
.\scripts\release.ps1 v0.7.9 -Push
```

脚本会：

- 要求已跟踪文件没有未提交改动
- 更新 `Cargo.toml` 和 `Cargo.lock` 里的 `fengheshell` 版本号
- 运行 `cargo check --locked`
- 验证 `fengheshell --version` 输出匹配 tag
- 提交版本号变更
- 创建 annotated tag
- 传入 `-Push` 时推送当前分支和 tag

如果想先在本地创建提交和 tag，不立即推送：

```powershell
.\scripts\release.ps1 v0.7.9
git push origin HEAD
git push origin v0.7.9
```

Release workflow 也会检查推送上来的 tag。比如 tag 名是 `v0.7.9` 时，
`Cargo.toml`、`Cargo.lock` 和构建出的 `fengheshell --version` 都必须是
`0.7.9`，否则 workflow 会在发布前失败。

推送 tag 后，Release workflow 会在 GitHub Actions 上构建 Windows / Linux / macOS
安装包并附到对应的 GitHub Release。也可以在 Actions 页面手动运行该 workflow，
只下载构建产物而不创建 Release。

<a name="english"></a>

## English

Use the release helper so the tag points at a commit whose Cargo package version
matches the tag.

```powershell
.\scripts\release.ps1 v0.7.9 -Push
```

The script:

- requires no uncommitted tracked-file changes
- updates `Cargo.toml` and the `fengheshell` entry in `Cargo.lock`
- runs `cargo check --locked`
- verifies that `fengheshell --version` matches the tag
- commits the version bump
- creates an annotated tag
- pushes the current branch and tag when `-Push` is passed

To prepare the commit and tag without pushing:

```powershell
.\scripts\release.ps1 v0.7.9
git push origin HEAD
git push origin v0.7.9
```

The release workflow also checks pushed tags. A tag named `v0.7.9` must match
`Cargo.toml`, `Cargo.lock`, and the built `fengheshell --version` output,
otherwise the workflow fails before publishing.

After the tag is pushed, the Release workflow builds Windows / Linux / macOS
packages on GitHub Actions and attaches them to the matching GitHub Release. You
can also run the workflow manually to download build artifacts without creating
a release.
