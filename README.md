# codex-policy-engine

> 把自然语言命令变成 Allow/Forbidden/Prompt 三态裁决的声明式安全引擎。

## 吸收来源
- execpolicy (2,698)
- shell-command (5,839)
- utils/approval-presets (73)
- utils/output-truncation (492)

## 功能边界
**做**：前缀规则匹配、网络域名白名单、Starlark 策略解析、tree-sitter bash/powershell 副作用判定、token 预算截断（判②偷师）。

**不做**：不执行命令、不弹 UI——裁决结果交宿主。

## API 草图
```
check(cmd: string[]): Decision
loadPolicy(starlarkSrc): Policy
mergeOverlay(base, overlay): Policy
```

## 验收标准
原版 policy.rs 全部测试翻译通过；对 1000 条真实命令与 codex 二进制裁决一致率 100%。

## 上游同步
基于 openai/codex@970b7f2ff4f6（Apache-2.0）。季度 diff 由 dsh-codex-ledger CI 触发，见 ledger/coverage.yaml 对应行。
