// dsh plugin entry for codex-policy-engine (ported from openai/codex execpolicy, Apache-2.0)
// Seam: ctx.on('tools/pre-execute') intercepts every tool call; we route
// bash/pwsh-style commands through the ported Policy engine.
import { Policy } from './policy.js';
import { prefixRule, altsToken, singleToken, type PatternToken } from './rule.js';
import { parsePolicyFile } from './starlarkLite.js';
import type { Decision } from './decision.js';

export const name = 'codex-policy-engine'
export const inject = ['tools']

function asRecord(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {}
}

/** Config is YAML-authored, so a decision must be validated before it reaches the engine. */
function isDecision(value: unknown): value is Decision {
  return value === 'Allow' || value === 'Forbidden' || value === 'Prompt'
}

/** Tokenize a command line the way shells roughly do (quote-aware). */
export function tokenizeCommand(line: unknown): string[] {
  if (typeof line !== 'string') return []
  const out: string[] = []; let cur = ''; let q: string | null = null
  for (const ch of line) {
    if (q) { if (ch === q) q = null; else cur += ch; continue }
    if (ch === '"' || ch === "'") { q = ch; continue }
    if (/\s/.test(ch)) { if (cur) { out.push(cur); cur = '' } continue }
    cur += ch
  }
  if (cur) out.push(cur)
  return out
}

export function policyFromConfig(config: unknown = {}): Policy {
  const cfg = asRecord(config)
  const policy = new Policy()
  // YAML-friendly normalization: accept bare strings / arrays / PatternToken objects.
  const normToken = (t: unknown): PatternToken | null => {
    if (typeof t === 'string') return singleToken(t)
    if (Array.isArray(t)) return altsToken(t.map(String))
    const kind = (t as { kind?: unknown } | null)?.kind
    if (t && typeof t === 'object' && (kind === 'Single' || kind === 'Alts')) return t as PatternToken
    return null
  }
  for (const r of Array.isArray(cfg.rules) ? cfg.rules : []) {
    const rule = asRecord(r)
    if (!rule.first || !isDecision(rule.decision)) continue
    const rest: PatternToken[] = []
    for (const raw of Array.isArray(rule.rest) ? rule.rest : []) {
      const t = normToken(raw)
      if (t) rest.push(t)
    }
    policy.addPrefixRule({ first: String(rule.first), rest, decision: rule.decision })
  }
  return policy
}

/** Evaluate a raw command line against the configured policy. */
export function evaluate(policy: Policy, line: unknown) {
  return policy.check(tokenizeCommand(line))
}

type PolicyHost = {
  tools?: { register?: (definition: unknown) => void }
  on?: (event: string, handler: (exec: unknown, next: () => unknown) => unknown, options?: { prepend?: boolean }) => void
}

export function apply(ctx: unknown, config: unknown = {}): void {
  const cfg = asRecord(config)
  const mode = cfg.mode === 'enforce' || cfg.mode === 'audit' ? cfg.mode : 'off'
  const patterns = (Array.isArray(cfg.commandTools) && cfg.commandTools.length)
    ? cfg.commandTools.map(String)
    : ['bash', 'pwsh', '*-bash*', '*-pwsh*', 'shell', 'terminal*']

  const wildcard = (pattern: string, value: unknown): boolean => {
    const esc = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')
    return new RegExp(`^${esc}$`, 'i').test(String(value ?? ''))
  }
  const isCommandTool = (toolName: unknown): boolean => patterns.some((p) => wildcard(p, toolName))

  const policy = policyFromConfig(cfg)
  const host = ctx as PolicyHost | null

  // Optional read-only inspection tool (always available).
  try {
    if (host?.tools?.register) {
      const defineTool = (definition: unknown): unknown => definition
      host.tools.register(defineTool({
        name: 'codex_policy_check',
        description: 'Evaluate a command line against the codex-policy-engine approval rules. Read-only.',
        parameters: {
          command: { type: 'string', required: true, description: 'raw command line to evaluate' },
        },
        output: { schema: { type: 'string' }, render: (_args: unknown, value: unknown) => [{ type: 'text', text: String(value) }] },
        async execute(rawArgs: unknown): Promise<string> {
          const args = asRecord(rawArgs)
          const ev = evaluate(policy, String(args.command ?? ''))
          return JSON.stringify({ command: args.command, decision: ev.decision, matchedPrograms: ev.matchedPrograms })
        },
        timeoutMs: 3000,
      }))
    }
  } catch { /* tool seam unavailable on this host */ }

  if (mode === 'off' || typeof host?.on !== 'function') return

  host.on('tools/pre-execute', (exec, next) => {
    const call = asRecord(exec)
    if (!isCommandTool(call.name)) return next()
    const line = String(asRecord(call.arguments).command ?? '')
    if (!line.trim()) return next()
    const ev = evaluate(policy, line)
    if (ev.decision === 'Allow') return next()
    if (ev.decision === 'Forbidden') {
      return { kind: 'deny', reason: `[codex-policy-engine] forbidden by rule (matched: ${ev.matchedPrograms.join(', ') || 'none'})` }
    }
    // Prompt → audit mode logs-and-allows, enforce mode asks the user.
    if (mode === 'audit') return next()
    return { kind: 'ask', reason: `[codex-policy-engine] no allow rule matched \`${line}\`` }
  }, { prepend: true })
}

export { Policy, prefixRule, altsToken, parsePolicyFile }
