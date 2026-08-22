// Minimal Starlark-subset parser for execpolicy policy files (Apache-2.0 port).
// Supports the constructs execpolicy policies actually use:
//   prefix_rule(program, [arg, ...] | [alt1, alt2], ALLOW|FORBIDDEN|PROMPT)
//   network_rule(host, PROTOCOL, ALLOW|FORBIDDEN|PROMPT)
// Lines starting with # are comments. Strings use double quotes.
import type { Decision } from './decision.js';
import type { PatternToken } from './rule.js';

type RawCall = { fn: string; args: string[] };

function tokenize(src: string): string[] {
  const toks: string[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (c === '#') { while (i < src.length && src[i] !== '\n') i++; continue; }
    if (/\s/.test(c)) { i++; continue; }
    if (c === '"' || c === "'") {
      let s = ''; i++;
      while (i < src.length && src[i] !== c) { s += src[i]; i++; }
      i++; toks.push(JSON.stringify(s)); continue;
    }
    if (/[A-Za-z_]/.test(c)) {
      let s = '';
      while (i < src.length && /[A-Za-z0-9_.]/.test(src[i])) { s += src[i]; i++; }
      toks.push(s); continue;
    }
    if (c === '[' || c === ']' || c === '(' || c === ')' || c === ',') { toks.push(c); i++; continue; }
    throw new Error('starlark-lite: unexpected char '+JSON.stringify(c));
  }
  return toks;
}

function parseCalls(toks: string[]): RawCall[] {
  const calls: RawCall[] = [];
  let i = 0;
  while (i < toks.length) {
    if (/^[a-z_]+$/.test(toks[i]) && toks[i+1] === '(') {
      const fn = toks[i]; i += 2;
      const args: string[] = []; let cur = '';
      let depth = 0;
      while (i < toks.length) {
        const t = toks[i];
        if (t === ')') { if (cur) args.push(cur); i++; break; }
        if (t === ',') { if (cur) args.push(cur); cur=''; i++; continue; }
        if (t === '[') { depth++; cur += t; i++; continue; }
        if (t === ']') { depth--; cur += t; i++; continue; }
        cur += t; i++;
      }
      calls.push({ fn, args });
    } else i++;
  }
  return calls;
}

function splitTopLevel(s: string): string[] {
  const parts: string[] = []; let cur=''; let inStr=false; let q=''; let depth=0;
  for (const ch of s) {
    if (inStr) { cur+=ch; if (ch===q) inStr=false; continue; }
    if (ch==='"'||ch==="'"){ inStr=true; q=ch; cur+=ch; continue; }
    if (ch==='['||ch==='('){ depth++; cur+=ch; continue; }
    if (ch===']'||ch===')'){ depth--; cur+=ch; continue; }
    if (ch===',' && depth===0){ parts.push(cur.trim()); cur=''; continue; }
    cur+=ch;
  }
  if (cur.trim()) parts.push(cur.trim());
  return parts.filter(Boolean);
}

function parseList(s: string): string[] {
  if (s.startsWith('[')) return splitTopLevel(s.slice(1,-1)).map((x)=>x.trim()).filter(Boolean);
  return [s];
}

export interface ParsedPolicy {
  prefixRules: { program: string; args: PatternToken[]; decision: Decision }[];
  networkRules: { host: string; protocol: string; decision: Decision }[];
}

const isDecision = (s:string): s is Decision => ['ALLOW','FORBIDDEN','PROMPT'].includes(s);
const normDecision = (s:string): Decision =>
  s==='ALLOW'?'Allow': s==='FORBIDDEN'?'Forbidden': 'Prompt';

export function parsePolicyFile(src: string): ParsedPolicy {
  const out: ParsedPolicy = { prefixRules: [], networkRules: [] };
  for (const call of parseCalls(tokenize(src))) {
    if (call.fn === 'prefix_rule' && call.args.length >= 3) {
      const program = JSON.parse(call.args[0]);
      const listRaw = parseList(call.args[1]);
      const tokens: PatternToken[] = listRaw.map((raw) => {
        const v = JSON.parse(raw);
        return v.startsWith('[')
          ? { kind:'Alts', values: parseList(v).map((x)=>JSON.parse(x)) }
          : { kind:'Single', value:v };
      });
      const d = call.args[2];
      if (!isDecision(d)) throw new Error('bad decision '+d);
      out.prefixRules.push({ program, args: tokens, decision: normDecision(d) });
    } else if (call.fn === 'network_rule' && call.args.length >= 3) {
      const host = JSON.parse(call.args[0]);
      const proto = call.args[1];
      const d = call.args[2];
      if (!isDecision(d)) throw new Error('bad decision '+d);
      out.networkRules.push({ host, protocol: proto, decision: normDecision(d) });
    }
    // unknown functions are ignored for forward compatibility
  }
  return out;
}
