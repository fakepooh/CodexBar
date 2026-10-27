// Unique SDK tools: missing registration cannot fall back to native filesystem tools.
import { createHash } from 'node:crypto';
import { createInterface } from 'node:readline';

export const NAMES = ['repo_view', 'repo_grep', 'repo_glob'];
export const digest = s => createHash('sha256').update(s).digest('hex');

export class BrokerRpc {
  constructor(child) {
    this.child = child; this.id = 0; this.pending = new Map(); this.audit = [];
    this.lines = createInterface({ input: child.stdout });
    this.lines.on('line', text => {
      if (Buffer.byteLength(text) > 1048576) { child.kill('SIGKILL'); return; }
      try {
        const value = JSON.parse(text), p = this.pending.get(value.id);
        if (!p) throw Error('UNEXPECTED_BROKER_RESPONSE');
        this.pending.delete(value.id); clearTimeout(p.timer); p.resolve(value);
      } catch { child.kill('SIGKILL'); }
    });
    child.once('exit', () => {
      for (const p of this.pending.values()) { clearTimeout(p.timer); p.reject(Error('BROKER_EXIT')); }
      this.pending.clear();
    });
  }
  call(tool, args = {}) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(id); this.child.kill('SIGKILL'); reject(Error('BROKER_DEADLINE')); }, 30000);
      this.pending.set(id, { resolve, reject, timer });
      this.child.stdin.write(JSON.stringify({ id, tool, arguments: args }) + '\n', error => {
        if (error) { clearTimeout(timer); this.pending.delete(id); reject(Error('BROKER_STDIN')); }
      });
    });
  }
  async tool(name, args) {
    const response = await this.call(name, args);
    const value = response.ok ? response.result : { error: response.error };
    const text = JSON.stringify(value);
    this.audit.push({ tool: name, arguments: args, ok: response.ok,
      response_sha256: digest(text), response_bytes: Buffer.byteLength(text), response: value });
    return { textResultForLlm: text, resultType: response.ok ? 'success' : 'failure' };
  }
  stop() { this.child.stdin.end(); this.lines.close(); }
}

const integer = { type: 'integer', minimum: 0 };
export function toolset(rpc) {
  const definitions = [
    ['view', 'Read tracked files by exact repository-relative path. Lines are 1-based, columns 0-based Unicode characters. Follow next_cursor. Use base64 mode for any binary bytes. Use repo_glob for directories; no host paths.',
      { path: { type: 'string' }, start_line: { type: 'integer', minimum: 1 },
        end_line: { type: 'integer', minimum: 1 }, column: integer,
        encoding: { type: 'string', enum: ['text', 'base64'] },
        byte_offset: integer, byte_limit: { type: 'integer', minimum: 1, maximum: 8192 } }, ['path']],
    ['grep', 'Search literal text in historical tracked files; explicit pagination. No shell or regex.',
      { query: { type: 'string' }, pattern: { type: 'string' }, cursor: integer, limit: integer }, ['query']],
    ['glob', 'List historical tracked paths by wildcard; explicit pagination.',
      { pattern: { type: 'string' }, cursor: integer, limit: integer }, []],
  ];
  return definitions.map(([operation, description, properties, required]) => ({ name: 'repo_' + operation, description,
    parameters: { type: 'object', properties, required, additionalProperties: false },
    defer: 'never', skipPermission: false,
    handler: args => rpc.tool(operation, args),
  }));
}

export function permission(request, invocation) {
  if (request.managedApprovalRequired || invocation?.managedSettingsEnabled)
    return { kind: 'reject', feedback: 'Managed approval cannot be bypassed' };
  return request.kind === 'custom-tool' && NAMES.includes(request.toolName)
    ? { kind: 'approve-once' } : { kind: 'reject', feedback: 'Only isolated readonly broker tools are permitted' };
}

export function hooks() {
  return { onPreToolUse: input => NAMES.includes(input.toolName) ? undefined : { permissionDecision: 'deny' },
    onErrorOccurred: () => ({ errorHandling: 'abort', retryCount: 0 }) };
}
