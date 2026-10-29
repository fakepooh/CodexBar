// Pure local fixture framing, never a model/backend client.
export function completionFixture(step, number, stream) {
  if (stream !== undefined && stream !== false && stream !== true) throw Error('INVALID_STREAM_MODE');
  if (!Number.isInteger(number) || number < 1 || number > 6) throw Error('INVALID_FIXTURE_SEQUENCE');
  const tool = step ? { id: 'probe-' + number, type: 'function',
    function: { name: step[0], arguments: JSON.stringify(step[1]) } } : null;
  const message = { role: 'assistant', content: tool ? null : 'OFFLINE_CALLBACK_PROOF_COMPLETE',
    ...(tool ? { tool_calls: [tool] } : {}) };
  const finish = tool ? 'tool_calls' : 'stop';
  const usage = { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 };
  if (stream !== true) return { contentType: 'application/json', body: JSON.stringify({
    id: 'probe-' + number, object: 'chat.completion', created: 0, model: 'offline-tool-stub',
    choices: [{ index: 0, message, finish_reason: finish }], usage }) };
  const delta = tool ? { role: 'assistant', tool_calls: [{ index: 0, ...tool }] } : message;
  const frames = [{ id: 'probe', object: 'chat.completion.chunk', model: 'offline-tool-stub',
    choices: [{ index: 0, delta, finish_reason: null }] },
  { id: 'probe', object: 'chat.completion.chunk', model: 'offline-tool-stub',
    choices: [{ index: 0, delta: {}, finish_reason: finish }], usage }];
  return { contentType: 'text/event-stream',
    body: frames.map(frame => 'data: ' + JSON.stringify(frame) + '\n\n').join('') + 'data: [DONE]\n\n' };
}
