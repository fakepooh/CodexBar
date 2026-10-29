import assert from 'node:assert/strict';
import { test } from 'node:test';
import { completionFixture } from '../mock-completions.mjs';
const step = ['repo_view', { path: 'source/example.txt', start_line: 2, end_line: 3 }];
test('absent or false stream returns a complete JSON chat completion', () => {
  for (const stream of [undefined, false]) {
    const response = completionFixture(step, 1, stream);
    assert.equal(response.contentType, 'application/json');
    const value = JSON.parse(response.body), choice = value.choices[0];
    assert.equal(value.object, 'chat.completion');
    assert.equal(choice.finish_reason, 'tool_calls');
    assert.equal(choice.message.tool_calls[0].function.name, 'repo_view');
    assert.deepEqual(JSON.parse(choice.message.tool_calls[0].function.arguments), step[1]);
    assert.equal(response.body.includes('data: '), false);
  }
});
test('non-streaming final answer is actual assistant content', () => {
  const value = JSON.parse(completionFixture(null, 6, false).body);
  assert.equal(value.choices[0].message.content, 'OFFLINE_CALLBACK_PROOF_COMPLETE');
  assert.equal(value.choices[0].finish_reason, 'stop');
});
test('explicit streaming preserves SSE framing, exact arguments and termination', () => {
  const response = completionFixture(step, 1, true);
  assert.equal(response.contentType, 'text/event-stream');
  const lines = response.body.trim().split('\n\n');
  assert.equal(lines.pop(), 'data: [DONE]');
  const values = lines.map(line => JSON.parse(line.slice(6)));
  assert.deepEqual(JSON.parse(values[0].choices[0].delta.tool_calls[0].function.arguments), step[1]);
  assert.equal(values[1].choices[0].finish_reason, 'tool_calls');
});
test('invalid stream modes and sequence values fail closed', () => {
  for (const mode of ['true', 1, null]) assert.throws(() => completionFixture(step, 1, mode));
  for (const number of [0, 7, true, 1.5]) assert.throws(() => completionFixture(step, number, false));
});
