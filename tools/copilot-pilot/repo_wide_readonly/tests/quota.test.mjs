import assert from 'node:assert/strict';
import { test } from 'node:test';
import { safeQuota } from '../safe-quota.mjs';

test('request units and percentages never become AI Credit allowances', () => {
  const value = safeQuota({ quotaSnapshots: { premium_interactions: { entitlementRequests: 50,
    usedRequests: 3, remainingPercentage: 94, overage: 0, overageAllowedWithExhaustedQuota: false } } });
  assert.equal(value.snapshots.premium_interactions.entitlementRequests, 50);
  assert.equal(value.numerical_ai_credit_allowance_proved, false);
  assert.equal(value.global_additional_paid_usage_state_proved, false);
  assert.equal(value.live_admissible, false);
});
test('unknown private fields and unknown category contents never reach diagnostics', () => {
  const value = safeQuota({ Authorization: 'SYNTHETIC_SECRET', quotaSnapshots: {
    chat: { entitlementRequests: 50, token: 'SYNTHETIC_SECRET' },
    SYNTHETIC_SECRET: { token: 'SYNTHETIC_SECRET' } } });
  assert.ok(!JSON.stringify(value).includes('SYNTHETIC_SECRET'));
  assert.equal(value.unsupported_category_count, 1);
});
test('wrong types and nonfinite values are not reported as quota numbers', () => {
  const value = safeQuota({ quotaSnapshots: { chat: { entitlementRequests: true,
    usedRequests: '50', overage: Infinity, overageAllowedWithExhaustedQuota: 'false' } } });
  assert.deepEqual(value.snapshots.chat, {});
  assert.equal(safeQuota(null).status, 'UNAVAILABLE');
});
