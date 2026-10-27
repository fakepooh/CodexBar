// Pure allowlisted metadata only. Request quotas are NEVER AI Credit allowances.
export function safeQuota(result) {
  const source = result?.quotaSnapshots;
  if (!source || typeof source !== 'object' || Array.isArray(source)) return { status: 'UNAVAILABLE' };
  const numeric = ['entitlementRequests', 'usedRequests', 'remainingPercentage', 'overage'];
  const boolean = ['isUnlimitedEntitlement', 'usageAllowedWithExhaustedQuota', 'overageAllowedWithExhaustedQuota'];
  const known = ['chat', 'completions', 'premium_interactions'];
  const snapshots = {};
  for (const name of known) {
    const raw = source[name];
    if (!raw || typeof raw !== 'object') continue;
    const value = {};
    for (const key of numeric) if (typeof raw[key] === 'number' && Number.isFinite(raw[key])) value[key] = raw[key];
    for (const key of boolean) if (typeof raw[key] === 'boolean') value[key] = raw[key];
    if (typeof raw.resetDate === 'string' && Number.isFinite(Date.parse(raw.resetDate)))
      value.resetDate = new Date(raw.resetDate).toISOString();
    snapshots[name] = value;
  }
  return { status: Object.keys(snapshots).length ? 'REQUEST_QUOTA_METADATA_ONLY' : 'UNAVAILABLE',
    snapshots, unsupported_category_count: Object.keys(source).filter(k => !known.includes(k)).length,
    numerical_ai_credit_allowance_proved: false,
    global_additional_paid_usage_state_proved: false,
    live_admissible: false };
}
