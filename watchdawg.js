const TOLERANCE = 0.009;
const FORBIDDEN_OBJECT_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const PLAN_KEYS = [
  'version',
  'createdAt',
  'sourceDigest',
  'proposals',
  'unhandledReviews',
  'requiresHumanApproval',
  'externalWritePerformed',
  'planDigest'
];
const PROPOSAL_KEYS = [
  'proposalId',
  'transactionIndex',
  'transactionId',
  'reason',
  'before',
  'changes'
];
const APPROVAL_KEYS = [
  'decision',
  'approver',
  'planDigest',
  'approvedAt',
  'expiresAt',
  'keyId',
  'signature'
];
const CORRECTABLE_FIELDS = new Set(['vault', 'spend']);
const ISO_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

const round = (value) => Math.round(Number(value) * 100) / 100;

const finite = (value) => {
  if (typeof value === 'number') return Number.isFinite(value);
  if (typeof value === 'string') return value.trim() !== '' && Number.isFinite(Number(value));
  return false;
};

const isObject = (value) => value && typeof value === 'object' && !Array.isArray(value);

const isPlainObject = (value) => {
  if (!isObject(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
};

const assertSafeJsonValue = (value, label = 'value', seen = new Set()) => {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError(`${label} contains a non-finite number`);
    return;
  }
  if (typeof value !== 'object') throw new TypeError(`${label} must contain only JSON values`);
  if (seen.has(value)) throw new TypeError(`${label} must not contain circular references`);
  seen.add(value);

  if (Array.isArray(value)) {
    const elementKeys = Reflect.ownKeys(value).filter((key) => key !== 'length');
    if (elementKeys.length !== value.length) {
      throw new TypeError(`${label} must not be sparse or contain extra fields`);
    }
    for (const key of elementKeys) {
      if (typeof key !== 'string' || !/^(0|[1-9]\d*)$/.test(key) || Number(key) >= value.length) {
        throw new TypeError(`${label} must not contain extra fields`);
      }
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor?.enumerable || descriptor.get || descriptor.set) {
        throw new TypeError(`${label}[${key}] must be an enumerable data property`);
      }
      assertSafeJsonValue(descriptor.value, `${label}[${key}]`, seen);
    }
  } else {
    if (!isPlainObject(value)) throw new TypeError(`${label} must be a plain object`);
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== 'string' || FORBIDDEN_OBJECT_KEYS.has(key)) {
        throw new TypeError(`${label} contains a forbidden object key`);
      }
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor?.enumerable || descriptor.get || descriptor.set) {
        throw new TypeError(`${label}.${key} must be an enumerable data property`);
      }
      assertSafeJsonValue(descriptor.value, `${label}.${key}`, seen);
    }
  }
  seen.delete(value);
};

const assertExactObjectKeys = (value, allowed, required, label) => {
  if (!isPlainObject(value)) throw new TypeError(`${label} must be a plain object`);
  const keys = Reflect.ownKeys(value);
  const allowedSet = new Set(allowed);
  for (const key of keys) {
    if (typeof key !== 'string' || FORBIDDEN_OBJECT_KEYS.has(key) || !allowedSet.has(key)) {
      throw new TypeError(`${label} contains an unknown or forbidden field`);
    }
  }
  for (const key of required) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) {
      throw new TypeError(`${label} is missing required field ${key}`);
    }
  }
};

const parseTimestamp = (value, label) => {
  if (typeof value !== 'string' || !ISO_TIMESTAMP.test(value)) {
    throw new TypeError(`${label} must be a canonical ISO-8601 UTC timestamp`);
  }
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    throw new TypeError(`${label} must be a valid timestamp`);
  }
  return milliseconds;
};

const currentTime = (value) => {
  if (value == null) {
    const milliseconds = Date.now();
    return { milliseconds, iso: new Date(milliseconds).toISOString() };
  }
  if (typeof value === 'string') {
    const milliseconds = parseTimestamp(value, 'options.now');
    return { milliseconds, iso: value };
  }
  if (value instanceof Date && Number.isFinite(value.getTime())) {
    return { milliseconds: value.getTime(), iso: value.toISOString() };
  }
  throw new TypeError('options.now must be a valid Date or canonical ISO-8601 UTC timestamp');
};

const isDigest = (value) => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);

const isTransactionId = (value) => value === null
  || typeof value === 'string'
  || (typeof value === 'number' && Number.isFinite(value));

const canonicalize = (value) => {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (isObject(value)) {
    return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, canonicalize(value[key])])
    );
  }
  return value;
};

const digest = async (value) => {
  if (!globalThis.crypto?.subtle) throw new Error('Web Crypto SHA-256 support is required');
  const bytes = new TextEncoder().encode(JSON.stringify(canonicalize(value)));
  const hash = await globalThis.crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(hash)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
};

const copyJson = (value) => JSON.parse(JSON.stringify(value));

const asMoney = (value) => `$${round(value).toFixed(2)}`;

export const sampleScenarios = {
  verified: {
    gross: 500,
    rate: 0.1,
    vault: 50,
    spend: 450,
    note: 'Clean deposit allocation'
  },
  ledger: {
    opening: { spendable: 1200, vaulted: 350 },
    transactions: [
      { id: 'GV-1001', type: 'Deposit', gross: 900, rate: 0.12, vault: 108, spend: 792 },
      { id: 'GV-1002', type: 'Purchase', amount: 150, rate: 0.08, vault: 12 },
      { id: 'GV-1003', type: 'vault-withdrawal', amount: 80 },
      { id: 'GV-1004', type: 'Deposit', gross: 640, rate: 0.15, vault: 96, spend: 544 }
    ]
  },
  anomaly: {
    opening: { spendable: 300, vaulted: 40 },
    transactions: [
      { id: 'GV-2001', type: 'Deposit', gross: 500, rate: 0.1, vault: 20, spend: 480 },
      { id: 'GV-2002', type: 'Purchase', amount: 625, rate: 0.05, vault: 31.25 },
      { id: 'GV-2003', type: 'mystery', amount: 25 }
    ]
  }
};

export function expectedVault(gross, rate) {
  return round(Number(gross) * Number(rate));
}

export function auditAllocation(tx) {
  const issues = [];

  if (!isObject(tx)) {
    return {
      status: 'REVIEW',
      expectedVault: null,
      expectedSpend: null,
      issues: ['Transaction payload must be an object']
    };
  }

  if (!finite(tx.gross) || !finite(tx.rate) || !finite(tx.vault)) {
    return {
      status: 'REVIEW',
      expectedVault: null,
      expectedSpend: null,
      issues: ['Invalid numeric transaction fields']
    };
  }

  const gross = Number(tx.gross);
  const rate = Number(tx.rate);
  const vault = Number(tx.vault);
  const expected = expectedVault(gross, rate);
  const expectedSpend = round(gross - expected);

  if (gross < 0) issues.push('Gross amount cannot be negative');
  if (rate < 0 || rate > 1) issues.push('Rate must be between 0 and 1');
  if (vault < 0) issues.push('Vault amount cannot be negative');

  if (Math.abs(expected - vault) > TOLERANCE) {
    issues.push(`Vault mismatch: expected ${expected.toFixed(2)}, got ${vault.toFixed(2)}`);
  }

  if (tx.spend != null) {
    if (!finite(tx.spend)) {
      issues.push('Spendable amount is not numeric');
    } else if (Number(tx.spend) < 0) {
      issues.push('Spendable amount cannot be negative');
    } else if (Math.abs(expectedSpend - Number(tx.spend)) > TOLERANCE) {
      issues.push(`Spendable mismatch: expected ${expectedSpend.toFixed(2)}, got ${Number(tx.spend).toFixed(2)}`);
    }
  }

  return {
    status: issues.length ? 'REVIEW' : 'VERIFIED',
    expectedVault: expected,
    expectedSpend,
    observed: {
      gross: round(gross),
      rate,
      vault: round(vault),
      spend: finite(tx.spend) ? round(tx.spend) : null
    },
    issues
  };
}

export function reconcile(opening, transactions) {
  let spendable = finite(opening?.spendable) ? Number(opening.spendable) : 0;
  let vaulted = finite(opening?.vaulted) ? Number(opening.vaulted) : 0;
  const reviews = [];
  const entries = [];
  const totals = { deposits: 0, purchases: 0, withdrawals: 0, unknown: 0 };

  for (const [index, tx] of (Array.isArray(transactions) ? transactions : []).entries()) {
    const type = String(tx?.type || '').toLowerCase();
    const before = { spendable: round(spendable), vaulted: round(vaulted) };
    let audit = { status: 'VERIFIED', issues: [] };
    let deltaSpendable = 0;
    let deltaVaulted = 0;

    if (type === 'deposit') {
      totals.deposits += 1;
      audit = auditAllocation(tx);
      const numericCore = finite(tx?.gross) && finite(tx?.rate) && finite(tx?.vault);

      if (numericCore) {
        deltaVaulted = Number(tx.vault);
        deltaSpendable = finite(tx.spend) ? Number(tx.spend) : audit.expectedSpend ?? 0;
      }

      if (audit.status !== 'VERIFIED') reviews.push({ tx, audit });
    } else if (type === 'purchase') {
      totals.purchases += 1;
      const amount = finite(tx?.amount) ? Number(tx.amount) : finite(tx?.gross) ? Number(tx.gross) : NaN;
      const vault = finite(tx?.vault) ? Number(tx.vault) : NaN;
      const rate = finite(tx?.rate) ? Number(tx.rate) : 0;

      if (!finite(amount) || amount < 0 || !finite(vault) || vault < 0) {
        audit = { status: 'REVIEW', issues: ['Invalid purchase amount or vault'] };
        reviews.push({ tx, audit });
      } else {
        audit = auditAllocation({ gross: amount, rate, vault });
        deltaSpendable = -(amount + vault);
        deltaVaulted = vault;
        if (audit.status !== 'VERIFIED') reviews.push({ tx, audit });
      }
    } else if (type === 'vault-withdrawal') {
      totals.withdrawals += 1;
      const amount = finite(tx?.amount) ? Number(tx.amount) : NaN;
      if (!finite(amount) || amount < 0) {
        audit = { status: 'REVIEW', issues: ['Invalid vault withdrawal amount'] };
        reviews.push({ tx, audit });
      } else {
        deltaVaulted = -amount;
      }
    } else {
      totals.unknown += 1;
      audit = { status: 'REVIEW', issues: ['Unknown transaction type'] };
      reviews.push({ tx, audit });
    }

    spendable += deltaSpendable;
    vaulted += deltaVaulted;

    if (spendable < -TOLERANCE || vaulted < -TOLERANCE) {
      const balanceAudit = { status: 'REVIEW', issues: ['Negative balance detected'] };
      reviews.push({ tx, audit: balanceAudit });
      audit = audit.status === 'VERIFIED'
        ? balanceAudit
        : { status: 'REVIEW', issues: [...audit.issues, 'Negative balance detected'] };
    }

    entries.push({
      id: tx?.id || `TX-${String(index + 1).padStart(4, '0')}`,
      type: tx?.type || 'unknown',
      status: audit.status,
      issues: audit.issues,
      before,
      deltaSpendable: round(deltaSpendable),
      deltaVaulted: round(deltaVaulted),
      after: { spendable: round(spendable), vaulted: round(vaulted) }
    });
  }

  return {
    spendable: round(spendable),
    vaulted: round(vaulted),
    status: reviews.length ? 'REVIEW' : 'VERIFIED',
    reviews,
    entries,
    totals: { ...totals, transactions: entries.length }
  };
}

export function dawScore(summary) {
  const reviewCount = summary?.reviews?.length || summary?.issues?.length || 0;
  const negativeBalancePenalty = summary?.reviews?.some((item) => item.audit?.issues?.includes('Negative balance detected')) ? 20 : 0;
  const basePenalty = Math.min(65, reviewCount * 14);
  return Math.max(0, 100 - basePenalty - negativeBalancePenalty);
}

export function runWatchDawg(payload) {
  if (Array.isArray(payload) || Array.isArray(payload?.transactions)) {
    const summary = reconcile(payload?.opening || {}, Array.isArray(payload) ? payload : payload.transactions);
    return {
      mode: 'ledger',
      status: summary.status,
      score: dawScore(summary),
      summary,
      report: explainAudit(summary)
    };
  }

  const audit = auditAllocation(payload);
  return {
    mode: 'transaction',
    status: audit.status,
    score: dawScore(audit),
    audit,
    report: explainAudit(audit)
  };
}

export async function createCorrectionPlan(payload, options = {}) {
  if (!isObject(payload) || !Array.isArray(payload.transactions)) {
    throw new TypeError('Correction planning requires a ledger object with transactions');
  }
  assertSafeJsonValue(payload, 'ledger');
  payload.transactions.forEach((tx, index) => {
    if (!isPlainObject(tx)) {
      throw new TypeError(`ledger.transactions[${index}] must be a plain object`);
    }
    if (Object.prototype.hasOwnProperty.call(tx, 'id') && tx.id != null && !isTransactionId(tx.id)) {
      throw new TypeError(`ledger.transactions[${index}].id must be a string, finite number, or null`);
    }
  });
  const source = copyJson(payload);
  const proposals = [];
  const unhandledReviews = [];

  source.transactions.forEach((tx, index) => {
    const type = String(tx?.type || '').toLowerCase();
    if (type !== 'deposit') {
      if (!['purchase', 'vault-withdrawal'].includes(type)) {
        unhandledReviews.push({ index, id: tx?.id || null, reason: 'Unknown transaction type' });
      }
      return;
    }
    const audit = auditAllocation(tx);
    const safeCore = finite(tx.gross) && Number(tx.gross) >= 0
      && finite(tx.rate) && Number(tx.rate) >= 0 && Number(tx.rate) <= 1
      && finite(tx.vault) && Number(tx.vault) >= 0;
    if (!safeCore || audit.expectedVault == null || audit.expectedSpend == null) {
      unhandledReviews.push({ index, id: tx?.id || null, reason: 'Invalid deposit fields require manual review' });
      return;
    }

    const changes = {};
    if (Math.abs(Number(tx.vault) - audit.expectedVault) > TOLERANCE) {
      changes.vault = audit.expectedVault;
    }
    if (tx.spend != null && finite(tx.spend)
      && Math.abs(Number(tx.spend) - audit.expectedSpend) > TOLERANCE) {
      changes.spend = audit.expectedSpend;
    }
    if (!Object.keys(changes).length) return;

    proposals.push({
      proposalId: `TX-${String(index + 1).padStart(4, '0')}`,
      transactionIndex: index,
      transactionId: tx.id ?? null,
      reason: 'Deterministic deposit allocation mismatch',
      before: Object.fromEntries(Object.keys(changes).map((key) => [key, round(tx[key])])),
      changes,
    });
  });

  const createdAt = options.createdAt || new Date().toISOString();
  parseTimestamp(createdAt, 'plan.createdAt');
  const plan = {
    version: 1,
    createdAt,
    sourceDigest: await digest(source),
    proposals,
    unhandledReviews,
    requiresHumanApproval: true,
    externalWritePerformed: false,
  };
  return { ...plan, planDigest: await digest(plan) };
}

const validateCorrectionPlan = (plan, transactionCount) => {
  assertSafeJsonValue(plan, 'correction plan');
  assertExactObjectKeys(plan, PLAN_KEYS, PLAN_KEYS, 'correction plan');
  if (plan.version !== 1
    || !Array.isArray(plan.proposals)
    || !Array.isArray(plan.unhandledReviews)
    || plan.requiresHumanApproval !== true
    || plan.externalWritePerformed !== false
    || !isDigest(plan.sourceDigest)
    || !isDigest(plan.planDigest)) {
    throw new TypeError('Unsupported or malformed correction plan');
  }
  parseTimestamp(plan.createdAt, 'plan.createdAt');

  const proposalIds = new Set();
  const transactionIndexes = new Set();
  for (const [proposalIndex, proposal] of plan.proposals.entries()) {
    const label = `correction plan proposal ${proposalIndex}`;
    assertExactObjectKeys(proposal, PROPOSAL_KEYS, PROPOSAL_KEYS, label);
    if (typeof proposal.proposalId !== 'string' || !/^TX-\d{4,}$/.test(proposal.proposalId)) {
      throw new TypeError(`${label} has an invalid proposalId`);
    }
    if (proposalIds.has(proposal.proposalId)) {
      throw new TypeError('Correction plan contains duplicate proposal IDs');
    }
    proposalIds.add(proposal.proposalId);

    if (!Number.isInteger(proposal.transactionIndex)
      || proposal.transactionIndex < 0
      || proposal.transactionIndex >= transactionCount) {
      throw new TypeError(`${label} has an invalid transaction index`);
    }
    if (transactionIndexes.has(proposal.transactionIndex)) {
      throw new TypeError('Correction plan contains duplicate transaction proposals');
    }
    transactionIndexes.add(proposal.transactionIndex);

    if (!isTransactionId(proposal.transactionId)
      || proposal.reason !== 'Deterministic deposit allocation mismatch') {
      throw new TypeError(`${label} has invalid identity or reason fields`);
    }

    if (!isPlainObject(proposal.before) || !isPlainObject(proposal.changes)) {
      throw new TypeError(`${label} before and changes must be plain objects`);
    }
    const beforeKeys = Reflect.ownKeys(proposal.before);
    const changeKeys = Reflect.ownKeys(proposal.changes);
    if (!changeKeys.length
      || beforeKeys.length !== changeKeys.length
      || changeKeys.some((key) => typeof key !== 'string' || !CORRECTABLE_FIELDS.has(key))
      || beforeKeys.some((key) => typeof key !== 'string' || !CORRECTABLE_FIELDS.has(key))
      || changeKeys.some((key) => !beforeKeys.includes(key))) {
      throw new TypeError(`${label} may change only matching vault and spend fields`);
    }
    for (const field of changeKeys) {
      if (typeof proposal.before[field] !== 'number' || !Number.isFinite(proposal.before[field])) {
        throw new TypeError(`${label}.before.${field} must be a finite number`);
      }
      if (typeof proposal.changes[field] !== 'number'
        || !Number.isFinite(proposal.changes[field])
        || proposal.changes[field] < 0) {
        throw new TypeError(`${label}.changes.${field} must be a non-negative finite number`);
      }
    }
  }

  const unhandledIndexes = new Set();
  for (const [reviewIndex, review] of plan.unhandledReviews.entries()) {
    const label = `correction plan unhandled review ${reviewIndex}`;
    assertExactObjectKeys(review, ['index', 'id', 'reason'], ['index', 'id', 'reason'], label);
    if (!Number.isInteger(review.index)
      || review.index < 0
      || review.index >= transactionCount
      || !isTransactionId(review.id)
      || typeof review.reason !== 'string'
      || !review.reason.trim()) {
      throw new TypeError(`${label} is malformed`);
    }
    if (unhandledIndexes.has(review.index)) {
      throw new TypeError('Correction plan contains duplicate unhandled reviews');
    }
    unhandledIndexes.add(review.index);
  }
};

const validateApproval = (approval, plan, nowMilliseconds) => {
  assertSafeJsonValue(approval, 'approval');
  assertExactObjectKeys(
    approval,
    APPROVAL_KEYS,
    ['decision', 'approver', 'planDigest'],
    'approval'
  );
  if (approval.decision !== 'APPROVE'
    || typeof approval.approver !== 'string'
    || !approval.approver.trim()
    || approval.planDigest !== plan.planDigest) {
    throw new Error('Exact human approval for this correction plan is required');
  }
  for (const field of ['keyId', 'signature']) {
    if (Object.prototype.hasOwnProperty.call(approval, field)
      && (typeof approval[field] !== 'string' || !approval[field].trim())) {
      throw new TypeError(`approval.${field} must be a non-empty string`);
    }
  }

  const planCreatedAt = parseTimestamp(plan.createdAt, 'plan.createdAt');
  if (planCreatedAt > nowMilliseconds) throw new Error('Correction plan timestamp is in the future');
  let approvedAt = null;
  if (Object.prototype.hasOwnProperty.call(approval, 'approvedAt')) {
    approvedAt = parseTimestamp(approval.approvedAt, 'approval.approvedAt');
    if (approvedAt < planCreatedAt) {
      throw new Error('Approval timestamp predates the correction plan');
    }
    if (approvedAt > nowMilliseconds) {
      throw new Error('Approval timestamp is in the future');
    }
  }
  if (Object.prototype.hasOwnProperty.call(approval, 'expiresAt')) {
    const expiresAt = parseTimestamp(approval.expiresAt, 'approval.expiresAt');
    if (expiresAt <= (approvedAt ?? planCreatedAt)) {
      throw new Error('Approval expiry must follow the approval and plan timestamps');
    }
    if (expiresAt <= nowMilliseconds) throw new Error('Approval has expired');
  }
};

export async function applyApprovedCorrectionPlan(payload, plan, approval, options = {}) {
  if (!isObject(options) || typeof options.verifyApproval !== 'function') {
    throw new Error('A trusted approval verifier is required');
  }
  if (!isObject(payload) || !Array.isArray(payload.transactions)) {
    throw new TypeError('Correction application requires a ledger object with transactions');
  }
  assertSafeJsonValue(payload, 'ledger');
  validateCorrectionPlan(plan, payload.transactions.length);
  const now = currentTime(options.now);
  validateApproval(approval, plan, now.milliseconds);

  const source = copyJson(payload);
  if (await digest(source) !== plan.sourceDigest) {
    throw new Error('Ledger changed after the correction plan was created');
  }
  const unsignedPlan = { ...plan };
  delete unsignedPlan.planDigest;
  if (await digest(unsignedPlan) !== plan.planDigest) {
    throw new Error('Correction plan integrity check failed');
  }

  const expectedPlan = await createCorrectionPlan(source, { createdAt: plan.createdAt });
  if (JSON.stringify(canonicalize(expectedPlan)) !== JSON.stringify(canonicalize(plan))) {
    throw new Error('Correction plan does not match the deterministic ledger corrections');
  }

  let approvalVerified = false;
  try {
    approvalVerified = await options.verifyApproval({
      approval: copyJson(approval),
      plan: copyJson(plan)
    });
  } catch {
    throw new Error('Trusted approval verification failed');
  }
  if (approvalVerified !== true) throw new Error('Trusted approval verification failed');

  const corrected = copyJson(source);
  for (const proposal of expectedPlan.proposals) {
    const tx = corrected.transactions[proposal.transactionIndex];
    if (!tx || (proposal.transactionId != null && tx.id !== proposal.transactionId)) {
      throw new Error('Correction proposal no longer matches its transaction');
    }
    for (const [field, value] of Object.entries(proposal.changes)) tx[field] = value;
  }
  const receipt = {
    planDigest: plan.planDigest,
    sourceDigest: plan.sourceDigest,
    resultDigest: await digest(corrected),
    decision: 'APPROVE',
    approver: String(approval.approver).trim(),
    approvedAt: approval.approvedAt || now.iso,
    appliedProposalIds: expectedPlan.proposals.map((item) => item.proposalId),
    externalWritePerformed: false,
  };
  return { corrected, receipt };
}

export function explainAudit(result) {
  if (result?.summary || result?.audit) return explainAudit(result.summary || result.audit);

  if (Array.isArray(result?.entries)) {
    const lines = [
      `Watch-Dawg ledger verdict: ${result.status}`,
      `Final spendable balance: ${asMoney(result.spendable)}`,
      `Final vaulted balance: ${asMoney(result.vaulted)}`,
      `Transactions scanned: ${result.entries.length}`,
      `Human review findings: ${result.reviews.length}`
    ];

    if (result.reviews.length) {
      lines.push('', 'Review queue:');
      result.reviews.forEach((item, index) => {
        const label = item.tx?.id || item.tx?.type || `Transaction ${index + 1}`;
        lines.push(`${index + 1}. ${label}: ${item.audit.issues.join('; ')}`);
      });
    } else {
      lines.push('', 'No anomalies detected. Allocation and reconciliation rules passed.');
    }

    return lines.join('\n');
  }

  const lines = [
    `Watch-Dawg transaction verdict: ${result?.status || 'REVIEW'}`,
    `Expected vault allocation: ${result?.expectedVault == null ? 'N/A' : asMoney(result.expectedVault)}`,
    `Expected spendable allocation: ${result?.expectedSpend == null ? 'N/A' : asMoney(result.expectedSpend)}`
  ];

  if (result?.issues?.length) {
    lines.push('', 'Review findings:');
    result.issues.forEach((issue, index) => lines.push(`${index + 1}. ${issue}`));
  } else {
    lines.push('', 'No anomalies detected. Transaction allocation passed.');
  }

  return lines.join('\n');
}
