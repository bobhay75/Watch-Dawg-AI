const TOLERANCE = 0.009;

const round = (value) => Math.round(Number(value) * 100) / 100;

const finite = (value) => {
  if (typeof value === 'number') return Number.isFinite(value);
  if (typeof value === 'string') return value.trim() !== '' && Number.isFinite(Number(value));
  return false;
};

const isObject = (value) => value && typeof value === 'object' && !Array.isArray(value);

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
