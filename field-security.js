const isObject = (value) => value && typeof value === 'object' && !Array.isArray(value);

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

const asArray = (value) => Array.isArray(value) ? value : [];
const normalize = (value) => String(value || '').trim().toLowerCase();
const uppercase = (value) => String(value || '').trim().toUpperCase();

const severityWeight = {
  critical: 32,
  high: 22,
  medium: 12,
  low: 6,
};

const severityRank = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

export const sampleFieldSecurityPilot = {
  recordKind: 'sample',
  siteId: 'WD-FIELD-001',
  siteName: 'Lakeview Remodel Jobsite',
  authorizedUse: true,
  capturedAt: '2026-09-28T06:00:00-05:00',
  ownerContact: {
    primary: 'Site owner',
    escalation: 'Crew lead',
  },
  zones: [
    {
      id: 'ZONE-PUBLIC-DRIVE',
      name: 'Public drive and delivery pull-off',
      boundaryType: 'open',
      allowedWindow: '06:00-18:00',
      status: 'normal',
      rule: 'Delivery and customer approach allowed during work hours.',
    },
    {
      id: 'ZONE-TOOLS-TRAILER',
      name: 'Tool trailer and materials stack',
      boundaryType: 'restricted',
      allowedWindow: '07:00-17:00',
      status: 'attention',
      rule: 'Any after-hours activity requires owner review and evidence capture.',
    },
    {
      id: 'ZONE-WEST-FENCE',
      name: 'West fence blind spot',
      boundaryType: 'restricted',
      allowedWindow: 'none',
      status: 'unmonitored',
      rule: 'No entry expected. Needs camera or closing photo coverage.',
    },
  ],
  incidents: [
    {
      id: 'INC-1001',
      zoneId: 'ZONE-TOOLS-TRAILER',
      title: 'After-hours movement near tool trailer',
      severity: 'high',
      status: 'open',
      occurredAt: '2026-09-27T21:42:00-05:00',
      observedBy: 'Owner review note',
      reviewStatus: 'needs-human-review',
      evidence: [
        { id: 'EV-1001-A', type: 'photo-note', description: 'Trailer latch photo uploaded by owner.' },
        { id: 'EV-1001-B', type: 'text-note', description: 'Crew confirmed no scheduled access after 17:00.' },
      ],
    },
    {
      id: 'INC-1002',
      zoneId: 'ZONE-WEST-FENCE',
      title: 'Fence-side material moved without closing photo',
      severity: 'medium',
      status: 'open',
      occurredAt: '2026-09-28T05:50:00-05:00',
      observedBy: 'Morning walkthrough',
      reviewStatus: 'needs-evidence',
      evidence: [],
    },
    {
      id: 'INC-1003',
      zoneId: 'ZONE-PUBLIC-DRIVE',
      title: 'Expected delivery verified',
      severity: 'low',
      status: 'resolved',
      occurredAt: '2026-09-27T10:14:00-05:00',
      observedBy: 'Delivery log',
      reviewStatus: 'human-reviewed',
      evidence: [
        { id: 'EV-1003-A', type: 'delivery-note', description: 'Material drop matched vendor invoice.' },
      ],
    },
  ],
};

function makeFinding(id, severity, category, message, evidenceRef = null) {
  return { id, severity, category, message, evidenceRef };
}

function highestSeverity(findings) {
  return findings.reduce((highest, finding) => {
    const next = severityRank[normalize(finding.severity)] || 0;
    const current = severityRank[highest] || 0;
    return next > current ? normalize(finding.severity) : highest;
  }, 'none');
}

function findZone(site, zoneId) {
  return asArray(site.zones).find((zone) => zone.id === zoneId) || null;
}

export function auditFieldSecuritySite(site) {
  const findings = [];

  if (!isObject(site)) {
    return {
      mode: 'field-security',
      status: 'REVIEW',
      score: 0,
      proofState: 'INSUFFICIENT_INPUT',
      siteName: 'Unknown site',
      summary: { zones: 0, incidents: 0, openIncidents: 0, evidenceItems: 0, restrictedZones: 0 },
      findings: [makeFinding('FIELD-INPUT-001', 'critical', 'input', 'Field-security audit requires a site object.')],
      report: 'Watch-Dawg field-security verdict: REVIEW\nCritical input problem: site payload must be an object.',
    };
  }

  const zones = asArray(site.zones);
  const incidents = asArray(site.incidents);
  const openIncidents = incidents.filter((incident) => normalize(incident.status) !== 'resolved');
  const evidenceItems = incidents.reduce((total, incident) => total + asArray(incident.evidence).length, 0);
  const restrictedZones = zones.filter((zone) => normalize(zone.boundaryType) === 'restricted');

  if (site.authorizedUse !== true) {
    findings.push(makeFinding(
      'FIELD-AUTH-001',
      'critical',
      'authorization',
      'Authorization flag is missing or false. Watch-Dawg requires owner or contract authority before field evidence is reviewed.'
    ));
  }

  if (!zones.length) {
    findings.push(makeFinding('FIELD-ZONE-001', 'medium', 'zone', 'No open-boundary zones are defined for the site.'));
  }

  if (!String(site.ownerContact?.primary || '').trim()) {
    findings.push(makeFinding('FIELD-CONTACT-001', 'medium', 'escalation', 'Primary owner/contact is missing. Escalation path is unclear.'));
  }

  zones.forEach((zone) => {
    if (normalize(zone.status) === 'unmonitored') {
      findings.push(makeFinding(
        `FIELD-ZONE-${uppercase(zone.id || zone.name || 'UNKNOWN')}`,
        'medium',
        'coverage',
        `${zone.name || zone.id || 'A restricted zone'} is marked unmonitored. Add a closing photo, camera view, or manual check requirement.`,
        zone.id || null
      ));
    }
  });

  // Resolved entries can still have missing evidence or review, especially in imported records.
  incidents.forEach((incident) => {
    const zone = findZone(site, incident.zoneId);
    const incidentSeverity = normalize(incident.severity) || 'medium';
    const zoneType = normalize(zone?.boundaryType);
    const incidentEvidence = asArray(incident.evidence);

    if (normalize(incident.status) !== 'resolved' && zoneType === 'restricted' && ['high', 'critical'].includes(incidentSeverity)) {
      findings.push(makeFinding(
        `FIELD-INCIDENT-${uppercase(incident.id || 'UNKNOWN')}`,
        incidentSeverity,
        'restricted-zone',
        `${incident.title || incident.id || 'Open incident'} is open inside a restricted zone and needs owner review before it is treated as resolved.`,
        incident.id || null
      ));
    }

    if (!incidentEvidence.length) {
      findings.push(makeFinding(
        `FIELD-EVIDENCE-${uppercase(incident.id || 'UNKNOWN')}`,
        'medium',
        'evidence',
        `${incident.title || incident.id || 'Incident'} has no evidence items. Add a photo reference, note, witness statement, or receipt before acting on the record.`,
        incident.id || null
      ));
    }

    if (normalize(incident.reviewStatus) !== 'human-reviewed') {
      findings.push(makeFinding(
        `FIELD-REVIEW-${uppercase(incident.id || 'UNKNOWN')}`,
        incidentSeverity === 'critical' ? 'high' : 'low',
        'human-review',
        `${incident.title || incident.id || 'Open incident'} has not been marked human-reviewed.`,
        incident.id || null
      ));
    }
  });

  const penalty = findings.reduce((total, finding) => total + (severityWeight[normalize(finding.severity)] || severityWeight.low), 0);
  const score = Math.max(0, 100 - penalty);
  const status = findings.length ? 'REVIEW' : 'VERIFIED';
  const audit = {
    mode: 'field-security',
    status,
    score,
    proofState: status === 'VERIFIED' ? 'REVIEW_READY' : 'HUMAN_REVIEW_REQUIRED',
    siteId: site.siteId || null,
    siteName: site.siteName || 'Unnamed site',
    capturedAt: site.capturedAt || null,
    highestSeverity: highestSeverity(findings),
    summary: {
      zones: zones.length,
      incidents: incidents.length,
      openIncidents: openIncidents.length,
      evidenceItems,
      restrictedZones: restrictedZones.length,
    },
    findings,
  };

  return { ...audit, report: explainFieldSecurityAudit(audit) };
}

export function explainFieldSecurityAudit(audit) {
  const lines = [
    `Watch-Dawg field-security verdict: ${audit.status}`,
    `Site: ${audit.siteName}`,
    `Field score: ${audit.score}`,
    `Proof state: ${audit.proofState}`,
    `Zones: ${audit.summary.zones}`,
    `Open incidents: ${audit.summary.openIncidents}`,
    `Evidence items captured: ${audit.summary.evidenceItems}`,
  ];

  if (audit.findings.length) {
    lines.push('', 'Human review queue:');
    audit.findings.forEach((finding, index) => {
      lines.push(`${index + 1}. [${finding.severity.toUpperCase()}] ${finding.message}`);
    });
  } else {
    lines.push('', 'No field-security findings detected. Site evidence is review-ready.');
  }

  lines.push('', 'Boundary: this report organizes captured site evidence. It is not proof of criminal intent, legal liability, exploitability, or surveillance coverage outside the submitted record.');
  return lines.join('\n');
}

export function buildFieldSecurityAiSummary(audit) {
  const firstFinding = audit.findings[0];
  const lines = [
    `Watch-Dawg sees ${audit.summary.openIncidents} open incident(s) across ${audit.summary.zones} zone(s).`,
    `Current field score is ${audit.score}; proof state is ${audit.proofState}.`,
  ];

  if (firstFinding) {
    lines.push(`Highest-priority action: ${firstFinding.message}`);
    lines.push('Recommended next step: capture missing evidence, mark owner review, then export a human-reviewed report.');
  } else {
    lines.push('Recommended next step: export the review-ready field report and keep normal closing-photo cadence.');
  }

  lines.push('AI boundary: summary is limited to the provided zone, incident, and evidence records.');
  return lines.join('\n');
}

export async function createFieldSecurityReceipt(site, audit, options = {}) {
  if (!isObject(site) || !isObject(audit)) throw new TypeError('Receipt requires site and audit objects');
  const unsignedReceipt = {
    version: 1,
    createdAt: options.createdAt || new Date().toISOString(),
    issuer: options.issuer || 'Watch-Dawg field-security pilot',
    siteId: audit.siteId || site.siteId || null,
    siteName: audit.siteName || site.siteName || 'Unnamed site',
    proofState: audit.proofState || 'HUMAN_REVIEW_REQUIRED',
    sourceDigest: await digest(site),
    auditDigest: await digest(audit),
    findings: audit.findings?.length || 0,
    limitations: [
      'Unsigned receipt records SHA-256 field evidence linkage only; it does not authenticate an author or timestamp.',
      'Receipt does not prove criminal intent, legal liability, or complete surveillance coverage.',
      'Human review remains required for any business, insurance, police, or customer action.',
    ],
  };

  return { ...unsignedReceipt, receiptDigest: await digest(unsignedReceipt) };
}
