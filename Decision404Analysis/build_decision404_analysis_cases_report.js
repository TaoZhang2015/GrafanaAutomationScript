#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const cwd = '/Users/tazhazha/Documents/oncall/javascript/Decision404Analysis/rerun';
const logPath = path.join(cwd, 'decision404_analysis_run.log');
const defaultOutPath = path.join(cwd, 'decision404_analysis_cases.html');

const GRAFANA_BASE_URL = 'https://oc1.octo.oraclecloud.com/grafana';
const MAX_CASES_PER_TYPE = 200;
const EXCLUDED_STEP34_MESSAGES = new Set(['Step 3.4 aggregation completed']);
const STEP34_MESSAGE_OVERRIDES = new Map([
  [
    'root cause: deployment became serving only after deployment-list cache round',
    'root cause: deployment became qualified (Activated/Default) after request; cache loading round used by request was earlier',
  ],
]);

function parseLine(raw, idx) {
  const m = raw.match(/^\[([^\]]+)\]\s+\[([^\]]+)\]\s+([^|]+?)(?:\s+\|\s+(.*))?$/);
  if (!m) return { raw, idx, ts: null, step: null, message: null, payload: null };
  let payload = null;
  if (m[4]) {
    try {
      payload = JSON.parse(m[4]);
    } catch (_) {
      payload = null;
    }
  }
  return {
    raw,
    idx,
    ts: m[1],
    step: m[2],
    message: m[3].trim(),
    payload,
  };
}

function parseArgs(argv) {
  const out = { traceID: null, outPath: null };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--traceid' && argv[i + 1]) {
      out.traceID = String(argv[i + 1]).trim();
      i += 1;
      continue;
    }
    if (a === '--out' && argv[i + 1]) {
      out.outPath = String(argv[i + 1]).trim();
      i += 1;
    }
  }
  return out;
}

function escapeHtml(v) {
  return String(v ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function buildExploreUrl(q) {
  const lokiUid = `loki-${q.region}-1-fa`;
  const fromMs = String(Math.floor(Number(q.startNs || 0) / 1e6));
  const toMs = String(Math.floor(Number(q.endNs || 0) / 1e6));
  const direction = String(q.direction || 'BACKWARD').toLowerCase();
  const panes = {
    ntl: {
      datasource: lokiUid,
      queries: [
        {
          refId: 'A',
          expr: q.expr || '',
          queryType: 'range',
          datasource: { type: 'loki', uid: lokiUid },
          editorMode: 'code',
          direction,
          maxLines: q.limit || 3000,
          legendFormat: '',
        },
      ],
      range: { from: fromMs, to: toMs },
      compact: false,
    },
  };
  return `${GRAFANA_BASE_URL}/explore?schemaVersion=1&panes=${encodeURIComponent(JSON.stringify(panes))}&orgId=1`;
}

function pickCompact(obj, keys) {
  const out = {};
  for (const k of keys) {
    if (obj && Object.prototype.hasOwnProperty.call(obj, k) && obj[k] != null) {
      out[k] = obj[k];
    }
  }
  return out;
}

function normalizeCompletionDistinctField(payload) {
  if (!payload || typeof payload !== 'object') return payload;
  if (
    payload.completionDistinctExtendCount == null &&
    payload.completionDistinctUsedCount != null
  ) {
    payload.completionDistinctExtendCount = payload.completionDistinctUsedCount;
  }
  return payload;
}

function stableStringify(value) {
  if (Array.isArray(value)) {
    return `[${value.map((v) => stableStringify(v)).join(',')}]`;
  }
  if (value && typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function formatRequestTimePst(nsValue) {
  const ns = Number(nsValue);
  if (!Number.isFinite(ns) || ns <= 0) return null;
  const ms = Math.floor(ns / 1e6);
  const d = new Date(ms);
  return d.toLocaleString('en-US', {
    timeZone: 'America/Los_Angeles',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

function displayStep34Message(message) {
  const key = String(message || '');
  return STEP34_MESSAGE_OVERRIDES.get(key) || key;
}

function inferQueryContextStep(lastStepMessage, queryPayload, requestTsNs) {
  const text = String(queryPayload?.expr || '');
  const startNs = Number(queryPayload?.startNs);
  const reqNs = Number(requestTsNs);

  if (text.includes('starting decision server|starting authz decision server')) {
    return 'restart evidence check';
  }
  if (text.includes('update deployment state successfully')) {
    return 'deployment state check evaluated';
  }
  if (text.includes('completed preparing policies runtime cache|completed preparing role assignments runtime cache|updated cache for deployment')) {
    if (Number.isFinite(startNs) && Number.isFinite(reqNs) && startNs >= reqNs) {
      return 'extending runtime cache completion search to post-request window +10m';
    }
    return 'runtime cache completion timing checked';
  }
  if (/\|\~\s*"([a-f0-9]{32})"/i.test(text)) {
    return 'trace error category determined';
  }
  if (
    text.includes('updating deployment list cache with deploymentID') ||
    text.includes('new deployment from latest DB records added to the cache')
  ) {
    return 'deployment list cache cross-check evaluated';
  }
  if (text.includes('updating deployment list cache with default deploymentID|new default deployment added to the cache')) {
    return 'default deployment lookup';
  }
  if (lastStepMessage === 'start link analysis') return 'default deployment lookup';
  return lastStepMessage || 'n/a';
}

function buildStep33Runs(records) {
  const sorted = (records || []).slice().sort((a, b) => a.idx - b.idx);
  const runs = [];
  let current = null;

  for (const r of sorted) {
    if (r.step !== 'STEP3.3' && r.step !== 'LOKI') continue;

    if (r.step === 'STEP3.3' && r.message === 'start link analysis') {
      if (current && current.records.length > 0) runs.push(current);
      current = { records: [] };
      current.records.push(r);
      continue;
    }

    if (!current) continue;
    current.records.push(r);

    if (r.step === 'STEP3.3' && r.message === 'final step3.3 conclusion for link') {
      runs.push(current);
      current = null;
    }
  }

  if (current && current.records.length > 0) runs.push(current);
  return runs;
}

function summarizeStep33Run(run) {
  const meta = {
    requestDeploymentID: null,
    resolvedDefaultDeploymentID: null,
    finalConclusion: null,
    traceCategory: null,
    endIdx: -1,
  };
  for (const r of run.records || []) {
    if (r.step !== 'STEP3.3') continue;
    if (meta.requestDeploymentID == null && r.payload?.requestDeploymentID != null) {
      meta.requestDeploymentID = String(r.payload.requestDeploymentID);
    }
    if (
      r.message === 'default deployment lookup completed' &&
      r.payload?.resolvedDefaultDeploymentID != null
    ) {
      meta.resolvedDefaultDeploymentID = String(r.payload.resolvedDefaultDeploymentID);
    }
    if (r.message === 'trace error category determined' && r.payload?.traceCategory != null) {
      meta.traceCategory = String(r.payload.traceCategory);
    }
    if (r.message === 'final step3.3 conclusion for link' && r.payload?.finalConclusion != null) {
      meta.finalConclusion = String(r.payload.finalConclusion);
    }
    if (r.idx > meta.endIdx) meta.endIdx = r.idx;
  }
  return meta;
}

function selectBestRunForStep34(step34Payload, runs) {
  if (!runs || runs.length === 0) return null;
  const wantReq = step34Payload?.requestedDeploymentID != null ? String(step34Payload.requestedDeploymentID) : null;
  const wantDef = step34Payload?.resolvedDefaultDeploymentID != null ? String(step34Payload.resolvedDefaultDeploymentID) : null;
  const wantConc = step34Payload?.step3_3Conclusion != null ? String(step34Payload.step3_3Conclusion) : null;
  const wantCat = step34Payload?.traceErrorCategory != null ? String(step34Payload.traceErrorCategory) : null;

  let best = null;
  for (const run of runs) {
    const meta = summarizeStep33Run(run);
    let score = 0;
    if (wantReq && meta.requestDeploymentID === wantReq) score += 100;
    if (wantDef && meta.resolvedDefaultDeploymentID === wantDef) score += 40;
    if (wantConc && meta.finalConclusion === wantConc) score += 20;
    if (wantCat && meta.traceCategory === wantCat) score += 10;
    if (!best || score > best.score || (score === best.score && meta.endIdx > best.meta.endIdx)) {
      best = { run, meta, score };
    }
  }
  return best?.run || null;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const traceIDFilter = args.traceID || null;
  const outPath = args.outPath
    || (traceIDFilter
      ? path.join(cwd, `decision404_analysis_cases_trace_${traceIDFilter}.html`)
      : defaultOutPath);

  if (!fs.existsSync(logPath)) {
    throw new Error(`Missing log file: ${logPath}`);
  }

  const parsed = fs
    .readFileSync(logPath, 'utf8')
    .split(/\r?\n/)
    .map((line, idx) => parseLine(line, idx));

  const step33ByTrace = new Map();
  const step34Cases = [];
  let activeTraceID = null;

  function pushTraceRecord(traceID, rec) {
    if (!traceID) return;
    const arr = step33ByTrace.get(traceID) || [];
    arr.push(rec);
    step33ByTrace.set(traceID, arr);
  }

  for (const rec of parsed) {
    if (!rec.step || !rec.message || !rec.payload) continue;

    if (rec.step === 'STEP3.3' && rec.payload.traceID) {
      const traceID = rec.payload.traceID;
      activeTraceID = traceID;
      pushTraceRecord(traceID, rec);
      continue;
    }

    // LOKI lines do not carry traceID; attach them to the currently active STEP3.3 trace.
    if (rec.step === 'LOKI' && rec.message === 'query_range start' && activeTraceID) {
      pushTraceRecord(activeTraceID, rec);
      continue;
    }

    if (
      rec.step === 'STEP3.4' &&
      !EXCLUDED_STEP34_MESSAGES.has(rec.message) &&
      rec.payload.traceID &&
      (!traceIDFilter || rec.payload.traceID === traceIDFilter)
    ) {
      step34Cases.push(rec);
    }
  }

  const typeCounts = new Map();
  for (const c of step34Cases) {
    typeCounts.set(c.message, (typeCounts.get(c.message) || 0) + 1);
  }

  const dedupedStep34Cases = [];
  const seenStep34 = new Set();
  for (const c of step34Cases) {
    const payload = normalizeCompletionDistinctField(c.payload);
    const key = `${c.message}::${stableStringify(payload || {})}`;
    if (seenStep34.has(key)) continue;
    seenStep34.add(key);
    dedupedStep34Cases.push(c);
  }

  const selectedCases = [];
  const perTypeCounter = new Map();

  for (const c of dedupedStep34Cases) {
    const curr = perTypeCounter.get(c.message) || 0;
    if (curr >= MAX_CASES_PER_TYPE) continue;
    perTypeCounter.set(c.message, curr + 1);
    selectedCases.push(c);
  }

  const enriched = selectedCases.map((c) => {
    const traceID = c.payload.traceID;
    const allS33 = (step33ByTrace.get(traceID) || []).slice().sort((a, b) => a.idx - b.idx);
    const s33Runs = buildStep33Runs(allS33);
    const selectedRun = selectBestRunForStep34(c.payload, s33Runs);
    const s33 = (selectedRun?.records || allS33).slice().sort((a, b) => a.idx - b.idx);
    normalizeCompletionDistinctField(c.payload);

    const queries = [];
    let lastStepMessage = 'n/a';
    let requestTsNs = null;

    for (const r of s33) {
      if (r.step === 'STEP3.3') {
        lastStepMessage = r.message;
        if (r.payload?.requestTsNs != null) requestTsNs = r.payload.requestTsNs;
      }
      if (r.step === 'LOKI' && r.message === 'query_range start') {
        queries.push({
          queryId: r.payload.queryId,
          region: r.payload.region,
          startPst: r.payload.startPst,
          endPst: r.payload.endPst,
          expr: r.payload.expr,
          contextStep: inferQueryContextStep(lastStepMessage, r.payload, requestTsNs),
          link: buildExploreUrl(r.payload),
        });
      }
    }

    const stepRows = s33.map((r) => {
      const payload = normalizeCompletionDistinctField(r.payload);
      return {
        ts: r.ts,
        message: r.message,
        detail: pickCompact(payload, [
        'env',
        'pod',
        'requestUrl',
        'requestDeploymentID',
        'resolvedDefaultDeploymentID',
        'targetDeploymentID',
        'traceCategory',
        'finalConclusion',
        'finalReason',
        'completionTimingReason',
        'completionDistinctExtendCount',
        'deploymentListReason',
        'postReason',
        ]),
      };
    });

    return {
      type: c.message,
      traceID,
      env: c.payload.env,
      rootCause: c.payload.rootCause || null,
      requestTsNs: requestTsNs ? String(requestTsNs) : null,
      requestTimePst: formatRequestTimePst(requestTsNs),
      step34Ts: c.ts,
      step34: c.payload,
      steps: stepRows,
      queries,
    };
  });

  enriched.sort((a, b) => {
    if (a.type !== b.type) return a.type.localeCompare(b.type);
    if ((a.env || '') !== (b.env || '')) return (a.env || '').localeCompare(b.env || '');
    return (a.traceID || '').localeCompare(b.traceID || '');
  });

  const grouped = new Map();
  for (const c of enriched) {
    const arr = grouped.get(c.type) || [];
    arr.push(c);
    grouped.set(c.type, arr);
  }

  let html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Decision404 Analysis Cases</title>
  <style>
    :root {
      --bg: #f7f9fc;
      --card: #fff;
      --ink: #17212f;
      --muted: #5f6978;
      --line: #d7deea;
      --accent: #0052cc;
      --soft: #eef3fb;
    }
    * { box-sizing: border-box; }
    body { margin: 0; background: var(--bg); color: var(--ink); font-family: "Avenir Next", "Segoe UI", sans-serif; }
    .wrap { max-width: 1500px; margin: 0 auto; padding: 16px; }
    h1 { margin: 0 0 8px; font-size: 24px; }
    h2 { margin: 14px 0 8px; font-size: 18px; }
    h3 { margin: 10px 0 6px; font-size: 14px; }
    .sub { color: var(--muted); margin-bottom: 6px; }
    .box { background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 12px; margin: 12px 0; }
    .case { background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 10px; margin: 10px 0; }
    .kvs { display: grid; grid-template-columns: repeat(6, minmax(160px, 1fr)); gap: 6px; margin-bottom: 8px; }
    .kv { border: 1px solid var(--line); background: var(--soft); border-radius: 8px; padding: 6px; font-size: 12px; }
    .kv b { display: block; color: var(--muted); margin-bottom: 2px; font-size: 11px; }
    table { width: 100%; border-collapse: collapse; font-size: 12px; }
    th, td { border: 1px solid var(--line); text-align: left; vertical-align: top; padding: 6px 8px; }
    th { background: #f2f6fd; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; word-break: break-all; }
    a { color: var(--accent); }
    details { margin-top: 8px; }
    summary { cursor: pointer; user-select: none; font-weight: 600; }
    @media (max-width: 1200px) { .kvs { grid-template-columns: repeat(3, minmax(160px, 1fr)); } }
    @media (max-width: 720px) { .kvs { grid-template-columns: repeat(2, minmax(140px, 1fr)); } }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Decision404 Analysis Cases</h1>
    <div class="sub">Source: <code>${escapeHtml(logPath)}</code></div>
    <div class="sub">Trace Filter: <code>${escapeHtml(traceIDFilter || 'ALL')}</code></div>
    <div class="sub">Generated UTC: <code>${escapeHtml(new Date().toISOString())}</code></div>
    <div class="sub">Case limit per type: <code>${MAX_CASES_PER_TYPE}</code></div>

    <div class="box">
      <h2>Case Type Summary</h2>
      <table>
        <thead><tr><th>STEP3.4 Message</th><th>Total In Log</th><th>Included In Page</th></tr></thead>
        <tbody>
`;

  const summaryRows = [...typeCounts.entries()].sort((a, b) => b[1] - a[1]);
  for (const [msg, total] of summaryRows) {
    const included = perTypeCounter.get(msg) || 0;
    html += `          <tr><td>${escapeHtml(displayStep34Message(msg))}</td><td>${total}</td><td>${included}</td></tr>\n`;
  }

  html += `        </tbody>
      </table>
    </div>
`;

  for (const [type, rows] of grouped.entries()) {
    html += `    <div class="box">\n`;
    html += `      <h2>${escapeHtml(displayStep34Message(type))}</h2>\n`;
    html += `      <div class="sub">Included cases: <b>${rows.length}</b></div>\n`;

    for (const c of rows) {
      const kvs = [
        ['env', c.env || 'N/A'],
        ['traceID', c.traceID || 'N/A'],
        ['request404TimePST', c.requestTimePst || 'N/A'],
        ['rootCause', c.rootCause || c.step34.result || 'N/A'],
        ['requestedDeploymentID', c.step34.requestedDeploymentID || 'N/A'],
        ['resolvedDefaultDeploymentID', c.step34.resolvedDefaultDeploymentID || 'N/A'],
        ['step3_3Conclusion', c.step34.step3_3Conclusion || 'N/A'],
      ];

      html += `      <section class="case">\n`;
      html += `        <div class="kvs">\n`;
      for (const [k, v] of kvs) {
        html += `          <div class="kv"><b>${escapeHtml(k)}</b><span class="mono">${escapeHtml(v)}</span></div>\n`;
      }
      html += `        </div>\n`;

      const step34Compact = pickCompact(c.step34, [
        'result',
        'postRequestRoundsChecked',
        'completionDistinctOriginalCount',
        'completionDistinctExtendCount',
        'completionExtensionUsed',
        'transitionEventCurState',
        'transitionEventNewState',
        'cacheRoundHitLokiTsNs',
      ]);

      html += `        <details open>\n`;
      html += `          <summary>Step 3.4 Case Details</summary>\n`;
      html += `          <pre class="mono">${escapeHtml(JSON.stringify(step34Compact, null, 2))}</pre>\n`;
      html += `        </details>\n`;

      html += `        <details>\n`;
      html += `          <summary>Step 3.3 Timeline (${c.steps.length} records)</summary>\n`;
      html += `          <table>\n`;
      html += `            <thead><tr><th>Timestamp</th><th>Step Message</th><th>Detail</th></tr></thead><tbody>\n`;
      for (const s of c.steps) {
        html += `              <tr><td>${escapeHtml(s.ts || '')}</td><td>${escapeHtml(s.message || '')}</td><td><pre class="mono">${escapeHtml(JSON.stringify(s.detail, null, 2))}</pre></td></tr>\n`;
      }
      html += `            </tbody></table>\n`;
      html += `        </details>\n`;

      html += `        <details>\n`;
      html += `          <summary>Loki Queries (${c.queries.length})</summary>\n`;
      html += `          <table>\n`;
      html += `            <thead><tr><th>Query ID</th><th>Context Step</th><th>Window (PST)</th><th>Expr</th><th>Link</th></tr></thead><tbody>\n`;
      for (const q of c.queries) {
        html += `              <tr>`;
        html += `<td>${escapeHtml(q.queryId)}</td>`;
        html += `<td>${escapeHtml(q.contextStep || '')}</td>`;
        html += `<td>${escapeHtml(`${q.startPst || ''} -> ${q.endPst || ''}`)}</td>`;
        html += `<td class="mono">${escapeHtml(q.expr || '')}</td>`;
        html += `<td><a href="${escapeHtml(q.link)}" target="_blank" rel="noopener noreferrer">Open Loki Search</a></td>`;
        html += `</tr>\n`;
      }
      html += `            </tbody></table>\n`;
      html += `        </details>\n`;

      html += `      </section>\n`;
    }

    html += `    </div>\n`;
  }

  html += `  </div>
</body>
</html>
`;

  fs.writeFileSync(outPath, html, 'utf8');

  console.log(`Generated: ${outPath}`);
  console.log(`Total STEP3.4 cases in log: ${step34Cases.length}`);
  console.log(`Total included in page: ${enriched.length}`);
  for (const [msg, total] of summaryRows) {
    const inc = perTypeCounter.get(msg) || 0;
    console.log(`- ${msg}: total=${total}, included=${inc}`);
  }
}

main();
