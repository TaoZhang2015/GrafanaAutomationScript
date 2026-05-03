/*
 * Multi-region HTTP 500 investigation script (Mimir + Loki) with CSV export (in-page save panel).
 *
 * Purpose
 * - Identify production environments (label: prd_env) that are returning HTTP 500s in each region
 *   during a specified time window.
 * - For each (region, env), correlate 5xx requests to trace IDs and extract unique error messages
 *   from JSON error log lines.
 *
 * NEW (previous request): print the discovered env list at the end of execution
 * - Collect a unique env set across all regions from the Mimir discovery step.
 * - At the end (in finally), print the env list as a JSON array.
 *
 * NEW (this request): configurable absolute start/end time for ALL Mimir + Loki queries
 * - Instead of "last LOOKBACK_DAYS", you can set an explicit time range, e.g.:
 *     2026-03-28 00:00:00  to  2026-03-30 23:59:59
 * - IMPORTANT: This script interprets the configured times as UTC by default.
 *   If you need local-time interpretation instead, say so and I’ll adjust the parser.
 *
 * CSV save UI
 * - Uses an in-page save panel with one button per file (same style as Decision404 analysis).
 * - Each button triggers browser save flow via File System Access API when available,
 *   otherwise falls back to a download link click.
 *
 * Data sources and approach
 * 1) Mimir (Prometheus API): environment discovery
 *    - Query (MIMIR_EXPR) selects environments that had processed requests with statuscode=500.
 *    - We use the resulting prd_env label values as the per-region environment candidate list.
 *
 * 2) Loki: trace correlation + error extraction
 *    a) For each env, query Loki for log lines that indicate a 5xx response:
 *         |~ `"requestHTTPStatusCode"\s*:\s*5|"responseStatusCode"\s*:\s*5`
 *       and extract trace IDs from JSON fields (traceId/trace_id/etc.) and regex fallbacks.
 *    b) For each trace ID, query Loki again for all lines containing that trace ID.
 *    c) From those lines, extract unique JSON error records only when:
 *       - the log line is valid JSON
 *       - level == "error"
 *       - the "error" field is present and non-empty
 *       - exact noise messages are skipped (case-insensitive):
 *           "rendering response", "key roleName not found", "internal server error"
 *       - uniqueness key preference:
 *           ORA-<code>  >  errorCode  >  full message
 *       - redundant errors are pruned when a longer message contains a shorter one.
 *
 * Outputs (CSV)
 * - management500_summary_by_env.csv
 *     Columns: region, env, url, request500Count, traceIdCount, recoveryStatus, uniqueErrorMessage
 * - management500_error_by_message.csv
 *     Columns: errorMessage, envCount, envs
 *
 * Operational notes
 * - Runs sequentially (no parallelism) to reduce load and avoid rate-limits.
 * - Per-trace Loki context queries are throttled with SLEEP_MS (increase if you see 429/502).
 * - Intended to run in an authenticated Grafana browser tab (DevTools Console).
 */

// -------------------------
// CONFIG (edit here)
// -------------------------
const REGIONS = ['af-casablanca', 'ap-hobsonville', 'ap-hyderabad', 'ap-melbourne', 'ap-mitaka', 'ap-mumbai', 'ap-osaka', 'ap-pathumthani', 'ap-samutprakan', 'ap-silverdale', 'ap-singapore', 'ap-suwon', 'ap-sydney', 'ap-tokyo', 'ap-westtokyo', 'ca-montreal', 'ca-toronto', 'eu-amsterdam', 'eu-frankfurt', 'eu-milan', 'eu-stockholm', 'eu-zurich', 'me-abudhabi', 'me-alain', 'me-alkhobar', 'me-dubai', 'me-ibri', 'me-jeddah', 'me-riyadh', 'mx-monterrey', 'sa-riodejaneiro', 'sa-santiago', 'sa-saopaulo', 'sa-vinhedo', 'uk-cardiff', 'uk-london', 'us-ashburn', 'us-newark', 'us-phoenix'];

// Time window configuration (UTC)
// Format: "YYYY-MM-DD HH:mm:ss"
const START_TIME_UTC = "2026-04-27 00:00:00";
const END_TIME_UTC = "2026-04-29 23:59:59";

const STEP_SEC = "300";
const LOKI_LIMIT = 3000;
const MAX_SPLIT_DEPTH = 3; // recursive window split on retriable Loki HTTP errors
const MIN_SPLIT_WINDOW_NS = 1000000n; // do not split below 1ms windows
const SPLITTABLE_HTTP_STATUS = new Set([400, 429, 500, 502, 503, 504]);
const MAX_RETRY_ATTEMPTS = 3;
const BASE_RETRY_DELAY_MS = 300;
const SLEEP_MS = 50; // try 250–1000ms if you still see 429/502

// Optional tag(s) included in the generated CSV filenames.
// Keep it short and non-sensitive; it will be "slugified" for filesystem safety.
const CSV_NAME_TAG = "ns_authz_fleet_faaas-prod";
const ENABLE_CONSOLE_TABLE_PREVIEW = false;
const ENABLE_ENV_LIST_JSON_PRINT = false;

const SKIP_EXACT = new Set([
  "rendering response",
  "key rolename not found",
  "internal server error",
]);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const shouldRetryStatus = (status) => {
  const n = Number(status);
  return n === 429 || (n >= 500 && n <= 599);
};
const isFailedToFetchError = (err) =>
  String(err?.message || err || "").toLowerCase().includes("failed to fetch");

function getGrafanaBasePath() {
  if (typeof location === "undefined") return "";
  return location.pathname.startsWith("/grafana/") ? "/grafana" : "";
}

function assignRequestsToMessageBuckets({
  requestCountByTraceId,
  noTraceRequestCount,
  traceIdToAssignedMessage,
} = {}) {
  const messageStats = new Map();
  const add = (message, traceId, reqCount) => {
    const requestCount = Number(reqCount || 0);
    if (requestCount <= 0) return;
    const msg = String(message || "N/A");
    if (!messageStats.has(msg)) {
      messageStats.set(msg, { request500Count: 0, traceIds: new Set() });
    }
    const bucket = messageStats.get(msg);
    bucket.request500Count += requestCount;
    if (traceId) bucket.traceIds.add(traceId);
  };

  for (const [traceId, reqCountRaw] of requestCountByTraceId?.entries?.() || []) {
    const reqCount = Number(reqCountRaw || 0);
    if (reqCount <= 0) continue;
    const assignedMsg = traceIdToAssignedMessage?.get?.(traceId) || "N/A";
    add(assignedMsg, traceId, reqCount);
  }
  add("N/A", null, Number(noTraceRequestCount || 0));
  return messageStats;
}

function buildSummaryRowsByEnv(traceIdsByEnvKey, urlStatsByEnvKey) {
  return Object.entries(traceIdsByEnvKey || {})
    .flatMap(([rk]) => {
      const [region, env] = rk.split("/", 2);
      const urlStats = urlStatsByEnvKey?.[rk] || new Map();
      return [...urlStats.entries()].flatMap(([url, stat]) => {
        const messageEntries = stat?.messageStats instanceof Map
          ? [...stat.messageStats.entries()]
          : [];
        if (messageEntries.length === 0) {
          return [{
            region,
            env,
            url,
            request500Count: Number(stat?.request500Count || 0),
            traceIdCount: Number(stat?.traceIds?.size || 0),
            recoveryStatus: String(stat?.recoveryStatus || "unknown"),
            uniqueErrorMessage: "N/A",
          }];
        }
        return messageEntries.map(([uniqueErrorMessage, bucket]) => ({
          region,
          env,
          url,
          request500Count: Number(bucket?.request500Count || 0),
          traceIdCount: Number(bucket?.traceIds?.size || 0),
          recoveryStatus: String(stat?.recoveryStatus || "unknown"),
          uniqueErrorMessage,
        }));
      });
    })
    .sort(
      (a, b) =>
        a.region.localeCompare(b.region) ||
        a.env.localeCompare(b.env) ||
        b.request500Count - a.request500Count ||
        a.url.localeCompare(b.url) ||
        a.uniqueErrorMessage.localeCompare(b.uniqueErrorMessage),
    );
}

function sumRequest500ByEnv(rows, region, env) {
  let sum = 0;
  for (const row of rows || []) {
    if (row?.region === region && row?.env === env) {
      sum += Number(row?.request500Count || 0);
    }
  }
  return sum;
}

function pickAssignedMessage(urlScopedMessages, traceLevelMessages) {
  const urlMsgs = Array.isArray(urlScopedMessages) ? urlScopedMessages : [];
  if (urlMsgs.length > 0) return String(urlMsgs[0] || "N/A");
  const traceMsgs = Array.isArray(traceLevelMessages) ? traceLevelMessages : [];
  if (traceMsgs.length > 0) return String(traceMsgs[0] || "N/A");
  return "N/A";
}

async function main() {
  // Grafana is often hosted under a subpath (e.g. /grafana). We derive it from the current page.
  const GRAFANA_BASE = getGrafanaBasePath();
  const gf = (p) => `${GRAFANA_BASE}${p}`;

  // Mimir query: find envs that had HTTP 500s (processed requests metric)
  const MIMIR_EXPR =
    'sum by (prd_env, path) (rate(application_processed_requests_total{prd_fleet="faaas-prod", job="authz-management", statuscode=~"500"}[5m])) > 0';

  const mimirUidForRegion = (r) => `mimir-${r}-1-fa`;
  const lokiUidForRegion = (r) => `loki-${r}-1-fa`;
  const envKey = (region, env) => `${region}/${env}`;

  // -------------------------
  // RUN STATUS / SUMMARY
  // -------------------------
  const runStartedAt = Date.now();
  const summary = {
    regionsTotal: REGIONS.length,
    regionsProcessed: 0,
    regionsSkippedMimir: 0,
    envsTotalFromMimir: 0,
    envsProcessed: 0,
    lokiTraceQueryFailures: 0,
    lokiTraceContextFailures: 0,
    lokiRecoveryQueryFailures: 0,
    fatalError: null,
  };

  // Collect the unique env list across all regions (from Mimir discovery).
  // Printed at the very end in the requested JSON-array format.
  const allEnvs = new Set();

  // -------------------------
  // TIME WINDOW HELPERS
  // -------------------------
  function parseUtcDateTimeToMs(s) {
    // Accept "YYYY-MM-DD HH:mm:ss" (or "YYYY-MM-DDTHH:mm:ss"), interpret as UTC.
    const iso = String(s).trim().replace(" ", "T") + "Z";
    const ms = Date.parse(iso);
    if (!Number.isFinite(ms)) throw new Error(`Invalid UTC datetime: "${s}" (expected "YYYY-MM-DD HH:mm:ss")`);
    return ms;
  }

  const START_MS = parseUtcDateTimeToMs(START_TIME_UTC);
  const END_MS = parseUtcDateTimeToMs(END_TIME_UTC);

  if (END_MS < START_MS) throw new Error(`END_TIME_UTC must be >= START_TIME_UTC (start=${START_TIME_UTC}, end=${END_TIME_UTC})`);

  const START_SEC = Math.floor(START_MS / 1000);
  const END_SEC = Math.floor(END_MS / 1000);
  const START_NS = BigInt(START_MS) * 1000000n;
  const END_NS = BigInt(END_MS) * 1000000n;

  console.log(
    `[START] script started at ${new Date(runStartedAt).toISOString()} | regions=${summary.regionsTotal}\n` +
    `Query time window (UTC): ${START_TIME_UTC}  ->  ${END_TIME_UTC}`
  );

  // -------------------------
  // FILENAME HELPERS (meaningful CSV names)
  // -------------------------
  function pad2(n) { return String(n).padStart(2, "0"); }

  // Safe for filenames across OSes
  function slug(s) {
    return String(s ?? "")
      .trim()
      .replace(/[^\w.-]+/g, "_")
      .replace(/_+/g, "_")
      .replace(/^_+|_+$/g, "");
  }

  function formatUtcStamp(d = new Date()) {
    return `${d.getUTCFullYear()}${pad2(d.getUTCMonth() + 1)}${pad2(d.getUTCDate())}T` +
      `${pad2(d.getUTCHours())}${pad2(d.getUTCMinutes())}${pad2(d.getUTCSeconds())}Z`;
  }

  function buildCsvName(kind, {
    startedAtMs,
    regions,
    envCount,
    extraTag,
  } = {}) {
    const stamp = formatUtcStamp(new Date(startedAtMs || Date.now()));
    const regionTag = `regions${regions?.length ?? 0}`;
    const envTag = (typeof envCount === "number") ? `envs${envCount}` : null;

    // Include a short time-window tag (UTC) to make the file self-describing.
    const winTag = `utc_${START_TIME_UTC.replace(/[-:\s]/g, "")}_to_${END_TIME_UTC.replace(/[-:\s]/g, "")}`;

    const parts = [
      "http500",
      kind, // summary_by_env | error_by_message
      extraTag ? slug(extraTag) : null,
      winTag,
      regionTag,
      envTag,
      stamp,
    ].filter(Boolean);

    return `${parts.join("_")}.csv`;
  }

  // -------------------------
  // CSV + SAVE PANEL
  // -------------------------
  function rowsToCsv(rows) {
    rows = Array.isArray(rows) ? rows : [];
    const colSet = new Set();
    for (const r of rows) for (const k of Object.keys(r || {})) colSet.add(k);
    const cols = [...colSet];
    const esc = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    return [
      cols.join(","),
      ...rows.map((r) => cols.map((c) => esc(r?.[c])).join(",")),
    ].join("\n");
  }

  function detectFileMetaByName(name) {
    const lower = String(name || "").toLowerCase();
    if (lower.endsWith(".csv")) {
      return {
        mimeType: "text/csv;charset=utf-8;",
        pickerTypes: [{ description: "CSV File", accept: { "text/csv": [".csv"] } }],
      };
    }
    return {
      mimeType: "text/plain;charset=utf-8;",
      pickerTypes: [{ description: "Text File", accept: { "text/plain": [".txt", ".log"] } }],
    };
  }

  async function saveFileContent({ suggestedName, content }) {
    const meta = detectFileMetaByName(suggestedName);
    if (typeof window !== "undefined" && typeof window.showSaveFilePicker === "function") {
      const fileHandle = await window.showSaveFilePicker({
        suggestedName,
        types: meta.pickerTypes,
      });
      const writable = await fileHandle.createWritable();
      await writable.write(String(content ?? ""));
      await writable.close();
      return;
    }

    const blob = new Blob([String(content ?? "")], { type: meta.mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = suggestedName;
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
  }

  function showCsvSavePanel(files) {
    if (typeof document === "undefined") return;
    const panelId = "http500-csv-save-panel";
    const old = document.getElementById(panelId);
    if (old) old.remove();

    const panel = document.createElement("div");
    panel.id = panelId;
    panel.style.position = "fixed";
    panel.style.right = "16px";
    panel.style.bottom = "16px";
    panel.style.zIndex = "2147483647";
    panel.style.background = "#fff";
    panel.style.border = "1px solid #666";
    panel.style.borderRadius = "10px";
    panel.style.padding = "10px";
    panel.style.maxWidth = "360px";
    panel.style.maxHeight = "70vh";
    panel.style.overflow = "auto";

    const title = document.createElement("div");
    title.textContent = "HTTP500 Exports";
    title.style.fontWeight = "600";
    title.style.marginBottom = "8px";
    panel.appendChild(title);

    files.forEach((f, idx) => {
      const btn = document.createElement("button");
      btn.textContent = `Save ${f.suggestedName}`;
      btn.style.display = "block";
      btn.style.width = "100%";
      btn.style.marginBottom = idx === files.length - 1 ? "0" : "6px";
      btn.style.padding = "8px 10px";
      btn.style.border = "1px solid #666";
      btn.style.borderRadius = "6px";
      btn.style.background = "#fff";
      btn.style.cursor = "pointer";
      btn.addEventListener("click", async () => {
        try {
          await saveFileContent(f);
        } catch (e) {
          console.error(`Failed saving ${f.suggestedName}:`, e);
        }
      });
      panel.appendChild(btn);
    });

    const closeBtn = document.createElement("button");
    closeBtn.textContent = "Close";
    closeBtn.style.display = "block";
    closeBtn.style.width = "100%";
    closeBtn.style.marginTop = "8px";
    closeBtn.style.padding = "8px 10px";
    closeBtn.style.border = "1px solid #666";
    closeBtn.style.borderRadius = "6px";
    closeBtn.style.background = "#f7f7f7";
    closeBtn.style.cursor = "pointer";
    closeBtn.addEventListener("click", () => panel.remove());
    panel.appendChild(closeBtn);

    document.body.appendChild(panel);
    console.info("Export save panel opened. Use buttons to save each file.");
  }

  // -------------------------
  // HELPERS
  // -------------------------
  function normalizeWs(s) {
    return String(s || "")
      .replace(/\n|\r|\t/g, " ")
      .replace(/\s+/g, " ")
      .trim();
  }

  function extractTraceIds(line) {
    const out = new Set();
    const s = String(line || "");

    // Primary: parse JSON and check common fields
    try {
      const obj = JSON.parse(s);
      for (const k of ["traceId", "traceID", "trace_id", "requestTraceId", "opcRequestId"]) {
        if (typeof obj?.[k] === "string" && obj[k].trim()) out.add(obj[k].trim());
      }
    } catch (_) { }

    // Fallback: regex extractions
    for (const re of [
      /"traceId"\s*:\s*"([^"]+)"/g,
      /"traceID"\s*:\s*"([^"]+)"/g,
      /"trace_id"\s*:\s*"([^"]+)"/g,
      /\btraceId=([A-Za-z0-9\-_:./]+)/g,
      /\btraceID=([A-Za-z0-9\-_:./]+)/g,
      /\btrace_id=([A-Za-z0-9\-_:./]+)/g,
    ]) {
      let m;
      while ((m = re.exec(s)) !== null) out.add(m[1]);
    }
    return [...out];
  }

  function extractUrl(line) {
    const s = String(line || "");
    try {
      const obj = JSON.parse(s);
      if (typeof obj?.url === "string" && obj.url.trim()) return obj.url.trim();
    } catch (_) { }
    const m = s.match(/"url"\s*:\s*"([^"]+)"/);
    return m?.[1] ? String(m[1]).trim() : null;
  }

  function extractErrorRecordFromErrorLine(line) {
    let obj;
    try {
      obj = JSON.parse(String(line || ""));
    } catch {
      return null;
    }
    if (String(obj?.level || "").toLowerCase() !== "error") return null;
    if (typeof obj?.error !== "string" || !obj.error.trim()) return null;

    const errorMsg = normalizeWs(obj.error);
    if (SKIP_EXACT.has(errorMsg.toLowerCase())) return null;

    const ora = errorMsg.match(/\bORA-(\d+)\b/i);
    if (ora) {
      const code = ora[1];
      const oraDisplayMatch = errorMsg.match(
        /\b(ORA-\d+:\s*[\s\S]*?)(?:\s+for query\s*:?\s*[\s\S]*$|$)/i
      );
      const display = normalizeWs(oraDisplayMatch?.[1] || `ORA-${code}`);
      return { key: `ORA-${code}`, display };
    }
    if (obj?.errorCode) {
      return { key: `CODE-${String(obj.errorCode).trim().toLowerCase()}`, display: errorMsg };
    }
    return { key: `MSG-${errorMsg.toLowerCase()}`, display: errorMsg };
  }

  function escapeRegexLiteral(s) {
    return String(s || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  function pruneContainingLongerMessages(messages) {
    const normalized = messages
      .map((m) => ({ raw: m, n: normalizeWs(m).toLowerCase() }))
      .filter((x) => x.n && !SKIP_EXACT.has(x.n));

    const keep = normalized.filter((a, i) => {
      return !normalized.some((b, j) => {
        if (i === j) return false;
        if (b.n.length >= a.n.length) return false;
        return a.n.includes(b.n);
      });
    });

    return [...new Set(keep.map((x) => x.raw))].sort();
  }

  // -------------------------
  // MIMIR (Prometheus API) query for env list (envs with HTTP 500s)
  // -------------------------
  async function getEnvListFromMimirForRegion(region) {
    const mimirUid = mimirUidForRegion(region);

    // Use the configured absolute window for Mimir as well.
    const endSec = END_SEC;
    const startSec = START_SEC;

    const candidatePaths = [
      gf(`/api/datasources/proxy/uid/${mimirUid}/api/v1/query_range`),
      gf(`/api/datasources/proxy/uid/${mimirUid}/prometheus/api/v1/query_range`),
    ];
    let lastErr = null;

    for (const path of candidatePaths) {
      const qs = new URLSearchParams({
        query: MIMIR_EXPR,
        start: String(startSec),
        end: String(endSec),
        step: STEP_SEC,
      }).toString();

      try {
        const resp = await fetch(`${path}?${qs}`, { credentials: "include" });
        if (!resp.ok) {
          lastErr = new Error(`HTTP ${resp.status} for ${path} (region=${region})`);
          continue;
        }
        const json = await resp.json();
        const result = json?.data?.result || [];
        return [...new Set(result.map((r) => r?.metric?.prd_env).filter(Boolean))].sort();
      } catch (e) {
        lastErr = e;
      }
    }

    throw lastErr || new Error(`All Mimir endpoints failed (region=${region})`);
  }

  // -------------------------
  // LOKI query + base path resolver (cache per datasource UID)
  // -------------------------
  const lokiBaseCache = new Map(); // lokiUid -> basePath

  async function resolveLokiBasePath(lokiUid) {
    const candidates = [
      gf(`/api/datasources/proxy/uid/${lokiUid}/loki/api/v1/labels`),
      gf(`/api/datasources/proxy/uid/${lokiUid}/api/v1/labels`),
    ];
    let last = null;

    for (const url of candidates) {
      try {
        const r = await fetch(url, { credentials: "include" });
        if (r.ok) return url.replace(/\/api\/v1\/labels$/, "");
        last = new Error(`HTTP ${r.status} for ${url}`);
      } catch (e) {
        last = e;
      }
    }

    throw last || new Error(`Unable to resolve Loki base path for uid=${lokiUid}`);
  }

  async function queryLokiForRegion(
    region,
    expr,
    {
      limit = LOKI_LIMIT,
      startNs = START_NS,
      endNs = END_NS,
      splitDepth = 0,
    } = {}
  ) {
    const sumLokiLineCount = (json) => {
      let count = 0;
      for (const stream of json?.data?.result || []) {
        count += Number(stream?.values?.length || 0);
      }
      return count;
    };

    const mergeLokiResults = (a, b) => ({
      data: {
        result: [
          ...(a?.data?.result || []),
          ...(b?.data?.result || []),
        ],
      },
    });

    const lokiUid = lokiUidForRegion(region);
    let base = lokiBaseCache.get(lokiUid);
    if (!base) {
      base = await resolveLokiBasePath(lokiUid);
      lokiBaseCache.set(lokiUid, base);
    }

    const qs = new URLSearchParams({
      query: expr,
      start: startNs.toString(),
      end: endNs.toString(),
      direction: "BACKWARD",
      limit: String(limit),
    }).toString();

    const url = `${base}/api/v1/query_range?${qs}`;
    let resp = null;
    let lastErr = null;
    for (let attempt = 0; attempt < MAX_RETRY_ATTEMPTS; attempt += 1) {
      try {
        resp = await fetch(url, { credentials: "include" });
        if (resp.ok) break;
        const retryable = shouldRetryStatus(resp.status);
        if (retryable && attempt < MAX_RETRY_ATTEMPTS - 1) {
          const delay = BASE_RETRY_DELAY_MS * Math.pow(2, attempt);
          console.warn(
            `Loki HTTP ${resp.status} region=${region}; retry=${attempt + 1}/${MAX_RETRY_ATTEMPTS} delayMs=${delay}`,
          );
          await sleep(delay);
          continue;
        }
        break;
      } catch (e) {
        lastErr = e;
        const retryable = isFailedToFetchError(e);
        if (retryable && attempt < MAX_RETRY_ATTEMPTS - 1) {
          const delay = BASE_RETRY_DELAY_MS * Math.pow(2, attempt);
          console.warn(
            `Loki fetch exception region=${region}; retry=${attempt + 1}/${MAX_RETRY_ATTEMPTS} delayMs=${delay} err=${String(
              e?.message || e,
            )}`,
          );
          await sleep(delay);
          continue;
        }
        throw e;
      }
    }
    if (!resp) throw lastErr || new Error(`Loki request failed for ${url} (region=${region})`);
    if (!resp.ok) {
      const windowNs = endNs - startNs;
      const canSplit = splitDepth < MAX_SPLIT_DEPTH && windowNs > MIN_SPLIT_WINDOW_NS;
      if (canSplit && SPLITTABLE_HTTP_STATUS.has(resp.status)) {
        const mid = (startNs + endNs) / 2n;
        console.warn(
          `HTTP ${resp.status} region=${region} split=${splitDepth}/${MAX_SPLIT_DEPTH}; splitting window ` +
          `${new Date(Number(startNs / 1000000n)).toISOString()} -> ${new Date(Number(endNs / 1000000n)).toISOString()}`
        );

        const first = await queryLokiForRegion(region, expr, {
          limit,
          startNs,
          endNs: mid,
          splitDepth: splitDepth + 1,
        });
        const second = await queryLokiForRegion(region, expr, {
          limit,
          startNs: mid + 1n,
          endNs,
          splitDepth: splitDepth + 1,
        });

        return {
          data: {
            result: [
              ...(first?.data?.result || []),
              ...(second?.data?.result || []),
            ],
          },
        };
      }
      throw new Error(`HTTP ${resp.status} for ${url} (region=${region})`);
    }
    const out = await resp.json();
    const lineCount = sumLokiLineCount(out);
    const windowNs = endNs - startNs;
    const canSplitOnLimit = splitDepth < MAX_SPLIT_DEPTH && windowNs > MIN_SPLIT_WINDOW_NS;
    const isLimitLikelyHit = lineCount >= Number(limit || 0);
    if (isLimitLikelyHit && canSplitOnLimit) {
      const mid = (startNs + endNs) / 2n;
      console.warn(
        `Loki limit-hit risk region=${region} lineCount=${lineCount} limit=${limit}; ` +
        `split=${splitDepth + 1}/${MAX_SPLIT_DEPTH} window=${new Date(Number(startNs / 1000000n)).toISOString()} -> ` +
        `${new Date(Number(endNs / 1000000n)).toISOString()}`
      );
      const first = await queryLokiForRegion(region, expr, {
        limit,
        startNs,
        endNs: mid,
        splitDepth: splitDepth + 1,
      });
      const second = await queryLokiForRegion(region, expr, {
        limit,
        startNs: mid + 1n,
        endNs,
        splitDepth: splitDepth + 1,
      });
      return mergeLokiResults(first, second);
    }
    if (isLimitLikelyHit && !canSplitOnLimit) {
      console.warn(
        `Loki limit-hit risk unsplittable region=${region} lineCount=${lineCount} limit=${limit} ` +
        `splitDepth=${splitDepth}/${MAX_SPLIT_DEPTH} windowNs=${String(windowNs)}`
      );
    }
    return out;
  }

  function buildErrorToEnvKeyTable(uniqueErrorsByEnvKey) {
    const map = new Map(); // errorMessage -> Set(region/env)
    for (const [rk, errors] of Object.entries(uniqueErrorsByEnvKey)) {
      for (const err of errors) {
        if (!map.has(err)) map.set(err, new Set());
        map.get(err).add(rk);
      }
    }
    const rows = [];
    for (const [errorMessage, set] of map.entries()) {
      const envs = [...set].sort();
      rows.push({ errorMessage, envCount: envs.length, envs: envs.join(", ") });
    }
    rows.sort((a, b) => b.envCount - a.envCount || a.errorMessage.localeCompare(b.errorMessage));
    return rows;
  }

  // -------------------------
  // RUN (SEQUENTIAL)
  // -------------------------
  const traceIdsByEnvKey = {};
  const uniqueErrorsByEnvKey = {};
  const urlStatsByEnvKey = {}; // rk -> Map(url -> { request500Count, traceIds:Set, requestCountByTraceId:Map, noTraceRequestCount:number, messageStats:Map, uniqueErrorMessages:string[], last500TsNs:number, recoveryStatus:string })
  const RECOVERY_RECENT_NOT_RECOVERED_MS = 10 * 60 * 1000; // 10 minutes

  try {
    for (const region of REGIONS) {
      summary.regionsProcessed++;
      console.log(`\n=== Region: ${region} (${summary.regionsProcessed}/${summary.regionsTotal}) ===`);

      let envList = [];
      try {
        envList = await getEnvListFromMimirForRegion(region);
        summary.envsTotalFromMimir += envList.length;

        // Capture unique env names across all regions (for final output).
        envList.forEach((e) => allEnvs.add(e));

        console.log(`envs=${envList.length}`);
      } catch (e) {
        summary.regionsSkippedMimir++;
        console.warn(`Skipping region=${region} (Mimir failed):`, e);
        continue;
      }

      // 1) Trace IDs per env (sequential)
      for (const env of envList) {
        summary.envsProcessed++;

        const expr =
          `{container=~"management",namespace="authz",prd_env="${env}"}` +
          ` != "/live" != "/ready" ` +
          ` |~ \`"requestHTTPStatusCode"\\s*:\\s*5|"responseStatusCode"\\s*:\\s*5\``;

        let json;
        try {
          json = await queryLokiForRegion(region, expr, { limit: LOKI_LIMIT });
        } catch (e) {
          summary.lokiTraceQueryFailures++;
          console.warn(`Loki trace query failed region=${region} env=${env}:`, e);
          traceIdsByEnvKey[envKey(region, env)] = [];
          uniqueErrorsByEnvKey[envKey(region, env)] = [];
          urlStatsByEnvKey[envKey(region, env)] = new Map([
            [
              "N/A",
              {
                request500Count: 0,
                traceIds: new Set(),
                requestCountByTraceId: new Map(),
                noTraceRequestCount: 0,
                messageStats: new Map(),
                uniqueErrorMessages: [],
                last500TsNs: 0,
                recoveryStatus: "unknown",
              },
            ],
          ]);
          continue;
        }

        const traceSet = new Set();
        const urlStats = new Map();
        for (const stream of json?.data?.result || []) {
          for (const [tsRaw, line] of stream.values || []) {
            const ids = extractTraceIds(line);
            for (const id of ids) traceSet.add(id);
            const u = extractUrl(line) || "N/A";
            if (!urlStats.has(u)) {
              urlStats.set(u, {
                request500Count: 0,
                traceIds: new Set(),
                requestCountByTraceId: new Map(),
                noTraceRequestCount: 0,
                messageStats: new Map(),
                uniqueErrorMessages: [],
                last500TsNs: 0,
                recoveryStatus: "unknown",
              });
            }
            const slot = urlStats.get(u);
            slot.request500Count += 1;
            for (const id of ids) slot.traceIds.add(id);
            if (ids.length > 0) {
              // Assign each request row to one primary trace so per-message request counts
              // can partition total request500Count without double counting.
              const primaryId = ids[0];
              slot.requestCountByTraceId.set(
                primaryId,
                Number(slot.requestCountByTraceId.get(primaryId) || 0) + 1,
              );
            } else {
              slot.noTraceRequestCount += 1;
            }
            const tsNum = Number(tsRaw);
            if (Number.isFinite(tsNum) && tsNum > Number(slot.last500TsNs || 0)) {
              slot.last500TsNs = tsNum;
            }
          }
        }

        if (urlStats.size === 0) {
          urlStats.set("N/A", {
            request500Count: 0,
            traceIds: new Set(traceSet),
            requestCountByTraceId: new Map(),
            noTraceRequestCount: 0,
            messageStats: new Map(),
            uniqueErrorMessages: [],
            last500TsNs: 0,
            recoveryStatus: "unknown",
          });
        }

        traceIdsByEnvKey[envKey(region, env)] = [...traceSet];
        urlStatsByEnvKey[envKey(region, env)] = urlStats;
        console.log(`region=${region} env=${env} traceIds=${traceSet.size} urls=${urlStats.size}`);

        // 2) Unique errors per env (iterate trace IDs sequentially)
        const keyToDisplay = new Map();
        const traceIdToErrorDisplays = new Map(); // traceId -> Set(display)
        for (const traceId of traceIdsByEnvKey[envKey(region, env)]) {
          const expr2 =
            `{container=~"management",namespace="authz",prd_env="${env}"}` +
            ` != "/live" != "/ready" |= "${traceId}"`;

          let json2;
          try {
            await sleep(SLEEP_MS);
            json2 = await queryLokiForRegion(region, expr2, { limit: LOKI_LIMIT });
          } catch (e) {
            summary.lokiTraceContextFailures++;
            console.warn(`Loki log query failed region=${region} env=${env} traceId=${traceId}:`, e);
            continue;
          }

          const traceKeyToDisplay = new Map();
          for (const stream of json2?.data?.result || []) {
            for (const [, line] of stream.values || []) {
              const rec = extractErrorRecordFromErrorLine(line);
              if (!rec) continue;
              const prev = keyToDisplay.get(rec.key);
              if (!prev || rec.display.length < prev.length) keyToDisplay.set(rec.key, rec.display);
              const prevTrace = traceKeyToDisplay.get(rec.key);
              if (!prevTrace || rec.display.length < prevTrace.length) {
                traceKeyToDisplay.set(rec.key, rec.display);
              }
            }
          }
          traceIdToErrorDisplays.set(traceId, new Set(traceKeyToDisplay.values()));
        }

        uniqueErrorsByEnvKey[envKey(region, env)] =
          pruneContainingLongerMessages([...keyToDisplay.values()]);

        const envUrlStats = urlStatsByEnvKey[envKey(region, env)] || new Map();
        for (const [url, stat] of envUrlStats.entries()) {
          // Strict URL scoping: message stats are computed from Loki lines
          // matched by BOTH traceID and this specific URL in this specific env+region.
          const urlExprEscaped = escapeRegexLiteral(url);
          const traceIdToAssignedMessage = new Map();
          for (const [traceId, reqCountRaw] of stat.requestCountByTraceId.entries()) {
            const reqCount = Number(reqCountRaw || 0);
            if (reqCount <= 0) continue;
            const traceMsgExpr =
              `{container=~"management",namespace="authz",prd_env="${env}"}` +
              ` != "/live" != "/ready" |= "${traceId}"` +
              ` |~ \`"url"\\s*:\\s*"${urlExprEscaped}"\``;
            let traceMsgJson;
            try {
              await sleep(SLEEP_MS);
              traceMsgJson = await queryLokiForRegion(region, traceMsgExpr, { limit: LOKI_LIMIT });
            } catch (e) {
              summary.lokiTraceContextFailures++;
              console.warn(
                `Loki URL-scoped message query failed region=${region} env=${env} url=${url} traceId=${traceId}:`,
                e,
              );
              continue;
            }
            const traceMsgKeyToDisplay = new Map();
            for (const stream of traceMsgJson?.data?.result || []) {
              for (const [, line] of stream.values || []) {
                const rec = extractErrorRecordFromErrorLine(line);
                if (!rec) continue;
                const prev = traceMsgKeyToDisplay.get(rec.key);
                if (!prev || rec.display.length < prev.length) {
                  traceMsgKeyToDisplay.set(rec.key, rec.display);
                }
              }
            }
            const traceMsgs = pruneContainingLongerMessages([...traceMsgKeyToDisplay.values()]);
            const traceLevelMsgs = pruneContainingLongerMessages(
              [...(traceIdToErrorDisplays.get(traceId) || new Set())],
            );
            const assignedMsg = pickAssignedMessage(traceMsgs, traceLevelMsgs);
            traceIdToAssignedMessage.set(traceId, assignedMsg);
          }

          const messageStats = assignRequestsToMessageBuckets({
            requestCountByTraceId: stat.requestCountByTraceId,
            noTraceRequestCount: stat.noTraceRequestCount,
            traceIdToAssignedMessage,
          });
          stat.messageStats = messageStats;
          stat.uniqueErrorMessages = [...messageStats.keys()].sort((a, b) => a.localeCompare(b));

          const last500TsNs = Number(stat.last500TsNs || 0);
          if (url === "N/A" || !Number.isFinite(last500TsNs) || last500TsNs <= 0) {
            stat.recoveryStatus = "unknown";
            continue;
          }

          const recoverExpr =
            `{container=~"management",namespace="authz",prd_env="${env}"}` +
            ` != "/live" != "/ready"` +
            ` |~ \`"requestHTTPStatusCode"\\s*:\\s*20|"responseStatusCode"\\s*:\\s*20\`` +
            ` |~ \`"url"\\s*:\\s*"${urlExprEscaped}"\``;
          const recoverStartNs = BigInt(last500TsNs);
          const recoverEndNs = BigInt(Date.now()) * 1000000n;

          try {
            const recoverJson = await queryLokiForRegion(region, recoverExpr, {
              limit: LOKI_LIMIT,
              startNs: recoverStartNs,
              endNs: recoverEndNs,
            });
            let recoverHitCount = 0;
            for (const stream of recoverJson?.data?.result || []) {
              recoverHitCount += Number(stream?.values?.length || 0);
            }
            if (recoverHitCount > 0) {
              stat.recoveryStatus = "recovered";
            } else {
              const ageMs = Date.now() - Math.floor(last500TsNs / 1e6);
              stat.recoveryStatus =
                ageMs <= RECOVERY_RECENT_NOT_RECOVERED_MS ? "not_recovered" : "unknown";
            }
          } catch (e) {
            summary.lokiRecoveryQueryFailures++;
            stat.recoveryStatus = "unknown";
            console.warn(
              `Loki recovery query failed region=${region} env=${env} url=${url}:`,
              e,
            );
          }
        }
      }
    }

    // -------------------------
    // OUTPUT TABLES
    // -------------------------
    const envTable = buildSummaryRowsByEnv(traceIdsByEnvKey, urlStatsByEnvKey);

    const errorTable = buildErrorToEnvKeyTable(uniqueErrorsByEnvKey);

    console.log(`\nEnv table rows=${envTable.length}`);
    console.log(`Error table rows=${errorTable.length}`);

    // -------------------------
    // DOWNLOADS (in-page save panel)
    // -------------------------
    const envCsvName = "management500_summary_by_env.csv";

    const errCsvName = "management500_error_by_message.csv";

    const files = [
      { suggestedName: envCsvName, content: rowsToCsv(envTable) },
      { suggestedName: errCsvName, content: rowsToCsv(errorTable) },
    ];

    showCsvSavePanel(files);

    if (ENABLE_CONSOLE_TABLE_PREVIEW) {
      console.log("\nEnv table preview (first 20 rows):");
      console.table(envTable.slice(0, 20));
      console.log("\nError table preview (first 20 rows):");
      console.table(errorTable.slice(0, 20));
    }

  } catch (e) {
    summary.fatalError = e;
    console.error("Script failed (fatal):", e);

  } finally {
    const ms = Date.now() - runStartedAt;
    const status = summary.fatalError ? "FAILED_EARLY" : "COMPLETED";
    console.log(
      `[FINISH] status=${status} elapsedMs=${ms} ` +
      `regionsTotal=${summary.regionsTotal} regionsProcessed=${summary.regionsProcessed} regionsSkippedMimir=${summary.regionsSkippedMimir} ` +
      `envsFromMimir=${summary.envsTotalFromMimir} envsProcessed=${summary.envsProcessed} ` +
      `lokiTraceQueryFailures=${summary.lokiTraceQueryFailures} lokiTraceContextFailures=${summary.lokiTraceContextFailures} ` +
      `lokiRecoveryQueryFailures=${summary.lokiRecoveryQueryFailures}`
    );
    if (summary.fatalError) console.log("[FINISH] fatalError:", summary.fatalError);

    // Print the unique env list at the end in the requested format.
    // Note: This list includes envs discovered from Mimir in regions that were successfully queried.
    if (ENABLE_ENV_LIST_JSON_PRINT) {
      const envArray = [...allEnvs].sort();
      console.log("\nEnv list (unique across all regions):");
      console.log(JSON.stringify(envArray, null, 2));
    }
  }
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    assignRequestsToMessageBuckets,
    buildSummaryRowsByEnv,
    sumRequest500ByEnv,
    pickAssignedMessage,
  };
}

if (typeof window !== "undefined") {
  main();
}
