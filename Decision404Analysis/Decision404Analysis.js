// Step 1: Find decision-service 404 activity in selected region (last 24h) from Mimir.
// Run in Grafana browser dev console.
//
// Default metric selector:
// sum by (prd_env) (rate(application_processed_requests_total{prd_fleet="faaas-prod", job="authz-decision", statuscode=~"404"}[5m])) > 0
//
// Output:
// - impacted env list (prd_env)
// - per-env summary (points > 0, max value, latest value)
// - per-env Loki 404 request log matches
// - parsed request records with required fields: url, traceID

const RUN_LOG_LINES = [];
let LOKI_QUERY_SEQ = 0;
let LAST_API_CALL_AT_MS = 0;

// Frequently changed runtime settings
const ANALYSIS_CONFIG = {
  activeRegion: "phx",
  iterateAllRegions: true,
  regionsToRun: ["phx"],
  maxParallelRegions: 4,
  maxParallelEnvs: 4,
  throttleBetweenRegionsMs: 400,
  grafanaApiMinIntervalMs: 120,
  grafanaRetryMaxAttempts: 1,
  grafanaRetryBaseDelayMs: 300,
  step1RangeStartPst: "2026-04-27T00:00:00-00:00",
  step1RangeEndPst: "2026-04-27T23:59:59-00:00",
  step3_3ReuseWindowMinutes: 10,
  step3_3CompletionExtend1Minutes: 15,
  step3_3CompletionExtend2Minutes: 30,
  step2AutoSplitOnLimit: true,
  step2SplitMaxDepth: 8,
  step2SplitMinWindowMinutes: 60,
  step2RunMetricCountOnUnsplittableLimitHit: true,
  step3_3SkipTraceLookupWhenStep2UnsplittableLimitHit: true,
  step3_3RepeatedTraceWarnThreshold: 2,
  step3_3RepeatedLinkIdentityWarnThreshold: 2,
  step3_3FastTimelineEnabled: true,
  step3_3FastTimelineMinRequestsPerHour: 100,
};

const ALL_REGIONS = [
  "af-casablanca",
  "ap-hobsonville",
  "ap-hyderabad",
  "ap-melbourne",
  "ap-mitaka",
  "ap-mumbai",
  "ap-osaka",
  "ap-pathumthani",
  "ap-samutprakan",
  "ap-silverdale",
  "ap-singapore",
  "ap-suwon",
  "ap-sydney",
  "ap-tokyo",
  "ap-westtokyo",
  "ca-montreal",
  "ca-toronto",
  "eu-amsterdam",
  "eu-frankfurt",
  "eu-milan",
  "eu-stockholm",
  "eu-zurich",
  "me-abudhabi",
  "me-alain",
  "me-alkhobar",
  "me-dubai",
  "me-ibri",
  "me-jeddah",
  "me-riyadh",
  "mx-monterrey",
  "sa-riodejaneiro",
  "sa-santiago",
  "sa-saopaulo",
  "sa-vinhedo",
  "uk-cardiff",
  "uk-london",
  "us-ashburn",
  "us-newark",
  "us-phoenix",
];

const REGION_DATASOURCE_CONFIG = {
  ashburn: {
    displayName: "Ashburn",
    mimirUid: "mimir-us-ashburn-1-fa",
    lokiUid: "loki-us-ashburn-1-fa",
  },
  phx: {
    displayName: "Phx",
    mimirUid: "mimir-us-phoenix-1-fa",
    lokiUid: "loki-us-phoenix-1-fa",
  },
};

function buildRegionConfig(regionKey) {
  const key = String(regionKey || "").trim().toLowerCase();
  if (REGION_DATASOURCE_CONFIG[key]) return REGION_DATASOURCE_CONFIG[key];
  return {
    displayName: regionKey,
    mimirUid: `mimir-${regionKey}-1-fa`,
    lokiUid: `loki-${regionKey}-1-fa`,
  };
}

let ACTIVE_REGION = ANALYSIS_CONFIG.activeRegion;

function getMaxParallelEnvs() {
  const configured = ANALYSIS_CONFIG.maxParallelEnvs ?? ANALYSIS_CONFIG.maxParallelRegions ?? 4;
  return Math.min(4, Math.max(1, Math.floor(Number(configured) || 4)));
}

// Support both latest and maintenance-2510 log signatures.
const LOG_PATTERNS = {
  cachePrepStart:
    "start loading policies, roles, role mappings for all deployments|starting to prepare decision server cache",
  runtimeCompletion:
    "completed preparing policies runtime cache|completed preparing role assignments runtime cache|updated cache for deployment '.*' with '[0-9]+' Speedle policies|updated cache for deployment '.*' with [0-9]+ Speedle Role policies",
  deploymentListDefault:
    "updating deployment list cache with default deploymentID|new default deployment added to the cache|default deployment from latest records|default deployment from existing cached list",
  deploymentListAny:
    "updating deployment list cache with default deploymentID|updating deployment list cache with deploymentID|new default deployment added to the cache|new deployment from latest DB records added to the cache|default deployment from latest records|default deployment from existing cached list",
};

function appendRunLog(step, message, details = null) {
  const ts = new Date().toISOString();
  let line = `[${ts}] [${String(step || "RUN").trim()}] ${String(message || "").trim()}`;
  if (details !== null && details !== undefined) {
    try {
      line += ` | ${typeof details === "string" ? details : JSON.stringify(details)}`;
    } catch (_) {
      line += ` | ${String(details)}`;
    }
  }
  RUN_LOG_LINES.push(line);
  console.log(line);
}

function formatNsToPst(ns) {
  const n = Number(ns);
  if (!Number.isFinite(n) || n <= 0) return null;
  const d = new Date(Math.floor(n / 1e6));
  return d.toLocaleString("en-US", {
    timeZone: "America/Los_Angeles",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    fractionalSecondDigits: 3,
    hour12: false,
  });
}

function getConfiguredStepWindowHours() {
  const startMs = new Date(ANALYSIS_CONFIG.step1RangeStartPst).getTime();
  const endMs = new Date(ANALYSIS_CONFIG.step1RangeEndPst).getTime();
  if (!Number.isFinite(startMs) || !Number.isFinite(endMs) || endMs <= startMs) return 1;
  const hours = (endMs - startMs) / (60 * 60 * 1000);
  if (!Number.isFinite(hours) || hours <= 0) return 1;
  return hours;
}

function sleepMs(ms) {
  return new Promise(resolve => setTimeout(resolve, Math.max(0, Number(ms) || 0)));
}

function resolveRegionContext(regionContext = null) {
  const region = String(regionContext || ACTIVE_REGION || "").trim();
  return {
    region,
    config: buildRegionConfig(region),
  };
}

async function mapWithConcurrency(items, maxConcurrency, worker) {
  const list = Array.isArray(items) ? items : [];
  const limit = Math.max(1, Math.floor(Number(maxConcurrency) || 1));
  const out = new Array(list.length);
  let nextIdx = 0;

  async function runWorker() {
    while (true) {
      const idx = nextIdx;
      if (idx >= list.length) return;
      nextIdx += 1;
      try {
        out[idx] = { status: "fulfilled", value: await worker(list[idx], idx) };
      } catch (e) {
        out[idx] = { status: "rejected", reason: e };
      }
    }
  }

  const workerCount = Math.min(limit, list.length);
  await Promise.all(Array.from({ length: workerCount }, () => runWorker()));
  return out;
}

function createEnvProgressTracker() {
  const regionEnvCount = new Map();
  let totalEnvCount = 0;
  let processedEnvCount = 0;

  function toInt(v) {
    const n = Number(v);
    if (!Number.isFinite(n)) return 0;
    return Math.max(0, Math.floor(n));
  }

  function calcProgress() {
    return {
      processedEnvCount,
      totalEnvCount,
      progressPct: totalEnvCount > 0 ? Number(((processedEnvCount / totalEnvCount) * 100).toFixed(2)) : 100,
    };
  }

  return {
    registerRegion(region, envCount) {
      const key = String(region || "");
      const next = toInt(envCount);
      const prev = regionEnvCount.get(key) || 0;
      if (next === prev) return calcProgress();
      regionEnvCount.set(key, next);
      totalEnvCount += next - prev;
      return calcProgress();
    },
    markEnvProcessed() {
      processedEnvCount += 1;
      return calcProgress();
    },
    getProgress() {
      return calcProgress();
    },
  };
}

function shouldLogRepeatCount(count, threshold = 2) {
  const n = Number(count);
  const min = Math.max(2, Number(threshold) || 2);
  if (!Number.isFinite(n) || n < min) return false;
  if (n === min) return true;
  return (n & (n - 1)) === 0;
}

async function throttleGrafanaApiAccess() {
  const minIntervalMs = Math.max(0, Number(ANALYSIS_CONFIG.grafanaApiMinIntervalMs || 0));
  if (minIntervalMs <= 0) return;
  const now = Date.now();
  const waitMs = minIntervalMs - (now - LAST_API_CALL_AT_MS);
  if (waitMs > 0) await sleepMs(waitMs);
  LAST_API_CALL_AT_MS = Date.now();
}

function shouldRetryGrafanaStatus(statusCode) {
  const n = Number(statusCode);
  return n === 429 || (n >= 500 && n <= 599);
}

function isFailedToFetchError(err) {
  const msg = String(err?.message || err || "").toLowerCase();
  return msg.includes("failed to fetch");
}

function shouldSplitOnGatewayStatus(statusCode) {
  const n = Number(statusCode);
  return n === 502 || n === 504;
}

async function queryMimirRange(
  expr,
  { hours = 24, stepSec = 300, startSec = null, endSec = null, regionContext = null } = {},
) {
  const { region, config } = resolveRegionContext(regionContext);
  const mimirUid = config.mimirUid;
  const actualEndSec = endSec ?? Math.floor(Date.now() / 1000);
  const actualStartSec = startSec ?? actualEndSec - hours * 60 * 60;
  const maxAttempts = Math.max(1, Number(ANALYSIS_CONFIG.grafanaRetryMaxAttempts || 1));
  const baseDelayMs = Math.max(50, Number(ANALYSIS_CONFIG.grafanaRetryBaseDelayMs || 300));

  const candidatePaths = [
    `/api/datasources/proxy/uid/${mimirUid}/api/v1/query_range`,
    `/api/datasources/proxy/uid/${mimirUid}/prometheus/api/v1/query_range`,
  ];

  let lastErr = null;
  for (const path of candidatePaths) {
    const qs = new URLSearchParams({
      query: expr,
      start: String(actualStartSec),
      end: String(actualEndSec),
      step: String(stepSec),
    }).toString();

    for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
      try {
        await throttleGrafanaApiAccess();
        const resp = await fetch(`${path}?${qs}`, { credentials: "include" });
        if (!resp.ok) {
          if (shouldRetryGrafanaStatus(resp.status) && attempt < maxAttempts - 1) {
            const delay = baseDelayMs * Math.pow(2, attempt);
            appendRunLog("MIMIR", "retrying query_range after transient status", {
              region,
              path,
              status: resp.status,
              attempt: attempt + 1,
              maxAttempts,
              delayMs: delay,
            });
            await sleepMs(delay);
            continue;
          }
          lastErr = new Error(`HTTP ${resp.status} from ${path}`);
          break;
        }
        return await resp.json();
      } catch (e) {
        const retryLimit = isFailedToFetchError(e) ? maxAttempts : 1;
        if (attempt < retryLimit - 1) {
          const delay = baseDelayMs * Math.pow(2, attempt);
          appendRunLog("MIMIR", "retrying query_range after exception", {
            region,
            path,
            attempt: attempt + 1,
            maxAttempts: retryLimit,
            delayMs: delay,
            error: String(e?.message || e),
          });
          await sleepMs(delay);
          continue;
        }
        lastErr = e;
        break;
      }
    }
  }

  throw lastErr || new Error("All Mimir endpoints failed");
}

async function queryLokiRange(
  expr,
  { hours = 24, limit = 3000, startNs = null, endNs = null, regionContext = null } = {},
) {
  const actualEndNs = endNs ?? Date.now() * 1e6;
  const actualStartNs = startNs ?? actualEndNs - hours * 60 * 60 * 1e9;
  return queryLoki(expr, {
    startNs: Math.floor(actualStartNs),
    endNs: Math.floor(actualEndNs),
    direction: "BACKWARD",
    limit,
    regionContext,
  });
}

function normalizeLokiRangeWindowNs(
  startNs,
  endNs,
  { minIntervalNs = 1e9, edgeGraceNs = 1e6 } = {},
) {
  let s = Number(startNs);
  let e = Number(endNs);
  if (!Number.isFinite(s)) s = Date.now() * 1e6 - minIntervalNs;
  if (!Number.isFinite(e)) e = s + minIntervalNs;
  s = Math.floor(s);
  e = Math.floor(e);
  const graceNs = Math.max(0, Math.floor(Number(edgeGraceNs) || 1e6));
  if (graceNs > 0) {
    s = Math.max(0, s - graceNs);
    e = e + graceNs;
  }
  const minNs = Math.max(1, Math.floor(Number(minIntervalNs) || 1e9));
  if (e < s) {
    const tmp = s;
    s = e;
    e = tmp;
  }
  if (e - s < minNs) {
    e = s + minNs;
  }
  return { startNs: s, endNs: e };
}

async function queryLoki(
  expr,
  { startNs, endNs, direction = "BACKWARD", limit = 3000, regionContext = null } = {},
) {
  const normalizedWindow = normalizeLokiRangeWindowNs(startNs, endNs, { minIntervalNs: 1e9 });
  const normalizedStartNs = normalizedWindow.startNs;
  const normalizedEndNs = normalizedWindow.endNs;
  const queryId = ++LOKI_QUERY_SEQ;
  const { region, config } = resolveRegionContext(regionContext);
  appendRunLog("LOKI", "query_range start", {
    queryId,
    region,
    direction,
    limit,
    startNs: String(normalizedStartNs),
    endNs: String(normalizedEndNs),
    startPst: formatNsToPst(normalizedStartNs),
    endPst: formatNsToPst(normalizedEndNs),
    expr: String(expr || ""),
  });

  const lokiUid = config.lokiUid;
  const MAX_SPLIT_DEPTH = 4; // 4 depth => up to 16 time chunks
  const MIN_SPLIT_WINDOW_NS = 60 * 1e9; // don't split below 1 minute window
  const MAX_ATTEMPTS = Math.max(1, Number(ANALYSIS_CONFIG.grafanaRetryMaxAttempts || 1));
  const BASE_RETRY_DELAY_MS = Math.max(50, Number(ANALYSIS_CONFIG.grafanaRetryBaseDelayMs || 300));

  const candidatePaths = [
    `/api/datasources/proxy/uid/${lokiUid}/loki/api/v1/query_range`,
    `/api/datasources/proxy/uid/${lokiUid}/api/v1/query_range`,
  ];

  function buildUrl(path, sNs, eNs) {
    const qs = new URLSearchParams({
      query: expr,
      start: String(sNs),
      end: String(eNs),
      direction,
      limit: String(limit),
    }).toString();
    return `${path}?${qs}`;
  }

  function mergeLokiResults(lhs, rhs) {
    const l = lhs?.data?.result || [];
    const r = rhs?.data?.result || [];
    return {
      data: {
        ...(lhs?.data || {}),
        result: l.concat(r),
      },
      status: lhs?.status || rhs?.status || "success",
    };
  }

  function isTooManyBytes400(bodyText) {
    const s = String(bodyText || "").toLowerCase();
    return s.includes("would read too many bytes") || s.includes("query would read too many bytes");
  }

  async function fetchPathWithSplit(path, sNs, eNs, splitDepth = 0) {
    const url = buildUrl(path, sNs, eNs);
    for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt += 1) {
      try {
        await throttleGrafanaApiAccess();
        const resp = await fetch(url, { credentials: "include" });
        if (!resp.ok) {
          let bodyText = "";
          try {
            bodyText = await resp.text();
          } catch (_) {}

          if (
            resp.status === 400 &&
            isTooManyBytes400(bodyText) &&
            splitDepth < MAX_SPLIT_DEPTH &&
            eNs - sNs > MIN_SPLIT_WINDOW_NS
          ) {
            appendRunLog("LOKI", "query_range split-on-400", {
              queryId,
              region,
              splitDepth: splitDepth + 1,
              startNs: String(sNs),
              endNs: String(eNs),
              startPst: formatNsToPst(sNs),
              endPst: formatNsToPst(eNs),
            });
            const mid = Math.floor((sNs + eNs) / 2);
            console.warn(
              `Loki split-on-400 depth=${splitDepth + 1}: ${new Date(
                sNs / 1e6,
              ).toISOString()} ~ ${new Date(eNs / 1e6).toISOString()}`,
            );
            const left = await fetchPathWithSplit(path, sNs, mid, splitDepth + 1);
            const right = await fetchPathWithSplit(path, mid + 1, eNs, splitDepth + 1);
            return mergeLokiResults(left, right);
          }

          if (
            shouldSplitOnGatewayStatus(resp.status) &&
            splitDepth < MAX_SPLIT_DEPTH &&
            eNs - sNs > MIN_SPLIT_WINDOW_NS &&
            attempt === 0
          ) {
            appendRunLog("LOKI", "query_range split-on-502-504", {
              queryId,
              region,
              status: resp.status,
              splitDepth: splitDepth + 1,
              startNs: String(sNs),
              endNs: String(eNs),
              startPst: formatNsToPst(sNs),
              endPst: formatNsToPst(eNs),
            });
            const mid = Math.floor((sNs + eNs) / 2);
            console.warn(
              `Loki split-on-${resp.status} depth=${splitDepth + 1}: ${new Date(
                sNs / 1e6,
              ).toISOString()} ~ ${new Date(eNs / 1e6).toISOString()}`,
            );
            const left = await fetchPathWithSplit(path, sNs, mid, splitDepth + 1);
            const right = await fetchPathWithSplit(path, mid + 1, eNs, splitDepth + 1);
            return mergeLokiResults(left, right);
          }

          if (shouldRetryGrafanaStatus(resp.status) && attempt < MAX_ATTEMPTS - 1) {
            const delay = BASE_RETRY_DELAY_MS * Math.pow(2, attempt);
            appendRunLog("LOKI", "query_range retry after transient status", {
              queryId,
              region,
              path,
              status: resp.status,
              attempt: attempt + 1,
              maxAttempts: MAX_ATTEMPTS,
              delayMs: delay,
            });
            await sleepMs(delay);
            continue;
          }

          const bodyHead = String(bodyText || "").slice(0, 600);
          throw new Error(`HTTP ${resp.status} from ${path}${bodyHead ? ` | body: ${bodyHead}` : ""}`);
        }
        return await resp.json();
      } catch (e) {
        const retryLimit = isFailedToFetchError(e) ? MAX_ATTEMPTS : 1;
        if (attempt < retryLimit - 1) {
          const delay = BASE_RETRY_DELAY_MS * Math.pow(2, attempt);
          appendRunLog("LOKI", "query_range retry after exception", {
            queryId,
            region,
            path,
            attempt: attempt + 1,
            maxAttempts: retryLimit,
            delayMs: delay,
            error: String(e?.message || e),
          });
          await sleepMs(delay);
          continue;
        }
        throw e;
      }
    }
  }

  let lastErr = null;
  let firstErr = null;
  for (const path of candidatePaths) {
    try {
      const out = await fetchPathWithSplit(path, normalizedStartNs, normalizedEndNs, 0);
      appendRunLog("LOKI", "query_range success", {
        queryId,
        region,
        path,
        streamCount: Number(out?.data?.result?.length || 0),
        startPst: formatNsToPst(normalizedStartNs),
        endPst: formatNsToPst(normalizedEndNs),
      });
      return out;
    } catch (e) {
      appendRunLog("LOKI", "query_range path failed", {
        queryId,
        region,
        path,
        error: String(e?.message || e),
      });
      if (!firstErr) firstErr = e;
      lastErr = e;
    }
  }

  appendRunLog("LOKI", "query_range failed", {
    queryId,
    region,
    startPst: formatNsToPst(normalizedStartNs),
    endPst: formatNsToPst(normalizedEndNs),
    error: String((firstErr || lastErr)?.message || firstErr || lastErr || "unknown"),
  });
  throw firstErr || lastErr || new Error("All Loki endpoints failed");
}

async function queryLokiInstant(expr, { timeNs, regionContext = null } = {}) {
  const { region, config } = resolveRegionContext(regionContext);
  const lokiUid = config.lokiUid;
  const MAX_ATTEMPTS = Math.max(1, Number(ANALYSIS_CONFIG.grafanaRetryMaxAttempts || 1));
  const BASE_RETRY_DELAY_MS = Math.max(50, Number(ANALYSIS_CONFIG.grafanaRetryBaseDelayMs || 300));
  const actualTimeNs = Number.isFinite(Number(timeNs)) ? Math.floor(Number(timeNs)) : Date.now() * 1e6;

  const candidatePaths = [
    `/api/datasources/proxy/uid/${lokiUid}/loki/api/v1/query`,
    `/api/datasources/proxy/uid/${lokiUid}/api/v1/query`,
  ];

  let lastErr = null;
  for (const path of candidatePaths) {
    const qs = new URLSearchParams({
      query: String(expr || ""),
      time: String(actualTimeNs),
    }).toString();
    const url = `${path}?${qs}`;

    for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt += 1) {
      try {
        appendRunLog("LOKI", "instant query start", {
          region,
          path,
          attempt: attempt + 1,
          maxAttempts: MAX_ATTEMPTS,
          timeNs: String(actualTimeNs),
          timePst: formatNsToPst(actualTimeNs),
          expr: String(expr || ""),
        });
        await throttleGrafanaApiAccess();
        const resp = await fetch(url, { credentials: "include" });
        if (!resp.ok) {
          if (shouldRetryGrafanaStatus(resp.status) && attempt < MAX_ATTEMPTS - 1) {
            const delay = BASE_RETRY_DELAY_MS * Math.pow(2, attempt);
            appendRunLog("LOKI", "instant query retry after transient status", {
              region,
              path,
              status: resp.status,
              attempt: attempt + 1,
              maxAttempts: MAX_ATTEMPTS,
              delayMs: delay,
            });
            await sleepMs(delay);
            continue;
          }
          const body = await resp.text().catch(() => "");
          throw new Error(
            `HTTP ${resp.status} from ${path}${body ? ` | body: ${String(body).slice(0, 600)}` : ""}`,
          );
        }
        const out = await resp.json();
        appendRunLog("LOKI", "instant query success", {
          region,
          path,
          timeNs: String(actualTimeNs),
          timePst: formatNsToPst(actualTimeNs),
          resultType: out?.data?.resultType || null,
          resultLength: Array.isArray(out?.data?.result) ? out.data.result.length : null,
          status: out?.status || null,
        });
        return out;
      } catch (e) {
        const retryLimit = isFailedToFetchError(e) ? MAX_ATTEMPTS : 1;
        if (attempt < retryLimit - 1) {
          const delay = BASE_RETRY_DELAY_MS * Math.pow(2, attempt);
          appendRunLog("LOKI", "instant query retry after exception", {
            region,
            path,
            attempt: attempt + 1,
            maxAttempts: retryLimit,
            delayMs: delay,
            error: String(e?.message || e),
          });
          await sleepMs(delay);
          continue;
        }
        lastErr = e;
        break;
      }
    }
  }

  throw lastErr || new Error("All Loki instant-query endpoints failed");
}

function countLokiResultLines(lokiJson) {
  let n = 0;
  for (const stream of lokiJson?.data?.result || []) {
    n += Number(stream?.values?.length || 0);
  }
  return n;
}

function collectLokiEntriesSortedAsc(lokiJson) {
  const entries = [];
  for (const stream of lokiJson?.data?.result || []) {
    for (const [tsNs, line] of stream.values || []) {
      const ts = Number(tsNs);
      if (!Number.isFinite(ts) || ts <= 0) continue;
      entries.push({
        lokiTsNs: String(tsNs),
        tsNsNum: ts,
        line: String(line || ""),
      });
    }
  }
  entries.sort((a, b) => a.tsNsNum - b.tsNsNum);
  return entries;
}

function mergeLokiEntriesSortedAsc(lhs, rhs) {
  const out = [...(lhs || []), ...(rhs || [])];
  out.sort((a, b) => Number(a?.tsNsNum || 0) - Number(b?.tsNsNum || 0));
  return out;
}

async function fetchLokiEntriesWithAutoSplitOnLimit(
  expr,
  {
    startNs,
    endNs,
    direction = "FORWARD",
    limit = 3000,
    regionContext = null,
    splitMaxDepth = 12,
    splitMinWindowMinutes = 1,
    logStep = "LOKI",
    logContext = {},
  } = {},
) {
  const minWindowNs = Math.max(
    1,
    Math.floor((Number(splitMinWindowMinutes || 1) || 1) * 60 * 1e9),
  );

  async function fetchWindow(sNs, eNs, depth = 0) {
    const json = await queryLoki(expr, {
      startNs: sNs,
      endNs: eNs,
      direction,
      limit,
      regionContext,
    });
    const lineCount = countLokiResultLines(json);
    const windowNs = Math.max(0, Number(eNs) - Number(sNs));
    const shouldSplit = lineCount >= Number(limit) && depth < splitMaxDepth && windowNs > minWindowNs;
    if (!shouldSplit) {
      return collectLokiEntriesSortedAsc(json);
    }
    const midNs = Math.floor((Number(sNs) + Number(eNs)) / 2);
    appendRunLog(logStep, "auto-split timeline query due to limit-hit risk", {
      ...logContext,
      depth: depth + 1,
      limit,
      lineCount,
      startNs: String(sNs),
      endNs: String(eNs),
      startPst: formatNsToPst(sNs),
      endPst: formatNsToPst(eNs),
      midNs: String(midNs),
      midPst: formatNsToPst(midNs),
      windowMinutes: Number((windowNs / 60e9).toFixed(3)),
    });
    const left = await fetchWindow(sNs, midNs, depth + 1);
    const right = await fetchWindow(midNs + 1, eNs, depth + 1);
    return mergeLokiEntriesSortedAsc(left, right);
  }

  return fetchWindow(Number(startNs), Number(endNs), 0);
}

function extractNumericMetricValueFromLokiInstantResponse(metricJson) {
  const data = metricJson?.data || {};
  const resultType = String(data?.resultType || "").toLowerCase();
  const result = data?.result;

  if (resultType === "scalar" && Array.isArray(result) && result.length >= 2) {
    const n = Number(result[1]);
    return Number.isFinite(n) ? n : null;
  }

  if (resultType === "vector" && Array.isArray(result) && result.length > 0) {
    const n = Number(result?.[0]?.value?.[1]);
    return Number.isFinite(n) ? n : null;
  }

  // Fallback for unexpected wrappers from proxy/plugin transforms.
  if (Array.isArray(result) && result.length > 0) {
    const first = result[0];
    if (Array.isArray(first?.value) && first.value.length >= 2) {
      const n = Number(first.value[1]);
      return Number.isFinite(n) ? n : null;
    }
  }

  return null;
}

function lineContains404Status(line) {
  const s = String(line || "");
  const obj = extractJsonObjectFromLogLine(s);
  if (obj && typeof obj === "object") {
    const req = Number(obj.requestHTTPStatusCode);
    const resp = Number(obj.responseStatusCode);
    if (req === 404 || resp === 404) return true;
  }
  return /"requestHTTPStatusCode"\s*:\s*404|"responseStatusCode"\s*:\s*404/.test(s);
}

function lineContains200Status(line) {
  const s = String(line || "");
  const obj = extractJsonObjectFromLogLine(s);
  if (obj && typeof obj === "object") {
    const req = Number(obj.requestHTTPStatusCode);
    const resp = Number(obj.responseStatusCode);
    if (req === 200 || resp === 200) return true;
  }
  return /"requestHTTPStatusCode"\s*:\s*200|"responseStatusCode"\s*:\s*200/.test(s);
}

function isLokiVolumeExceededError(err) {
  const msg = String(err?.message || err || "").toLowerCase();
  if (!msg) return false;
  return (
    msg.includes("max entries limit") ||
    msg.includes("max entries") ||
    msg.includes("limit per query exceeded") ||
    (msg.includes("limit") && msg.includes("exceed"))
  );
}

async function countDecision200LogsForRecovery(
  env,
  { startNs, endNs, regionContext = null, limit = 3000 } = {},
) {
  const expr =
    `${buildDecisionSelector(env, null)}` +
    ` != "/live" != "/ready"` +
    ` |~ \`"requestHTTPStatusCode"\\s*:\\s*200|"responseStatusCode"\\s*:\\s*200\``;

  const start = Number(startNs);
  const end = Number(endNs);
  if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) {
    return {
      count200: 0,
      usedSecondHalfAutoSplit: false,
      secondHalfWindowStartNs: null,
      secondHalfWindowEndNs: null,
      queryError: null,
      expr,
    };
  }

  try {
    const json = await queryLoki(expr, {
      startNs: start,
      endNs: end,
      direction: "FORWARD",
      limit,
      regionContext,
    });
    let count200 = 0;
    for (const stream of json?.data?.result || []) {
      for (const [, line] of stream.values || []) {
        if (lineContains200Status(line)) count200 += 1;
      }
    }
    return {
      count200,
      usedSecondHalfAutoSplit: false,
      secondHalfWindowStartNs: null,
      secondHalfWindowEndNs: null,
      queryError: null,
      expr,
    };
  } catch (e) {
    if (!isLokiVolumeExceededError(e)) throw e;
    const midNs = Math.floor((start + end) / 2);
    const secondHalfStartNs = midNs + 1;
    appendRunLog("STEP3.5", "recovery query hit volume limit; fallback to second-half auto-split", {
      env,
      startNs: String(start),
      endNs: String(end),
      startPst: formatNsToPst(start),
      endPst: formatNsToPst(end),
      secondHalfStartNs: String(secondHalfStartNs),
      secondHalfStartPst: formatNsToPst(secondHalfStartNs),
      limit,
      error: String(e?.message || e),
    });
    const entries = await fetchLokiEntriesWithAutoSplitOnLimit(expr, {
      startNs: secondHalfStartNs,
      endNs: end,
      direction: "FORWARD",
      limit,
      regionContext,
      splitMaxDepth: 12,
      splitMinWindowMinutes: 1,
      logStep: "STEP3.5",
      logContext: {
        env,
        mode: "second_half_auto_split",
      },
    });
    let count200 = 0;
    for (const rec of entries || []) {
      if (lineContains200Status(rec?.line || "")) count200 += 1;
    }
    return {
      count200,
      usedSecondHalfAutoSplit: true,
      secondHalfWindowStartNs: String(secondHalfStartNs),
      secondHalfWindowEndNs: String(end),
      queryError: String(e?.message || e),
      expr,
    };
  }
}

async function evaluateRecoveryStatusByEnv(step3ParsedByEnv, { regionContext = null } = {}) {
  const envs = Object.keys(step3ParsedByEnv || {});
  const nowNs = Math.floor(Date.now() * 1e6);
  const recoveredThresholdCount = 100;
  const recoveredThresholdWindowNs = 12 * 60 * 60 * 1e9;
  const out = {};

  await mapWithConcurrency(envs, getMaxParallelEnvs(), async env => {
    const records = step3ParsedByEnv?.[env]?.records || [];
    let last404TsNs = 0;
    for (const rec of records) {
      const ts = Number(rec?.lokiTsNs || 0);
      if (Number.isFinite(ts) && ts > last404TsNs) last404TsNs = ts;
    }
    if (!Number.isFinite(last404TsNs) || last404TsNs <= 0) {
      out[env] = {
        recoveryStatus: "not_sure",
        recoveryReason: "no_404_reference_found",
        recovery200Count: 0,
        recoveryWindowStartNs: null,
        recoveryWindowEndNs: String(nowNs),
        recoveryWindowHours: 0,
        recoveryLast404TsNs: null,
        recoveryUsedSecondHalfAutoSplit: false,
        recoverySecondHalfWindowStartNs: null,
        recoverySecondHalfWindowEndNs: null,
        recoveryQueryError: null,
      };
      return;
    }

    const startNs = Math.floor(last404TsNs + 10 * 1e9);
    const endNs = nowNs;
    const intervalNs = Math.max(0, endNs - startNs);
    const intervalHours = intervalNs / (60 * 60 * 1e9);

    let countResult = null;
    try {
      countResult = await countDecision200LogsForRecovery(env, {
        startNs,
        endNs,
        regionContext,
        limit: 3000,
      });
    } catch (e) {
      out[env] = {
        recoveryStatus: "not_sure",
        recoveryReason: "recovery_query_failed",
        recovery200Count: 0,
        recoveryWindowStartNs: String(startNs),
        recoveryWindowEndNs: String(endNs),
        recoveryWindowHours: Number(intervalHours.toFixed(3)),
        recoveryLast404TsNs: String(last404TsNs),
        recoveryUsedSecondHalfAutoSplit: false,
        recoverySecondHalfWindowStartNs: null,
        recoverySecondHalfWindowEndNs: null,
        recoveryQueryError: String(e?.message || e),
      };
      appendRunLog("STEP3.5", "recovery check failed for env", {
        env,
        startNs: String(startNs),
        endNs: String(endNs),
        error: String(e?.message || e),
      });
      return;
    }

    const count200 = Number(countResult?.count200 || 0);
    let recoveryStatus = "not_sure";
    let recoveryReason = "insufficient_evidence";
    if (count200 === 0) {
      recoveryStatus = "not_recovered";
      recoveryReason = "no_http_200_after_last_404_plus_10s";
    } else if (count200 > recoveredThresholdCount && intervalNs > recoveredThresholdWindowNs) {
      recoveryStatus = "recovered";
      recoveryReason = "http_200_count_gt_100_and_window_gt_12h";
    }

    out[env] = {
      recoveryStatus,
      recoveryReason,
      recovery200Count: count200,
      recoveryWindowStartNs: String(startNs),
      recoveryWindowEndNs: String(endNs),
      recoveryWindowHours: Number(intervalHours.toFixed(3)),
      recoveryLast404TsNs: String(last404TsNs),
      recoveryUsedSecondHalfAutoSplit: Boolean(countResult?.usedSecondHalfAutoSplit),
      recoverySecondHalfWindowStartNs: countResult?.secondHalfWindowStartNs || null,
      recoverySecondHalfWindowEndNs: countResult?.secondHalfWindowEndNs || null,
      recoveryQueryError: countResult?.queryError || null,
    };
    appendRunLog("STEP3.5", "env recovery status evaluated", {
      env,
      isRecovered: recoveryStatus === "recovered",
      recoveryStatus,
      recoveryReason,
      recovery200Count: count200,
      recoveryWindowStartNs: String(startNs),
      recoveryWindowEndNs: String(endNs),
      recoveryWindowHours: Number(intervalHours.toFixed(3)),
      recoveryLast404TsNs: String(last404TsNs),
      recoveryUsedSecondHalfAutoSplit: Boolean(countResult?.usedSecondHalfAutoSplit),
      recoverySecondHalfWindowStartNs: countResult?.secondHalfWindowStartNs || null,
      recoverySecondHalfWindowEndNs: countResult?.secondHalfWindowEndNs || null,
      recoveryQueryError: countResult?.queryError || null,
    });
  });

  return out;
}

function buildDecisionSelector(env, pod) {
  const labels = ['container=~"decision"', 'namespace="authz"', `prd_env="${env}"`];
  if (pod) labels.push(`pod="${pod}"`);
  return `{ ${labels.join(", ")} }`;
}

function filterDecision404StreamsFromLoki(rawStreams, { limit = 3000, sampleCap = 20 } = {}) {
  let matchedLineCount = 0;
  const sampleLines = [];
  const filteredStreams = [];

  for (const stream of rawStreams || []) {
    const keptValues = [];
    for (const pair of stream.values || []) {
      const line = pair?.[1];
      if (!lineContains404Status(line)) continue;
      keptValues.push(pair);
      matchedLineCount += 1;
      if (sampleLines.length < sampleCap) sampleLines.push(line);
    }
    if (keptValues.length) {
      filteredStreams.push({
        stream: stream.stream,
        values: keptValues,
      });
    }
  }

  return {
    matchedLineCount,
    streamCount: filteredStreams.length,
    streams: filteredStreams,
    sampleLines,
    isLimitLikelyHit: matchedLineCount >= limit,
  };
}

function mergeDecision404ChunkResults(lhs, rhs, sampleCap = 20) {
  const streamMap = new Map();

  for (const src of [lhs, rhs]) {
    for (const s of src?.streams || []) {
      const key = JSON.stringify(s?.stream || {});
      if (!streamMap.has(key)) {
        streamMap.set(key, {
          stream: s?.stream || {},
          values: [...(s?.values || [])],
        });
        continue;
      }
      const existing = streamMap.get(key);
      existing.values.push(...(s?.values || []));
    }
  }

  const mergedStreams = [...streamMap.values()];
  let mergedMatchedLineCount = 0;
  for (const s of mergedStreams) {
    mergedMatchedLineCount += Number(s?.values?.length || 0);
  }

  const mergedSampleLines = [...(lhs?.sampleLines || []), ...(rhs?.sampleLines || [])].slice(0, sampleCap);

  return {
    streams: mergedStreams,
    streamCount: mergedStreams.length,
    matchedLineCount: mergedMatchedLineCount,
    sampleLines: mergedSampleLines,
    chunksQueried: Number(lhs?.chunksQueried || 0) + Number(rhs?.chunksQueried || 0),
    splitCount: Number(lhs?.splitCount || 0) + Number(rhs?.splitCount || 0),
    maxSplitDepthUsed: Math.max(
      Number(lhs?.maxSplitDepthUsed || 0),
      Number(rhs?.maxSplitDepthUsed || 0),
    ),
    unsplittableLimitHitCount:
      Number(lhs?.unsplittableLimitHitCount || 0) + Number(rhs?.unsplittableLimitHitCount || 0),
    limitHitLeafCount:
      Number(lhs?.limitHitLeafCount || 0) + Number(rhs?.limitHitLeafCount || 0),
    metricCountQueryAttempts:
      Number(lhs?.metricCountQueryAttempts || 0) + Number(rhs?.metricCountQueryAttempts || 0),
    metricCountQuerySuccessCount:
      Number(lhs?.metricCountQuerySuccessCount || 0) + Number(rhs?.metricCountQuerySuccessCount || 0),
    metricCount404EstimateSum:
      Number(lhs?.metricCount404EstimateSum || 0) + Number(rhs?.metricCount404EstimateSum || 0),
    isLimitLikelyHit:
      Boolean(lhs?.isLimitLikelyHit) || Boolean(rhs?.isLimitLikelyHit),
  };
}

async function collectDecision404LogsForEnvWithAutoSplit(
  env,
  expr,
  { hours = 24, limit = 3000, startNs = null, endNs = null, regionContext = null } = {},
) {
  const actualEndNs = endNs ?? Date.now() * 1e6;
  const actualStartNs = startNs ?? actualEndNs - hours * 60 * 60 * 1e9;
  const maxSplitDepth = Math.max(0, Number(ANALYSIS_CONFIG.step2SplitMaxDepth || 0));
  const minSplitWindowNs = Math.max(
    1,
    Math.floor((Number(ANALYSIS_CONFIG.step2SplitMinWindowMinutes || 5) || 5) * 60 * 1e9),
  );
  const autoSplitEnabled = ANALYSIS_CONFIG.step2AutoSplitOnLimit !== false;
  const metricCountEnabled = ANALYSIS_CONFIG.step2RunMetricCountOnUnsplittableLimitHit !== false;

  async function fetchWindow(sNs, eNs, depth = 0) {
    const lokiJson = await queryLokiRange(expr, {
      hours,
      limit,
      startNs: sNs,
      endNs: eNs,
      regionContext,
    });
    const filtered = filterDecision404StreamsFromLoki(lokiJson?.data?.result || [], { limit });
    const windowNs = Math.max(0, Number(eNs) - Number(sNs));
    const canSplit = depth < maxSplitDepth && windowNs > minSplitWindowNs;
    const shouldSplit = autoSplitEnabled && filtered.isLimitLikelyHit && canSplit;

    if (shouldSplit) {
      const midNs = Math.floor((Number(sNs) + Number(eNs)) / 2);
      appendRunLog("STEP2", "split env query window due to limit-hit risk", {
        env,
        depth: depth + 1,
        limit,
        startNs: String(sNs),
        endNs: String(eNs),
        startPst: formatNsToPst(sNs),
        endPst: formatNsToPst(eNs),
        midNs: String(midNs),
        midPst: formatNsToPst(midNs),
        windowMinutes: Number((windowNs / 60e9).toFixed(3)),
      });
      const left = await fetchWindow(sNs, midNs, depth + 1);
      const right = await fetchWindow(midNs + 1, eNs, depth + 1);
      const merged = mergeDecision404ChunkResults(left, right);
      merged.splitCount += 1;
      merged.maxSplitDepthUsed = Math.max(merged.maxSplitDepthUsed, depth + 1);
      return merged;
    }

    const unsplittableLimitHit = filtered.isLimitLikelyHit && !shouldSplit;
    let metricCount404Estimate = null;
    let metricCountQueryAttempted = false;
    let metricCountQuerySucceeded = false;
    if (unsplittableLimitHit) {
      appendRunLog("STEP2", "warning: potential missing log entries due to step2 limit-hit leaf", {
        env,
        depth,
        limit,
        startNs: String(sNs),
        endNs: String(eNs),
        startPst: formatNsToPst(sNs),
        endPst: formatNsToPst(eNs),
        windowMinutes: Number((windowNs / 60e9).toFixed(3)),
        maxSplitDepth,
        minSplitWindowMinutes: Number(ANALYSIS_CONFIG.step2SplitMinWindowMinutes || 5),
      });
      console.warn(
        `STEP2 warning env=${env}: potential missing log entries (matchedLineCount>=${limit}) in unsplittable leaf window ${formatNsToPst(
          sNs,
        )} ~ ${formatNsToPst(eNs)}.`,
      );

      if (metricCountEnabled) {
        metricCountQueryAttempted = true;
        const windowSeconds = Math.max(1, Math.ceil(windowNs / 1e9));
        const metricExpr = `sum(count_over_time(${expr} [${windowSeconds}s]))`;
        try {
          const metricJson = await queryLokiInstant(metricExpr, { timeNs: eNs, regionContext });
          const n = extractNumericMetricValueFromLokiInstantResponse(metricJson);
          if (Number.isFinite(n)) {
            metricCount404Estimate = n;
            metricCountQuerySucceeded = true;
          }
          const metricData = metricJson?.data || {};
          const metricResult = metricData?.result;
          let metricResultSample = null;
          if (Array.isArray(metricResult) && metricResult.length > 0) {
            metricResultSample = metricResult[0];
          } else if (metricResult !== undefined) {
            metricResultSample = metricResult;
          }
          appendRunLog("STEP2", "metric fallback query for unsplittable limit-hit leaf completed", {
            env,
            depth,
            startNs: String(sNs),
            endNs: String(eNs),
            startPst: formatNsToPst(sNs),
            endPst: formatNsToPst(eNs),
            windowSeconds,
            matchedLineCountAtLimitQuery: filtered.matchedLineCount,
            limit,
            metricCount404Estimate,
            metricCountQuerySucceeded,
            metricResultType: metricData?.resultType || null,
            metricResultLength: Array.isArray(metricResult) ? metricResult.length : null,
            metricResultSample,
            metricExpr,
          });
          if (!metricCountQuerySucceeded) {
            appendRunLog("STEP2", "warning: metric fallback query returned unparsable value", {
              env,
              depth,
              startNs: String(sNs),
              endNs: String(eNs),
              metricExpr,
              metricResultType: metricData?.resultType || null,
              metricResultLength: Array.isArray(metricResult) ? metricResult.length : null,
              metricResultSample,
            });
          }
        } catch (metricErr) {
          appendRunLog("STEP2", "metric fallback query for unsplittable limit-hit leaf failed", {
            env,
            depth,
            startNs: String(sNs),
            endNs: String(eNs),
            startPst: formatNsToPst(sNs),
            endPst: formatNsToPst(eNs),
            error: String(metricErr?.message || metricErr),
          });
        }
      }
    }

    return {
      ...filtered,
      chunksQueried: 1,
      splitCount: 0,
      maxSplitDepthUsed: depth,
      unsplittableLimitHitCount: unsplittableLimitHit ? 1 : 0,
      limitHitLeafCount: filtered.isLimitLikelyHit ? 1 : 0,
      metricCountQueryAttempts: metricCountQueryAttempted ? 1 : 0,
      metricCountQuerySuccessCount: metricCountQuerySucceeded ? 1 : 0,
      metricCount404EstimateSum: Number(metricCount404Estimate || 0),
    };
  }

  return fetchWindow(Math.floor(actualStartNs), Math.floor(actualEndNs), 0);
}

function summarizeDecision404Series(mimirJson) {
  const result = mimirJson?.data?.result || [];
  const byEnv = {};

  for (const ts of result) {
    const env = ts?.metric?.prd_env || "unknown";
    const values = ts?.values || [];

    let positivePoints = 0;
    let maxValue = 0;
    let latestValue = 0;

    for (const [, v] of values) {
      const n = Number(v);
      if (!Number.isFinite(n)) continue;
      if (n > 0) positivePoints += 1;
      if (n > maxValue) maxValue = n;
      latestValue = n;
    }

    if (!byEnv[env]) {
      byEnv[env] = { positivePoints: 0, maxValue: 0, latestValue: 0, seriesCount: 0 };
    }
    byEnv[env].positivePoints += positivePoints;
    byEnv[env].maxValue = Math.max(byEnv[env].maxValue, maxValue);
    byEnv[env].latestValue = latestValue;
    byEnv[env].seriesCount += 1;
  }

  const impactedEnvs = Object.entries(byEnv)
    .filter(([, s]) => s.positivePoints > 0 || s.maxValue > 0 || s.latestValue > 0)
    .map(([env]) => env)
    .sort();

  return { impactedEnvs, byEnv };
}

async function saveTextViaManualButton({ text, suggestedName, buttonId, buttonText }) {
  return new Promise((resolve, reject) => {
    if (typeof document === "undefined" || typeof window === "undefined") {
      reject(new Error("Browser save is unavailable."));
      return;
    }

    const existing = document.getElementById(buttonId);
    if (existing) existing.remove();

    const btn = document.createElement("button");
    btn.id = buttonId;
    btn.textContent = buttonText;
    btn.style.position = "fixed";
    btn.style.right = "16px";
    btn.style.bottom = "16px";
    btn.style.zIndex = "2147483647";
    btn.style.padding = "10px 14px";
    btn.style.border = "1px solid #666";
    btn.style.borderRadius = "8px";
    btn.style.background = "#fff";
    btn.style.cursor = "pointer";

    btn.addEventListener(
      "click",
      async () => {
        try {
          const fileHandle = await window.showSaveFilePicker({
            suggestedName,
            types: [{ description: "Text File", accept: { "text/plain": [".txt"] } }],
          });
          const writable = await fileHandle.createWritable();
          await writable.write(text);
          await writable.close();
          btn.remove();
          resolve(true);
        } catch (e) {
          console.error("Manual save failed:", e?.message || String(e));
          reject(e);
        }
      },
      { once: true },
    );

    document.body.appendChild(btn);
    console.info(`Click '${buttonText}' button (bottom-right) to save ${suggestedName}.`);
  });
}

async function saveEnvListTxtFromStep1(envList, suggestedName = "EnvList.txt") {
  const text = [...new Set((envList || []).filter(Boolean))].join("\n") + "\n";

  if (typeof window !== "undefined" && typeof window.showSaveFilePicker === "function") {
    try {
      const fileHandle = await window.showSaveFilePicker({
        suggestedName,
        types: [{ description: "Text File", accept: { "text/plain": [".txt"] } }],
      });
      const writable = await fileHandle.createWritable();
      await writable.write(text);
      await writable.close();
      return { saved: true, mode: "showSaveFilePicker" };
    } catch (e) {
      const msg = e?.message || String(e);
      if (!msg.includes("user gesture")) {
        throw e;
      }
      await saveTextViaManualButton({
        text,
        suggestedName,
        buttonId: "decision404-save-envlist-btn",
        buttonText: "Save EnvList.txt",
      });
      return { saved: true, mode: "manual-button" };
    }
  }

  const blob = new Blob([text], { type: "text/plain;charset=utf-8;" });
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
  return { saved: true, mode: "download-link" };
}

function escapeCsvValue(value) {
  const s = String(value ?? "");
  if (s.includes('"') || s.includes(",") || s.includes("\n")) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

function normalizeCsvCell(value) {
  if (value === null || value === undefined) return "";
  if (Array.isArray(value) || (typeof value === "object" && value !== null)) {
    try {
      return JSON.stringify(value);
    } catch (_) {
      return String(value);
    }
  }
  return String(value);
}

function rowsToCsv(rows) {
  const list = Array.isArray(rows) ? rows : [];
  if (!list.length) return "no_data\n";

  const headers = [];
  const seen = new Set();
  for (const row of list) {
    for (const key of Object.keys(row || {})) {
      if (!seen.has(key)) {
        seen.add(key);
        headers.push(key);
      }
    }
  }

  const lines = [headers.map(escapeCsvValue).join(",")];
  for (const row of list) {
    const vals = headers.map(h => escapeCsvValue(normalizeCsvCell(row?.[h])));
    lines.push(vals.join(","));
  }
  return lines.join("\n") + "\n";
}

function mapToRows(mapObj, keyName = "key") {
  const rows = [];
  for (const [k, v] of Object.entries(mapObj || {})) {
    if (v && typeof v === "object" && !Array.isArray(v)) {
      rows.push({ [keyName]: k, ...v });
    } else {
      rows.push({ [keyName]: k, value: v });
    }
  }
  return rows;
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
    pickerTypes: [{ description: "Text File", accept: { "text/plain": [".log", ".txt"] } }],
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
  const panelId = "decision404-csv-save-panel";
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
  title.textContent = "Decision404 Exports";
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

async function collectDecision404LogsByEnv(
  envList,
  { hours = 24, limit = 3000, startNs = null, endNs = null, regionContext = null } = {},
) {
  const byEnv = {};
  const maxParallelEnvs = getMaxParallelEnvs();

  await mapWithConcurrency(envList, maxParallelEnvs, async env => {
    const expr =
      `${buildDecisionSelector(env, null)}` +
      ` != "/live" != "/ready"` +
      ` |~ \`"requestHTTPStatusCode"\\s*:\\s*404|"responseStatusCode"\\s*:\\s*404\``;

    try {
      const splitResult = await collectDecision404LogsForEnvWithAutoSplit(env, expr, {
        hours,
        limit,
        startNs,
        endNs,
        regionContext,
      });
      const matchedLineCount = Number(splitResult?.matchedLineCount || 0);
      const streamCount = Number(splitResult?.streamCount || 0);
      const filteredStreams = splitResult?.streams || [];
      const sampleLines = splitResult?.sampleLines || [];
      const isLimitLikelyHit = Boolean(splitResult?.isLimitLikelyHit);
      const splitMeta = {
        chunksQueried: Number(splitResult?.chunksQueried || 0),
        splitCount: Number(splitResult?.splitCount || 0),
        maxSplitDepthUsed: Number(splitResult?.maxSplitDepthUsed || 0),
        limitHitLeafCount: Number(splitResult?.limitHitLeafCount || 0),
        unsplittableLimitHitCount: Number(splitResult?.unsplittableLimitHitCount || 0),
        metricCountQueryAttempts: Number(splitResult?.metricCountQueryAttempts || 0),
        metricCountQuerySuccessCount: Number(splitResult?.metricCountQuerySuccessCount || 0),
        metricCount404EstimateSum: Number(splitResult?.metricCount404EstimateSum || 0),
      };

      byEnv[env] = {
        lokiQuery: expr,
        matchedLineCount,
        streamCount,
        streams: filteredStreams,
        sampleLines,
        isLimitLikelyHit,
        splitMeta,
        error: null,
      };

      console.log(
        `Step 2 env=${env} matchedLineCount=${matchedLineCount} streamCount=${streamCount} limit=${limit} chunks=${splitMeta.chunksQueried} splitDepth=${splitMeta.maxSplitDepthUsed} limitHitLeaves=${splitMeta.limitHitLeafCount}`,
      );
      appendRunLog("STEP2", "env 404 collection completed", {
        env,
        matchedLineCount,
        streamCount,
        limit,
        chunksQueried: splitMeta.chunksQueried,
        splitCount: splitMeta.splitCount,
        maxSplitDepthUsed: splitMeta.maxSplitDepthUsed,
        limitHitLeafCount: splitMeta.limitHitLeafCount,
        unsplittableLimitHitCount: splitMeta.unsplittableLimitHitCount,
        metricCountQueryAttempts: splitMeta.metricCountQueryAttempts,
        metricCountQuerySuccessCount: splitMeta.metricCountQuerySuccessCount,
        metricCount404EstimateSum: splitMeta.metricCount404EstimateSum,
        isLimitLikelyHit,
      });
    } catch (e) {
      byEnv[env] = {
        lokiQuery: expr,
        matchedLineCount: 0,
        streamCount: 0,
        streams: [],
        sampleLines: [],
        isLimitLikelyHit: false,
        splitMeta: {
          chunksQueried: 0,
          splitCount: 0,
          maxSplitDepthUsed: 0,
          limitHitLeafCount: 0,
          unsplittableLimitHitCount: 0,
          metricCountQueryAttempts: 0,
          metricCountQuerySuccessCount: 0,
          metricCount404EstimateSum: 0,
        },
        error: String(e?.message || e),
      };
      console.error(`Step 2 env=${env} failed:`, e);
    }
  });

  return byEnv;
}

function extractJsonObjectFromLogLine(line) {
  const s = String(line || "").trim();
  if (!s) return null;

  // Most logs have a prefix like: "2026-...info{...json...}"
  const start = s.indexOf("{");
  const end = s.lastIndexOf("}");
  if (start >= 0 && end > start) {
    const candidate = s.slice(start, end + 1);
    try {
      return JSON.parse(candidate);
    } catch (_) {}
  }

  // Fallback: line itself might already be JSON.
  try {
    return JSON.parse(s);
  } catch (_) {
    return null;
  }
}

function parseElapsedTimeMs(v) {
  const s = String(v || "").trim();
  if (!s) return null;

  // Fast path: single-unit values like "3.87s", "120ms", "900us".
  const single = s.match(/^([0-9]*\.?[0-9]+)\s*(ns|us|µs|ms|s|m|h)$/i);
  if (single) {
    const n = Number(single[1]);
    if (!Number.isFinite(n)) return null;
    const unit = single[2].toLowerCase();
    if (unit === "ns") return n / 1e6;
    if (unit === "us" || unit === "µs") return n / 1e3;
    if (unit === "ms") return n;
    if (unit === "s") return n * 1000;
    if (unit === "m") return n * 60 * 1000;
    if (unit === "h") return n * 60 * 60 * 1000;
    return null;
  }

  // Go-style composite durations like "4m32.295997305s", "1h2m3.5s".
  // Parse ordered `<number><unit>` tokens and sum them.
  const tokenRe = /([0-9]*\.?[0-9]+)\s*(ns|us|µs|ms|s|m|h)/gi;
  let totalMs = 0;
  let tokenCount = 0;
  let m;
  while ((m = tokenRe.exec(s)) !== null) {
    tokenCount += 1;
    const n = Number(m[1]);
    if (!Number.isFinite(n)) return null;
    const unit = String(m[2]).toLowerCase();
    if (unit === "ns") totalMs += n / 1e6;
    else if (unit === "us" || unit === "µs") totalMs += n / 1e3;
    else if (unit === "ms") totalMs += n;
    else if (unit === "s") totalMs += n * 1000;
    else if (unit === "m") totalMs += n * 60 * 1000;
    else if (unit === "h") totalMs += n * 60 * 60 * 1000;
    else return null;
  }

  if (tokenCount === 0) return null;
  const compact = s.replace(/\s+/g, "");
  const matchedCompactLen = compact.match(/([0-9]*\.?[0-9]+)(ns|us|µs|ms|s|m|h)/gi)?.join("").length || 0;
  if (matchedCompactLen !== compact.length) return null;
  return totalMs;
}

function parseDecision404Record(line, lokiTsNs, env, pod = null) {
  const obj = extractJsonObjectFromLogLine(line);
  if (!obj || typeof obj !== "object") return null;

  const traceID = String(
    obj.traceID || obj.traceId || obj.trace_id || obj.requestTraceId || "",
  ).trim();
  const url = String(obj.url || obj.requestURL || obj.requestUrl || "").trim();

  if (!traceID || !url) return null;

  const methodNameRaw = obj.requestMethod ?? obj.methodName ?? null;
  const methodName = methodNameRaw ? String(methodNameRaw).trim() : null;
  const messageRaw =
    obj.message ?? obj.A_message ?? obj.a_message ?? obj.log_message ?? obj.msg ?? null;
  const message = messageRaw ? String(messageRaw).trim() : null;
  const elapsedTime = obj.elapsedTime ? String(obj.elapsedTime).trim() : null;
  const elapsedTimeMs = parseElapsedTimeMs(elapsedTime);
  const responseStatusCode = Number(obj.responseStatusCode);
  const requestHTTPStatusCode = Number(obj.requestHTTPStatusCode);

  return {
    env,
    pod: pod || null,
    lokiTsNs: String(lokiTsNs || ""),
    timestamp: obj.timestamp ? String(obj.timestamp) : null,
    url,
    traceID,
    elapsedTime,
    elapsedTimeMs,
    methodName,
    message,
    responseStatusCode: Number.isFinite(responseStatusCode) ? responseStatusCode : null,
    requestHTTPStatusCode: Number.isFinite(requestHTTPStatusCode) ? requestHTTPStatusCode : null,
    level: obj.level ? String(obj.level) : null,
  };
}

function deriveDecision404RequestStartTsNs(rec) {
  const reqEndNs = Number(rec?.lokiTsNs);
  const elapsedMs = Number(rec?.elapsedTimeMs);
  if (!Number.isFinite(reqEndNs) || reqEndNs <= 0) return null;
  if (!Number.isFinite(elapsedMs) || elapsedMs < 0) return null;
  // Round up duration to the next ms for conservative back-calculation.
  const elapsedRoundedMs = Math.ceil(elapsedMs);
  const startNs = Math.floor(reqEndNs - elapsedRoundedMs * 1e6);
  if (!Number.isFinite(startNs) || startNs <= 0 || startNs > reqEndNs) return null;
  return {
    requestStartTimeNs: String(startNs),
    elapsedTimeRoundedMs: elapsedRoundedMs,
  };
}

function buildRequestIdentityKey(
  rec,
  { includePod = true, includeTimestamp = true, includeMethod = true, includeMessage = true } = {},
) {
  if (!rec || typeof rec !== "object") return "";
  const parts = [String(rec?.env || "")];
  if (includePod) parts.push(String(rec?.pod || ""));
  parts.push(String(rec?.traceID || ""));
  parts.push(String(rec?.url || ""));
  if (includeTimestamp) parts.push(String(rec?.lokiTsNs || ""));
  if (includeMethod) parts.push(String(rec?.methodName || ""));
  if (includeMessage) parts.push(String(rec?.message || ""));
  return parts.join("|");
}

function dedupeDecision404Records(records) {
  const deduped = [];
  let collapsedCount = 0;
  const keyToIdx = new Map();

  for (const rec of records || []) {
    const key = buildRequestIdentityKey(rec);

    if (!keyToIdx.has(key)) {
      keyToIdx.set(key, deduped.length);
      deduped.push({
        ...rec,
        duplicateCount: 1,
      });
      continue;
    }

    collapsedCount += 1;
    const idx = keyToIdx.get(key);
    deduped[idx].duplicateCount = Number(deduped[idx].duplicateCount || 1) + 1;
  }

  return {
    records: deduped,
    dedupedRecordCount: deduped.length,
    collapsedCount,
  };
}

function isValidDecision404Url(url) {
  const s = String(url || "").trim();
  return /^\/v1:\$\d+\/authorize$/.test(s) || s === "/v1/authorize";
}

function isValidStep3_1Message(message) {
  const s = String(message || "").trim();
  if (!s) return false;
  if (s === "request received and completed") return true;
  if (s.startsWith("executed operation: request received for")) return true;
  if (s === "no activated / default deployment found") return true;
  if (s.startsWith("executed operation: authorization elapsed time")) return true;
  return false;
}

function validateStep3_1Record(rec) {
  const reasons = [];
  if (!isValidStep3_1Message(rec.message)) {
    reasons.push("message_mismatch");
  }
  if (rec.methodName !== "POST") {
    reasons.push("method_mismatch");
  }
  if (!isValidDecision404Url(rec.url)) {
    reasons.push("url_mismatch");
  }
  return {
    isValid: reasons.length === 0,
    reasons,
  };
}

function buildStep3_1Validation(parsedByEnv) {
  const byEnv = {};

  for (const [env, item] of Object.entries(parsedByEnv || {})) {
    const records = item.records || [];
    const validRecords = [];
    const invalidRecords = [];
    const reasonCounts = {
      message_mismatch: 0,
      method_mismatch: 0,
      url_mismatch: 0,
    };

    for (const rec of records) {
      const v = validateStep3_1Record(rec);
      if (v.isValid) {
        validRecords.push(rec);
        continue;
      }

      for (const reason of v.reasons) {
        reasonCounts[reason] = (reasonCounts[reason] || 0) + 1;
      }
      invalidRecords.push({
        reasons: v.reasons,
        record: rec,
      });
    }

    byEnv[env] = {
      totalParsedRecords: records.length,
      validRecordCount: validRecords.length,
      invalidRecordCount: invalidRecords.length,
      reasonCounts,
      validRecords,
      invalidSamples: invalidRecords.slice(0, 20),
      splitMeta: item?.splitMeta || null,
      step2UnsplittableLimitHitCount: Number(item?.step2UnsplittableLimitHitCount || 0),
    };

    console.log(
      `Step 3.1 env=${env} valid=${validRecords.length} invalid=${invalidRecords.length}`,
    );
  }

  return byEnv;
}

function summarizeStep3Records(parsedByEnv) {
  const out = {};

  for (const [env, item] of Object.entries(parsedByEnv)) {
    const records = item.records || [];
    const traceSet = new Set();
    const urlCount = new Map();
    let elapsedSumMs = 0;
    let elapsedCount = 0;

    for (const r of records) {
      traceSet.add(r.traceID);
      urlCount.set(r.url, (urlCount.get(r.url) || 0) + 1);
      if (typeof r.elapsedTimeMs === "number") {
        elapsedSumMs += r.elapsedTimeMs;
        elapsedCount += 1;
      }
    }

    const topUrls = [...urlCount.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([url, count]) => ({ url, count }));

    out[env] = {
      parsedRecordCount: records.length,
      rawParsedRecordCount: item.rawRecordCount || records.length,
      dedupCollapsedCount: item.dedupCollapsedCount || 0,
      uniqueTraceCount: traceSet.size,
      uniqueUrlCount: urlCount.size,
      avgElapsedTimeMs: elapsedCount ? Number((elapsedSumMs / elapsedCount).toFixed(6)) : null,
      topUrls,
      invalidLineCount: item.invalidLineCount || 0,
      totalMatchedLineCount: item.totalMatchedLineCount || 0,
    };
  }

  return out;
}

function summarizeStep3_1Validation(validationByEnv) {
  const out = {};
  for (const [env, item] of Object.entries(validationByEnv || {})) {
    out[env] = {
      totalParsedRecords: item.totalParsedRecords || 0,
      validRecordCount: item.validRecordCount || 0,
      invalidRecordCount: item.invalidRecordCount || 0,
      reasonCounts: item.reasonCounts || {},
    };
  }
  return out;
}

function pickLatestLokiLogAtOrBeforeTs(lokiJson, endNs) {
  let best = null;
  const end = Number(endNs);

  for (const stream of lokiJson?.data?.result || []) {
    for (const [tsNs, line] of stream.values || []) {
      const n = Number(tsNs);
      if (!Number.isFinite(n)) continue;
      if (n > end) continue;
      if (!best || n > best.tsNsNum) {
        best = {
          tsNsNum: n,
          tsNs: String(tsNs),
          line: String(line || ""),
        };
      }
    }
  }

  return best;
}

async function findLastCachePrepLogBeforeRecord(
  rec,
  { lookbackHours = 24, regionContext = null } = {},
) {
  const recTsNsNum = Number(rec.lokiTsNs);
  if (!Number.isFinite(recTsNsNum) || recTsNsNum <= 0) {
    return { matched: false, reason: "invalid_request_timestamp", previousLog: null };
  }

  const endNs = subtractNsWithPrecisionGuard(recTsNsNum, 1);
  const startNs = Math.floor(endNs - lookbackHours * 60 * 60 * 1e9);

  const expr =
    `${buildDecisionSelector(rec.env, rec.pod)}` +
    ` != "/live" != "/ready"` +
    ` |~ "${LOG_PATTERNS.cachePrepStart}"`;

  const lokiJson = await queryLoki(expr, {
    startNs,
    endNs,
    direction: "BACKWARD",
    limit: 1,
    regionContext,
  });

  const latest = pickLatestLokiLogAtOrBeforeTs(lokiJson, endNs);
  if (!latest) {
    return {
      matched: false,
      reason: "no_prior_cache_prep_log",
      query: expr,
      previousLog: null,
    };
  }

  const parsed = extractJsonObjectFromLogLine(latest.line);
  const deltaMs = Number(((recTsNsNum - latest.tsNsNum) / 1e6).toFixed(3));
  return {
    matched: true,
    reason: null,
    query: expr,
    previousLog: {
      lokiTsNs: latest.tsNs,
      timestamp: parsed?.timestamp ? String(parsed.timestamp) : null,
      level: parsed?.level ? String(parsed.level) : null,
      message: parsed?.message ? String(parsed.message) : null,
      line: latest.line,
      parsed: parsed || null,
      deltaMsFromRequestLog: deltaMs,
    },
  };
}

function parseCachePrepStartRecord(line, lokiTsNs) {
  const parsed = extractJsonObjectFromLogLine(line);
  const message = String(parsed?.message || parsed?.A_message || line || "");
  return {
    lokiTsNs: String(lokiTsNs),
    tsNsNum: Number(lokiTsNs),
    timestamp: parsed?.timestamp ? String(parsed.timestamp) : null,
    level: parsed?.level ? String(parsed.level) : null,
    message: message || null,
    line: String(line || ""),
    parsed: parsed || null,
  };
}

function pickLatestAnchorAtOrBeforeTs(anchorRecordsSortedAsc, requestCompleteTimeNs) {
  const target = Number(requestCompleteTimeNs);
  if (!Number.isFinite(target) || target <= 0) return null;
  const arr = anchorRecordsSortedAsc || [];
  let lo = 0;
  let hi = arr.length - 1;
  let ans = -1;
  while (lo <= hi) {
    const mid = Math.floor((lo + hi) / 2);
    const midTs = Number(arr[mid]?.tsNsNum || 0);
    if (Number.isFinite(midTs) && midTs <= target) {
      ans = mid;
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  return ans >= 0 ? arr[ans] : null;
}

async function buildStep3_2PreviousLogByEnv(
  step3_1ValidationByEnv,
  { lookbackHours = 1, regionContext = null } = {},
) {
  const byEnv = {};

  for (const [env, item] of Object.entries(step3_1ValidationByEnv || {})) {
    const requestRecords = item.validRecords || [];
    const weightedRequestRecordCount = requestRecords.reduce(
      (sum, r) => sum + Number(r?.duplicateCount || 1),
      0,
    );
    const links = [];
    let matchedCount = 0;
    let missCount = 0;

    const recordsByPod = new Map();
    for (const rec of requestRecords) {
      const podKey = String(rec?.pod || "__NO_POD__");
      if (!recordsByPod.has(podKey)) recordsByPod.set(podKey, []);
      recordsByPod.get(podKey).push(rec);
    }

    const podAnchorIndex = new Map();
    for (const [podKey, podRecords] of recordsByPod.entries()) {
      const pod = podKey === "__NO_POD__" ? null : podKey;
      const validTs = podRecords
        .map(r => Number(r?.lokiTsNs))
        .filter(n => Number.isFinite(n) && n > 0);
      if (!validTs.length) {
        podAnchorIndex.set(podKey, { recordsAsc: [], query: null });
        continue;
      }

      let minReqNs = validTs[0];
      let maxReqNs = validTs[0];
      for (let j = 1; j < validTs.length; j += 1) {
        const v = validTs[j];
        if (v < minReqNs) minReqNs = v;
        if (v > maxReqNs) maxReqNs = v;
      }
      const startNs = Math.max(0, Math.floor(minReqNs - lookbackHours * 60 * 60 * 1e9));
      const endNs = subtractNsWithPrecisionGuard(maxReqNs, 1);
      const expr =
        `${buildDecisionSelector(env, pod)}` +
        ` != "/live" != "/ready"` +
        ` |~ "${LOG_PATTERNS.cachePrepStart}"`;
      appendRunLog("STEP3.2", "pod anchor prefetch start", {
        env,
        pod: pod || null,
        requestCount: podRecords.length,
        lookbackHours,
        startNs: String(startNs),
        endNs: String(endNs),
        startPst: formatNsToPst(startNs),
        endPst: formatNsToPst(endNs),
        expr,
      });
      const lokiJson = await queryLoki(expr, {
        startNs,
        endNs,
        direction: "FORWARD",
        limit: 3000,
        regionContext,
      });
      const anchorPrefetchLineCount = countLokiResultLines(lokiJson);
      if (anchorPrefetchLineCount >= 3000) {
        appendRunLog("STEP3.2", "warning: pod anchor prefetch may be truncated due to limit-hit risk", {
          env,
          pod: pod || null,
          limit: 3000,
          lineCount: anchorPrefetchLineCount,
          startNs: String(startNs),
          endNs: String(endNs),
          startPst: formatNsToPst(startNs),
          endPst: formatNsToPst(endNs),
          lookbackHours,
          expr,
        });
        console.warn(
          `STEP3.2 warning env=${env} pod=${pod || "N/A"}: pod anchor prefetch lineCount>=3000 in ${formatNsToPst(
            startNs,
          )} ~ ${formatNsToPst(endNs)}; potential missing anchor entries.`,
        );
      }
      const anchors = [];
      for (const stream of lokiJson?.data?.result || []) {
        for (const [tsNs, line] of stream.values || []) {
          const rec = parseCachePrepStartRecord(line, tsNs);
          if (!Number.isFinite(rec.tsNsNum) || rec.tsNsNum <= 0) continue;
          anchors.push(rec);
        }
      }
      anchors.sort((a, b) => a.tsNsNum - b.tsNsNum);
      appendRunLog("STEP3.2", "pod anchor prefetch completed", {
        env,
        pod: pod || null,
        requestCount: podRecords.length,
        anchorRecordCount: anchors.length,
        startNs: String(startNs),
        endNs: String(endNs),
      });
      podAnchorIndex.set(podKey, { recordsAsc: anchors, query: expr });
    }

    for (let i = 0; i < requestRecords.length; i += 1) {
      const rec = requestRecords[i];
      const requestTiming = deriveDecision404RequestStartTsNs(rec);
      const podKey = String(rec?.pod || "__NO_POD__");
      const podPrefetch = podAnchorIndex.get(podKey) || { recordsAsc: [], query: null };
      const latest = pickLatestAnchorAtOrBeforeTs(podPrefetch.recordsAsc, Number(rec?.lokiTsNs));
      const recTsNsNum = Number(rec?.lokiTsNs);
      const found = latest
        ? {
            matched: true,
            reason: null,
            query: podPrefetch.query,
            previousLog: {
              lokiTsNs: latest.lokiTsNs,
              timestamp: latest.timestamp,
              level: latest.level,
              message: latest.message,
              line: latest.line,
              parsed: latest.parsed,
              deltaMsFromRequestLog:
                Number.isFinite(recTsNsNum) && Number.isFinite(latest.tsNsNum)
                  ? Number(((recTsNsNum - latest.tsNsNum) / 1e6).toFixed(3))
                  : null,
            },
          }
        : {
            matched: false,
            reason: "no_prior_cache_prep_log",
            query: podPrefetch.query,
            previousLog: null,
          };

      const duplicateCount = Number(rec.duplicateCount || 1);
      if (found.matched) matchedCount += duplicateCount;
      else missCount += duplicateCount;

      links.push({
        request: {
          env: rec.env,
          pod: rec.pod || null,
          lokiTsNs: rec.lokiTsNs,
          timestamp: rec.timestamp,
          traceID: rec.traceID,
          url: rec.url,
          elapsedTime: rec.elapsedTime || null,
          elapsedTimeMs: Number.isFinite(Number(rec.elapsedTimeMs)) ? Number(rec.elapsedTimeMs) : null,
          elapsedTimeRoundedMs: requestTiming?.elapsedTimeRoundedMs ?? null,
          requestStartTimeNs: requestTiming?.requestStartTimeNs ?? null,
          methodName: rec.methodName,
          message: rec.message,
          duplicateCount,
        },
        matched: found.matched,
        missReason: found.reason,
        query: found.query || null,
        previousLog: found.previousLog,
      });

      if ((i + 1) % 100 === 0) {
        console.log(`Step 3.2 env=${env} processed=${i + 1}/${requestRecords.length}`);
      }
    }

    byEnv[env] = {
      requestRecordCount: weightedRequestRecordCount,
      dedupedRequestRecordCount: requestRecords.length,
      matchedCount,
      missCount,
      lookbackHours,
      links,
      missSamples: links.filter(x => !x.matched).slice(0, 20),
      splitMeta: item?.splitMeta || null,
      step2UnsplittableLimitHitCount: Number(item?.step2UnsplittableLimitHitCount || 0),
    };

    console.log(
      `Step 3.2 env=${env} requestRecords=${weightedRequestRecordCount} dedupedRequestRecords=${requestRecords.length} matched=${matchedCount} missed=${missCount}`,
    );
  }

  return byEnv;
}

function summarizeStep3_2PreviousLog(step3_2ByEnv) {
  const out = {};
  for (const [env, item] of Object.entries(step3_2ByEnv || {})) {
    out[env] = {
      requestRecordCount: item.requestRecordCount || 0,
      dedupedRequestRecordCount: item.dedupedRequestRecordCount || 0,
      matchedCount: item.matchedCount || 0,
      missCount: item.missCount || 0,
      lookbackHours: item.lookbackHours || 24,
    };
  }
  return out;
}

function normalizeWs(s) {
  return String(s || "")
    .replace(/\\n|\\r|\\t/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function normalizeErrorSignatureText(s) {
  return normalizeWs(s)
    .toLowerCase()
    .replace(/^received error from isallowedbulk\s+/i, "")
    .replace(/^received error from isallowed\s+/i, "");
}

function extractErrorSignatureFromTraceEntry(entry) {
  if (!entry || typeof entry !== "object") return null;
  const candidates = [entry.error, entry.A_message, entry.a_message, entry.message];
  for (const c of candidates) {
    const normalized = normalizeErrorSignatureText(c);
    if (normalized) return normalized;
  }
  return null;
}

function deepClone(value) {
  try {
    return structuredClone(value);
  } catch (_) {
    try {
      return JSON.parse(JSON.stringify(value));
    } catch (_) {
      return value;
    }
  }
}

function subtractNsWithPrecisionGuard(ns, deltaNs = 1) {
  const n = Number(ns);
  if (!Number.isFinite(n)) return n;
  let d = Math.max(1, Math.floor(Number(deltaNs) || 1));
  let out = n - d;
  // At nanosecond-scale epoch values (~1e18), JS Number precision is coarse.
  // Ensure subtraction actually moves the boundary left.
  if (out === n) {
    d = Math.max(1024, d);
    while (d < 1e9 && n - d === n) d *= 2;
    out = n - d;
  }
  return Math.floor(out);
}

function extractDeploymentIdFromLine(line, parsedObj) {
  const obj = parsedObj || extractJsonObjectFromLogLine(line);
  for (const k of ["deploymentID", "deploymentId", "deployment_id"]) {
    if (obj && obj[k] !== undefined && obj[k] !== null) {
      const v = String(obj[k]).trim();
      if (v) return v;
    }
  }

  const raw = String(line || "");
  const m = raw.match(/\bdeploymentID\b["\s:=]+["']?([A-Za-z0-9._:-]+)["']?/i);
  if (m && m[1]) return m[1];
  return null;
}

function extractDefaultDeploymentIdFromLine(line, parsedObj) {
  const obj = parsedObj || extractJsonObjectFromLogLine(line);
  for (const k of [
    "defaultDeploymentID",
    "defaultDeploymentId",
    "default_deployment_id",
    "Default Deployment",
  ]) {
    if (obj && obj[k] !== undefined && obj[k] !== null) {
      const v = String(obj[k]).trim();
      if (v) return v;
    }
  }

  const raw = String(line || "");
  const m = raw.match(/\bdefault deploymentID\b["\s:=]+["']?([A-Za-z0-9._:-]+)["']?/i);
  if (m && m[1]) return m[1];
  return null;
}

function extractErrorRecordFromErrorLine(line) {
  let obj;
  try {
    obj = JSON.parse(String(line || ""));
  } catch (_) {
    return null;
  }

  if (String(obj?.level || "").toLowerCase() !== "error") return null;
  if (typeof obj?.error !== "string" || !obj.error.trim()) return null;

  const errorMsg = normalizeWs(obj.error);
  if (errorMsg.toLowerCase() === "rendering response") return null;

  const ora = errorMsg.match(/\bORA-(\d+)\b/i);
  if (ora) {
    const code = ora[1];
    const oraDisplayMatch = errorMsg.match(
      /\b(ORA-\d+:\s*[\s\S]*?)(?:\s+for query\s*:?\s*[\s\S]*$|$)/i,
    );
    const display = normalizeWs(oraDisplayMatch?.[1] || `ORA-${code}`);
    return { key: `ORA-${code}`, display };
  }

  if (obj?.errorCode) {
    return {
      key: `CODE-${String(obj.errorCode).trim().toLowerCase()}`,
      display: errorMsg,
    };
  }

  return {
    key: `MSG-${errorMsg.toLowerCase()}`,
    display: errorMsg,
  };
}

function extractErrorRecordFromParsedLogObject(obj) {
  if (!obj || typeof obj !== "object") return null;
  if (String(obj?.level || "").toLowerCase() !== "error") return null;
  if (typeof obj?.error !== "string" || !obj.error.trim()) return null;

  const errorMsg = normalizeWs(obj.error);
  if (errorMsg.toLowerCase() === "rendering response") return null;

  const ora = errorMsg.match(/\bORA-(\d+)\b/i);
  if (ora) {
    const code = ora[1];
    const oraDisplayMatch = errorMsg.match(
      /\b(ORA-\d+:\s*[\s\S]*?)(?:\s+for query\s*:?\s*[\s\S]*$|$)/i,
    );
    const display = normalizeWs(oraDisplayMatch?.[1] || `ORA-${code}`);
    return { key: `ORA-${code}`, display };
  }

  if (obj?.errorCode) {
    return {
      key: `CODE-${String(obj.errorCode).trim().toLowerCase()}`,
      display: errorMsg,
    };
  }

  return {
    key: `MSG-${errorMsg.toLowerCase()}`,
    display: errorMsg,
  };
}

function pruneContainingLongerMessages(messages) {
  const normalized = messages
    .map(m => ({ raw: m, n: normalizeWs(m).toLowerCase() }))
    .filter(x => x.n && x.n !== "rendering response");

  const keep = normalized.filter((a, i) => {
    return !normalized.some((b, j) => {
      if (i === j) return false;
      if (b.n.length >= a.n.length) return false;
      return a.n.includes(b.n);
    });
  });

  return [...new Set(keep.map(x => x.raw))].sort();
}

function buildErrorToEnvMap(uniqueErrorsByEnv) {
  const map = new Map();

  for (const [env, errors] of Object.entries(uniqueErrorsByEnv || {})) {
    for (const err of errors || []) {
      if (!map.has(err)) map.set(err, new Set());
      map.get(err).add(env);
    }
  }

  const out = {};
  for (const [err, envSet] of map.entries()) {
    out[err] = [...envSet].sort();
  }
  return out;
}

function parseCompletedCachePrepareRecord(line, lokiTsNs) {
  const parsed = extractJsonObjectFromLogLine(line);
  const message = String(parsed?.message || parsed?.A_message || line || "");
  const lower = message.toLowerCase();
  let deploymentID = String(parsed?.deploymentID || parsed?.deploymentId || "").trim();
  if (!deploymentID) {
    const m = message.match(/updated cache for deployment ['"]?([A-Za-z0-9._:-]+)['"]?/i);
    if (m && m[1]) deploymentID = String(m[1]).trim();
  }
  if (!deploymentID) return null;
  let completionKind = "unknown";
  if (lower.includes("completed preparing policies runtime cache")) {
    completionKind = "new_policies";
  } else if (lower.includes("completed preparing role assignments runtime cache")) {
    completionKind = "new_role_assignments";
  } else if (
    lower.includes("updated cache for deployment") &&
    (lower.includes("speedle policies") || lower.includes("speedle role policies"))
  ) {
    completionKind = "legacy_single";
  }
  const elapsedTime = parsed?.elapsedTime ? String(parsed.elapsedTime).trim() : null;
  const elapsedTimeMs = parseElapsedTimeMs(elapsedTime);
  return {
    lokiTsNs: String(lokiTsNs),
    deploymentID,
    completionKind,
    elapsedTime,
    elapsedTimeMs,
    timestamp: parsed?.timestamp ? String(parsed.timestamp) : null,
    message: message || null,
    line: String(line || ""),
  };
}

function pickEarliestCompletionForDeployment(candidates, targetDeploymentID) {
  const target = String(targetDeploymentID || "").trim();
  if (!target) return null;
  const matched = (candidates || [])
    .filter(x => String(x?.deploymentID || "").trim() === target)
    .sort((a, b) => Number(b.lokiTsNs) - Number(a.lokiTsNs));
  return matched[0] || null;
}

function completionMatchesStartRound(rec, startNs) {
  const elapsedMs = Number(rec?.elapsedTimeMs);
  const tsNs = Number(rec?.lokiTsNs);
  if (!Number.isFinite(elapsedMs) || !Number.isFinite(tsNs) || !Number.isFinite(startNs)) return false;
  const expectedStartNs = Math.round(tsNs - elapsedMs * 1e6);
  const toleranceNs = 1e6; // 1ms tolerance for log timestamp/back-calculation jitter.
  return expectedStartNs >= Number(startNs) - toleranceNs;
}

function parseDeploymentListCacheUpdateRecord(line, lokiTsNs) {
  const parsed = extractJsonObjectFromLogLine(line);
  const message = String(parsed?.message || parsed?.A_message || line || "");
  const lower = message.toLowerCase();
  const isDefault =
    lower.includes("updating deployment list cache with default deploymentid") ||
    lower.includes("new default deployment added to the cache") ||
    lower.includes("default deployment from latest records") ||
    lower.includes("default deployment from existing cached list");
  const isRegular =
    lower.includes("updating deployment list cache with deploymentid") ||
    lower.includes("new deployment from latest db records added to the cache");
  if (!isDefault && !isRegular) return null;

  const deploymentID = isDefault
    ? extractDefaultDeploymentIdFromLine(line, parsed)
    : extractDeploymentIdFromLine(line, parsed);
  if (!deploymentID) return null;

  return {
    lokiTsNs: String(lokiTsNs),
    deploymentID: String(deploymentID),
    timestamp: parsed?.timestamp ? String(parsed.timestamp) : null,
    message: parsed?.message ? String(parsed.message) : null,
    kind: isDefault ? "default" : "deployment",
    line: String(line || ""),
  };
}

function buildDeploymentListCacheRounds(records, { roundGapMs = 5000 } = {}) {
  const sorted = [...(records || [])].sort((a, b) => Number(a.lokiTsNs) - Number(b.lokiTsNs));
  const rounds = [];
  let current = null;

  function toRoundOut(r) {
    const deployments = Object.keys(r.deploymentLastSeenTsNs)
      .sort((a, b) => Number(r.deploymentLastSeenTsNs[b]) - Number(r.deploymentLastSeenTsNs[a]));
    return {
      startLokiTsNs: String(r.startNs),
      endLokiTsNs: String(r.endNs),
      defaultDeploymentID: r.defaultDeploymentID || null,
      deployments,
      deploymentLastSeenTsNs: r.deploymentLastSeenTsNs,
      deploymentLastSeenKind: r.deploymentLastSeenKind,
      entryCount: r.entries.length,
      entries: r.entries,
    };
  }

  for (const rec of sorted) {
    const ts = Number(rec.lokiTsNs);
    if (!Number.isFinite(ts)) continue;
    const needNewRound = !current || (ts - current.endNs) / 1e6 > roundGapMs;
    if (needNewRound) {
      if (current) rounds.push(toRoundOut(current));
      current = {
        startNs: ts,
        endNs: ts,
        defaultDeploymentID: null,
        deploymentLastSeenTsNs: {},
        deploymentLastSeenKind: {},
        entries: [],
      };
    }
    current.endNs = ts;
    current.entries.push(rec);
    current.deploymentLastSeenTsNs[rec.deploymentID] = String(rec.lokiTsNs);
    current.deploymentLastSeenKind[rec.deploymentID] = rec.kind;
    if (rec.kind === "default") current.defaultDeploymentID = rec.deploymentID;
  }
  if (current) rounds.push(toRoundOut(current));

  rounds.sort((a, b) => Number(b.endLokiTsNs) - Number(a.endLokiTsNs));
  return rounds;
}

function evaluateDeploymentListCachePresence({
  reqInfo,
  reqTsNs,
  resolvedDefaultDeploymentID,
  roundsLatest2,
}) {
  const last = roundsLatest2?.[0] || null;
  const second = roundsLatest2?.[1] || null;
  if (!last) {
    return { decision: "unknown", reason: "no_cache_round_found", targetDeploymentID: null };
  }

  function targetForRound(round) {
    if (!round) return null;
    if (reqInfo?.type === "explicit") return reqInfo?.deploymentID || null;
    if (reqInfo?.type === "default") {
      return round.defaultDeploymentID || resolvedDefaultDeploymentID || null;
    }
    return null;
  }

  function foundInRound(round, target) {
    if (!round || !target) return { found: false, hitTsNs: null, hitKind: null };
    const hitTsNs = round.deploymentLastSeenTsNs?.[target] || null;
    const hitKind = round.deploymentLastSeenKind?.[target] || null;
    return { found: Boolean(hitTsNs), hitTsNs, hitKind };
  }

  const lastTarget = targetForRound(last);
  if (!lastTarget) {
    return { decision: "unknown", reason: "target_deployment_unknown", targetDeploymentID: null };
  }

  const lastHit = foundInRound(last, lastTarget);
  if (!lastHit.found) {
    return {
      decision: "target_not_ready",
      reason: "target_not_in_last_round",
      targetDeploymentID: lastTarget,
      usedRound: "last",
      usedRoundEndLokiTsNs: last.endLokiTsNs,
      usedRoundTargetHitLokiTsNs: null,
      usedRoundTargetHitKind: null,
    };
  }

  if (Number(lastHit.hitTsNs) <= Number(reqTsNs)) {
    return {
      decision: "target_present",
      reason: "target_in_last_round_before_request",
      targetDeploymentID: lastTarget,
      usedRound: "last",
      usedRoundEndLokiTsNs: last.endLokiTsNs,
      usedRoundTargetHitLokiTsNs: String(lastHit.hitTsNs),
      usedRoundTargetHitKind: lastHit.hitKind || null,
    };
  }

  const secondTarget = targetForRound(second);
  const secondHit = foundInRound(second, secondTarget);
  if (secondHit.found && Number(secondHit.hitTsNs) <= Number(reqTsNs)) {
    return {
      decision: "target_present",
      reason: "last_round_after_request_fallback_to_second_last_found",
      targetDeploymentID: secondTarget,
      usedRound: "second_last",
      usedRoundEndLokiTsNs: second.endLokiTsNs,
      usedRoundTargetHitLokiTsNs: String(secondHit.hitTsNs),
      usedRoundTargetHitKind: secondHit.hitKind || null,
    };
  }

  return {
    decision: "target_not_ready",
    reason: secondHit.found
      ? "last_round_after_request_second_last_hit_after_request"
      : "last_round_after_request_second_last_not_found",
    targetDeploymentID: secondTarget || lastTarget,
    usedRound: "second_last",
    usedRoundEndLokiTsNs: second?.endLokiTsNs || null,
    usedRoundTargetHitLokiTsNs: null,
    usedRoundTargetHitKind: null,
  };
}

function evaluateDeploymentListCacheAfterRequest({
  reqInfo,
  reqTsNs,
  resolvedDefaultDeploymentID,
  roundsAfterRequest,
  roundsToCheck = 2,
}) {
  const targetFromReq =
    reqInfo?.type === "explicit"
      ? String(reqInfo?.deploymentID || "").trim() || null
      : reqInfo?.type === "default"
        ? String(resolvedDefaultDeploymentID || "").trim() || null
        : null;
  const roundsChrono = [...(roundsAfterRequest || [])].sort(
    (a, b) => Number(a.startLokiTsNs) - Number(b.startLokiTsNs),
  );
  const candidateRounds = roundsChrono
    .filter(r => Number(r?.startLokiTsNs) >= Number(reqTsNs))
    .slice(0, Math.max(1, Number(roundsToCheck) || 2));

  if (!targetFromReq) {
    return {
      checked: false,
      reason: "target_deployment_unknown",
      targetDeploymentID: null,
      roundsChecked: 0,
      foundInCheckedRounds: false,
    };
  }
  if (!candidateRounds.length) {
    return {
      checked: false,
      reason: "no_post_request_round_found",
      targetDeploymentID: targetFromReq,
      roundsChecked: 0,
      foundInCheckedRounds: false,
    };
  }

  const matchedRound = candidateRounds.find(r => Boolean(r?.deploymentLastSeenTsNs?.[targetFromReq])) || null;
  return {
    checked: true,
    reason: matchedRound ? "target_found_in_post_request_rounds" : "target_not_found_in_post_request_rounds",
    targetDeploymentID: targetFromReq,
    roundsChecked: candidateRounds.length,
    checkedRounds: candidateRounds.map(r => ({
      startLokiTsNs: r.startLokiTsNs,
      endLokiTsNs: r.endLokiTsNs,
      defaultDeploymentID: r.defaultDeploymentID || null,
      deployments: r.deployments || [],
      entryCount: Number(r.entryCount || 0),
    })),
    foundInCheckedRounds: Boolean(matchedRound),
    matchedRound: matchedRound
      ? {
          startLokiTsNs: matchedRound.startLokiTsNs,
          endLokiTsNs: matchedRound.endLokiTsNs,
          targetHitLokiTsNs: matchedRound.deploymentLastSeenTsNs?.[targetFromReq] || null,
          targetHitKind: matchedRound.deploymentLastSeenKind?.[targetFromReq] || null,
        }
      : null,
  };
}

function classifyDecision404ErrorByTrace(entries) {
  let runtimeServicesHit = null;
  let deploymentListHit = null;
  let runtimeServicesCount = 0;
  let deploymentListCount = 0;

  for (const e of entries || []) {
    if (String(e?.level || "").toLowerCase() !== "error") continue;
    const err = String(e?.error || "");
    const msg = String(e?.message || e?.A_message || e?.a_message || "");
    const text = `${err} ${msg}`.toLowerCase();
    if (/spdl-2001\s+application\s+.+\s+is not found/i.test(text)) {
      runtimeServicesCount += 1;
      if (!runtimeServicesHit) {
        runtimeServicesHit = {
          category: "runtime_services_not_found",
          matchedPattern: "SPDL-2001 Application %s is not found",
          matchedEntry: e,
        };
      }
    }
    if (
      (/failed to validate deployment/i.test(text) &&
        /related object/i.test(text) &&
        /type ['"]deployment['"] not found/i.test(text)) ||
      /related object ['"].+['"] of type ['"]deployment['"] not found/i.test(text)
    ) {
      deploymentListCount += 1;
      if (!deploymentListHit) {
        deploymentListHit = {
          category: "deployment_list_not_found",
          matchedPattern: "related object '%s' of type 'deployment' not found",
          matchedEntry: e,
        };
      }
    }
  }
  // If both patterns appear in the same trace window, prioritize deployment-list failure branch first.
  if (deploymentListHit) {
    return {
      ...deploymentListHit,
      runtimeServicesCount,
      deploymentListCount,
      bothPatternsPresent: runtimeServicesCount > 0 && deploymentListCount > 0,
      runtimeServicesFirstHitTsNs: runtimeServicesHit?.matchedEntry?.lokiTsNs || null,
      deploymentListFirstHitTsNs: deploymentListHit?.matchedEntry?.lokiTsNs || null,
    };
  }
  if (runtimeServicesHit) {
    return {
      ...runtimeServicesHit,
      runtimeServicesCount,
      deploymentListCount,
      bothPatternsPresent: runtimeServicesCount > 0 && deploymentListCount > 0,
      runtimeServicesFirstHitTsNs: runtimeServicesHit?.matchedEntry?.lokiTsNs || null,
      deploymentListFirstHitTsNs: deploymentListHit?.matchedEntry?.lokiTsNs || null,
    };
  }
  return {
    category: "unknown",
    matchedPattern: null,
    matchedEntry: null,
    runtimeServicesCount,
    deploymentListCount,
    bothPatternsPresent: false,
    runtimeServicesFirstHitTsNs: null,
    deploymentListFirstHitTsNs: null,
  };
}

function parseDeploymentStateUpdateRecord(line, lokiTsNs) {
  const parsed = extractJsonObjectFromLogLine(line);
  if (!parsed || typeof parsed !== "object") return null;
  const messageRaw = String(parsed.message || parsed.A_message || parsed.a_message || line || "");
  const message = messageRaw.toLowerCase();
  if (!message.includes("update deployment state successfully")) return null;
  let deploymentID = String(
    parsed.deploymentID || parsed.deploymentId || parsed.B_deploymentID || "",
  ).trim();
  if (!deploymentID) {
    const raw = String(line || "");
    const m = raw.match(/\b(?:B_deploymentID|deploymentID)\b["\s:=]+["']?([A-Za-z0-9._:-]+)["']?/i);
    if (m && m[1]) deploymentID = String(m[1]).trim();
  }
  const newState = String(parsed.newState || "").trim();
  const curState = String(parsed.curState || "").trim();
  if (!deploymentID || !newState) return null;
  return {
    lokiTsNs: String(lokiTsNs),
    deploymentID,
    newState,
    curState: curState || null,
    timestamp: parsed.timestamp ? String(parsed.timestamp) : null,
    message: messageRaw || null,
    line: String(line || ""),
  };
}

function buildDeploymentStateIndexByDeployment(records) {
  const byDeployment = new Map();
  for (const rec of records || []) {
    const id = String(rec?.deploymentID || "").trim();
    const ts = Number(rec?.lokiTsNs || 0);
    if (!id || !Number.isFinite(ts)) continue;
    if (!byDeployment.has(id)) byDeployment.set(id, []);
    byDeployment.get(id).push({
      ...rec,
      tsNsNum: ts,
    });
  }
  for (const list of byDeployment.values()) {
    list.sort((a, b) => Number(a?.tsNsNum || 0) - Number(b?.tsNsNum || 0));
  }
  return byDeployment;
}

function findLatestDefaultDeploymentBeforeTs(podTimeline, tsNs) {
  const targetTs = Number(tsNs);
  if (!podTimeline || !Number.isFinite(targetTs)) return null;
  let best = null;
  for (const rec of podTimeline?.defaultDeploymentEvents || []) {
    const ts = Number(rec?.lokiTsNs || 0);
    if (!Number.isFinite(ts) || ts > targetTs) continue;
    if (!best || ts > Number(best?.lokiTsNs || 0)) best = rec;
  }
  if (best) {
    return {
      defaultDeploymentID: String(best.deploymentID || ""),
      lokiTsNs: String(best.lokiTsNs || ""),
      source: "default_event",
    };
  }
  const rounds = podTimeline?.deploymentListRounds || [];
  for (const r of rounds) {
    const endTs = Number(r?.endLokiTsNs || 0);
    if (!Number.isFinite(endTs) || endTs > targetTs) continue;
    if (r?.defaultDeploymentID) {
      return {
        defaultDeploymentID: String(r.defaultDeploymentID),
        lokiTsNs: String(r.endLokiTsNs),
        source: "deployment_list_round",
      };
    }
  }
  return null;
}

function findLastCachePrepStartBeforeTs(podTimeline, tsNs) {
  const targetTs = Number(tsNs);
  if (!podTimeline || !Number.isFinite(targetTs)) return null;
  let best = null;
  for (const rec of podTimeline?.cachePrepStarts || []) {
    const ts = Number(rec?.lokiTsNs || 0);
    if (!Number.isFinite(ts) || ts >= targetTs) continue;
    if (!best || ts > Number(best?.lokiTsNs || 0)) best = rec;
  }
  return best;
}

function distinctCompletionByDeploymentForFast(records) {
  const byDeployment = new Map();
  for (const r of records || []) {
    const id = String(r?.deploymentID || "").trim();
    if (!id) continue;
    if (!byDeployment.has(id)) {
      byDeployment.set(id, {
        latestLegacySingle: null,
        latestPolicies: null,
        latestRoleAssignments: null,
      });
    }
    const slot = byDeployment.get(id);
    const ts = Number(r?.lokiTsNs || 0);
    if (!Number.isFinite(ts)) continue;
    if (r?.completionKind === "legacy_single") {
      if (!slot.latestLegacySingle || ts > Number(slot.latestLegacySingle?.lokiTsNs || 0)) {
        slot.latestLegacySingle = r;
      }
      continue;
    }
    if (r?.completionKind === "new_policies") {
      if (!slot.latestPolicies || ts > Number(slot.latestPolicies?.lokiTsNs || 0)) {
        slot.latestPolicies = r;
      }
      continue;
    }
    if (r?.completionKind === "new_role_assignments") {
      if (!slot.latestRoleAssignments || ts > Number(slot.latestRoleAssignments?.lokiTsNs || 0)) {
        slot.latestRoleAssignments = r;
      }
    }
  }

  const out = [];
  for (const [id, slot] of byDeployment.entries()) {
    let evidence = null;
    let completionEvidenceMode = null;
    if (slot.latestLegacySingle) {
      evidence = slot.latestLegacySingle;
      completionEvidenceMode = "legacy_single";
    } else if (slot.latestPolicies && slot.latestRoleAssignments) {
      const pTs = Number(slot.latestPolicies.lokiTsNs || 0);
      const rTs = Number(slot.latestRoleAssignments.lokiTsNs || 0);
      evidence = pTs >= rTs ? slot.latestPolicies : slot.latestRoleAssignments;
      completionEvidenceMode = "new_parallel_both_required";
    }
    if (!evidence) continue;
    out.push({
      deploymentID: id,
      lokiTsNs: evidence.lokiTsNs,
      elapsedTime: evidence.elapsedTime || null,
      elapsedTimeMs: evidence.elapsedTimeMs,
      timestamp: evidence.timestamp,
      message: evidence.message || null,
      completionKind: evidence.completionKind || null,
      completionEvidenceMode,
    });
  }
  out.sort((a, b) => Number(b?.lokiTsNs || 0) - Number(a?.lokiTsNs || 0));
  return out;
}

function evaluateDeploymentStateFromTimeline({
  managementStateIndexByDeployment,
  targetDeploymentID,
  reqTsNs,
  cacheRoundHitTsNs,
}) {
  const servingStates = new Set(["Activated", "Default", "Activating"]);
  const out = {
    checked: false,
    reason: "not_required",
    targetDeploymentID: targetDeploymentID || null,
    query: null,
    window: null,
    found: false,
    latest: null,
    isServingState: null,
    cacheRoundHitLokiTsNs: Number.isFinite(cacheRoundHitTsNs) ? String(cacheRoundHitTsNs) : null,
    latestAtOrBeforeCacheHit: null,
    latestAtOrBeforeCacheHitIsServing: null,
    servingTransitionAfterCacheHitBeforeRequest: false,
    servingTransitionEvent: null,
  };
  if (!targetDeploymentID || !managementStateIndexByDeployment) return out;
  const rows = managementStateIndexByDeployment.get(String(targetDeploymentID)) || [];
  if (!rows.length) {
    out.checked = true;
    out.reason = "no_deployment_state_records_in_window";
    return out;
  }
  out.checked = true;
  out.reason = null;
  out.found = true;
  const reqNs = Number(reqTsNs);
  const latestBeforeReq = [...rows].reverse().find(x => Number(x?.tsNsNum || 0) <= reqNs) || rows[rows.length - 1];
  out.latest = latestBeforeReq
    ? {
        deploymentID: latestBeforeReq.deploymentID,
        newState: latestBeforeReq.newState || null,
        curState: latestBeforeReq.curState || null,
        lokiTsNs: latestBeforeReq.lokiTsNs || null,
      }
    : null;
  out.isServingState = latestBeforeReq ? servingStates.has(String(latestBeforeReq.newState || "")) : null;

  const cacheHitNs = Number(cacheRoundHitTsNs);
  if (Number.isFinite(cacheHitNs) && cacheHitNs > 0) {
    const latestAtOrBeforeCacheHit =
      [...rows].reverse().find(x => Number(x?.tsNsNum || 0) <= cacheHitNs) || null;
    out.latestAtOrBeforeCacheHit = latestAtOrBeforeCacheHit
      ? {
          deploymentID: latestAtOrBeforeCacheHit.deploymentID,
          newState: latestAtOrBeforeCacheHit.newState || null,
          curState: latestAtOrBeforeCacheHit.curState || null,
          lokiTsNs: latestAtOrBeforeCacheHit.lokiTsNs || null,
        }
      : null;
    out.latestAtOrBeforeCacheHitIsServing = latestAtOrBeforeCacheHit
      ? servingStates.has(String(latestAtOrBeforeCacheHit.newState || ""))
      : null;
    const transition = rows.find(x => {
      const ts = Number(x?.tsNsNum || 0);
      if (!Number.isFinite(ts)) return false;
      if (!(ts > cacheHitNs && ts <= reqNs)) return false;
      const cur = String(x?.curState || "");
      const next = String(x?.newState || "");
      return !servingStates.has(cur) && servingStates.has(next);
    });
    if (transition) {
      out.servingTransitionAfterCacheHitBeforeRequest = true;
      out.servingTransitionEvent = {
        deploymentID: transition.deploymentID,
        curState: transition.curState || null,
        newState: transition.newState || null,
        lokiTsNs: transition.lokiTsNs || null,
      };
    }
  }
  return out;
}

function inferFastTraceCategory({
  deploymentListCacheCheck,
  deploymentListPostRequestCheck,
  completionExtensionUsed,
  completionDistinctOriginalCount,
  completionDistinctExtendCount,
  completionFoundAfterOriginalWindow,
}) {
  if (deploymentListCacheCheck?.decision === "target_not_ready") return "deployment_list_not_found";
  if (
    completionExtensionUsed &&
    Number(completionDistinctOriginalCount || 0) < 3 &&
    Number(completionDistinctExtendCount || 0) >= 3 &&
    completionFoundAfterOriginalWindow
  ) {
    return "runtime_services_not_found";
  }
  if (deploymentListPostRequestCheck?.checked && deploymentListPostRequestCheck?.foundInCheckedRounds === false) {
    return "deployment_list_not_found";
  }
  return "unknown";
}

function buildFastTraceErrorSummary(category) {
  if (category === "deployment_list_not_found") {
    return {
      category,
      matchedPattern: "related object '%s' of type 'deployment' not found",
      matchedEntry: null,
      runtimeServicesCount: 0,
      deploymentListCount: 1,
      bothPatternsPresent: false,
      runtimeServicesFirstHitTsNs: null,
      deploymentListFirstHitTsNs: null,
      entriesSample: [],
    };
  }
  if (category === "runtime_services_not_found") {
    return {
      category,
      matchedPattern: "SPDL-2001 Application %s is not found",
      matchedEntry: null,
      runtimeServicesCount: 1,
      deploymentListCount: 0,
      bothPatternsPresent: false,
      runtimeServicesFirstHitTsNs: null,
      deploymentListFirstHitTsNs: null,
      entriesSample: [],
    };
  }
  return {
    category: "unknown",
    matchedPattern: null,
    matchedEntry: null,
    runtimeServicesCount: 0,
    deploymentListCount: 0,
    bothPatternsPresent: false,
    runtimeServicesFirstHitTsNs: null,
    deploymentListFirstHitTsNs: null,
    entriesSample: [],
  };
}

function fastAnalyzeStep3_3ForLinkFromTimeline(link, envTimeline) {
  const env = link?.request?.env;
  const pod = link?.request?.pod || null;
  const reqTsNs = Number(link?.request?.lokiTsNs);
  if (!env || !pod || !Number.isFinite(reqTsNs) || reqTsNs <= 0) return null;
  const podTimeline = envTimeline?.podTimelines?.get(String(pod)) || null;
  if (!podTimeline) return null;
  const reqInfo = extractRequestedDeploymentFromUrl(link?.request?.url);
  if (reqInfo.type === "invalid") return null;

  const runtimeCacheStartTimeNs = Number(link?.previousLog?.lokiTsNs || 0);
  const lastPrep = findLastCachePrepStartBeforeTs(podTimeline, reqTsNs);
  const startNs = Number.isFinite(runtimeCacheStartTimeNs) && runtimeCacheStartTimeNs > 0 ? runtimeCacheStartTimeNs : Number(lastPrep?.lokiTsNs || 0);
  if (!Number.isFinite(startNs) || startNs <= 0 || startNs >= reqTsNs) return null;
  const endNs = subtractNsWithPrecisionGuard(reqTsNs, 1);

  const resolvedDefault = findLatestDefaultDeploymentBeforeTs(podTimeline, endNs);
  let targetDeploymentID = null;
  if (reqInfo.type === "explicit") targetDeploymentID = reqInfo.deploymentID;
  if (reqInfo.type === "default") targetDeploymentID = resolvedDefault?.defaultDeploymentID || null;
  if (!targetDeploymentID) return null;

  const roundsLatest2 = (podTimeline?.deploymentListRounds || []).slice(0, 2);
  const deploymentListCacheCheck = evaluateDeploymentListCachePresence({
    reqInfo,
    reqTsNs,
    resolvedDefaultDeploymentID: resolvedDefault?.defaultDeploymentID || null,
    roundsLatest2,
  });

  let deploymentListPostRequestCheck = {
    checked: false,
    reason: "not_required",
    targetDeploymentID: targetDeploymentID || null,
    roundsChecked: 0,
    foundInCheckedRounds: false,
    checkedRounds: [],
    matchedRound: null,
    window: null,
  };
  if (deploymentListCacheCheck?.decision === "target_not_ready") {
    const postStartNs = Math.floor(reqTsNs);
    const postEndNs = Math.floor(reqTsNs + 10 * 60 * 1e9);
    const postRounds = (podTimeline?.deploymentListRoundsChrono || []).filter(
      r => Number(r?.startLokiTsNs || 0) >= postStartNs && Number(r?.startLokiTsNs || 0) <= postEndNs,
    );
    const evaluated = evaluateDeploymentListCacheAfterRequest({
      reqInfo,
      reqTsNs,
      resolvedDefaultDeploymentID: resolvedDefault?.defaultDeploymentID || null,
      roundsAfterRequest: postRounds,
      roundsToCheck: 2,
    });
    deploymentListPostRequestCheck = {
      ...evaluated,
      roundsFound: postRounds.length,
      window: { startNs: String(postStartNs), endNs: String(postEndNs) },
    };
  }

  const completionRecords = podTimeline?.completionRecords || [];
  const completionCandidatesOriginal = completionRecords.filter(r => {
    const ts = Number(r?.lokiTsNs || 0);
    return Number.isFinite(ts) && ts >= startNs && ts <= endNs;
  });
  const completionRoundMatchedOriginal = completionCandidatesOriginal.filter(r =>
    completionMatchesStartRound(r, startNs),
  );
  const completionDistinctOriginalAll = distinctCompletionByDeploymentForFast(completionRoundMatchedOriginal);
  const completionDistinctOriginalTop3 = completionDistinctOriginalAll.slice(0, 3);
  let completionCandidates = completionCandidatesOriginal;
  let completionRoundMatched = completionRoundMatchedOriginal;
  let completionDistinctUsedAll = completionDistinctOriginalAll;
  let completionDistinctUsedTop3 = completionDistinctOriginalTop3;
  let completionExtensionUsed = false;
  let completionWindowEndNs = endNs;
  if (completionDistinctOriginalTop3.length < 3) {
    return {
      fastPathFallbackRequired: true,
      fallbackReason: "need_previous_round_check_for_insufficient_completion_in_current_round",
      window: { startNs: String(startNs), endNs: String(endNs) },
      completionDistinctOriginalCount: completionDistinctOriginalTop3.length,
    };
  }
  const earliestCompletionMatch =
    completionDistinctUsedAll.find(x => String(x?.deploymentID || "") === String(targetDeploymentID || "")) || null;
  const completionFoundAfterOriginalWindow = Boolean(
    earliestCompletionMatch && Number(earliestCompletionMatch.lokiTsNs) > endNs,
  );
  const targetInOriginalTop3 = completionDistinctOriginalTop3.some(
    x => String(x?.deploymentID || "") === String(targetDeploymentID || ""),
  );
  const targetInUsedTop3 = completionDistinctUsedTop3.some(
    x => String(x?.deploymentID || "") === String(targetDeploymentID || ""),
  );

  const restartEntries = (podTimeline?.restartEntries || []).filter(r => {
    const ts = Number(r?.lokiTsNs || 0);
    return Number.isFinite(ts) && ts >= startNs && ts <= endNs;
  });
  const timelineFailureRecords = (podTimeline?.failureRecords || []).filter(r => {
    const ts = Number(r?.lokiTsNs || 0);
    if (!Number.isFinite(ts) || ts < startNs || ts > endNs) return false;
    const lineTraceID = String(r?.traceID || "").trim();
    const requestTraceID = String(link?.request?.traceID || "").trim();
    if (requestTraceID && lineTraceID && lineTraceID === requestTraceID) return false;
    return true;
  });
  const timelineFailureMap = new Map();
  for (const r of timelineFailureRecords) {
    const key = String(r?.key || "").trim();
    const display = String(r?.display || "").trim();
    if (!key || !display) continue;
    if (!timelineFailureMap.has(key) || display.length < String(timelineFailureMap.get(key) || "").length) {
      timelineFailureMap.set(key, display);
    }
  }
  const timelineUniqueFailureErrors = pruneContainingLongerMessages([...timelineFailureMap.values()]);
  const restartEvidence = {
    count: restartEntries.length,
    entries: restartEntries.slice(0, 20),
    query: podTimeline?.decisionTimelineExpr || null,
  };

  let conclusion = null;
  let reason = null;
  if (completionDistinctUsedTop3.length >= 3) {
    if (timelineUniqueFailureErrors.length > 0) {
      conclusion = "cache_load_failure";
      reason = "failure_evidence_in_timeline_window";
    } else {
      return {
        fastPathFallbackRequired: true,
        fallbackReason: "timeline_failure_evidence_missing_for_completed_round",
        window: { startNs: String(startNs), endNs: String(endNs) },
        completionDistinctExtendCount: completionDistinctUsedTop3.length,
        failureEvidenceCount: 0,
      };
    }
  } else if (restartEntries.length >= 1) {
    conclusion = "cache_load_failure";
    reason = "restart_warmup";
  } else {
    return null;
  }

  const deploymentStateCheck = evaluateDeploymentStateFromTimeline({
    managementStateIndexByDeployment: envTimeline?.managementStateIndexByDeployment || null,
    targetDeploymentID:
      deploymentListCacheCheck?.targetDeploymentID || targetDeploymentID || null,
    reqTsNs,
    cacheRoundHitTsNs: Number(deploymentListCacheCheck?.usedRoundTargetHitLokiTsNs || 0),
  });

  const inferredTraceCategory = inferFastTraceCategory({
    deploymentListCacheCheck,
    deploymentListPostRequestCheck,
    completionExtensionUsed,
    completionDistinctOriginalCount: completionDistinctOriginalTop3.length,
    completionDistinctExtendCount: completionDistinctUsedTop3.length,
    completionFoundAfterOriginalWindow,
  });
  const traceErrorSummary = buildFastTraceErrorSummary(inferredTraceCategory);

  const out = {
    conclusion,
    reason,
    window: { startNs: String(startNs), endNs: String(endNs) },
    defaultLookupWindow: null,
    queries: {
      timelineMode: true,
      decisionTimelineExpr: podTimeline?.decisionTimelineExpr || null,
      managementTimelineExpr: envTimeline?.managementTimelineExpr || null,
    },
    successfulDeploymentsAll: completionDistinctUsedTop3,
    successfulDeploymentsLatestTop3: completionDistinctUsedTop3,
    completionDistinctOriginalCount: completionDistinctOriginalTop3.length,
    completionDistinctExtendCount: completionDistinctUsedTop3.length,
    targetInOriginalTop3,
    targetInUsedTop3,
    resolvedDefaultDeployment: resolvedDefault
      ? {
          defaultDeploymentID: resolvedDefault.defaultDeploymentID || null,
          lokiTsNs: resolvedDefault.lokiTsNs || null,
          source: resolvedDefault.source || null,
        }
      : null,
    defaultDeploymentCandidates: [],
    targetDeploymentID: targetDeploymentID || null,
    deploymentListCacheWindow: null,
    deploymentListCacheCandidatesCount: Number(podTimeline?.deploymentListRecords?.length || 0),
    deploymentListCacheCandidatesSample: (podTimeline?.deploymentListRecords || []).slice(-30),
    deploymentListCacheRoundsCount: Number(podTimeline?.deploymentListRounds?.length || 0),
    deploymentListCacheRoundsLatest2: roundsLatest2,
    deploymentListCacheCheck,
    deploymentListPostRequestCheck,
    traceErrorSummary,
    deploymentStateCheck,
    completionWindowEndNs: String(completionWindowEndNs),
    completionExtensionUsed,
    completionUsedPreviousRound,
    previousRoundCompletionCheck,
    completionFoundAfterOriginalWindow,
    completionCandidatesCount: completionCandidates.length,
    completionCandidatesSample: completionCandidates.slice(-20),
    earliestCompletionMatch,
    completionTiming: {
      matched: Boolean(earliestCompletionMatch && Number(earliestCompletionMatch.lokiTsNs) > startNs),
      reason: earliestCompletionMatch ? null : "no_completed_cache_log_for_target_deployment",
      startLokiTsNs: String(startNs),
      expectedStartFromCompletionLokiTsNs: null,
      deltaSec: null,
      toleranceSec: null,
    },
    failureEvidenceCount: timelineUniqueFailureErrors.length,
    failureEvidence: timelineUniqueFailureErrors.slice(0, 20),
    uniqueFailureErrors: timelineUniqueFailureErrors,
    restartEvidence,
    fastPathTimelineUsed: true,
  };
  return out;
}

async function buildFastTimelinesByEnv(step3_2ByEnv, { regionContext = null } = {}) {
  const byEnv = new Map();
  const decisionTimelinePattern = `${LOG_PATTERNS.cachePrepStart}|${LOG_PATTERNS.runtimeCompletion}|${LOG_PATTERNS.deploymentListAny}|starting decision server|starting authz decision server`;

  for (const [env, item] of Object.entries(step3_2ByEnv || {})) {
    const links = item?.links || [];
    if (!links.length) continue;
    const podToReqTs = new Map();
    let minReqTs = null;
    let maxReqTs = null;
    for (const link of links) {
      const pod = String(link?.request?.pod || "").trim();
      const reqTsNs = Number(link?.request?.lokiTsNs);
      if (!pod || !Number.isFinite(reqTsNs) || reqTsNs <= 0) continue;
      if (!podToReqTs.has(pod)) podToReqTs.set(pod, []);
      podToReqTs.get(pod).push(reqTsNs);
      if (!Number.isFinite(minReqTs) || reqTsNs < minReqTs) minReqTs = reqTsNs;
      if (!Number.isFinite(maxReqTs) || reqTsNs > maxReqTs) maxReqTs = reqTsNs;
    }
    if (!Number.isFinite(minReqTs) || !Number.isFinite(maxReqTs)) continue;

    const podTimelines = new Map();
    for (const [pod, reqList] of podToReqTs.entries()) {
      let podMin = reqList[0];
      let podMax = reqList[0];
      for (let i = 1; i < reqList.length; i += 1) {
        if (reqList[i] < podMin) podMin = reqList[i];
        if (reqList[i] > podMax) podMax = reqList[i];
      }
      const startNs = Math.max(0, Math.floor(podMin - 10 * 60 * 1e9));
      const endNs = Math.floor(podMax + 30 * 60 * 1e9);
      const decisionTimelineExpr =
        `${buildDecisionSelector(env, pod)}` +
        ` != "/live" != "/ready" |~ "${decisionTimelinePattern}"`;
      const entries = await fetchLokiEntriesWithAutoSplitOnLimit(decisionTimelineExpr, {
        startNs,
        endNs,
        direction: "FORWARD",
        limit: 3000,
        regionContext,
        splitMaxDepth: 12,
        splitMinWindowMinutes: 1,
        logStep: "STEP3.TL",
        logContext: { env, pod, timeline: "decision" },
      });
      const cachePrepStarts = [];
      const completionRecords = [];
      const deploymentListRecords = [];
      const defaultDeploymentEvents = [];
      const restartEntries = [];
      const failureRecords = [];
      for (const e of entries) {
        const parsedObj = extractJsonObjectFromLogLine(e.line);
        const recStart = parseCachePrepStartRecord(e.line, e.lokiTsNs);
        if (
          recStart &&
          new RegExp(LOG_PATTERNS.cachePrepStart, "i").test(String(recStart?.message || recStart?.line || ""))
        ) {
          cachePrepStarts.push(recStart);
        }
        const recComp = parseCompletedCachePrepareRecord(e.line, e.lokiTsNs);
        if (recComp) completionRecords.push(recComp);
        const recList = parseDeploymentListCacheUpdateRecord(e.line, e.lokiTsNs);
        if (recList) {
          deploymentListRecords.push(recList);
          if (recList.kind === "default") defaultDeploymentEvents.push(recList);
        }
        const failureRec = extractErrorRecordFromParsedLogObject(parsedObj);
        if (failureRec) {
          failureRecords.push({
            lokiTsNs: e.lokiTsNs,
            key: failureRec.key,
            display: failureRec.display,
            traceID: String(
              parsedObj?.traceID ?? parsedObj?.traceId ?? parsedObj?.trace_id ?? "",
            ).trim() || null,
            timestamp: parsedObj?.timestamp ? String(parsedObj.timestamp) : null,
            message: parsedObj?.message ? String(parsedObj.message) : null,
            error: parsedObj?.error ? String(parsedObj.error) : null,
            line: e.line,
          });
        }
        const msg = String(parsedObj?.message || e.line || "").toLowerCase();
        if (
          msg.includes("starting decision server") ||
          msg.includes("starting authz decision server")
        ) {
          restartEntries.push({
            lokiTsNs: e.lokiTsNs,
            timestamp: parsedObj?.timestamp || null,
            message: parsedObj?.message || null,
            line: e.line,
          });
        }
      }
      cachePrepStarts.sort((a, b) => Number(a?.lokiTsNs || 0) - Number(b?.lokiTsNs || 0));
      completionRecords.sort((a, b) => Number(a?.lokiTsNs || 0) - Number(b?.lokiTsNs || 0));
      deploymentListRecords.sort((a, b) => Number(a?.lokiTsNs || 0) - Number(b?.lokiTsNs || 0));
      defaultDeploymentEvents.sort((a, b) => Number(a?.lokiTsNs || 0) - Number(b?.lokiTsNs || 0));
      restartEntries.sort((a, b) => Number(a?.lokiTsNs || 0) - Number(b?.lokiTsNs || 0));
      failureRecords.sort((a, b) => Number(a?.lokiTsNs || 0) - Number(b?.lokiTsNs || 0));
      const deploymentListRounds = buildDeploymentListCacheRounds(deploymentListRecords);
      const deploymentListRoundsChrono = [...deploymentListRounds].sort(
        (a, b) => Number(a?.startLokiTsNs || 0) - Number(b?.startLokiTsNs || 0),
      );
      podTimelines.set(pod, {
        pod,
        startNs,
        endNs,
        decisionTimelineExpr,
        cachePrepStarts,
        completionRecords,
        deploymentListRecords,
        deploymentListRounds,
        deploymentListRoundsChrono,
        defaultDeploymentEvents,
        restartEntries,
        failureRecords,
      });
      appendRunLog("STEP3.TL", "decision timeline built", {
        env,
        pod,
        startNs: String(startNs),
        endNs: String(endNs),
        cachePrepStartCount: cachePrepStarts.length,
        completionCount: completionRecords.length,
        deploymentListRecordCount: deploymentListRecords.length,
        deploymentListRoundCount: deploymentListRounds.length,
        restartCount: restartEntries.length,
        failureRecordCount: failureRecords.length,
      });
    }

    const mgmtStartNs = Math.max(0, Math.floor(minReqTs - 10 * 60 * 1e9));
    const mgmtEndNs = Math.floor(maxReqTs + 10 * 60 * 1e9);
    const managementTimelineExpr =
      `{ container=~"management", namespace="authz", prd_env="${env}" }` +
      ` != "/live" != "/ready" |~ "update deployment state successfully"`;
    const mgmtEntries = await fetchLokiEntriesWithAutoSplitOnLimit(managementTimelineExpr, {
      startNs: mgmtStartNs,
      endNs: mgmtEndNs,
      direction: "FORWARD",
      limit: 3000,
      regionContext,
      splitMaxDepth: 12,
      splitMinWindowMinutes: 1,
      logStep: "STEP3.TL",
      logContext: { env, timeline: "management" },
    });
    const managementStateRecords = [];
    for (const e of mgmtEntries) {
      const rec = parseDeploymentStateUpdateRecord(e.line, e.lokiTsNs);
      if (!rec) continue;
      managementStateRecords.push(rec);
    }
    managementStateRecords.sort((a, b) => Number(a?.lokiTsNs || 0) - Number(b?.lokiTsNs || 0));
    byEnv.set(env, {
      env,
      podTimelines,
      managementTimelineExpr,
      managementStateRecords,
      managementStateIndexByDeployment: buildDeploymentStateIndexByDeployment(managementStateRecords),
    });
    appendRunLog("STEP3.TL", "management timeline built", {
      env,
      startNs: String(mgmtStartNs),
      endNs: String(mgmtEndNs),
      deploymentStateRecordCount: managementStateRecords.length,
      deploymentStateDeploymentCount: byEnv.get(env).managementStateIndexByDeployment.size,
    });
  }
  return byEnv;
}

async function analyzeStep3_3ForLink(
  link,
  {
    errorLimit = 3000,
    defaultLookbackMinutes = 10,
    queryLokiFn = null,
    prefetchedTraceErrorSummary = null,
  } = {},
) {
  const queryLokiForStep = typeof queryLokiFn === "function" ? queryLokiFn : queryLoki;
  const env = link?.request?.env;
  const pod = link?.request?.pod || null;
  const reqTsNs = Number(link?.request?.lokiTsNs);
  const reqStartTsNs = Number(link?.request?.requestStartTimeNs);
  const runtimeCacheStartTimeNs = Number(link?.previousLog?.lokiTsNs);
  const reqInfo = extractRequestedDeploymentFromUrl(link?.request?.url);
  const traceID = String(link?.request?.traceID || "").trim();
  const logCtx = {
    env,
    traceID: traceID || null,
    pod: pod || null,
    requestCompleteTimeNs: Number.isFinite(reqTsNs) ? String(reqTsNs) : null,
    requestStartTimeNs:
      Number.isFinite(reqStartTsNs) && reqStartTsNs > 0 ? String(reqStartTsNs) : null,
    requestUrl: link?.request?.url || null,
    requestDeploymentType: reqInfo.type,
    requestDeploymentID: reqInfo.deploymentID || null,
  };
  appendRunLog("STEP3.3", "start link analysis", logCtx);

  if (!env || !Number.isFinite(reqTsNs) || reqTsNs <= 0) {
    appendRunLog("STEP3.3", "invalid request context, mark cache_load_unknown", logCtx);
    return {
      conclusion: "cache_load_unknown",
      reason: "invalid_request_context",
      successfulDeploymentsAll: [],
      successfulDeploymentsLatestTop3: [],
      failureEvidence: [],
    };
  }
  if (!link?.matched || !Number.isFinite(runtimeCacheStartTimeNs) || runtimeCacheStartTimeNs <= 0 || runtimeCacheStartTimeNs >= reqTsNs) {
    const restartLookbackMinutesNoAnchor = 10;
    const restartLookbackNsNoAnchor = restartLookbackMinutesNoAnchor * 60 * 1e9;
    const restartQueryStartNsNoAnchor = Math.max(
      0,
      subtractNsWithPrecisionGuard(reqTsNs, restartLookbackNsNoAnchor),
    );
    const restartQueryEndNsNoAnchor = subtractNsWithPrecisionGuard(reqTsNs, 1);
    const restartExprNoAnchor =
      `${buildDecisionSelector(env, pod)}` +
      ` != "/live" != "/ready"` +
      ` |~ "starting decision server|starting authz decision server"`;
    const restartJsonNoAnchor = await queryLokiForStep(restartExprNoAnchor, {
      startNs: restartQueryStartNsNoAnchor,
      endNs: restartQueryEndNsNoAnchor,
      direction: "BACKWARD",
      limit: 20,
    });
    const restartEntriesNoAnchor = [];
    for (const stream of restartJsonNoAnchor?.data?.result || []) {
      for (const [tsNs, line] of stream.values || []) {
        const parsed = extractJsonObjectFromLogLine(line);
        restartEntriesNoAnchor.push({
          lokiTsNs: String(tsNs),
          timestamp: parsed?.timestamp ? String(parsed.timestamp) : null,
          message: parsed?.message ? String(parsed.message) : null,
          line: String(line || ""),
        });
      }
    }
    const restartEvidenceNoAnchor = {
      count: restartEntriesNoAnchor.length,
      entries: restartEntriesNoAnchor.slice(0, 20),
      query: restartExprNoAnchor,
      startNs: String(restartQueryStartNsNoAnchor),
      endNs: String(restartQueryEndNsNoAnchor),
      lookbackNs: String(restartLookbackNsNoAnchor),
      mode: "request_relative_fallback_no_step3_2_anchor",
    };

    if (restartEvidenceNoAnchor.count > 0) {
      appendRunLog("STEP3.3", "missing Step 3.2 anchor; fallback restart evidence found in request-relative window", {
        ...logCtx,
        runtimeCacheStartTimeNs: Number.isFinite(runtimeCacheStartTimeNs) ? String(runtimeCacheStartTimeNs) : null,
        restartEvidenceCount: restartEvidenceNoAnchor.count,
        restartWindowStartNs: restartEvidenceNoAnchor.startNs,
        restartWindowEndNs: restartEvidenceNoAnchor.endNs,
      });
      return {
        conclusion: "cache_load_failure",
        reason: "restart_warmup",
        successfulDeploymentsAll: [],
        successfulDeploymentsLatestTop3: [],
        failureEvidence: [],
        restartEvidence: restartEvidenceNoAnchor,
      };
    }

    appendRunLog("STEP3.3", "missing or invalid Step 3.2 anchor, mark cache_load_unknown", {
      ...logCtx,
      runtimeCacheStartTimeNs: Number.isFinite(runtimeCacheStartTimeNs) ? String(runtimeCacheStartTimeNs) : null,
      restartEvidenceCount: restartEvidenceNoAnchor.count,
      restartWindowStartNs: restartEvidenceNoAnchor.startNs,
      restartWindowEndNs: restartEvidenceNoAnchor.endNs,
    });
    return {
      conclusion: "cache_load_unknown",
      reason: "missing_or_invalid_step3_2_anchor",
      successfulDeploymentsAll: [],
      successfulDeploymentsLatestTop3: [],
      failureEvidence: [],
      restartEvidence: restartEvidenceNoAnchor,
    };
  }

  const startNs = Math.floor(runtimeCacheStartTimeNs);
  const endNs = subtractNsWithPrecisionGuard(reqTsNs, 1);

  const deploymentListCacheExpr =
    `${buildDecisionSelector(env, pod)}` +
    ` != "/live" != "/ready"` +
    ` |~ "${LOG_PATTERNS.deploymentListAny}"`;
  const deploymentListCacheWindowEndNs = Math.floor(reqTsNs + 15 * 1e9);
  // Deployment-list cache refresh is independent from runtime-cache prep start.
  // Keep this search request-relative with a fixed 60s lookback from Step3.3-B end.
  const deploymentListCacheWindowStartNs = Math.max(0, Math.floor(deploymentListCacheWindowEndNs - 60 * 1e9));
  const deploymentListCacheJson = await queryLokiForStep(deploymentListCacheExpr, {
    startNs: deploymentListCacheWindowStartNs,
    endNs: deploymentListCacheWindowEndNs,
    direction: "FORWARD",
    limit: 3000,
  });
  const deploymentListCacheCandidates = [];
  for (const stream of deploymentListCacheJson?.data?.result || []) {
    for (const [tsNs, line] of stream.values || []) {
      const rec = parseDeploymentListCacheUpdateRecord(line, tsNs);
      if (!rec) continue;
      deploymentListCacheCandidates.push(rec);
    }
  }
  const defaultDeploymentCandidates = deploymentListCacheCandidates
    .filter(rec => String(rec?.kind || "") === "default" && Number(rec?.lokiTsNs || 0) <= endNs)
    .map(rec => ({
      defaultDeploymentID: rec?.deploymentID ? String(rec.deploymentID) : null,
      lokiTsNs: rec?.lokiTsNs ? String(rec.lokiTsNs) : null,
      timestamp: rec?.timestamp ? String(rec.timestamp) : null,
      message: rec?.message ? String(rec.message) : null,
      line: rec?.line ? String(rec.line) : "",
    }));
  defaultDeploymentCandidates.sort((a, b) => Number(b.lokiTsNs) - Number(a.lokiTsNs));
  const resolvedDefaultDeployment = defaultDeploymentCandidates[0] || null;
  appendRunLog("STEP3.3", "default deployment lookup completed (from deployment-list cache query)", {
    ...logCtx,
    defaultCandidatesCount: defaultDeploymentCandidates.length,
    resolvedDefaultDeploymentID: resolvedDefaultDeployment?.defaultDeploymentID || null,
    defaultLookupStartNs: String(deploymentListCacheWindowStartNs),
    defaultLookupEndNs: String(endNs),
    defaultLookupSource: "step3_3_deployment_list_cache_query",
    defaultLookupExcludedPostRequestEntries: true,
  });

  let targetDeploymentID = null;
  if (reqInfo.type === "explicit") targetDeploymentID = reqInfo.deploymentID;
  if (reqInfo.type === "default") targetDeploymentID = resolvedDefaultDeployment?.defaultDeploymentID || null;
  const deploymentListCacheRounds = buildDeploymentListCacheRounds(deploymentListCacheCandidates);
  const deploymentListCacheRoundsLatest2 = deploymentListCacheRounds.slice(0, 2);
  const deploymentListCacheCheck = evaluateDeploymentListCachePresence({
    reqInfo,
    reqTsNs,
    resolvedDefaultDeploymentID: resolvedDefaultDeployment?.defaultDeploymentID || null,
    roundsLatest2: deploymentListCacheRoundsLatest2,
  });
  const latestRoundDistinctDeploymentCount = new Set(
    (deploymentListCacheRoundsLatest2?.[0]?.deployments || []).map(x => String(x || "").trim()).filter(Boolean),
  ).size;
  appendRunLog("STEP3.3", "deployment list cache cross-check evaluated", {
    ...logCtx,
    targetDeploymentID: deploymentListCacheCheck?.targetDeploymentID || targetDeploymentID || null,
    deploymentListDecision: deploymentListCacheCheck?.decision || null,
    deploymentListReason: deploymentListCacheCheck?.reason || null,
    deploymentListUsedRound: deploymentListCacheCheck?.usedRound || null,
    deploymentListUsedRoundHitKind: deploymentListCacheCheck?.usedRoundTargetHitKind || null,
    deploymentListRoundsCount: deploymentListCacheRounds.length,
  });
  let deploymentListPostRequestCheck = {
    checked: false,
    reason: "not_required",
    targetDeploymentID: targetDeploymentID || null,
    roundsChecked: 0,
    foundInCheckedRounds: false,
    checkedRounds: [],
    matchedRound: null,
    window: null,
  };
  if (deploymentListCacheCheck?.decision === "target_not_ready") {
    if (latestRoundDistinctDeploymentCount >= 3) {
      deploymentListPostRequestCheck = {
        checked: false,
        reason: "skipped_target_missing_in_last_round_with_3_distinct_deployments",
        targetDeploymentID: deploymentListCacheCheck?.targetDeploymentID || targetDeploymentID || null,
        roundsChecked: 0,
        foundInCheckedRounds: false,
        checkedRounds: [],
        matchedRound: null,
        roundsFound: deploymentListCacheRounds.length,
        window: null,
      };
      appendRunLog("STEP3.3", "deployment list post-request extended check skipped", {
        ...logCtx,
        postReason: deploymentListPostRequestCheck.reason,
        latestRoundDistinctDeploymentCount,
        deploymentListRoundsCount: deploymentListCacheRounds.length,
        postTargetDeploymentID: deploymentListPostRequestCheck.targetDeploymentID,
      });
    } else {
      const postStartNs = Math.floor(reqTsNs);
      const postEndNs = Math.floor(reqTsNs + 10 * 60 * 1e9);
      const postJson = await queryLokiForStep(deploymentListCacheExpr, {
        startNs: postStartNs,
        endNs: postEndNs,
        direction: "FORWARD",
        limit: 3000,
      });
      const postCandidates = [];
      for (const stream of postJson?.data?.result || []) {
        for (const [tsNs, line] of stream.values || []) {
          const rec = parseDeploymentListCacheUpdateRecord(line, tsNs);
          if (!rec) continue;
          postCandidates.push(rec);
        }
      }
      const postRounds = buildDeploymentListCacheRounds(postCandidates);
      const evaluated = evaluateDeploymentListCacheAfterRequest({
        reqInfo,
        reqTsNs,
        resolvedDefaultDeploymentID: resolvedDefaultDeployment?.defaultDeploymentID || null,
        roundsAfterRequest: postRounds,
        roundsToCheck: 2,
      });
      deploymentListPostRequestCheck = {
        ...evaluated,
        window: { startNs: String(postStartNs), endNs: String(postEndNs) },
        roundsFound: postRounds.length,
      };
      appendRunLog("STEP3.3", "deployment list post-request extended check evaluated", {
        ...logCtx,
        windowStartNs: String(postStartNs),
        windowEndNs: String(postEndNs),
        roundsFound: deploymentListPostRequestCheck.roundsFound,
        roundsChecked: deploymentListPostRequestCheck.roundsChecked,
        foundInCheckedRounds: deploymentListPostRequestCheck.foundInCheckedRounds,
        postReason: deploymentListPostRequestCheck.reason,
        postTargetDeploymentID: deploymentListPostRequestCheck.targetDeploymentID,
      });
    }
  }
  const traceExpr =
    `${buildDecisionSelector(env, pod)}` +
    ` != "/live" != "/ready" |~ "${String(link?.request?.traceID || "").trim()}"`;
  let traceErrorSummary = {
    category: "unknown",
    matchedPattern: null,
    matchedEntry: null,
    runtimeServicesCount: 0,
    deploymentListCount: 0,
    bothPatternsPresent: false,
    runtimeServicesFirstHitTsNs: null,
    deploymentListFirstHitTsNs: null,
    entriesSample: [],
  };
  if (traceID) {
    if (
      prefetchedTraceErrorSummary &&
      typeof prefetchedTraceErrorSummary === "object" &&
      String(prefetchedTraceErrorSummary.traceID || "") === traceID
    ) {
      appendRunLog("STEP3.3", "using prefetched trace error summary from reuse signature lookup", {
        ...logCtx,
      });
      traceErrorSummary = {
        ...traceErrorSummary,
        ...prefetchedTraceErrorSummary,
      };
    } else {
      const traceWindowStartNs =
        Number.isFinite(reqStartTsNs) && reqStartTsNs > 0 && reqStartTsNs <= reqTsNs
          ? Math.floor(reqStartTsNs)
          : Math.floor(reqTsNs);
      const traceWindowEndNs = Math.floor(reqTsNs);
      const traceJson = await queryLokiForStep(traceExpr, {
        startNs: traceWindowStartNs,
        endNs: traceWindowEndNs,
        direction: "BACKWARD",
        limit: 300,
      });
      const traceEntries = [];
      for (const stream of traceJson?.data?.result || []) {
        for (const [tsNs, line] of stream.values || []) {
          const parsed = extractJsonObjectFromLogLine(line);
          if (!parsed || typeof parsed !== "object") continue;
          traceEntries.push({
            lokiTsNs: String(tsNs),
            level: parsed.level ? String(parsed.level) : null,
            error: parsed.error ? String(parsed.error) : null,
            message: parsed.message ? String(parsed.message) : null,
            deploymentID: parsed.deploymentID ? String(parsed.deploymentID) : null,
            traceID: parsed.traceID ? String(parsed.traceID) : null,
            timestamp: parsed.timestamp ? String(parsed.timestamp) : null,
            line: String(line || ""),
          });
        }
      }
      traceEntries.sort((a, b) => Number(a.lokiTsNs) - Number(b.lokiTsNs));
      const classified = classifyDecision404ErrorByTrace(traceEntries);
      traceErrorSummary = {
        ...traceErrorSummary,
        traceID,
        category: classified.category,
        matchedPattern: classified.matchedPattern,
        matchedEntry: classified.matchedEntry,
        runtimeServicesCount: Number(classified.runtimeServicesCount || 0),
        deploymentListCount: Number(classified.deploymentListCount || 0),
        bothPatternsPresent: Boolean(classified.bothPatternsPresent),
        runtimeServicesFirstHitTsNs: classified.runtimeServicesFirstHitTsNs || null,
        deploymentListFirstHitTsNs: classified.deploymentListFirstHitTsNs || null,
        entriesSample: traceEntries.slice(-30),
      };
    }
    appendRunLog("STEP3.3", "trace error category determined", {
      ...logCtx,
      traceCategory: traceErrorSummary.category,
      tracePattern: traceErrorSummary.matchedPattern,
      traceRuntimeServicesCount: traceErrorSummary.runtimeServicesCount,
      traceDeploymentListCount: traceErrorSummary.deploymentListCount,
      traceBothPatternsPresent: traceErrorSummary.bothPatternsPresent,
      traceRuntimeServicesFirstHitTsNs: traceErrorSummary.runtimeServicesFirstHitTsNs,
      traceDeploymentListFirstHitTsNs: traceErrorSummary.deploymentListFirstHitTsNs,
    });
  }
  const deploymentStateExpr =
    `{ container=~"decision|management", namespace="authz", prd_env="${env}" }` +
    ` != "/live" != "/ready" |~ "update deployment state successfully"`;
  let deploymentStateCheck = {
    checked: false,
    reason: "not_required",
    targetDeploymentID: deploymentListCacheCheck?.targetDeploymentID || targetDeploymentID || null,
    query: null,
    window: null,
    found: false,
    latest: null,
    isServingState: null,
    cacheRoundHitLokiTsNs: deploymentListCacheCheck?.usedRoundTargetHitLokiTsNs || null,
    latestAtOrBeforeCacheHit: null,
    latestAtOrBeforeCacheHitIsServing: null,
    servingTransitionAfterCacheHitBeforeRequest: false,
    servingTransitionEvent: null,
  };
  const cacheRoundHitTsNs = Number(deploymentListCacheCheck?.usedRoundTargetHitLokiTsNs || 0);
  const stateCheckEndNs = Number.isFinite(reqTsNs) && reqTsNs > 0 ? Math.floor(reqTsNs) : cacheRoundHitTsNs;
  if (
    deploymentListCacheCheck?.decision === "target_present" &&
    deploymentListCacheCheck?.usedRoundTargetHitKind === "deployment" &&
    deploymentStateCheck.targetDeploymentID &&
    Number.isFinite(stateCheckEndNs) &&
    stateCheckEndNs > 0
  ) {
    const stateCheckStartNs = Math.max(0, Math.floor(stateCheckEndNs - 30 * 60 * 1e9));
    deploymentStateCheck.checked = true;
    deploymentStateCheck.reason = null;
    deploymentStateCheck.query = deploymentStateExpr;
    deploymentStateCheck.window = {
      startNs: String(stateCheckStartNs),
      endNs: String(stateCheckEndNs),
    };
    const stateJson = await queryLokiForStep(deploymentStateExpr, {
      startNs: stateCheckStartNs,
      endNs: stateCheckEndNs,
      direction: "BACKWARD",
      limit: 3000,
    });
    const stateCandidates = [];
    for (const stream of stateJson?.data?.result || []) {
      for (const [tsNs, line] of stream.values || []) {
        const rec = parseDeploymentStateUpdateRecord(line, tsNs);
        if (!rec) continue;
        if (rec.deploymentID !== deploymentStateCheck.targetDeploymentID) continue;
        stateCandidates.push(rec);
      }
    }
    stateCandidates.sort((a, b) => Number(b.lokiTsNs) - Number(a.lokiTsNs));
    const servingStates = new Set(["Activated", "Default", "Activating"]);
    const latestBeforeRequest =
      stateCandidates.find(x => Number(x?.lokiTsNs) <= Number(reqTsNs)) || stateCandidates[0] || null;
    const latestAtOrBeforeCacheHit =
      stateCandidates.find(x => Number(x?.lokiTsNs) <= Number(cacheRoundHitTsNs)) || null;

    const transitionEvent =
      stateCandidates.find(x => {
        const ts = Number(x?.lokiTsNs);
        if (!Number.isFinite(ts)) return false;
        if (!(ts > Number(cacheRoundHitTsNs) && ts <= Number(reqTsNs))) return false;
        const cur = String(x?.curState || "");
        const next = String(x?.newState || "");
        return !servingStates.has(cur) && servingStates.has(next);
      }) || null;

    if (latestBeforeRequest) {
      deploymentStateCheck.found = true;
      deploymentStateCheck.latest = latestBeforeRequest;
      deploymentStateCheck.isServingState = servingStates.has(String(latestBeforeRequest.newState || ""));
      deploymentStateCheck.latestAtOrBeforeCacheHit = latestAtOrBeforeCacheHit;
      deploymentStateCheck.latestAtOrBeforeCacheHitIsServing = latestAtOrBeforeCacheHit
        ? servingStates.has(String(latestAtOrBeforeCacheHit.newState || ""))
        : null;
      deploymentStateCheck.servingTransitionEvent = transitionEvent;
      deploymentStateCheck.servingTransitionAfterCacheHitBeforeRequest = Boolean(
        transitionEvent ||
          (latestAtOrBeforeCacheHit &&
            !servingStates.has(String(latestAtOrBeforeCacheHit.newState || "")) &&
            servingStates.has(String(latestBeforeRequest.newState || "")) &&
            Number(latestBeforeRequest.lokiTsNs) > Number(cacheRoundHitTsNs) &&
            Number(latestBeforeRequest.lokiTsNs) <= Number(reqTsNs)),
      );
    } else {
      deploymentStateCheck.found = false;
      deploymentStateCheck.latest = null;
      deploymentStateCheck.isServingState = null;
      deploymentStateCheck.latestAtOrBeforeCacheHit = latestAtOrBeforeCacheHit;
      deploymentStateCheck.latestAtOrBeforeCacheHitIsServing = latestAtOrBeforeCacheHit
        ? servingStates.has(String(latestAtOrBeforeCacheHit.newState || ""))
        : null;
      deploymentStateCheck.servingTransitionEvent = transitionEvent;
      deploymentStateCheck.servingTransitionAfterCacheHitBeforeRequest = Boolean(transitionEvent);
    }
    appendRunLog("STEP3.3", "deployment state check evaluated", {
      ...logCtx,
      deploymentStateTarget: deploymentStateCheck.targetDeploymentID,
      cacheRoundHitLokiTsNs: deploymentStateCheck.cacheRoundHitLokiTsNs,
      latestAtOrBeforeCacheHitLokiTsNs:
        deploymentStateCheck.latestAtOrBeforeCacheHit?.lokiTsNs || null,
      latestAtOrBeforeCacheHitNewState:
        deploymentStateCheck.latestAtOrBeforeCacheHit?.newState || null,
      latestByRequestLokiTsNs: deploymentStateCheck.latest?.lokiTsNs || null,
      latestByRequestNewState: deploymentStateCheck.latest?.newState || null,
      transitionEventLokiTsNs: deploymentStateCheck.servingTransitionEvent?.lokiTsNs || null,
      transitionEventCurState: deploymentStateCheck.servingTransitionEvent?.curState || null,
      transitionEventNewState: deploymentStateCheck.servingTransitionEvent?.newState || null,
      servingTransitionAfterCacheHitBeforeRequest:
        deploymentStateCheck.servingTransitionAfterCacheHitBeforeRequest,
      stateCheckWindowStartNs: String(stateCheckStartNs),
      stateCheckWindowEndNs: String(stateCheckEndNs),
    });
  }

  const errorExpr =
    `${buildDecisionSelector(env, pod)}` +
    ` != "/live" != "/ready"` +
    ` |~ "${LOG_PATTERNS.cachePrepStart}"`;

  const completionExpr =
    `${buildDecisionSelector(env, pod)}` +
    ` != "/live" != "/ready" |~ "${LOG_PATTERNS.runtimeCompletion}"`;

  async function collectCompletionRecordsInRange(rangeStartNs, rangeEndNs) {
    const completionJson = await queryLokiForStep(completionExpr, {
      startNs: rangeStartNs,
      endNs: rangeEndNs,
      direction: "BACKWARD",
      limit: 3000,
    });
    const out = [];
    for (const stream of completionJson?.data?.result || []) {
      for (const [tsNs, line] of stream.values || []) {
        const rec = parseCompletedCachePrepareRecord(line, tsNs);
        if (!rec) continue;
        out.push(rec);
      }
    }
    out.sort((a, b) => Number(a.lokiTsNs) - Number(b.lokiTsNs));
    return out;
  }

  function distinctCompletionByDeployment(records) {
    const byDeployment = new Map();
    for (const r of records || []) {
      const id = String(r?.deploymentID || "").trim();
      if (!id) continue;
      if (!byDeployment.has(id)) {
        byDeployment.set(id, {
          latestLegacySingle: null,
          latestPolicies: null,
          latestRoleAssignments: null,
        });
      }
      const slot = byDeployment.get(id);
      const ts = Number(r?.lokiTsNs || 0);
      if (!Number.isFinite(ts)) continue;
      if (r?.completionKind === "legacy_single") {
        if (!slot.latestLegacySingle || ts > Number(slot.latestLegacySingle?.lokiTsNs || 0)) {
          slot.latestLegacySingle = r;
        }
        continue;
      }
      if (r?.completionKind === "new_policies") {
        if (!slot.latestPolicies || ts > Number(slot.latestPolicies?.lokiTsNs || 0)) {
          slot.latestPolicies = r;
        }
        continue;
      }
      if (r?.completionKind === "new_role_assignments") {
        if (
          !slot.latestRoleAssignments ||
          ts > Number(slot.latestRoleAssignments?.lokiTsNs || 0)
        ) {
          slot.latestRoleAssignments = r;
        }
      }
    }

    const out = [];
    for (const [id, slot] of byDeployment.entries()) {
      let evidence = null;
      let completionEvidenceMode = null;
      if (slot.latestLegacySingle) {
        evidence = slot.latestLegacySingle;
        completionEvidenceMode = "legacy_single";
      } else if (slot.latestPolicies && slot.latestRoleAssignments) {
        const pTs = Number(slot.latestPolicies.lokiTsNs || 0);
        const rTs = Number(slot.latestRoleAssignments.lokiTsNs || 0);
        evidence = pTs >= rTs ? slot.latestPolicies : slot.latestRoleAssignments;
        completionEvidenceMode = "new_parallel_both_required";
      }
      if (!evidence) continue;
      out.push({
        deploymentID: id,
        lokiTsNs: evidence.lokiTsNs,
        elapsedTime: evidence.elapsedTime || null,
        elapsedTimeMs: evidence.elapsedTimeMs,
        timestamp: evidence.timestamp,
        message: evidence.message || null,
        completionKind: evidence.completionKind || null,
        completionEvidenceMode,
      });
    }
    out.sort((a, b) => Number(b.lokiTsNs) - Number(a.lokiTsNs));
    return out;
  }

  let completionWindowEndNs = endNs;
  let completionExtensionUsed = false;
  let completionUsedPreviousRound = false;
  const previousRoundCompletionCheck = {
    checked: false,
    reason: "not_required",
    previousRoundStartNs: null,
    previousRoundEndNs: null,
    previousRoundDistinctCount: 0,
    previousRoundContainsTarget: false,
    usedAsCompletionEvidence: false,
    error: null,
  };
  const completionCandidatesOriginal = await collectCompletionRecordsInRange(startNs, endNs);
  const completionRoundMatchedOriginal = completionCandidatesOriginal.filter(r =>
    completionMatchesStartRound(r, startNs),
  );
  const completionDistinctOriginalAll = distinctCompletionByDeployment(completionRoundMatchedOriginal);
  const completionDistinctOriginalTop3 = completionDistinctOriginalAll.slice(0, 3);

  let completionCandidates = completionCandidatesOriginal;
  let completionRoundMatched = completionRoundMatchedOriginal;
  let completionDistinctUsedAll = completionDistinctOriginalAll;
  let completionDistinctUsedTop3 = completionDistinctOriginalTop3;
  let shouldRunPostRequestExtension = false;
  if (completionDistinctOriginalTop3.length < 3) {
    previousRoundCompletionCheck.checked = true;
    const previousRoundLookupEndNs = subtractNsWithPrecisionGuard(startNs, 1);
    if (!(Number.isFinite(previousRoundLookupEndNs) && previousRoundLookupEndNs > 0)) {
      previousRoundCompletionCheck.reason = "invalid_previous_round_lookup_window";
      appendRunLog("STEP3.3", "warning: previous round lookup skipped due to invalid window", {
        ...logCtx,
        startNs: String(startNs),
        previousRoundLookupEndNs: String(previousRoundLookupEndNs),
      });
    } else {
      const previousRoundLookupStartNs = Math.max(0, Math.floor(previousRoundLookupEndNs - 60 * 60 * 1e9));
      const previousRoundAnchorExpr =
        `${buildDecisionSelector(env, pod)}` +
        ` != "/live" != "/ready"` +
        ` |~ "${LOG_PATTERNS.cachePrepStart}"`;
      try {
        const previousRoundAnchorJson = await queryLokiForStep(previousRoundAnchorExpr, {
          startNs: previousRoundLookupStartNs,
          endNs: previousRoundLookupEndNs,
          direction: "BACKWARD",
          limit: 20,
        });
        const previousRoundAnchor = pickLatestLokiLogAtOrBeforeTs(
          previousRoundAnchorJson,
          previousRoundLookupEndNs,
        );
        const previousRoundStartNs = Number(previousRoundAnchor?.tsNsNum || 0);
        if (!Number.isFinite(previousRoundStartNs) || previousRoundStartNs <= 0) {
          previousRoundCompletionCheck.reason = "previous_round_anchor_not_found";
          appendRunLog("STEP3.3", "warning: previous round anchor not found", {
            ...logCtx,
            previousRoundLookupStartNs: String(previousRoundLookupStartNs),
            previousRoundLookupEndNs: String(previousRoundLookupEndNs),
            previousRoundAnchorExpr,
          });
        } else {
          previousRoundCompletionCheck.reason = "checked";
          previousRoundCompletionCheck.previousRoundStartNs = String(previousRoundStartNs);
          previousRoundCompletionCheck.previousRoundEndNs = String(previousRoundLookupEndNs);
          try {
            const previousRoundCandidates = await collectCompletionRecordsInRange(
              previousRoundStartNs,
              previousRoundLookupEndNs,
            );
            const previousRoundMatched = previousRoundCandidates.filter(r =>
              completionMatchesStartRound(r, previousRoundStartNs),
            );
            const previousRoundDistinctAll = distinctCompletionByDeployment(previousRoundMatched);
            const previousRoundDistinctTop3 = previousRoundDistinctAll.slice(0, 3);
            const previousRoundContainsTarget = Boolean(
              targetDeploymentID &&
                previousRoundDistinctTop3.some(
                  x => String(x?.deploymentID || "") === String(targetDeploymentID || ""),
                ),
            );
            previousRoundCompletionCheck.previousRoundDistinctCount = previousRoundDistinctTop3.length;
            previousRoundCompletionCheck.previousRoundContainsTarget = previousRoundContainsTarget;
            if (previousRoundDistinctTop3.length >= 3 && previousRoundContainsTarget) {
              completionUsedPreviousRound = true;
              previousRoundCompletionCheck.usedAsCompletionEvidence = true;
              completionCandidates = previousRoundCandidates;
              completionRoundMatched = previousRoundMatched;
              completionDistinctUsedAll = previousRoundDistinctAll;
              completionDistinctUsedTop3 = previousRoundDistinctTop3;
              completionWindowEndNs = previousRoundLookupEndNs;
              appendRunLog("STEP3.3", "using previous runtime-cache round completion evidence", {
                ...logCtx,
                previousRoundStartNs: String(previousRoundStartNs),
                previousRoundEndNs: String(previousRoundLookupEndNs),
                previousRoundDistinctCount: previousRoundDistinctTop3.length,
                previousRoundContainsTarget,
              });
            } else if (previousRoundDistinctTop3.length >= 3 && !previousRoundContainsTarget) {
              shouldRunPostRequestExtension = true;
              appendRunLog(
                "STEP3.3",
                "previous runtime-cache round has 3 distinct deployments but target absent; continue with post-request extension",
                {
                  ...logCtx,
                  previousRoundStartNs: String(previousRoundStartNs),
                  previousRoundEndNs: String(previousRoundLookupEndNs),
                  previousRoundDistinctCount: previousRoundDistinctTop3.length,
                  previousRoundContainsTarget,
                },
              );
            } else {
              previousRoundCompletionCheck.reason = "previous_round_distinct_lt_3";
              appendRunLog(
                "STEP3.3",
                "previous runtime-cache round still has <3 distinct deployments; skip extension and mark for further analysis",
                {
                  ...logCtx,
                  previousRoundStartNs: String(previousRoundStartNs),
                  previousRoundEndNs: String(previousRoundLookupEndNs),
                  previousRoundDistinctCount: previousRoundDistinctTop3.length,
                },
              );
            }
          } catch (previousRoundCompletionErr) {
            previousRoundCompletionCheck.reason = "previous_round_completion_query_failed";
            previousRoundCompletionCheck.error = String(
              previousRoundCompletionErr?.message || previousRoundCompletionErr,
            );
            appendRunLog("STEP3.3", "warning: previous round completion lookup failed", {
              ...logCtx,
              previousRoundStartNs: String(previousRoundStartNs),
              previousRoundEndNs: String(previousRoundLookupEndNs),
              error: String(previousRoundCompletionErr?.message || previousRoundCompletionErr),
            });
          }
        }
      } catch (previousRoundErr) {
        previousRoundCompletionCheck.reason = "previous_round_anchor_query_failed";
        previousRoundCompletionCheck.error = String(previousRoundErr?.message || previousRoundErr);
        appendRunLog("STEP3.3", "warning: previous round anchor lookup failed", {
          ...logCtx,
          previousRoundLookupStartNs: String(previousRoundLookupStartNs),
          previousRoundLookupEndNs: String(previousRoundLookupEndNs),
          previousRoundAnchorExpr,
          error: String(previousRoundErr?.message || previousRoundErr),
        });
      }
    }
  }
  if (shouldRunPostRequestExtension) {
    completionExtensionUsed = true;
    const postExtend1Minutes = Math.max(1, Number(ANALYSIS_CONFIG.step3_3CompletionExtend1Minutes || 15));
    const postExtend2Minutes = Math.max(
      postExtend1Minutes,
      Number(ANALYSIS_CONFIG.step3_3CompletionExtend2Minutes || 30),
    );
    const postWindow1StartNs = Math.floor(reqTsNs);
    const postWindow1EndNs = Math.floor(reqTsNs + postExtend1Minutes * 60 * 1e9);
    completionWindowEndNs = postWindow1EndNs;
    appendRunLog(
      "STEP3.3",
      `extending runtime cache completion search to post-request window +${postExtend1Minutes}m`,
      {
        ...logCtx,
        originalDistinctCount: completionDistinctOriginalTop3.length,
        originalWindowStartNs: String(startNs),
        originalWindowEndNs: String(endNs),
        extendedWindowStartNs: String(postWindow1StartNs),
        extendedWindowEndNs: String(postWindow1EndNs),
      },
    );
    const completionCandidatesPost1 = await collectCompletionRecordsInRange(
      postWindow1StartNs,
      postWindow1EndNs,
    );
    let completionCandidatesPostUsed = completionCandidatesOriginal.concat(completionCandidatesPost1);
    completionCandidatesPostUsed.sort((a, b) => Number(a.lokiTsNs) - Number(b.lokiTsNs));
    let completionRoundMatchedPostUsed = completionCandidatesPostUsed.filter(r =>
      completionMatchesStartRound(r, startNs),
    );

    if (distinctCompletionByDeployment(completionRoundMatchedPostUsed).length < 3) {
      const postWindow2StartNs = postWindow1EndNs;
      const postWindow2EndNs = Math.floor(reqTsNs + postExtend2Minutes * 60 * 1e9);
      completionWindowEndNs = postWindow2EndNs;
      appendRunLog(
        "STEP3.3",
        `post-request +${postExtend1Minutes}m window insufficient; extending to +${postExtend2Minutes}m`,
        {
          ...logCtx,
          priorPostWindowDistinctCount: distinctCompletionByDeployment(completionRoundMatchedPostUsed).length,
          extendedWindowStartNs: String(postWindow2StartNs),
          extendedWindowEndNs: String(postWindow2EndNs),
        },
      );
      const completionCandidatesPost2 = await collectCompletionRecordsInRange(
        postWindow2StartNs,
        postWindow2EndNs,
      );
      completionCandidatesPostUsed = completionCandidatesPostUsed.concat(completionCandidatesPost2);
      completionCandidatesPostUsed.sort((a, b) => Number(a.lokiTsNs) - Number(b.lokiTsNs));
      completionRoundMatchedPostUsed = completionCandidatesPostUsed.filter(r =>
        completionMatchesStartRound(r, startNs),
      );
    }

    completionCandidates = completionCandidatesPostUsed;
    completionRoundMatched = completionRoundMatchedPostUsed;
    completionDistinctUsedAll = distinctCompletionByDeployment(completionRoundMatched);
    completionDistinctUsedTop3 = completionDistinctUsedAll.slice(0, 3);
  }

  const earliestCompletionMatch =
    completionDistinctUsedAll.find(
      x => String(x?.deploymentID || "") === String(targetDeploymentID || ""),
    ) || null;
  const completionFoundAfterOriginalWindow = Boolean(
    earliestCompletionMatch && Number(earliestCompletionMatch.lokiTsNs) > endNs,
  );
  const targetInOriginalTop3 = Boolean(
    targetDeploymentID &&
      completionDistinctOriginalTop3.some(x => String(x?.deploymentID || "") === String(targetDeploymentID)),
  );
  const targetInUsedTop3 = Boolean(
    targetDeploymentID &&
      completionDistinctUsedTop3.some(x => String(x?.deploymentID || "") === String(targetDeploymentID)),
  );

  let successfulDeploymentsAll = completionDistinctUsedTop3;
  const latestTop3 = completionDistinctUsedTop3;

  const completionTiming = {
    matched: false,
    reason: null,
    startLokiTsNs: String(startNs),
    expectedStartFromCompletionLokiTsNs: null,
    deltaSec: null,
    toleranceSec: null,
  };
  if (!targetDeploymentID) {
    completionTiming.reason = "target_deployment_unknown";
  } else if (!earliestCompletionMatch) {
    completionTiming.reason = "no_completed_cache_log_for_target_deployment";
  } else if (!Number.isFinite(earliestCompletionMatch.elapsedTimeMs)) {
    completionTiming.reason = "completed_cache_log_missing_elapsed_time";
  } else {
    const expectedStartNs = Number(
      Math.round(Number(earliestCompletionMatch.lokiTsNs) - earliestCompletionMatch.elapsedTimeMs * 1e6),
    );
    const deltaSec = (expectedStartNs - startNs) / 1e9;
    completionTiming.expectedStartFromCompletionLokiTsNs = String(expectedStartNs);
    completionTiming.deltaSec = Number(deltaSec.toFixed(6));
    if (expectedStartNs > startNs) {
      completionTiming.matched = true;
      completionTiming.reason = null;
    } else {
      completionTiming.reason = "elapsed_time_backcalc_not_after_cache_load_start";
    }
  }
  appendRunLog("STEP3.3", "runtime cache completion timing checked", {
    ...logCtx,
    targetDeploymentID: targetDeploymentID || null,
    runtimeCompletionWindowStartNs: String(startNs),
    runtimeCompletionWindowEndNs: String(completionWindowEndNs),
    completionTimingMatched: completionTiming.matched,
    completionTimingReason: completionTiming.reason,
    completionRoundMatchedOriginalCount: completionRoundMatchedOriginal.length,
    completionRoundMatchedUsedCount: completionRoundMatched.length,
    completionDistinctOriginalCount: completionDistinctOriginalTop3.length,
    completionDistinctExtendCount: completionDistinctUsedTop3.length,
    runtimeCompletionDistinctDeploymentsOriginalTop3: completionDistinctOriginalTop3
      .map(x => String(x?.deploymentID || "").trim())
      .filter(Boolean),
    runtimeCompletionDistinctDeploymentsUsedTop3: completionDistinctUsedTop3
      .map(x => String(x?.deploymentID || "").trim())
      .filter(Boolean),
    runtimeCompletionDistinctDeploymentsUsedAll: completionDistinctUsedAll
      .map(x => String(x?.deploymentID || "").trim())
      .filter(Boolean)
      .slice(0, 20),
    runtimeCompletionTargetPresentInOriginalTop3: targetInOriginalTop3,
    runtimeCompletionTargetPresentInUsedTop3: targetInUsedTop3,
    completionExtensionUsed,
    completionUsedPreviousRound,
    previousRoundCompletionCheck,
    completionFoundAfterOriginalWindow,
    earliestCompletionDeploymentID: earliestCompletionMatch?.deploymentID || null,
    earliestCompletionLokiTsNs: earliestCompletionMatch?.lokiTsNs || null,
  });

  const completionSuccessRecord = completionTiming.matched && earliestCompletionMatch ? earliestCompletionMatch : null;

  const hasCompletionEvidenceBeforeRequest = Boolean(
    completionTiming.matched &&
      completionSuccessRecord &&
      Number(completionSuccessRecord.lokiTsNs) <= endNs,
  );
  const hasThreeCompletedDeployments = completionDistinctUsedTop3.length >= 3;
  const hasSuccessBeforeRequest = hasThreeCompletedDeployments;
  const conclusion = hasThreeCompletedDeployments ? "cache_load_success" : "cache_load_unknown";

  // Use the same fixed restart evidence lookback policy as no-anchor fallback.
  const restartLookbackMinutes = 10;
  const restartLookbackNs = restartLookbackMinutes * 60 * 1e9;
  const restartBaseStartNs = Math.max(0, subtractNsWithPrecisionGuard(startNs, restartLookbackNs));
  const previousRoundStartNsForRestart = Number(previousRoundCompletionCheck?.previousRoundStartNs || 0);
  const restartFromPreviousRoundNs = Number.isFinite(previousRoundStartNsForRestart) && previousRoundStartNsForRestart > 0
    ? Math.max(0, subtractNsWithPrecisionGuard(previousRoundStartNsForRestart, restartLookbackNs))
    : null;
  const restartQueryStartNs = restartFromPreviousRoundNs == null
    ? restartBaseStartNs
    : Math.min(restartBaseStartNs, restartFromPreviousRoundNs);
  const restartExpr =
    `${buildDecisionSelector(env, pod)}` +
    ` != "/live" != "/ready"` +
    ` |~ "starting decision server|starting authz decision server"`;
  const restartJson = await queryLokiForStep(restartExpr, {
    startNs: restartQueryStartNs,
    endNs,
    direction: "BACKWARD",
    limit: 20,
  });
  const restartEntries = [];
  for (const stream of restartJson?.data?.result || []) {
    for (const [tsNs, line] of stream.values || []) {
      const parsed = extractJsonObjectFromLogLine(line);
      restartEntries.push({
        lokiTsNs: String(tsNs),
        timestamp: parsed?.timestamp ? String(parsed.timestamp) : null,
        message: parsed?.message ? String(parsed.message) : null,
        line: String(line || ""),
      });
    }
  }
  const restartEvidence = {
    count: restartEntries.length,
    entries: restartEntries.slice(0, 20),
    query: restartExpr,
    startNs: String(restartQueryStartNs),
    endNs: String(endNs),
    lookbackNs: String(restartLookbackNs),
    previousRoundStartNs:
      Number.isFinite(previousRoundStartNsForRestart) && previousRoundStartNsForRestart > 0
        ? String(previousRoundStartNsForRestart)
        : null,
  };
  let uniqueFailureErrors = [];
  let finalConclusion = conclusion;
  let finalReason = null;
  if (!hasSuccessBeforeRequest) {
    appendRunLog("STEP3.3", "not enough success evidence; checking error and restart evidence", {
      ...logCtx,
      completionDistinctExtendCount: completionDistinctUsedTop3.length,
    });
    // Query cache-loading error evidence after success checks, right before restart evidence.
    const errorJson = await queryLokiForStep(errorExpr, {
      startNs,
      endNs,
      direction: "BACKWARD",
      limit: errorLimit,
    });
    let errorStreamCount = 0;
    let errorLineCount = 0;
    let extractedErrorRecordCount = 0;
    let excludedSameTraceErrorCount = 0;
    const keyToDisplay = new Map();
    for (const stream of errorJson?.data?.result || []) {
      errorStreamCount += 1;
      for (const [, line] of stream.values || []) {
        errorLineCount += 1;
        const parsed = extractJsonObjectFromLogLine(line);
        const lineTraceID = String(
          parsed?.traceID ?? parsed?.traceId ?? parsed?.trace_id ?? "",
        ).trim();
        // Exclude request-trace-local errors (e.g. SPDL-2001 for the same trace)
        // so cache-load-failure evidence comes from cache preparation failures.
        if (traceID && lineTraceID && lineTraceID === String(traceID)) {
          excludedSameTraceErrorCount += 1;
          continue;
        }
        const rec = extractErrorRecordFromErrorLine(line);
        if (!rec) continue;
        extractedErrorRecordCount += 1;
        const prev = keyToDisplay.get(rec.key);
        if (!prev || rec.display.length < prev.length) {
          keyToDisplay.set(rec.key, rec.display);
        }
      }
    }
    uniqueFailureErrors = pruneContainingLongerMessages([...keyToDisplay.values()]);
    appendRunLog("STEP3.3", "cache-load error evidence evaluation completed", {
      ...logCtx,
      errorWindowStartNs: String(startNs),
      errorWindowEndNs: String(endNs),
      errorExpr,
      errorStreamCount,
      errorLineCount,
      extractedErrorRecordCount,
      excludedSameTraceErrorCount,
      uniqueFailureErrorCount: uniqueFailureErrors.length,
      uniqueFailureErrors: uniqueFailureErrors.slice(0, 20),
    });
    if (uniqueFailureErrors.length > 0) {
      finalConclusion = "cache_load_failure";
    }

    if (restartEvidence.count >= 1 && uniqueFailureErrors.length === 0) {
      // Treat restart warmup as cache load failure per updated categorization policy.
      finalConclusion = "cache_load_failure";
      finalReason = "restart_warmup";
    }
  }
  appendRunLog("STEP3.3", "final step3.3 conclusion for link", {
    ...logCtx,
    finalConclusion,
    finalReason,
    failureEvidenceCount: uniqueFailureErrors.length,
    restartEvidenceCount: restartEvidence.count,
  });

  return {
    conclusion: finalConclusion,
    reason: finalReason,
    window: { startNs: String(startNs), endNs: String(endNs) },
    defaultLookupWindow: {
      startNs: String(deploymentListCacheWindowStartNs),
      endNs: String(endNs),
    },
    queries: {
      deploymentListCacheExpr,
      traceExpr: traceID ? traceExpr : null,
      deploymentStateExpr,
      errorExpr,
      completionExpr,
      restartExpr: restartEvidence.query,
    },
    successfulDeploymentsAll,
    successfulDeploymentsLatestTop3: latestTop3,
    completionDistinctOriginalCount: completionDistinctOriginalTop3.length,
    completionDistinctExtendCount: completionDistinctUsedTop3.length,
    targetInOriginalTop3,
    targetInUsedTop3,
    resolvedDefaultDeployment,
    defaultDeploymentCandidates: defaultDeploymentCandidates.slice(0, 20),
    targetDeploymentID: targetDeploymentID || null,
    deploymentListCacheWindow: {
      startNs: String(deploymentListCacheWindowStartNs),
      endNs: String(deploymentListCacheWindowEndNs),
    },
    deploymentListCacheCandidatesCount: deploymentListCacheCandidates.length,
    deploymentListCacheCandidatesSample: deploymentListCacheCandidates.slice(0, 30),
    deploymentListCacheRoundsCount: deploymentListCacheRounds.length,
    deploymentListCacheLatestRoundDistinctDeploymentCount: latestRoundDistinctDeploymentCount,
    deploymentListCacheRoundsLatest2,
    deploymentListCacheCheck,
    deploymentListPostRequestCheck,
    traceErrorSummary,
    deploymentStateCheck,
    completionWindowEndNs: String(completionWindowEndNs),
    completionExtensionUsed,
    completionUsedPreviousRound,
    previousRoundCompletionCheck,
    completionFoundAfterOriginalWindow,
    completionCandidatesCount: completionCandidates.length,
    completionCandidatesSample: completionCandidates.slice(0, 20),
    earliestCompletionMatch,
    completionTiming,
    failureEvidenceCount: uniqueFailureErrors.length,
    failureEvidence: uniqueFailureErrors.slice(0, 20),
    uniqueFailureErrors,
    restartEvidence,
  };
}

async function fetchTraceErrorSignatureForReuse(link, { regionContext = null } = {}) {
  const env = link?.request?.env;
  const pod = link?.request?.pod || null;
  const traceID = String(link?.request?.traceID || "").trim();
  const reqTsNs = Number(link?.request?.lokiTsNs);
  const reqStartTsNs = Number(link?.request?.requestStartTimeNs);
  if (!env || !traceID || !Number.isFinite(reqTsNs) || reqTsNs <= 0) return null;

  const traceExpr =
    `${buildDecisionSelector(env, pod)}` +
    ` != "/live" != "/ready" |~ "${traceID}"`;
  const TRACE_LOOKBACK_BEFORE_REQUEST_NS = 2 * 1e9;
  const TRACE_LOOKAHEAD_AFTER_REQUEST_NS = 5 * 1e9;
  const startNs =
    Number.isFinite(reqStartTsNs) && reqStartTsNs > 0 && reqStartTsNs <= reqTsNs
      ? Math.max(0, Math.floor(reqStartTsNs - TRACE_LOOKBACK_BEFORE_REQUEST_NS))
      : Math.max(0, Math.floor(reqTsNs - 5 * 1e9));
  const endNs = Math.floor(reqTsNs + TRACE_LOOKAHEAD_AFTER_REQUEST_NS);
  const traceJson = await queryLoki(traceExpr, {
    startNs,
    endNs,
    direction: "BACKWARD",
    limit: 200,
    regionContext,
  });

  const entries = [];
  for (const stream of traceJson?.data?.result || []) {
    for (const [tsNs, line] of stream.values || []) {
      const parsed = extractJsonObjectFromLogLine(line);
      if (!parsed || typeof parsed !== "object") continue;
      entries.push({
        lokiTsNs: String(tsNs),
        level: parsed.level ? String(parsed.level) : null,
        error: parsed.error ? String(parsed.error) : null,
        message: parsed.message ? String(parsed.message) : null,
        A_message: parsed.A_message ? String(parsed.A_message) : null,
      });
    }
  }
  entries.sort((a, b) => Number(a.lokiTsNs) - Number(b.lokiTsNs));
  const errorEntries = entries.filter(e => String(e?.level || "").toLowerCase() === "error");
  const selected = errorEntries[0] || entries[0] || null;
  const signature = extractErrorSignatureFromTraceEntry(selected);
  const classified = classifyDecision404ErrorByTrace(entries);
  const traceErrorSummary = {
    traceID,
    category: classified.category,
    matchedPattern: classified.matchedPattern,
    matchedEntry: classified.matchedEntry,
    runtimeServicesCount: Number(classified.runtimeServicesCount || 0),
    deploymentListCount: Number(classified.deploymentListCount || 0),
    bothPatternsPresent: Boolean(classified.bothPatternsPresent),
    runtimeServicesFirstHitTsNs: classified.runtimeServicesFirstHitTsNs || null,
    deploymentListFirstHitTsNs: classified.deploymentListFirstHitTsNs || null,
    entriesSample: entries.slice(-30),
  };
  return {
    signature,
    selectedEntry: selected,
    query: traceExpr,
    window: { startNs: String(startNs), endNs: String(endNs) },
    traceErrorSummary,
  };
}

async function buildStep3_3CacheLoadingByEnv(
  step3_2ByEnv,
  { regionContext = null, envProgressTracker = null } = {},
) {
  const byEnv = {};
  const fastTimelineEnabled = ANALYSIS_CONFIG.step3_3FastTimelineEnabled !== false;
  const fastTimelineMinRequestsPerHour = Math.max(
    0,
    Number(ANALYSIS_CONFIG.step3_3FastTimelineMinRequestsPerHour || 100),
  );
  const stepWindowHours = getConfiguredStepWindowHours();
  const fastTimelineDecisionByEnv = new Map();
  const step3_2ByEnvForTimeline = {};
  for (const [env, item] of Object.entries(step3_2ByEnv || {})) {
    const requestRecordCount = Number(item?.requestRecordCount || 0);
    const requestsPerHour = requestRecordCount / stepWindowHours;
    const eligible = fastTimelineEnabled && requestsPerHour >= fastTimelineMinRequestsPerHour;
    fastTimelineDecisionByEnv.set(env, {
      enabled: eligible,
      requestRecordCount,
      stepWindowHours,
      requestsPerHour,
    });
    if (eligible) step3_2ByEnvForTimeline[env] = item;
  }
  let fastTimelineByEnv = new Map();
  if (fastTimelineEnabled && Object.keys(step3_2ByEnvForTimeline).length > 0) {
    try {
      fastTimelineByEnv = await buildFastTimelinesByEnv(step3_2ByEnvForTimeline, { regionContext });
    } catch (e) {
      appendRunLog("STEP3.3", "failed to build fast timelines; fallback to deep-analysis only", {
        region: regionContext || null,
        error: String(e?.message || e),
      });
      fastTimelineByEnv = new Map();
    }
  }
  const envEntries = Object.entries(step3_2ByEnv || {});
  const totalEnvCount = envEntries.length;

  for (let envIdx = 0; envIdx < envEntries.length; envIdx += 1) {
    const [env, item] = envEntries[envIdx];
    const links = item.links || [];
    const analyzedLinks = [];
    const conclusionCounts = {};
    const traceSeenCounts = new Map();
    const linkIdentitySeenCounts = new Map();
    const timelineDecision = fastTimelineDecisionByEnv.get(env) || {
      enabled: false,
      requestRecordCount: Number(item?.requestRecordCount || 0),
      stepWindowHours,
      requestsPerHour: 0,
    };
    const envTimeline = timelineDecision.enabled ? fastTimelineByEnv.get(env) || null : null;
    let fastPathUsedCount = 0;
    let deepAnalysisCount = 0;
    appendRunLog("STEP3.3", "fast timeline mode decision for env", {
      env,
      region: regionContext || null,
      fastTimelineEnabled: timelineDecision.enabled,
      fastTimelineMinRequestsPerHour,
      requestRecordCount: timelineDecision.requestRecordCount,
      stepWindowHours: Number(timelineDecision.stepWindowHours.toFixed(4)),
      requestsPerHour: Number(timelineDecision.requestsPerHour.toFixed(4)),
      decisionReason: timelineDecision.enabled ? "high_volume" : "low_volume",
    });
    appendRunLog("STEP3.3", "reuse logic disabled; force full analysis per link", {
      env,
      fastTimelineEnabled: timelineDecision.enabled,
      fastTimelineAvailable: Boolean(envTimeline),
    });

    function buildLinkExactIdentityKey(link) {
      const req = link?.request || {};
      return [
        String(req?.env || ""),
        String(req?.pod || ""),
        String(req?.traceID || ""),
        String(req?.url || ""),
        String(req?.lokiTsNs || ""),
        String(link?.previousLog?.lokiTsNs || ""),
      ].join("|");
    }

    for (let i = 0; i < links.length; i += 1) {
      const link = links[i];
      const linkExactIdentityKey = buildLinkExactIdentityKey(link);
      const reqUrl = String(link?.request?.url || "");
      const reqTsNs = Number(link?.request?.lokiTsNs);
      const reqStartTsNs = Number(link?.request?.requestStartTimeNs);
      const reqTraceID = String(link?.request?.traceID || "");
      const linkSeenCount = (linkIdentitySeenCounts.get(linkExactIdentityKey) || 0) + 1;
      linkIdentitySeenCounts.set(linkExactIdentityKey, linkSeenCount);

      if (
        linkExactIdentityKey &&
        shouldLogRepeatCount(
          linkSeenCount,
          Number(ANALYSIS_CONFIG.step3_3RepeatedLinkIdentityWarnThreshold || 2),
        )
      ) {
        appendRunLog("STEP3.3", "warning: repeated link identity observed during iteration", {
          env,
          processed: i + 1,
          total: links.length,
          traceID: reqTraceID || null,
          requestUrl: reqUrl || null,
          requestCompleteTimeNs: Number.isFinite(reqTsNs) ? String(reqTsNs) : null,
          repeatedLinkIdentityCount: linkSeenCount,
          linkExactIdentityKey,
        });
      }

      if (reqTraceID) {
        const traceSeenCount = (traceSeenCounts.get(reqTraceID) || 0) + 1;
        traceSeenCounts.set(reqTraceID, traceSeenCount);
        if (
          shouldLogRepeatCount(
            traceSeenCount,
            Number(ANALYSIS_CONFIG.step3_3RepeatedTraceWarnThreshold || 2),
          )
        ) {
          appendRunLog("STEP3.3", "warning: repeated traceID observed during iteration", {
            env,
            processed: i + 1,
            total: links.length,
            traceID: reqTraceID,
            requestUrl: reqUrl || null,
            requestCompleteTimeNs: Number.isFinite(reqTsNs) ? String(reqTsNs) : null,
            repeatedTraceCount: traceSeenCount,
            linkExactIdentityKey,
          });
        }
      }

      let result = null;
      let fullAnalysisPerformed = false;

      if (!result && envTimeline) {
        const fastResult = fastAnalyzeStep3_3ForLinkFromTimeline(link, envTimeline);
        if (fastResult) {
          if (fastResult.fastPathFallbackRequired) {
            appendRunLog("STEP3.3", "timeline fast-path fallback to full analysis for link", {
              env,
              traceID: reqTraceID || null,
              pod: String(link?.request?.pod || "") || null,
              requestUrl: reqUrl || null,
              fallbackReason: fastResult?.fallbackReason || null,
              window: fastResult?.window || null,
              completionDistinctExtendCount:
                Number(fastResult?.completionDistinctExtendCount || 0),
            });
          } else {
            result = fastResult;
            fastPathUsedCount += 1;
            appendRunLog("STEP3.3", "timeline fast-path used for link", {
              env,
              traceID: reqTraceID || null,
              pod: String(link?.request?.pod || "") || null,
              requestUrl: reqUrl || null,
              targetDeploymentID: result?.targetDeploymentID || null,
              conclusion: result?.conclusion || null,
            });
          }
        }
      }

      if (!result) {
        deepAnalysisCount += 1;
        fullAnalysisPerformed = true;
        result = await analyzeStep3_3ForLink(link, {
          queryLokiFn: (expr, opts = {}) => queryLoki(expr, { ...opts, regionContext }),
        });
      }

      const duplicateCount = Number(link?.request?.duplicateCount || 1);
      const k = result.conclusion || "cache_load_unknown";
      conclusionCounts[k] = (conclusionCounts[k] || 0) + duplicateCount;

      analyzedLinks.push({
        request: {
          ...(link.request || {}),
          duplicateCount,
        },
        anchorLog: link.previousLog || null,
        step3_2Matched: Boolean(link.matched),
        step3_2MissReason: link.missReason || null,
        conclusion: result.conclusion,
        reason: result.reason,
        window: result.window || null,
        defaultLookupWindow: result.defaultLookupWindow || null,
        successfulDeploymentsAll: result.successfulDeploymentsAll || [],
        successfulDeploymentsLatestTop3: result.successfulDeploymentsLatestTop3 || [],
        completionDistinctOriginalCount: result.completionDistinctOriginalCount || 0,
        completionDistinctExtendCount:
          result.completionDistinctExtendCount ?? result.completionDistinctUsedCount ?? 0,
        targetInOriginalTop3: Boolean(result.targetInOriginalTop3),
        targetInUsedTop3: Boolean(result.targetInUsedTop3),
        resolvedDefaultDeployment: result.resolvedDefaultDeployment || null,
        defaultDeploymentCandidates: result.defaultDeploymentCandidates || [],
        targetDeploymentID: result.targetDeploymentID || null,
        deploymentListCacheWindow: result.deploymentListCacheWindow || null,
        deploymentListCacheCandidatesCount: result.deploymentListCacheCandidatesCount || 0,
        deploymentListCacheCandidatesSample: result.deploymentListCacheCandidatesSample || [],
        deploymentListCacheRoundsCount: result.deploymentListCacheRoundsCount || 0,
        deploymentListCacheRoundsLatest2: result.deploymentListCacheRoundsLatest2 || [],
        deploymentListCacheCheck: result.deploymentListCacheCheck || null,
        deploymentListPostRequestCheck: result.deploymentListPostRequestCheck || null,
        traceErrorSummary: result.traceErrorSummary || null,
        deploymentStateCheck: result.deploymentStateCheck || null,
        completionWindowEndNs: result.completionWindowEndNs || null,
        completionExtensionUsed: Boolean(result.completionExtensionUsed),
        completionUsedPreviousRound: Boolean(result.completionUsedPreviousRound),
        previousRoundCompletionCheck: result.previousRoundCompletionCheck || null,
        completionFoundAfterOriginalWindow: Boolean(result.completionFoundAfterOriginalWindow),
        completionCandidatesCount: result.completionCandidatesCount || 0,
        completionCandidatesSample: result.completionCandidatesSample || [],
        earliestCompletionMatch: result.earliestCompletionMatch || null,
        completionTiming: result.completionTiming || null,
        failureEvidenceCount: result.failureEvidenceCount || 0,
        failureEvidence: result.failureEvidence || [],
        uniqueFailureErrors: result.uniqueFailureErrors || [],
        restartEvidence: result.restartEvidence || { count: 0, entries: [], query: null },
        queries: result.queries || null,
        reusedFromTraceID: null,
        reuseMeta: null,
        fullAnalysisPerformed,
      });

      if ((i + 1) % 50 === 0) {
        console.log(`Step 3.3 env=${env} processed=${i + 1}/${links.length}`);
        appendRunLog("STEP3.3", "progress", { env, processed: i + 1, total: links.length });
      }
    }

    const weightedRequestCount = links.reduce(
      (sum, l) => sum + Number(l?.request?.duplicateCount || 1),
      0,
    );
    byEnv[env] = {
      requestRecordCount: weightedRequestCount,
      dedupedRequestRecordCount: links.length,
      conclusionCounts,
      fastPathUsedCount,
      deepAnalysisCount,
      reusedResultCount: 0,
      links: analyzedLinks,
      failureSamples: analyzedLinks
        .filter(x => x.conclusion === "cache_load_failure")
        .slice(0, 20),
    };

    console.log(`Step 3.3 env=${env} summary=`, byEnv[env].conclusionCounts);
    appendRunLog("STEP3.3", "env summary completed", {
      env,
      requestRecordCount: weightedRequestCount,
      dedupedRequestRecordCount: links.length,
      conclusionCounts,
      fastPathUsedCount,
      deepAnalysisCount,
      reusedResultCount: 0,
      fastTimelineEnabled: timelineDecision.enabled,
      fastTimelineMinRequestsPerHour,
      requestsPerHour: Number(timelineDecision.requestsPerHour.toFixed(4)),
      fastTimelineAvailable: Boolean(envTimeline),
    });
    const progress =
      envProgressTracker && typeof envProgressTracker.markEnvProcessed === "function"
        ? envProgressTracker.markEnvProcessed()
        : {
            processedEnvCount: envIdx + 1,
            totalEnvCount,
            progressPct: totalEnvCount > 0 ? Number((((envIdx + 1) / totalEnvCount) * 100).toFixed(2)) : 100,
          };
    appendRunLog("STEP3.3", "env analysis progress", {
      env,
      region: regionContext || null,
      processedEnvCount: progress.processedEnvCount,
      totalEnvCount: progress.totalEnvCount,
      progressPct: progress.progressPct,
    });
  }

  return byEnv;
}

function summarizeStep3_3CacheLoading(step3_3ByEnv) {
  const out = {};
  for (const [env, item] of Object.entries(step3_3ByEnv || {})) {
    out[env] = {
      requestRecordCount: item.requestRecordCount || 0,
      dedupedRequestRecordCount: item.dedupedRequestRecordCount || 0,
      fastPathUsedCount: item.fastPathUsedCount || 0,
      deepAnalysisCount: item.deepAnalysisCount || 0,
      reusedResultCount: item.reusedResultCount || 0,
      conclusionCounts: item.conclusionCounts || {},
    };
  }
  return out;
}

function buildStep3_3UniqueErrorsByEnv(step3_3ByEnv) {
  const out = {};
  for (const [env, item] of Object.entries(step3_3ByEnv || {})) {
    const errors = [];
    for (const link of item.links || []) {
      if (link.conclusion !== "cache_load_failure") continue;
      errors.push(...(link.uniqueFailureErrors || []));
    }
    out[env] = pruneContainingLongerMessages(errors);
  }
  return out;
}

function buildStep3_3FailureErrorToEnvMap(step3_3ByEnv) {
  const uniqueErrorsByEnv = buildStep3_3UniqueErrorsByEnv(step3_3ByEnv);
  return buildErrorToEnvMap(uniqueErrorsByEnv);
}

function extractRequestedDeploymentFromUrl(url) {
  const s = String(url || "").trim();
  const explicit = s.match(/^\/v1:\$([0-9]+)\/authorize$/);
  if (explicit) {
    return {
      type: "explicit",
      deploymentID: explicit[1],
      rawUrl: s,
    };
  }
  if (s === "/v1/authorize") {
    return {
      type: "default",
      deploymentID: null,
      rawUrl: s,
    };
  }
  return {
    type: "invalid",
    deploymentID: null,
    rawUrl: s,
  };
}

function buildStep3_4DeploymentCacheCheck(
  step3_3ByEnv,
  authzVersionByEnv = {},
  { step2ByEnv = {} } = {},
) {
  function rootCauseExpectedDirection(rootCause) {
    const x = String(rootCause || "");
    if (
      x === "404_due_to_runtime_services_cache_load_failure" ||
      x === "404_due_to_deployment_not_in_top_3_runtime_cache" ||
      x === "404_due_to_runtime_cache_not_ready" ||
      x === "404_due_to_runtime_cache_not_ready_yet"
    ) {
      return "runtime_services_not_found";
    }
    if (
      x === "404_due_to_deployment_not_in_top_3_list_cache" ||
      x === "404_due_to_deployment_not_ready_in_deployment_list_cache" ||
      x === "404_due_to_deployment_not_in_top_3_latest_deployments"
    ) {
      return "deployment_list_not_found";
    }
    if (x === "404_due_to_decision_service_restart_cache_warmup") {
      return "either";
    }
    return null;
  }

  function collectTraceSupportedDirections(row) {
    const supported = new Set();
    const primary = String(row?.traceErrorCategory || "").trim();
    if (primary) supported.add(primary);
    if (Number(row?.traceErrorRuntimeServicesCount || 0) > 0) supported.add("runtime_services_not_found");
    if (Number(row?.traceErrorDeploymentListCount || 0) > 0) supported.add("deployment_list_not_found");
    return supported;
  }

  function checkRootCauseTraceAlignment(row) {
    const expected = rootCauseExpectedDirection(row?.rootCause);
    const supported = collectTraceSupportedDirections(row);
    if (!expected || expected === "either") {
      return { aligned: true, expectedDirection: expected, supportedDirections: [...supported] };
    }
    return {
      aligned: supported.has(expected),
      expectedDirection: expected,
      supportedDirections: [...supported],
    };
  }

  const rootCauseTable = [];
  const furtherAnalysisTable = [];
  const buildFurtherAnalysisIdentityKey = row =>
    [
      String(row?.env || ""),
      String(row?.traceID || ""),
      String(row?.requestLokiTsNs || ""),
      String(row?.url || ""),
      String(row?.pod || ""),
    ].join("|");

  for (const [env, s2] of Object.entries(step2ByEnv || {})) {
    if (!s2?.error) continue;
    furtherAnalysisTable.push({
      env,
      authzVersion: authzVersionByEnv[String(env || "").toLowerCase()] || "N/A",
      traceID: null,
      pod: null,
      requestTimestamp: null,
      requestLokiTsNs: null,
      requestStartTimeNs: null,
      requestElapsedTime: null,
      requestElapsedTimeMs: null,
      requestElapsedTimeRoundedMs: null,
      url: null,
      requestedDeploymentType: null,
      requestedDeploymentID: null,
      resolvedDefaultDeploymentID: null,
      cacheDeploymentListCount: 0,
      cacheDeploymentList: [],
      step3_3Conclusion: "cache_load_unknown",
      result: "step2_loki_query_failed",
      step2Error: String(s2.error),
      action: "further_analysis_required",
    });
  }

  for (const [env, item] of Object.entries(step3_3ByEnv || {})) {
    for (const link of item.links || []) {
      const request = link.request || {};
      const reqInfo = extractRequestedDeploymentFromUrl(request.url);
      const uniqueCacheDeployments = [];
      const seen = new Set();
      for (const d of link.successfulDeploymentsAll || []) {
        const id = String(d?.deploymentID || "").trim();
        if (!id || seen.has(id)) continue;
        seen.add(id);
        uniqueCacheDeployments.push(id);
      }

      const baseRow = {
        env,
        authzVersion: authzVersionByEnv[String(env || "").toLowerCase()] || "N/A",
        duplicateCount: Number(request.duplicateCount || 1),
        traceID: request.traceID || null,
        pod: request.pod || null,
        requestTimestamp: request.timestamp || null,
        requestLokiTsNs: request.lokiTsNs || null,
        requestStartTimeNs: request.requestStartTimeNs || null,
        requestElapsedTime: request.elapsedTime || null,
        requestElapsedTimeMs:
          Number.isFinite(Number(request.elapsedTimeMs)) ? Number(request.elapsedTimeMs) : null,
        requestElapsedTimeRoundedMs:
          Number.isFinite(Number(request.elapsedTimeRoundedMs))
            ? Number(request.elapsedTimeRoundedMs)
            : null,
        url: request.url || null,
        requestedDeploymentType: reqInfo.type,
        requestedDeploymentID: reqInfo.deploymentID,
        resolvedDefaultDeploymentID: link.resolvedDefaultDeployment?.defaultDeploymentID || null,
        cacheDeploymentListCount: uniqueCacheDeployments.length,
        cacheDeploymentList: uniqueCacheDeployments,
        step3_3Conclusion: link.conclusion || null,
        deploymentListCacheDecision: link.deploymentListCacheCheck?.decision || null,
        deploymentListCacheReason: link.deploymentListCacheCheck?.reason || null,
        deploymentListCacheTargetDeploymentID: link.deploymentListCacheCheck?.targetDeploymentID || null,
        deploymentListCacheUsedRound: link.deploymentListCacheCheck?.usedRound || null,
        deploymentListCacheUsedRoundEndLokiTsNs:
          link.deploymentListCacheCheck?.usedRoundEndLokiTsNs || null,
        deploymentListCacheUsedRoundTargetHitLokiTsNs:
          link.deploymentListCacheCheck?.usedRoundTargetHitLokiTsNs || null,
        deploymentListCacheUsedRoundTargetHitKind:
          link.deploymentListCacheCheck?.usedRoundTargetHitKind || null,
        deploymentListPostRequestChecked: Boolean(link.deploymentListPostRequestCheck?.checked),
        deploymentListPostRequestReason: link.deploymentListPostRequestCheck?.reason || null,
        deploymentListPostRequestRoundsFound:
          Number(link.deploymentListPostRequestCheck?.roundsFound || 0),
        deploymentListPostRequestRoundsChecked:
          Number(link.deploymentListPostRequestCheck?.roundsChecked || 0),
        deploymentListPostRequestFoundInCheckedRounds:
          Boolean(link.deploymentListPostRequestCheck?.foundInCheckedRounds),
        deploymentListPostRequestWindowStartNs:
          link.deploymentListPostRequestCheck?.window?.startNs || null,
        deploymentListPostRequestWindowEndNs:
          link.deploymentListPostRequestCheck?.window?.endNs || null,
        deploymentStateCheckFound: Boolean(link.deploymentStateCheck?.found),
        deploymentStateCheckNewState: link.deploymentStateCheck?.latest?.newState || null,
        deploymentStateCheckCurState: link.deploymentStateCheck?.latest?.curState || null,
        deploymentStateCheckIsServingState: link.deploymentStateCheck?.isServingState,
        deploymentStateCheckHitLokiTsNs: link.deploymentStateCheck?.latest?.lokiTsNs || null,
        deploymentStateCheckCacheRoundHitLokiTsNs:
          link.deploymentStateCheck?.cacheRoundHitLokiTsNs || null,
        deploymentStateCheckLatestAtOrBeforeCacheHitNewState:
          link.deploymentStateCheck?.latestAtOrBeforeCacheHit?.newState || null,
        deploymentStateCheckLatestAtOrBeforeCacheHitLokiTsNs:
          link.deploymentStateCheck?.latestAtOrBeforeCacheHit?.lokiTsNs || null,
        deploymentStateCheckLatestAtOrBeforeCacheHitIsServing:
          link.deploymentStateCheck?.latestAtOrBeforeCacheHitIsServing,
        deploymentStateCheckServingTransitionAfterCacheHitBeforeRequest:
          Boolean(link.deploymentStateCheck?.servingTransitionAfterCacheHitBeforeRequest),
        deploymentStateCheckTransitionEventLokiTsNs:
          link.deploymentStateCheck?.servingTransitionEvent?.lokiTsNs || null,
        deploymentStateCheckTransitionEventCurState:
          link.deploymentStateCheck?.servingTransitionEvent?.curState || null,
        deploymentStateCheckTransitionEventNewState:
          link.deploymentStateCheck?.servingTransitionEvent?.newState || null,
        traceErrorCategory: link.traceErrorSummary?.category || null,
        traceErrorPattern: link.traceErrorSummary?.matchedPattern || null,
        traceErrorRuntimeServicesCount: Number(link.traceErrorSummary?.runtimeServicesCount || 0),
        traceErrorDeploymentListCount: Number(link.traceErrorSummary?.deploymentListCount || 0),
        traceErrorBothPatternsPresent: Boolean(link.traceErrorSummary?.bothPatternsPresent),
        traceErrorRuntimeServicesFirstHitTsNs:
          link.traceErrorSummary?.runtimeServicesFirstHitTsNs || null,
        traceErrorDeploymentListFirstHitTsNs:
          link.traceErrorSummary?.deploymentListFirstHitTsNs || null,
      };
      const decisionLogCtx = {
        env,
        traceID: baseRow.traceID || null,
        traceErrorCategory: baseRow.traceErrorCategory || "unknown",
        step3_3Conclusion: baseRow.step3_3Conclusion || null,
        requestedDeploymentType: baseRow.requestedDeploymentType || null,
        requestedDeploymentID: baseRow.requestedDeploymentID || null,
        resolvedDefaultDeploymentID: baseRow.resolvedDefaultDeploymentID || null,
      };
      const restartEvidenceCount = Math.max(
        Number(link?.restartEvidence?.count || 0),
        Array.isArray(link?.restartEvidence?.entries) ? link.restartEvidence.entries.length : 0,
      );
      const failureEvidenceCount = Number(
        link?.failureEvidenceCount ??
          (Array.isArray(link?.uniqueFailureErrors) ? link.uniqueFailureErrors.length : 0),
      );
      const restartWarmupLikely =
        String(link?.reason || "") === "restart_warmup" ||
        (restartEvidenceCount >= 1 &&
          (failureEvidenceCount === 0 ||
            String(link?.traceErrorSummary?.category || "") === "runtime_services_not_found"));
      const restartWarmupConfirmedByStep3 =
        (baseRow.step3_3Conclusion === "cache_load_failure" ||
          baseRow.step3_3Conclusion === "cache_load_restart_warmup") &&
        (String(link?.reason || "") === "restart_warmup" ||
          (restartEvidenceCount >= 1 && failureEvidenceCount === 0));
      const completionDistinctExtendCount = Number(
        link?.completionDistinctExtendCount ?? link?.completionDistinctUsedCount ?? 0,
      );
      const latestRoundDistinctDeploymentCount = Number(
        link?.deploymentListCacheLatestRoundDistinctDeploymentCount || 0,
      );

      // Step 3.3 has already concluded restart warmup with evidence for this link.
      // Classify it immediately to avoid falling through to inconclusive cache cross-check paths.
      if (restartWarmupConfirmedByStep3) {
        rootCauseTable.push({
          ...baseRow,
          result: "single_restart_log_in_step3_3_window",
          rootCause: "404_due_to_decision_service_restart_cache_warmup",
        });
        appendRunLog("STEP3.4", "restart warmup confirmed by Step3.3; classify before cache cross-check", {
          ...decisionLogCtx,
          result: "single_restart_log_in_step3_3_window",
          rootCause: "404_due_to_decision_service_restart_cache_warmup",
          restartEvidenceCount,
          failureEvidenceCount,
          step3Reason: String(link?.reason || "") || null,
        });
        continue;
      }

      if (link.traceErrorSummary?.category === "runtime_services_not_found") {
        if (completionDistinctExtendCount > 3) {
          furtherAnalysisTable.push({
            ...baseRow,
            result: "runtime_cache_completion_distinct_gt_3",
            action: "further_analysis_required",
          });
          appendRunLog("STEP3.4", "runtime services branch used completion distinct > 3 -> further analysis", {
            ...decisionLogCtx,
            result: "runtime_cache_completion_distinct_gt_3",
            completionDistinctOriginalCount: Number(link.completionDistinctOriginalCount || 0),
            completionDistinctExtendCount,
          });
          continue;
        }
        if (
          link.completionExtensionUsed &&
          Number(link.completionDistinctOriginalCount || 0) < 3 &&
          completionDistinctExtendCount === 3
        ) {
          if (restartWarmupLikely) {
            rootCauseTable.push({
              ...baseRow,
              result: "restart_evidence_preempts_runtime_cache_not_ready_yet",
              rootCause: "404_due_to_decision_service_restart_cache_warmup",
            });
            appendRunLog("STEP3.4", "restart evidence preempts runtime_cache_not_ready_yet", {
              ...decisionLogCtx,
              result: "restart_evidence_preempts_runtime_cache_not_ready_yet",
              rootCause: "404_due_to_decision_service_restart_cache_warmup",
              restartEvidenceCount: Number(link?.restartEvidence?.count || 0),
            });
            continue;
          }
          rootCauseTable.push({
            ...baseRow,
            result: "cache_prepare_completed_after_request_window",
            rootCause: "404_due_to_runtime_cache_not_ready_yet",
          });
          appendRunLog("STEP3.4", "root cause: runtime cache completed only after extended window", {
            ...decisionLogCtx,
            result: "cache_prepare_completed_after_request_window",
            rootCause: "404_due_to_runtime_cache_not_ready_yet",
            completionDistinctOriginalCount: Number(link.completionDistinctOriginalCount || 0),
            completionDistinctExtendCount,
            completionExtensionUsed: Boolean(link.completionExtensionUsed),
          });
          continue;
        }
        appendRunLog("STEP3.4", "runtime services branch fallthrough to standard checks", {
          ...decisionLogCtx,
          result: "runtime_services_fallthrough_standard_checks",
          completionDistinctOriginalCount: Number(link.completionDistinctOriginalCount || 0),
          completionDistinctExtendCount,
          completionExtensionUsed: Boolean(link.completionExtensionUsed),
        });
        // If Step 3.3 already indicates restart warmup for runtime-services traces,
        // classify it immediately instead of falling into unknown/cache-crosscheck handling.
        if (restartWarmupLikely && baseRow.step3_3Conclusion !== "cache_load_success") {
          rootCauseTable.push({
            ...baseRow,
            result: "restart_evidence_preempts_runtime_services_fallthrough",
            rootCause: "404_due_to_decision_service_restart_cache_warmup",
          });
          appendRunLog("STEP3.4", "restart evidence preempts runtime services fallthrough", {
            ...decisionLogCtx,
            result: "restart_evidence_preempts_runtime_services_fallthrough",
            rootCause: "404_due_to_decision_service_restart_cache_warmup",
            restartEvidenceCount: Number(link?.restartEvidence?.count || 0),
            failureEvidenceCount: Number(link?.failureEvidenceCount || 0),
          });
          continue;
        }
      }

      if (link.traceErrorSummary?.category === "deployment_list_not_found") {
        if (link.deploymentListCacheCheck?.decision === "target_not_ready") {
          if (restartWarmupLikely) {
            rootCauseTable.push({
              ...baseRow,
              result: "restart_evidence_preempts_deployment_list_not_ready",
              rootCause: "404_due_to_decision_service_restart_cache_warmup",
            });
            appendRunLog("STEP3.4", "restart evidence preempts deployment_not_ready_in_deployment_list_cache", {
              ...decisionLogCtx,
              result: "restart_evidence_preempts_deployment_list_not_ready",
              rootCause: "404_due_to_decision_service_restart_cache_warmup",
              restartEvidenceCount: Number(link?.restartEvidence?.count || 0),
            });
            continue;
          }
          if (
            String(link.deploymentListPostRequestCheck?.reason || "") ===
            "skipped_target_missing_in_last_round_with_3_distinct_deployments"
          ) {
            rootCauseTable.push({
              ...baseRow,
              result: "requested_deployment_not_in_list_cache",
              rootCause: "404_due_to_deployment_not_in_top_3_list_cache",
            });
            appendRunLog(
              "STEP3.4",
              "root cause: target missing in complete latest deployment-list top3 (post-check skipped)",
              {
                ...decisionLogCtx,
                result: "requested_deployment_not_in_list_cache",
                rootCause: "404_due_to_deployment_not_in_top_3_list_cache",
                latestRoundDistinctDeploymentCount,
                completionDistinctExtendCount,
              },
            );
            continue;
          }
          if (link.deploymentListPostRequestCheck?.checked) {
            if (link.deploymentListPostRequestCheck?.foundInCheckedRounds) {
              rootCauseTable.push({
                ...baseRow,
                result: "target_deployment_not_ready_in_deployment_list_cache",
                rootCause: "404_due_to_deployment_not_ready_in_deployment_list_cache",
              });
              appendRunLog("STEP3.4", "root cause: target appears only after request (post-request rounds)", {
                ...decisionLogCtx,
                result: "target_deployment_not_ready_in_deployment_list_cache",
                rootCause: "404_due_to_deployment_not_ready_in_deployment_list_cache",
                postRequestRoundsChecked: link.deploymentListPostRequestCheck?.roundsChecked || 0,
              });
              continue;
            }
            rootCauseTable.push({
              ...baseRow,
              result: "requested_deployment_not_in_list_cache",
              rootCause: "404_due_to_deployment_not_in_top_3_list_cache",
            });
            appendRunLog(
              "STEP3.4",
              "root cause: target not found in post-request deployment-list rounds (top3 latest)",
              {
                ...decisionLogCtx,
                result: "requested_deployment_not_in_list_cache",
                rootCause: "404_due_to_deployment_not_in_top_3_list_cache",
                postRequestRoundsChecked: link.deploymentListPostRequestCheck?.roundsChecked || 0,
              },
            );
            continue;
          }
          rootCauseTable.push({
            ...baseRow,
            result: "target_deployment_not_ready_in_deployment_list_cache",
            rootCause: "404_due_to_deployment_not_ready_in_deployment_list_cache",
          });
          appendRunLog("STEP3.4", "root cause: target not ready in deployment list cache", {
            ...decisionLogCtx,
            result: "target_deployment_not_ready_in_deployment_list_cache",
            rootCause: "404_due_to_deployment_not_ready_in_deployment_list_cache",
          });
          continue;
        }
        if (link.deploymentListCacheCheck?.decision !== "target_present") {
          furtherAnalysisTable.push({
            ...baseRow,
            result: "deployment_list_cache_crosscheck_inconclusive",
            action: "further_analysis_required",
          });
          appendRunLog("STEP3.4", "deployment list cache cross-check inconclusive -> further analysis", {
            ...decisionLogCtx,
            result: "deployment_list_cache_crosscheck_inconclusive",
          });
          continue;
        }
        if (link.deploymentListCacheCheck?.usedRoundTargetHitKind === "default") {
          const runtimeCacheNotReadyYetLikely =
            link.completionTiming?.matched &&
            link.completionExtensionUsed &&
            Number(link.completionDistinctOriginalCount || 0) < 3 &&
            completionDistinctExtendCount >= 3 &&
            link.completionFoundAfterOriginalWindow;
          if (runtimeCacheNotReadyYetLikely) {
            if (restartWarmupLikely) {
              rootCauseTable.push({
                ...baseRow,
                result: "restart_evidence_preempts_runtime_cache_not_ready_yet",
                rootCause: "404_due_to_decision_service_restart_cache_warmup",
              });
              appendRunLog("STEP3.4", "restart evidence preempts runtime_cache_not_ready_yet", {
                ...decisionLogCtx,
                result: "restart_evidence_preempts_runtime_cache_not_ready_yet",
                rootCause: "404_due_to_decision_service_restart_cache_warmup",
                restartEvidenceCount: Number(link?.restartEvidence?.count || 0),
              });
              continue;
            }
            rootCauseTable.push({
              ...baseRow,
              result: "cache_prepare_completed_after_request_window",
              rootCause: "404_due_to_runtime_cache_not_ready_yet",
            });
            appendRunLog(
              "STEP3.4",
              "default-kind deployment list hit but runtime completion evidence indicates cache not ready yet",
              {
                ...decisionLogCtx,
                result: "cache_prepare_completed_after_request_window",
                rootCause: "404_due_to_runtime_cache_not_ready_yet",
                completionDistinctOriginalCount: Number(link.completionDistinctOriginalCount || 0),
                completionDistinctExtendCount,
                completionExtensionUsed: Boolean(link.completionExtensionUsed),
                completionFoundAfterOriginalWindow: Boolean(link.completionFoundAfterOriginalWindow),
              },
            );
            continue;
          }
          furtherAnalysisTable.push({
            ...baseRow,
            result: "deployment_list_cache_hit_default_kind",
            action: "further_analysis_required",
          });
          appendRunLog("STEP3.4", "deployment list hit kind=default -> further analysis", {
            ...decisionLogCtx,
            result: "deployment_list_cache_hit_default_kind",
          });
          continue;
        }
        if (link.deploymentListCacheCheck?.usedRoundTargetHitKind === "deployment") {
          if (!link.deploymentStateCheck?.found) {
            furtherAnalysisTable.push({
              ...baseRow,
              result: "deployment_state_check_missing",
              action: "further_analysis_required",
            });
            appendRunLog("STEP3.4", "deployment state check missing -> further analysis", {
              ...decisionLogCtx,
              result: "deployment_state_check_missing",
            });
            continue;
          }
          if (link.deploymentStateCheck?.servingTransitionAfterCacheHitBeforeRequest === true) {
            rootCauseTable.push({
              ...baseRow,
              result: "target_deployment_state_serving_transition_after_cache_round",
              rootCause: "404_due_to_deployment_not_ready_in_deployment_list_cache",
            });
            appendRunLog(
              "STEP3.4",
              "root cause: deployment became serving only after deployment-list cache round",
              {
                ...decisionLogCtx,
                result: "target_deployment_state_serving_transition_after_cache_round",
                rootCause: "404_due_to_deployment_not_ready_in_deployment_list_cache",
                cacheRoundHitLokiTsNs:
                  link.deploymentStateCheck?.cacheRoundHitLokiTsNs || null,
                latestAtOrBeforeCacheHitNewState:
                  link.deploymentStateCheck?.latestAtOrBeforeCacheHit?.newState || null,
                latestByRequestNewState: link.deploymentStateCheck?.latest?.newState || null,
                transitionEventCurState:
                  link.deploymentStateCheck?.servingTransitionEvent?.curState || null,
                transitionEventNewState:
                  link.deploymentStateCheck?.servingTransitionEvent?.newState || null,
                transitionEventLokiTsNs:
                  link.deploymentStateCheck?.servingTransitionEvent?.lokiTsNs || null,
              },
            );
            continue;
          }
          if (link.deploymentStateCheck?.isServingState !== true) {
            rootCauseTable.push({
              ...baseRow,
              result: "target_deployment_state_not_serving",
              rootCause: "404_due_to_deployment_not_ready_in_deployment_list_cache",
            });
            appendRunLog("STEP3.4", "root cause: deployment state not serving", {
              ...decisionLogCtx,
              result: "target_deployment_state_not_serving",
              rootCause: "404_due_to_deployment_not_ready_in_deployment_list_cache",
            });
            continue;
          }
        }
      } else {
        // Unknown trace error category: keep both checks as guardrails.
        if (link.deploymentListCacheCheck?.decision !== "target_present") {
          furtherAnalysisTable.push({
            ...baseRow,
            result: "deployment_list_cache_crosscheck_inconclusive",
            action: "further_analysis_required",
          });
          appendRunLog("STEP3.4", "unknown trace category and cache check inconclusive -> further analysis", {
            ...decisionLogCtx,
            result: "deployment_list_cache_crosscheck_inconclusive",
          });
          continue;
        }
      }

      if (
        link.completionTiming?.matched &&
        link.completionExtensionUsed &&
        Number(link.completionDistinctOriginalCount || 0) < 3 &&
        completionDistinctExtendCount >= 3 &&
        link.targetInUsedTop3 &&
        !link.targetInOriginalTop3 &&
        link.completionFoundAfterOriginalWindow &&
        link.earliestCompletionMatch?.deploymentID
      ) {
        if (restartWarmupLikely) {
          rootCauseTable.push({
            ...baseRow,
            result: "restart_evidence_preempts_runtime_cache_not_ready_yet",
            rootCause: "404_due_to_decision_service_restart_cache_warmup",
          });
          appendRunLog("STEP3.4", "restart evidence preempts runtime_cache_not_ready_yet", {
            ...decisionLogCtx,
            result: "restart_evidence_preempts_runtime_cache_not_ready_yet",
            rootCause: "404_due_to_decision_service_restart_cache_warmup",
            restartEvidenceCount: Number(link?.restartEvidence?.count || 0),
          });
          continue;
        }
        rootCauseTable.push({
          ...baseRow,
          result: "cache_prepare_completed_after_request_window",
          rootCause: "404_due_to_runtime_cache_not_ready_yet",
        });
        appendRunLog("STEP3.4", "root cause: extended completion evidence indicates cache not ready", {
          ...decisionLogCtx,
          result: "cache_prepare_completed_after_request_window",
          rootCause: "404_due_to_runtime_cache_not_ready_yet",
        });
        continue;
      }

      if (uniqueCacheDeployments.length > 3) {
        furtherAnalysisTable.push({
          ...baseRow,
          issue: "cache_deployment_list_gt_3",
          action: "further_analysis_required",
        });
      }

      if (baseRow.step3_3Conclusion !== "cache_load_success") {
        if (
          baseRow.step3_3Conclusion === "cache_load_restart_warmup" ||
          link.reason === "restart_warmup"
        ) {
          rootCauseTable.push({
            ...baseRow,
            result: "single_restart_log_in_step3_3_window",
            rootCause: "404_due_to_decision_service_restart_cache_warmup",
          });
          appendRunLog("STEP3.4", "root cause: restart warmup", {
            ...decisionLogCtx,
            result: "single_restart_log_in_step3_3_window",
            rootCause: "404_due_to_decision_service_restart_cache_warmup",
          });
          continue;
        }
        if (baseRow.step3_3Conclusion === "cache_load_failure") {
          rootCauseTable.push({
            ...baseRow,
            result: "runtime_services_cache_load_failure",
            rootCause: "404_due_to_runtime_services_cache_load_failure",
          });
          appendRunLog("STEP3.4", "root cause: runtime services cache load failure", {
            ...decisionLogCtx,
            result: "runtime_services_cache_load_failure",
            rootCause: "404_due_to_runtime_services_cache_load_failure",
            failureEvidenceCount: Number(link.failureEvidenceCount || 0),
          });
          continue;
        }
        furtherAnalysisTable.push({
          ...baseRow,
          result: "cache_load_not_success_skip_cache_membership_check",
          action: "further_analysis_required",
        });
        appendRunLog("STEP3.4", "step3.3 not success -> further analysis", {
          ...decisionLogCtx,
          result: "cache_load_not_success_skip_cache_membership_check",
        });
        continue;
      }

      if (reqInfo.type === "explicit") {
        if (seen.has(reqInfo.deploymentID)) {
          furtherAnalysisTable.push({
            ...baseRow,
            result: "requested_deployment_found_in_cache",
            action: "further_analysis_required",
          });
          appendRunLog("STEP3.4", "explicit deployment found in cache -> further analysis", {
            ...decisionLogCtx,
            result: "requested_deployment_found_in_cache",
          });
        } else {
          rootCauseTable.push({
            ...baseRow,
            result: "requested_deployment_not_in_runtime_cache",
            rootCause: "404_due_to_deployment_not_in_top_3_runtime_cache",
          });
          appendRunLog("STEP3.4", "root cause: explicit deployment missing in runtime cache", {
            ...decisionLogCtx,
            result: "requested_deployment_not_in_runtime_cache",
            rootCause: "404_due_to_deployment_not_in_top_3_runtime_cache",
            completionDistinctOriginalCount: Number(link.completionDistinctOriginalCount || 0),
            completionDistinctExtendCount,
            completionExtensionUsed: Boolean(link.completionExtensionUsed),
          });
        }
        continue;
      }

      if (reqInfo.type === "default") {
        const resolvedDefaultId = baseRow.resolvedDefaultDeploymentID;
        if (!resolvedDefaultId) {
          furtherAnalysisTable.push({
            ...baseRow,
            result: "default_deployment_id_not_found_in_window",
            action: "further_analysis_required",
          });
          appendRunLog("STEP3.4", "default deployment id not resolved -> further analysis", {
            ...decisionLogCtx,
            result: "default_deployment_id_not_found_in_window",
          });
        } else if (seen.has(resolvedDefaultId)) {
          furtherAnalysisTable.push({
            ...baseRow,
            result: "default_deployment_found_in_cache",
            action: "further_analysis_required",
          });
          appendRunLog("STEP3.4", "default deployment found in cache -> further analysis", {
            ...decisionLogCtx,
            result: "default_deployment_found_in_cache",
          });
        } else {
          rootCauseTable.push({
            ...baseRow,
            result: "default_deployment_not_in_cache",
            rootCause: "404_due_to_deployment_not_in_top_3_runtime_cache",
          });
          appendRunLog("STEP3.4", "root cause: default deployment missing in runtime cache", {
            ...decisionLogCtx,
            result: "default_deployment_not_in_cache",
            rootCause: "404_due_to_deployment_not_in_top_3_runtime_cache",
            completionDistinctOriginalCount: Number(link.completionDistinctOriginalCount || 0),
            completionDistinctExtendCount,
            completionExtensionUsed: Boolean(link.completionExtensionUsed),
          });
        }
        continue;
      }

      furtherAnalysisTable.push({
        ...baseRow,
        result: "invalid_or_unexpected_url_pattern",
        action: "further_analysis_required",
      });
      appendRunLog("STEP3.4", "invalid or unexpected URL pattern -> further analysis", {
        ...decisionLogCtx,
        result: "invalid_or_unexpected_url_pattern",
      });
    }
  }

  const alignedRootCauseTable = [];
  for (const row of rootCauseTable) {
    const align = checkRootCauseTraceAlignment(row);
    if (align.aligned) {
      alignedRootCauseTable.push(row);
      continue;
    }
    furtherAnalysisTable.push({
      ...row,
      result: "trace_pattern_root_cause_mismatch",
      action: "further_analysis_required",
      expectedDirection: align.expectedDirection,
      supportedDirections: align.supportedDirections,
    });
    appendRunLog("STEP3.4", "trace pattern/root cause mismatch -> further analysis", {
      env: row?.env || null,
      traceID: row?.traceID || null,
      traceErrorCategory: row?.traceErrorCategory || null,
      rootCause: row?.rootCause || null,
      expectedDirection: align.expectedDirection,
      supportedDirections: align.supportedDirections,
    });
  }

  const fullAnalysisFurtherAnalysisIdentitySet = new Set();
  for (const [env, item] of Object.entries(step3_3ByEnv || {})) {
    for (const link of item?.links || []) {
      if (!Boolean(link?.fullAnalysisPerformed)) continue;
      const request = link?.request || {};
      fullAnalysisFurtherAnalysisIdentitySet.add(
        buildFurtherAnalysisIdentityKey({
          env,
          traceID: request.traceID || null,
          requestLokiTsNs: request.lokiTsNs || null,
          url: request.url || null,
          pod: request.pod || null,
        }),
      );
    }
  }
  const filteredFurtherAnalysisTable = furtherAnalysisTable.filter(row =>
    fullAnalysisFurtherAnalysisIdentitySet.has(buildFurtherAnalysisIdentityKey(row)),
  );
  if (filteredFurtherAnalysisTable.length !== furtherAnalysisTable.length) {
    appendRunLog("STEP3.4", "filtered further analysis table to full-analysis links only", {
      beforeCount: furtherAnalysisTable.length,
      afterCount: filteredFurtherAnalysisTable.length,
      removedCount: furtherAnalysisTable.length - filteredFurtherAnalysisTable.length,
    });
  }

  return {
    rootCauseTable: alignedRootCauseTable,
    furtherAnalysisTable: filteredFurtherAnalysisTable,
  };
}

function summarizeStep3_4(step3_4Result) {
  const weightedRootCauseCount = (step3_4Result?.rootCauseTable || []).reduce(
    (sum, r) => sum + Number(r?.duplicateCount || 1),
    0,
  );
  const weightedFurtherAnalysisCount = (step3_4Result?.furtherAnalysisTable || []).reduce(
    (sum, r) => sum + Number(r?.duplicateCount || 1),
    0,
  );
  return {
    rootCauseCount: weightedRootCauseCount,
    furtherAnalysisCount: weightedFurtherAnalysisCount,
    dedupedRootCauseRowCount: step3_4Result?.rootCauseTable?.length || 0,
    dedupedFurtherAnalysisRowCount: step3_4Result?.furtherAnalysisTable?.length || 0,
  };
}

function isLikelyCacheLoadingErrorContext(parsedObj, rawLine) {
  const text = `${String(parsedObj?.message || "")} ${String(parsedObj?.error || "")} ${String(
    rawLine || "",
  )}`.toLowerCase();
  return (
    text.includes("cache") ||
    text.includes("start loading policies") ||
    text.includes("role mappings for all deployments") ||
    text.includes("prepare decision server cache") ||
    text.includes("deployment list cache")
  );
}

async function runMandatoryFurtherAnalysisLokiChecks(
  step3_4Result,
  { regionContext = null, queryLokiFn = null } = {},
) {
  const queryLokiForStep = typeof queryLokiFn === "function" ? queryLokiFn : queryLoki;
  const rows = step3_4Result?.furtherAnalysisTable || [];
  const lookbackMinutes = 10;
  const lookbackNs = lookbackMinutes * 60 * 1e9;
  const evidenceByCaseKey = {};
  const queryResultCache = new Map();
  let checkedRowCount = 0;
  let skippedRowCount = 0;
  let restartHitRowCount = 0;
  let cacheErrorHitRowCount = 0;
  let queryCacheHitCount = 0;
  let queryExecutedCount = 0;

  async function queryWithCache(expr, opts) {
    const key = JSON.stringify({
      expr: String(expr || ""),
      startNs: String(opts?.startNs ?? ""),
      endNs: String(opts?.endNs ?? ""),
      direction: String(opts?.direction || ""),
      limit: Number(opts?.limit || 0),
      regionContext: String(opts?.regionContext || ""),
    });
    if (queryResultCache.has(key)) {
      queryCacheHitCount += 1;
      return queryResultCache.get(key);
    }
    queryExecutedCount += 1;
    const result = await queryLokiForStep(expr, opts);
    queryResultCache.set(key, result);
    return result;
  }

  for (const row of rows) {
    const env = String(row?.env || "").trim();
    const pod = String(row?.pod || "").trim();
    const traceID = String(row?.traceID || "").trim() || null;
    const reqTsNs = Number(row?.requestLokiTsNs);
    const caseKey = [env, traceID || "", String(row?.requestLokiTsNs || ""), String(row?.url || ""), pod].join(
      "|",
    );

    if (!env || !pod || !Number.isFinite(reqTsNs) || reqTsNs <= 0) {
      skippedRowCount += 1;
      evidenceByCaseKey[caseKey] = {
        checked: false,
        reason: "missing_env_or_pod_or_request_timestamp",
      };
      appendRunLog("STEP3.4", "mandatory 10m further-analysis Loki checks skipped", {
        env: env || null,
        traceID,
        pod: pod || null,
        requestLokiTsNs: Number.isFinite(reqTsNs) ? String(reqTsNs) : null,
        reason: "missing_env_or_pod_or_request_timestamp",
      });
      continue;
    }

    const startNs = Math.max(0, subtractNsWithPrecisionGuard(reqTsNs, lookbackNs));
    const endNs = subtractNsWithPrecisionGuard(reqTsNs, 1);
    const selector = `${buildDecisionSelector(env, pod)} != "/live" != "/ready"`;
    const restartExpr = `${selector} |~ "starting decision server|starting authz decision server"`;
    const cacheErrorExpr = `${selector} |~ \`"level"\\s*:\\s*"error"|"error"\\s*:|panic|exception|failed\``;

    const [restartJson, cacheErrorJson] = await Promise.all([
      queryWithCache(restartExpr, {
        startNs,
        endNs,
        direction: "BACKWARD",
        limit: 200,
        regionContext,
      }),
      queryWithCache(cacheErrorExpr, {
        startNs,
        endNs,
        direction: "BACKWARD",
        limit: 1000,
        regionContext,
      }),
    ]);

    const restartEntries = [];
    for (const stream of restartJson?.data?.result || []) {
      for (const [tsNs, line] of stream.values || []) {
        const parsed = extractJsonObjectFromLogLine(line);
        restartEntries.push({
          lokiTsNs: String(tsNs),
          timestamp: parsed?.timestamp ? String(parsed.timestamp) : null,
          message: parsed?.message ? String(parsed.message) : null,
          line: String(line || ""),
        });
      }
    }

    const cacheErrorEntries = [];
    for (const stream of cacheErrorJson?.data?.result || []) {
      for (const [tsNs, line] of stream.values || []) {
        const parsed = extractJsonObjectFromLogLine(line);
        const rec = extractErrorRecordFromParsedLogObject(parsed);
        if (!rec) continue;
        if (!isLikelyCacheLoadingErrorContext(parsed, line)) continue;
        cacheErrorEntries.push({
          lokiTsNs: String(tsNs),
          timestamp: parsed?.timestamp ? String(parsed.timestamp) : null,
          message: parsed?.message ? String(parsed.message) : null,
          error: parsed?.error ? String(parsed.error) : null,
          display: rec.display || null,
          line: String(line || ""),
        });
      }
    }

    checkedRowCount += 1;
    if (restartEntries.length > 0) restartHitRowCount += 1;
    if (cacheErrorEntries.length > 0) cacheErrorHitRowCount += 1;
    evidenceByCaseKey[caseKey] = {
      checked: true,
      requestLokiTsNs: String(reqTsNs),
      startNs: String(startNs),
      endNs: String(endNs),
      restartQuery: restartExpr,
      cacheErrorQuery: cacheErrorExpr,
      restartEvidenceCount: restartEntries.length,
      cacheLoadErrorEvidenceCount: cacheErrorEntries.length,
      restartEvidenceSample: restartEntries.slice(0, 5),
      cacheLoadErrorEvidenceSample: cacheErrorEntries.slice(0, 5),
    };
    appendRunLog("STEP3.4", "mandatory 10m further-analysis Loki checks completed", {
      env,
      traceID,
      pod,
      requestLokiTsNs: String(reqTsNs),
      windowStartNs: String(startNs),
      windowEndNs: String(endNs),
      restartEvidenceCount: restartEntries.length,
      cacheLoadErrorEvidenceCount: cacheErrorEntries.length,
      restartQuery: restartExpr,
      cacheErrorQuery: cacheErrorExpr,
    });
  }

  const summary = {
    lookbackMinutes,
    checkedRowCount,
    skippedRowCount,
    restartHitRowCount,
    cacheErrorHitRowCount,
    queryExecutedCount,
    queryCacheHitCount,
    evidenceByCaseKey,
  };
  if (step3_4Result && typeof step3_4Result === "object") {
    step3_4Result.mandatoryFurtherChecks = summary;
  }
  appendRunLog("STEP3.4", "mandatory 10m further-analysis Loki checks summary", {
    lookbackMinutes,
    totalFurtherRows: rows.length,
    checkedRowCount,
    skippedRowCount,
    restartHitRowCount,
    cacheErrorHitRowCount,
    queryExecutedCount,
    queryCacheHitCount,
  });
  return summary;
}

function buildStep3_4SummaryByEnvTable(
  step3_4Result,
  step2SummaryByEnv = {},
  step3_3ByEnv = {},
  recoveryByEnv = {},
) {
  const rootCauseToSummaryColumn = {
    "404_due_to_runtime_cache_not_ready_yet": "cache_not_ready_yet",
    "404_due_to_deployment_not_ready_in_deployment_list_cache":
      "cache_not_ready_yet",
    "404_due_to_deployment_not_in_top_3_list_cache":
      "deployment_not_in_top_3_latest_deployments",
    "404_due_to_deployment_not_in_top_3_latest_deployments":
      "deployment_not_in_top_3_latest_deployments",
    "404_due_to_decision_service_restart_cache_warmup": "cache_not_ready_yet",
    "404_due_to_runtime_services_cache_load_failure": "runtime_services_cache_load_failure",
    "404_due_to_deployment_not_in_top_3_runtime_cache":
      "deployment_not_in_top_3_latest_deployments",
    "404_due_to_runtime_cache_not_ready": "deployment_not_in_top_3_latest_deployments",
    "404_due_to_deployment_not_in_memory_cache": "deployment_not_in_top_3_latest_deployments",
    "404_due_to_default_deployment_not_in_memory_cache": "deployment_not_in_top_3_latest_deployments",
  };
  const summaryRootCauseColumns = [
    "cache_not_ready_yet",
    "deployment_not_in_top_3_latest_deployments",
    "runtime_services_cache_load_failure",
    "root_cause_unknown",
  ];
  const byEnv = {};
  const rootCauseCountsByEnv = {};
  const ensureEnv = env => {
    const key = String(env || "");
    if (!byEnv[key]) {
      const row = {
        env: key,
        total404: 0,
        rootCauseCount: 0,
        recoveryStatus: null,
      };
      for (const col of summaryRootCauseColumns) row[col] = 0;
      byEnv[key] = row;
    }
    if (!rootCauseCountsByEnv[key]) rootCauseCountsByEnv[key] = new Map();
    return byEnv[key];
  };

  // Preserve all Step 2/3.3 envs in summary output, even when no root-cause/further rows exist.
  for (const env of Object.keys(step2SummaryByEnv || {})) ensureEnv(env);
  for (const env of Object.keys(step3_3ByEnv || {})) ensureEnv(env);

  for (const row of step3_4Result?.rootCauseTable || []) {
    const x = ensureEnv(row.env);
    const dup = Number(row?.duplicateCount || 1);
    x.total404 += dup;
    x.rootCauseCount += dup;
    const cause = String(row.rootCause || "");
    const causeMap = rootCauseCountsByEnv[String(row.env || "")];
    if (causeMap) {
      causeMap.set(cause, Number(causeMap.get(cause) || 0) + dup);
    }
    const summaryCol = rootCauseToSummaryColumn[cause];
    if (summaryCol) {
      x[summaryCol] += dup;
    }
  }
  for (const row of step3_4Result?.furtherAnalysisTable || []) {
    const x = ensureEnv(row.env);
    const dup = Number(row?.duplicateCount || 1);
    x.total404 += dup;
    x.rootCauseCount += dup;
    x.root_cause_unknown += dup;
  }

  // Reconcile per-env totals with raw Step2 matched volume.
  // Invariant:
  // - total404 must equal Step2 raw matched count when Step2 data exists.
  // - total404 must equal the sum of the four summary root-cause columns.
  for (const row of Object.values(byEnv)) {
    const env = String(row?.env || "");
    const hasStep2MatchedCount =
      step2SummaryByEnv &&
      Object.prototype.hasOwnProperty.call(step2SummaryByEnv, env) &&
      Number.isFinite(Number(step2SummaryByEnv?.[env]?.matchedLineCount));
    if (!hasStep2MatchedCount) continue;

    const rawMatchedCount = Number(step2SummaryByEnv?.[env]?.matchedLineCount || 0);
    const knownRootCauseCount =
      Number(row.cache_not_ready_yet || 0) +
      Number(row.deployment_not_in_top_3_latest_deployments || 0) +
      Number(row.runtime_services_cache_load_failure || 0);

    if (knownRootCauseCount > rawMatchedCount) {
      appendRunLog("STEP3.4", "summary reconciliation warning: known causes exceed step2 matched count", {
        env,
        step2MatchedLineCount: rawMatchedCount,
        knownRootCauseCount,
        cache_not_ready_yet: Number(row.cache_not_ready_yet || 0),
        deployment_not_in_top_3_latest_deployments: Number(
          row.deployment_not_in_top_3_latest_deployments || 0,
        ),
        runtime_services_cache_load_failure: Number(
          row.runtime_services_cache_load_failure || 0,
        ),
      });
    }

    row.root_cause_unknown = Math.max(0, rawMatchedCount - knownRootCauseCount);
    row.rootCauseCount =
      Number(row.cache_not_ready_yet || 0) +
      Number(row.deployment_not_in_top_3_latest_deployments || 0) +
      Number(row.runtime_services_cache_load_failure || 0) +
      Number(row.root_cause_unknown || 0);
    row.total404 = row.rootCauseCount;
  }

  for (const row of Object.values(byEnv)) {
    const env = String(row?.env || "");
    const recovery = recoveryByEnv?.[env] || null;
    row.recoveryStatus = recovery?.recoveryStatus || "not_sure";
  }

  return Object.values(byEnv).sort((a, b) => String(a.env).localeCompare(String(b.env)));
}

function buildStep3ParsedByEnv(step2ByEnv) {
  const out = {};

  for (const [env, item] of Object.entries(step2ByEnv || {})) {
    const records = [];
    let invalidLineCount = 0;
    const streams = item.streams || [];

    for (const stream of streams) {
      const pod = stream?.stream?.pod || null;
      for (const [tsNs, line] of stream.values || []) {
        const rec = parseDecision404Record(line, tsNs, env, pod);
        if (!rec) {
          invalidLineCount += 1;
          continue;
        }
        records.push(rec);
      }
    }

    const dedupeRes = dedupeDecision404Records(records);
    const traceCounts = new Map();
    for (const rec of dedupeRes.records || []) {
      const traceID = String(rec?.traceID || "");
      if (!traceID) continue;
      traceCounts.set(traceID, (traceCounts.get(traceID) || 0) + 1);
    }
    const repeatedTraceStats = [...traceCounts.entries()]
      .filter(([, count]) => count > 1)
      .sort((a, b) => b[1] - a[1]);
    const repeatedTraceCount = repeatedTraceStats.length;
    const repeatedTraceRows = repeatedTraceStats.reduce((sum, [, count]) => sum + count, 0);
    const maxTraceRepeatCount = repeatedTraceStats.length ? repeatedTraceStats[0][1] : 1;
    const repeatedTraceSamples = repeatedTraceStats
      .slice(0, 10)
      .map(([traceID, count]) => ({ traceID, count }));

    out[env] = {
      records: dedupeRes.records,
      invalidLineCount,
      totalMatchedLineCount: item.matchedLineCount || 0,
      rawRecordCount: records.length,
      dedupedRecordCount: dedupeRes.dedupedRecordCount,
      dedupCollapsedCount: dedupeRes.collapsedCount,
      splitMeta: item.splitMeta || null,
      step2UnsplittableLimitHitCount: Number(item?.splitMeta?.unsplittableLimitHitCount || 0),
    };

    console.log(
      `Step 3 env=${env} rawParsedRecords=${records.length} dedupedRecords=${dedupeRes.dedupedRecordCount} dedupCollapsed=${dedupeRes.collapsedCount} invalidLineCount=${invalidLineCount}`,
    );
    appendRunLog("STEP3", "parsed and deduped records for env", {
      env,
      rawParsedRecords: records.length,
      dedupedRecords: dedupeRes.dedupedRecordCount,
      dedupCollapsed: dedupeRes.collapsedCount,
      invalidLineCount,
    });
    appendRunLog("STEP3", "traceID repetition snapshot for env", {
      env,
      dedupedRecords: dedupeRes.dedupedRecordCount,
      uniqueTraceCount: traceCounts.size,
      repeatedTraceCount,
      repeatedTraceRows,
      maxTraceRepeatCount,
      repeatedTraceSamples,
    });
  }

  return out;
}

function buildStep2CompactSummary(step2ByEnv) {
  const out = {};
  for (const [env, item] of Object.entries(step2ByEnv || {})) {
    const matchedLineCount = Number(item.matchedLineCount || 0);
    const metricCount404EstimateSum = Number(item?.splitMeta?.metricCount404EstimateSum || 0);
    const estimatedTotal404 = Math.max(matchedLineCount, metricCount404EstimateSum);
    const unsplittableLimitHitCount = Number(item?.splitMeta?.unsplittableLimitHitCount || 0);
    out[env] = {
      matchedLineCount,
      estimatedTotal404,
      metricCount404EstimateSum,
      unsplittableLimitHitCount,
      streamCount: item.streamCount || 0,
      isLimitLikelyHit: Boolean(item.isLimitLikelyHit),
    };
  }
  return out;
}

function getStep1WindowConfig() {
  const step1RangeStartMs = new Date(ANALYSIS_CONFIG.step1RangeStartPst).getTime();
  const step1RangeEndMs = new Date(ANALYSIS_CONFIG.step1RangeEndPst).getTime();
  const step1RangeStartSec = Math.floor(step1RangeStartMs / 1000);
  const step1RangeEndSec = Math.floor(step1RangeEndMs / 1000);
  const step1MimirHours = Math.round((step1RangeEndMs - step1RangeStartMs) / (60 * 60 * 1000));
  return {
    step1RangeStartMs,
    step1RangeEndMs,
    step1RangeStartSec,
    step1RangeEndSec,
    step1MimirHours,
  };
}

async function runStep1ForRegion(region, { envProgressTracker = null } = {}) {
  const activeRegion = String(region || "").trim();
  const activeRegionConfig = buildRegionConfig(activeRegion);
  appendRunLog("RUN", "Region analysis started", {
    region: activeRegion,
    displayName: activeRegionConfig.displayName,
    mimirUid: activeRegionConfig.mimirUid,
    lokiUid: activeRegionConfig.lokiUid,
  });

  const { step1RangeStartMs, step1RangeEndMs, step1RangeStartSec, step1RangeEndSec, step1MimirHours } =
    getStep1WindowConfig();

  const expr =
    'sum by (prd_env) (rate(application_processed_requests_total{prd_fleet="faaas-prod", job="authz-decision", statuscode=~"404"}[5m])) > 0';
  const mimirJson = await queryMimirRange(expr, {
    stepSec: 300,
    hours: step1MimirHours,
    startSec: step1RangeStartSec,
    endSec: step1RangeEndSec,
    regionContext: activeRegion,
  });
  const summary = summarizeDecision404Series(mimirJson);
  appendRunLog("STEP1", "Mimir query completed", {
    region: activeRegion,
    impactedEnvCount: summary.impactedEnvs.length,
    rangeStartUtc: new Date(step1RangeStartMs).toISOString(),
    rangeEndUtc: new Date(step1RangeEndMs).toISOString(),
  });
  if (envProgressTracker && typeof envProgressTracker.registerRegion === "function") {
    const p = envProgressTracker.registerRegion(activeRegion, summary.impactedEnvs.length);
    appendRunLog("RUN", "Global env progress registered for region", {
      region: activeRegion,
      regionImpactedEnvCount: summary.impactedEnvs.length,
      processedEnvCount: p.processedEnvCount,
      totalEnvCount: p.totalEnvCount,
      progressPct: p.progressPct,
    });
  }

  console.log(
    `Step 1 complete: decision service 404s in ${activeRegionConfig.displayName} (${activeRegion}) (fixed range)`,
  );
  console.log(
    `Step 1 range (PST): ${ANALYSIS_CONFIG.step1RangeStartPst} to ${ANALYSIS_CONFIG.step1RangeEndPst} | UTC: ${new Date(
      step1RangeStartMs,
    ).toISOString()} to ${new Date(step1RangeEndMs).toISOString()}`,
  );
  console.log("Impacted env count:", summary.impactedEnvs.length);
  console.log("Impacted env list:", summary.impactedEnvs);
  console.log("Per-env summary:", summary.byEnv);

  return {
    region: activeRegion,
    activeRegionConfig,
    summary,
    step1RangeStartMs,
    step1RangeEndMs,
    step1RangeStartSec,
    step1RangeEndSec,
    step1MimirHours,
  };
}

async function runDecision404AnalysisForRegion(region, { envProgressTracker = null, step1Result = null } = {}) {
  const activeRegion = String(region || "").trim();
  const activeRegionConfig = buildRegionConfig(activeRegion);
  const resolvedStep1 =
    step1Result && step1Result.summary
      ? step1Result
      : await runStep1ForRegion(region);

  const {
    summary,
    step1RangeStartMs,
    step1RangeEndMs,
    step1RangeStartSec,
    step1RangeEndSec,
    step1MimirHours,
  } = resolvedStep1;
  appendRunLog("RUN", "Region Step2/Step3 processing started", {
    region: activeRegion,
    impactedEnvCount: summary.impactedEnvs.length,
  });

  const step2RangeStartNs = step1RangeStartSec * 1e9;
  const step2RangeEndNs = step1RangeEndSec * 1e9;
  const STEP2_LOKI_HOURS = step1MimirHours;
  const lokiByEnv = await collectDecision404LogsByEnv(summary.impactedEnvs, {
    hours: STEP2_LOKI_HOURS,
    limit: 3000,
    startNs: step2RangeStartNs,
    endNs: step2RangeEndNs,
    regionContext: activeRegion,
  });

  console.log("Step 2 complete.");
  console.log(`Step 2 time window hours: ${STEP2_LOKI_HOURS}`);
  console.log(
    `Step 2 range (PST): ${ANALYSIS_CONFIG.step1RangeStartPst} to ${ANALYSIS_CONFIG.step1RangeEndPst} | UTC: ${new Date(
      step1RangeStartMs,
    ).toISOString()} to ${new Date(step1RangeEndMs).toISOString()}`,
  );
  const step2Summary = buildStep2CompactSummary(lokiByEnv);
  appendRunLog("STEP2", "Loki 404 request collection completed", {
    region: activeRegion,
    envCount: Object.keys(step2Summary || {}).length,
  });
  console.log("Step 2 summary:", step2Summary);

  const step3ParsedByEnv = buildStep3ParsedByEnv(lokiByEnv);
  const step3_1ValidationByEnv = buildStep3_1Validation(step3ParsedByEnv);
  const step3_1SummaryByEnv = summarizeStep3_1Validation(step3_1ValidationByEnv);
  const step3_2ByEnv = await buildStep3_2PreviousLogByEnv(step3_1ValidationByEnv, {
    lookbackHours: 1,
    regionContext: activeRegion,
  });
  const step3_2SummaryByEnv = summarizeStep3_2PreviousLog(step3_2ByEnv);
  const step3_3ByEnv = await buildStep3_3CacheLoadingByEnv(step3_2ByEnv, {
    regionContext: activeRegion,
    envProgressTracker,
  });
  const step3_3SummaryByEnv = summarizeStep3_3CacheLoading(step3_3ByEnv);
  const step3_3FailureErrorToEnvMap = buildStep3_3FailureErrorToEnvMap(step3_3ByEnv);
  const authzVersionByEnv = {};
  const step3_4Result = buildStep3_4DeploymentCacheCheck(step3_3ByEnv, authzVersionByEnv, {
    step2ByEnv: lokiByEnv,
  });
  await runMandatoryFurtherAnalysisLokiChecks(step3_4Result, {
    regionContext: activeRegion,
  });
  const step3_4Summary = summarizeStep3_4(step3_4Result);
  const step3_5RecoveryByEnv = await evaluateRecoveryStatusByEnv(step3ParsedByEnv, {
    regionContext: activeRegion,
  });
  const step3_4SummaryByEnvTable = buildStep3_4SummaryByEnvTable(
    step3_4Result,
    step2Summary,
    step3_3ByEnv,
    step3_5RecoveryByEnv,
  );
  const step3Summary = summarizeStep3Records(step3ParsedByEnv);
  appendRunLog("STEP3.4", "Step 3.4 aggregation completed", {
    region: activeRegion,
    rootCauseCount: step3_4Summary.rootCauseCount,
    furtherAnalysisCount: step3_4Summary.furtherAnalysisCount,
    summaryByEnvRows: step3_4SummaryByEnvTable.length,
  });
  appendRunLog("STEP3.5", "Step 3.5 recovery check completed", {
    region: activeRegion,
    envCount: Object.keys(step3_5RecoveryByEnv || {}).length,
    recoveredEnvCount: Object.values(step3_5RecoveryByEnv || {}).filter(
      x => String(x?.recoveryStatus || "") === "recovered",
    ).length,
    notRecoveredEnvCount: Object.values(step3_5RecoveryByEnv || {}).filter(
      x => String(x?.recoveryStatus || "") === "not_recovered",
    ).length,
    notSureEnvCount: Object.values(step3_5RecoveryByEnv || {}).filter(
      x => String(x?.recoveryStatus || "") === "not_sure",
    ).length,
  });

  console.log("Step 3.1 complete.");
  console.log("Step 3.1 summary:", step3_1SummaryByEnv);

  console.log("Step 3.2 complete.");
  console.log("Step 3.2 summary:", step3_2SummaryByEnv);

  console.log("Step 3.3 complete.");
  console.log("Step 3.3 summary:", step3_3SummaryByEnv);
  console.log("Step 3.3 cache-load-failure error->env map:", step3_3FailureErrorToEnvMap);

  console.log("Step 3.4 complete.");
  console.log("Step 3.4 summary:", step3_4Summary);

  console.log("Step 3 complete.");
  console.log("Step 3 summary:", step3Summary);

  return {
    region: activeRegion,
    impactedEnvs: summary.impactedEnvs,
    rootCauseCount: step3_4Summary.rootCauseCount,
    furtherAnalysisCount: step3_4Summary.furtherAnalysisCount,
    summaryRows: (step3_4SummaryByEnvTable || []).map(r => ({ region: activeRegion, ...r })),
    furtherRows: (step3_4Result.furtherAnalysisTable || []).map(r => ({ region: activeRegion, ...r })),
  };
}

if (typeof window !== "undefined") {
  (async () => {
    try {
      appendRunLog("RUN", "Decision404 analysis started");
      const requestedRegions = ANALYSIS_CONFIG.iterateAllRegions
        ? ALL_REGIONS
        : ANALYSIS_CONFIG.regionsToRun;
      const regions = [...new Set((requestedRegions || []).filter(Boolean))];
      const maxParallelEnvs = getMaxParallelEnvs();
      appendRunLog("RUN", "Region plan determined", {
        iterateAllRegions: Boolean(ANALYSIS_CONFIG.iterateAllRegions),
        regionCount: regions.length,
        maxParallelRegions: 1,
        maxParallelEnvs,
        regions,
      });

      const allSummaryRows = [];
      const allFurtherRows = [];
      const allImpactedEnvs = new Set();
      let totalRootCauseCount = 0;
      let totalFurtherAnalysisCount = 0;
      const envProgressTracker = createEnvProgressTracker();
      const step1ByRegion = new Map();

      appendRunLog("RUN", "Step1 pre-discovery started", {
        regionCount: regions.length,
        maxParallelRegions: 1,
      });
      const step1Results = await mapWithConcurrency(regions, 1, async (region, idx) => {
        const waitMs = Math.max(0, Number(ANALYSIS_CONFIG.throttleBetweenRegionsMs || 0));
        if (waitMs > 0 && idx > 0) await sleepMs(waitMs);
        return runStep1ForRegion(region);
      });

      for (let i = 0; i < step1Results.length; i += 1) {
        const region = regions[i];
        const step1Run = step1Results[i];
        if (step1Run?.status === "fulfilled") {
          const res = step1Run.value;
          step1ByRegion.set(region, res);
          for (const env of res?.summary?.impactedEnvs || []) allImpactedEnvs.add(env);
          continue;
        }

        const step1Err = step1Run?.reason;
        appendRunLog("RUN", "Region Step1 failed; region will be skipped", {
          region,
          error: String(step1Err?.message || step1Err),
        });
        console.error(`Region Step1 failed region=${region}:`, step1Err);
      }

      for (const region of regions) {
        const step1 = step1ByRegion.get(region);
        if (!step1) continue;
        const p = envProgressTracker.registerRegion(region, step1.summary.impactedEnvs.length);
        appendRunLog("RUN", "Global env progress registered for region", {
          region,
          regionImpactedEnvCount: step1.summary.impactedEnvs.length,
          processedEnvCount: p.processedEnvCount,
          totalEnvCount: p.totalEnvCount,
          progressPct: p.progressPct,
        });
      }

      const finalizedProgress = envProgressTracker.getProgress();
      appendRunLog("RUN", "Global env total finalized before Step2/Step3", {
        processedEnvCount: finalizedProgress.processedEnvCount,
        totalEnvCount: finalizedProgress.totalEnvCount,
        progressPct: finalizedProgress.progressPct,
        regionsWithStep1Success: step1ByRegion.size,
      });

      const regionsForAnalysis = regions.filter(region => step1ByRegion.has(region));
      const regionResults = await mapWithConcurrency(regionsForAnalysis, 1, async (region, idx) => {
        const waitMs = Math.max(0, Number(ANALYSIS_CONFIG.throttleBetweenRegionsMs || 0));
        if (waitMs > 0 && idx > 0) await sleepMs(waitMs);
        return runDecision404AnalysisForRegion(region, {
          envProgressTracker,
          step1Result: step1ByRegion.get(region),
        });
      });

      for (let i = 0; i < regionResults.length; i += 1) {
        const region = regionsForAnalysis[i];
        const runResult = regionResults[i];
        if (runResult?.status === "fulfilled") {
          const res = runResult.value;
          totalRootCauseCount += Number(res?.rootCauseCount || 0);
          totalFurtherAnalysisCount += Number(res?.furtherAnalysisCount || 0);
          allSummaryRows.push(...(res?.summaryRows || []));
          allFurtherRows.push(...(res?.furtherRows || []));
          continue;
        }

        const regionErr = runResult?.reason;
        appendRunLog("RUN", "Region analysis failed; continue with next region", {
          region,
          error: String(regionErr?.message || regionErr),
        });
        console.error(`Region analysis failed region=${region}:`, regionErr);
      }

      try {
        const saveRes = await saveEnvListTxtFromStep1([...allImpactedEnvs], "EnvList.txt");
        console.log("Step 1 EnvList.txt export:", saveRes);
      } catch (e) {
        console.error("Step 1 EnvList.txt export failed:", e);
      }

      const runLogContent =
        [
          "Decision404 Analysis Run Log",
          `generatedAtUtc=${new Date().toISOString()}`,
          `rootCauseCount=${totalRootCauseCount}`,
          `furtherAnalysisCount=${totalFurtherAnalysisCount}`,
          `regionCount=${regions.length}`,
          "",
          ...RUN_LOG_LINES,
        ].join("\n") + "\n";

      const csvFiles = [
        {
          suggestedName: "decision404_summary_by_env.csv",
          content: rowsToCsv(allSummaryRows),
        },
        {
          suggestedName: "decision404_further_analysis_table.csv",
          content: rowsToCsv(allFurtherRows),
        },
        {
          suggestedName: "decision404_analysis_run.log",
          content: runLogContent,
        },
      ];
      appendRunLog("RUN", "Export panel opened", {
        files: csvFiles.map(f => f.suggestedName),
        regionCount: regions.length,
      });
      showCsvSavePanel(csvFiles);
    } catch (e) {
      appendRunLog("RUN", "Decision404 analysis failed", { error: String(e?.message || e) });
      console.error("Decision 404 analysis failed:", e);
    }
  })();
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    buildRequestIdentityKey,
    dedupeDecision404Records,
    subtractNsWithPrecisionGuard,
    parseElapsedTimeMs,
    isValidDecision404Url,
    isValidStep3_1Message,
    validateStep3_1Record,
    extractRequestedDeploymentFromUrl,
    analyzeStep3_3ForLink,
    buildStep3_4DeploymentCacheCheck,
    runMandatoryFurtherAnalysisLokiChecks,
    buildStep3_4SummaryByEnvTable,
  };
}
