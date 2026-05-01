const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const {
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
} = require("./Decision404Analysis.js");

test("subtractNsWithPrecisionGuard moves boundary at nanosecond-scale epoch values", () => {
  const startNs = 1777078642853147400;
  const naive = Math.floor(startNs - 1);
  const guarded = subtractNsWithPrecisionGuard(startNs, 1);

  // Reproduces precision issue on JS Number at ~1e18 scale.
  assert.equal(naive, startNs);
  assert.ok(guarded < startNs);
});

test("buildRequestIdentityKey includes exact timestamp and request dimensions", () => {
  const rec = {
    env: "erzr-dev23",
    pod: "authz-decision-67bb884ffd-wnllr",
    traceID: "trace-123",
    url: "/v1:$1058/authorize",
    lokiTsNs: "1777145831036911000",
    methodName: "POST",
    message: "request received and completed",
  };
  const key = buildRequestIdentityKey(rec);
  assert.equal(
    key,
    [
      "erzr-dev23",
      "authz-decision-67bb884ffd-wnllr",
      "trace-123",
      "/v1:$1058/authorize",
      "1777145831036911000",
      "POST",
      "request received and completed",
    ].join("|"),
  );
});

test("dedupeDecision404Records collapses exact duplicates only", () => {
  const base = {
    env: "erzr-dev23",
    pod: "authz-decision-67bb884ffd-wnllr",
    traceID: "trace-123",
    url: "/v1:$1058/authorize",
    lokiTsNs: "1777145831036911000",
    methodName: "POST",
    message: "request received and completed",
  };

  const res = dedupeDecision404Records([base, { ...base }]);
  assert.equal(res.dedupedRecordCount, 1);
  assert.equal(res.collapsedCount, 1);
  assert.equal(res.records[0].duplicateCount, 2);
});

test("dedupeDecision404Records does not collapse same traceID with close timestamps", () => {
  const a = {
    env: "erzr-dev23",
    pod: "authz-decision-67bb884ffd-wnllr",
    traceID: "trace-123",
    url: "/v1:$1058/authorize",
    lokiTsNs: "1777145831036911000",
    methodName: "POST",
    message: "request received and completed",
  };
  const b = { ...a, lokiTsNs: "1777145831036911001" };

  const res = dedupeDecision404Records([a, b]);
  assert.equal(res.dedupedRecordCount, 2);
  assert.equal(res.collapsedCount, 0);
  assert.equal(res.records[0].duplicateCount, 1);
  assert.equal(res.records[1].duplicateCount, 1);
});

test("dedupeDecision404Records does not collapse same timestamp when message differs", () => {
  const a = {
    env: "erzr-dev23",
    pod: "authz-decision-67bb884ffd-wnllr",
    traceID: "trace-123",
    url: "/v1:$1058/authorize",
    lokiTsNs: "1777145831036911000",
    methodName: "POST",
    message: "request received and completed",
  };
  const b = {
    ...a,
    message: "executed operation: request received for deployment '1058'",
  };

  const res = dedupeDecision404Records([a, b]);
  assert.equal(res.dedupedRecordCount, 2);
  assert.equal(res.collapsedCount, 0);
});

test("parseElapsedTimeMs preserves legacy unit parsing behavior", () => {
  assert.equal(parseElapsedTimeMs("3.87s"), 3870);
  assert.equal(parseElapsedTimeMs("120ms"), 120);
  assert.equal(parseElapsedTimeMs("900us"), 0.9);
  assert.equal(parseElapsedTimeMs("1h2m3.5s"), 3723500);
  assert.equal(parseElapsedTimeMs("4m32.295997305s"), 272295.997305);
  assert.equal(parseElapsedTimeMs(""), null);
  assert.equal(parseElapsedTimeMs("bad-value"), null);
});

test("isValidDecision404Url keeps legacy matching rules", () => {
  assert.equal(isValidDecision404Url("/v1:$123/authorize"), true);
  assert.equal(isValidDecision404Url("/v1/authorize"), true);
  assert.equal(isValidDecision404Url("/v1:$abc/authorize"), false);
  assert.equal(isValidDecision404Url("/v2:$123/authorize"), false);
});

test("isValidStep3_1Message keeps legacy allow-list", () => {
  assert.equal(isValidStep3_1Message("request received and completed"), true);
  assert.equal(isValidStep3_1Message("executed operation: request received for deployment '1'"), true);
  assert.equal(isValidStep3_1Message("no activated / default deployment found"), true);
  assert.equal(isValidStep3_1Message("executed operation: authorization elapsed time 10ms"), true);
  assert.equal(isValidStep3_1Message("some other message"), false);
});

test("validateStep3_1Record reports expected reason flags", () => {
  const valid = validateStep3_1Record({
    message: "request received and completed",
    methodName: "POST",
    url: "/v1:$123/authorize",
  });
  assert.equal(valid.isValid, true);
  assert.deepEqual(valid.reasons, []);

  const invalid = validateStep3_1Record({
    message: "unexpected",
    methodName: "GET",
    url: "/v1:$abc/authorize",
  });
  assert.equal(invalid.isValid, false);
  assert.deepEqual(invalid.reasons, ["message_mismatch", "method_mismatch", "url_mismatch"]);
});

test("extractRequestedDeploymentFromUrl keeps explicit/default/invalid behavior", () => {
  assert.deepEqual(extractRequestedDeploymentFromUrl("/v1:$1058/authorize"), {
    type: "explicit",
    deploymentID: "1058",
    rawUrl: "/v1:$1058/authorize",
  });
  assert.deepEqual(extractRequestedDeploymentFromUrl("/v1/authorize"), {
    type: "default",
    deploymentID: null,
    rawUrl: "/v1/authorize",
  });
  assert.deepEqual(extractRequestedDeploymentFromUrl("/v1:$abc/authorize"), {
    type: "invalid",
    deploymentID: null,
    rawUrl: "/v1:$abc/authorize",
  });
});

function parseRunLogCases(logPath) {
  const lines = fs
    .readFileSync(logPath, "utf8")
    .split(/\r?\n/)
    .filter(Boolean);

  let rootCauseCountHeader = null;
  let furtherAnalysisCountHeader = null;
  let regionCountHeader = null;
  const step3_4Roots = [];
  const step3_3Finals = [];
  const step3_4Agg = [];

  for (const line of lines) {
    if (line.startsWith("rootCauseCount=")) {
      rootCauseCountHeader = Number(line.slice("rootCauseCount=".length));
      continue;
    }
    if (line.startsWith("furtherAnalysisCount=")) {
      furtherAnalysisCountHeader = Number(line.slice("furtherAnalysisCount=".length));
      continue;
    }
    if (line.startsWith("regionCount=")) {
      regionCountHeader = Number(line.slice("regionCount=".length));
      continue;
    }

    const payloadIdx = line.indexOf("| ");
    if (payloadIdx < 0) continue;
    const raw = line.slice(payloadIdx + 2);
    let obj = null;
    try {
      obj = JSON.parse(raw);
    } catch (_) {
      continue;
    }
    if (line.includes("[STEP3.4] root cause:")) step3_4Roots.push(obj);
    if (line.includes("[STEP3.3] final step3.3 conclusion for link")) step3_3Finals.push(obj);
    if (line.includes("[STEP3.4] Step 3.4 aggregation completed")) step3_4Agg.push(obj);
  }

  return {
    rootCauseCountHeader,
    furtherAnalysisCountHeader,
    regionCountHeader,
    step3_4Roots,
    step3_3Finals,
    step3_4Agg,
  };
}

test("2026-04-22 run log: all processed Step3.4 case types are covered", () => {
  const logPath = path.join(__dirname, "2026-04-22", "decision404_analysis_run.log");
  const { step3_4Roots } = parseRunLogCases(logPath);

  const allowedCasePairs = [
    "cache_prepare_completed_after_request_window|404_due_to_runtime_cache_not_ready_yet",
    "requested_deployment_not_in_list_cache|404_due_to_deployment_not_in_top_3_list_cache",
    "requested_deployment_not_in_runtime_cache|404_due_to_deployment_not_in_top_3_runtime_cache",
    "target_deployment_not_ready_in_deployment_list_cache|404_due_to_deployment_not_ready_in_deployment_list_cache",
    "target_deployment_state_serving_transition_after_cache_round|404_due_to_deployment_not_ready_in_deployment_list_cache",
  ].sort();
  const uniqueCasePairs = [...new Set(step3_4Roots.map(x => `${x.result}|${x.rootCause}`))].sort();
  assert.deepEqual(uniqueCasePairs, allowedCasePairs);

  const uniqueTraceCategories = [...new Set(step3_4Roots.map(x => x.traceErrorCategory))].sort();
  assert.deepEqual(uniqueTraceCategories, ["deployment_list_not_found", "runtime_services_not_found"]);
});

test("2026-04-22 run log: Step3.3 final outcomes keep expected behavior", () => {
  const logPath = path.join(__dirname, "2026-04-22", "decision404_analysis_run.log");
  const { step3_3Finals } = parseRunLogCases(logPath);

  assert.ok(step3_3Finals.length > 0);
  const finalConclusions = [...new Set(step3_3Finals.map(x => x.finalConclusion))].sort();
  assert.deepEqual(finalConclusions, ["cache_load_success"]);

  const finalReasons = [...new Set(step3_3Finals.map(x => String(x.finalReason)))].sort();
  assert.deepEqual(finalReasons, ["null"]);
});

test("2026-04-22 run log: Step3.4 aggregation distribution remains stable", () => {
  const logPath = path.join(__dirname, "2026-04-22", "decision404_analysis_run.log");
  const {
    rootCauseCountHeader,
    furtherAnalysisCountHeader,
    regionCountHeader,
    step3_4Roots,
    step3_4Agg,
  } = parseRunLogCases(logPath);

  assert.equal(step3_4Roots.length, rootCauseCountHeader);
  assert.equal(step3_4Agg.length, regionCountHeader);

  const totalRootCauseFromAgg = step3_4Agg.reduce((sum, x) => sum + Number(x.rootCauseCount || 0), 0);
  const totalFurtherFromAgg = step3_4Agg.reduce((sum, x) => sum + Number(x.furtherAnalysisCount || 0), 0);
  assert.equal(totalRootCauseFromAgg, rootCauseCountHeader);
  assert.equal(totalFurtherFromAgg, furtherAnalysisCountHeader);

  const nonZeroAgg = step3_4Agg
    .filter(x => Number(x.rootCauseCount || 0) > 0 || Number(x.furtherAnalysisCount || 0) > 0)
    .map(x => `${x.region}:${x.rootCauseCount}/${x.furtherAnalysisCount}`)
    .sort();
  assert.ok(nonZeroAgg.length > 0);
  assert.ok(nonZeroAgg.some(x => x.startsWith("us-phoenix:")));
});

test("buildStep3_4SummaryByEnvTable keeps zero-count envs from Step 2 summary", () => {
  const step3_4Result = { rootCauseTable: [], furtherAnalysisTable: [] };
  const step2SummaryByEnv = {
    ecvr: { matchedLineCount: 0, estimatedTotal404: 0, unsplittableLimitHitCount: 0 },
  };
  const table = buildStep3_4SummaryByEnvTable(step3_4Result, step2SummaryByEnv, {});
  assert.equal(table.length, 1);
  assert.deepEqual(table[0], {
    env: "ecvr",
    total404: 0,
    rootCauseCount: 0,
    recoveryStatus: "not_sure",
    cache_not_ready_yet: 0,
    deployment_not_in_top_3_latest_deployments: 0,
    runtime_services_cache_load_failure: 0,
    root_cause_unknown: 0,
  });
});

test("buildStep3_4SummaryByEnvTable maps further-analysis counts to root_cause_unknown", () => {
  const step3_4Result = {
    rootCauseTable: [],
    furtherAnalysisTable: [
      { env: "ecvr", duplicateCount: 2 },
      { env: "ecvr", duplicateCount: 3 },
    ],
  };
  const table = buildStep3_4SummaryByEnvTable(step3_4Result, {}, {});
  assert.equal(table.length, 1);
  assert.equal(table[0].env, "ecvr");
  assert.equal(table[0].total404, 5);
  assert.equal(table[0].rootCauseCount, 5);
  assert.equal(table[0].root_cause_unknown, 5);
});

test("buildStep3_4SummaryByEnvTable reconciles total404 to Step2 raw matches", () => {
  const step3_4Result = {
    rootCauseTable: [
      { env: "env-a", rootCause: "404_due_to_runtime_cache_not_ready_yet", duplicateCount: 2 },
    ],
    furtherAnalysisTable: [],
  };
  const step2SummaryByEnv = {
    "env-a": { matchedLineCount: 10 },
  };

  const table = buildStep3_4SummaryByEnvTable(step3_4Result, step2SummaryByEnv, {});
  assert.equal(table.length, 1);
  const row = table[0];
  assert.equal(row.env, "env-a");
  assert.equal(row.total404, 10);
  assert.equal(row.rootCauseCount, 10);
  assert.equal(row.cache_not_ready_yet, 2);
  assert.equal(row.deployment_not_in_top_3_latest_deployments, 0);
  assert.equal(row.runtime_services_cache_load_failure, 0);
  assert.equal(row.root_cause_unknown, 8);
});

test("buildStep3_4SummaryByEnvTable keeps total404 equal to sum of root-cause columns", () => {
  const step3_4Result = {
    rootCauseTable: [
      {
        env: "env-b",
        rootCause: "404_due_to_deployment_not_in_top_3_list_cache",
        duplicateCount: 3,
      },
    ],
    // further-analysis rows should also end up under root_cause_unknown after reconciliation
    // so that total404 still equals Step2 raw matched count.
    furtherAnalysisTable: [{ env: "env-b", duplicateCount: 1 }],
  };
  const step2SummaryByEnv = {
    "env-b": { matchedLineCount: 5 },
  };

  const table = buildStep3_4SummaryByEnvTable(step3_4Result, step2SummaryByEnv, {});
  assert.equal(table.length, 1);
  const row = table[0];
  const categorySum =
    Number(row.cache_not_ready_yet || 0) +
    Number(row.deployment_not_in_top_3_latest_deployments || 0) +
    Number(row.runtime_services_cache_load_failure || 0) +
    Number(row.root_cause_unknown || 0);
  assert.equal(row.total404, 5);
  assert.equal(categorySum, 5);
  assert.equal(row.total404, categorySum);
});

test("runStep1ForRegion signature includes optional envProgressTracker (regression)", () => {
  const src = fs.readFileSync(path.join(__dirname, "Decision404Analysis.js"), "utf8");
  assert.match(
    src,
    /async function runStep1ForRegion\(region,\s*\{\s*envProgressTracker\s*=\s*null\s*\}\s*=\s*\{\}\)/,
  );
});

test("Step3.5 recovery query uses Loki-safe regex quoting (regression)", () => {
  const src = fs.readFileSync(path.join(__dirname, "Decision404Analysis.js"), "utf8");
  assert.ok(
    src.includes(`"requestHTTPStatusCode"\\\\s*:\\\\s*200|"responseStatusCode"\\\\s*:\\\\s*200`),
    "expected Step3.5 recovery query to include unescaped JSON keys in regex pattern",
  );
  assert.ok(
    !src.includes(`\\\\"requestHTTPStatusCode\\\\"\\\\s*:\\\\s*200|\\\\"responseStatusCode\\\\"\\\\s*:\\\\s*200`),
    "Step3.5 recovery query should not use over-escaped quotes that trigger Loki parse errors",
  );
});

test("Step3.3 signature reuse lookup failure is handled as non-fatal (regression)", () => {
  const src = fs.readFileSync(path.join(__dirname, "Decision404Analysis.js"), "utf8");
  assert.ok(
    src.includes("trace signature lookup failed; continue without signature reuse"),
    "expected Step3.3 to log and continue when trace signature lookup fails",
  );
});

function mkLink(overrides = {}) {
  return {
    request: {
      duplicateCount: 1,
      traceID: "trace-1",
      pod: "pod-1",
      timestamp: "2026-04-22T00:00:00.000Z",
      lokiTsNs: "1776816509448025300",
      url: "/v1:$57/authorize",
      ...((overrides && overrides.request) || {}),
    },
    conclusion: "cache_load_success",
    reason: null,
    successfulDeploymentsAll: [{ deploymentID: "1001" }, { deploymentID: "1002" }, { deploymentID: "1003" }],
    resolvedDefaultDeployment: { defaultDeploymentID: "1001" },
    deploymentListCacheCheck: {
      decision: "target_present",
      usedRoundTargetHitKind: "deployment",
      ...((overrides && overrides.deploymentListCacheCheck) || {}),
    },
    deploymentListPostRequestCheck: {
      checked: false,
      foundInCheckedRounds: false,
      roundsChecked: 0,
      ...((overrides && overrides.deploymentListPostRequestCheck) || {}),
    },
    deploymentStateCheck: {
      found: true,
      isServingState: true,
      servingTransitionAfterCacheHitBeforeRequest: false,
      latest: { newState: "Default", lokiTsNs: "1" },
      ...((overrides && overrides.deploymentStateCheck) || {}),
    },
    traceErrorSummary: {
      category: "runtime_services_not_found",
      runtimeServicesCount: 1,
      deploymentListCount: 0,
      bothPatternsPresent: false,
      ...((overrides && overrides.traceErrorSummary) || {}),
    },
    completionTiming: {
      matched: false,
      ...((overrides && overrides.completionTiming) || {}),
    },
    completionExtensionUsed: false,
    completionDistinctOriginalCount: 3,
    completionDistinctExtendCount: 3,
    completionFoundAfterOriginalWindow: false,
    targetInUsedTop3: true,
    targetInOriginalTop3: true,
    earliestCompletionMatch: null,
    restartEvidence: { count: 0, entries: [] },
    failureEvidenceCount: 0,
    fullAnalysisPerformed: true,
    ...overrides,
  };
}

test("Step3.4 fixture: runtime cache not ready yet branch", () => {
  const step3_3ByEnv = {
    env1: {
      links: [
        mkLink({
          traceErrorSummary: { category: "runtime_services_not_found", runtimeServicesCount: 2 },
          completionTiming: { matched: true },
          completionExtensionUsed: true,
          completionDistinctOriginalCount: 0,
          completionDistinctExtendCount: 3,
        }),
      ],
    },
  };
  const out = buildStep3_4DeploymentCacheCheck(step3_3ByEnv, {});
  assert.equal(out.rootCauseTable.length, 1);
  assert.equal(out.rootCauseTable[0].result, "cache_prepare_completed_after_request_window");
  assert.equal(out.rootCauseTable[0].rootCause, "404_due_to_runtime_cache_not_ready_yet");
});

test("Step3.4 fixture: deployment transition after cache round branch", () => {
  const step3_3ByEnv = {
    env1: {
      links: [
        mkLink({
          traceErrorSummary: { category: "deployment_list_not_found", deploymentListCount: 1, runtimeServicesCount: 0 },
          deploymentListCacheCheck: {
            decision: "target_present",
            usedRoundTargetHitKind: "deployment",
          },
          deploymentStateCheck: {
            found: true,
            isServingState: true,
            servingTransitionAfterCacheHitBeforeRequest: true,
            latest: { newState: "Default" },
          },
        }),
      ],
    },
  };
  const out = buildStep3_4DeploymentCacheCheck(step3_3ByEnv, {});
  assert.equal(out.rootCauseTable.length, 1);
  assert.equal(out.rootCauseTable[0].result, "target_deployment_state_serving_transition_after_cache_round");
  assert.equal(
    out.rootCauseTable[0].rootCause,
    "404_due_to_deployment_not_ready_in_deployment_list_cache",
  );
});

test("Step3.4 fixture: cache_load_failure branch", () => {
  const step3_3ByEnv = {
    env1: {
      links: [
        mkLink({
          conclusion: "cache_load_failure",
          traceErrorSummary: { category: "runtime_services_not_found", runtimeServicesCount: 1 },
          failureEvidenceCount: 2,
        }),
      ],
    },
  };
  const out = buildStep3_4DeploymentCacheCheck(step3_3ByEnv, {});
  assert.equal(out.rootCauseTable.length, 1);
  assert.equal(out.rootCauseTable[0].result, "runtime_services_cache_load_failure");
  assert.equal(out.rootCauseTable[0].rootCause, "404_due_to_runtime_services_cache_load_failure");
});

test("Step3.4 fixture: runtime_services fallthrough is preempted by restart warmup", () => {
  const step3_3ByEnv = {
    env1: {
      links: [
        mkLink({
          conclusion: "cache_load_failure",
          reason: "restart_warmup",
          failureEvidenceCount: 0,
          restartEvidence: { count: 2, entries: [] },
          traceErrorSummary: { category: "runtime_services_not_found", runtimeServicesCount: 2 },
          completionDistinctOriginalCount: 1,
          completionDistinctExtendCount: 1,
          deploymentListCacheCheck: {
            decision: "target_not_ready",
            reason: "last_round_after_request_second_last_not_found",
          },
        }),
      ],
    },
  };
  const out = buildStep3_4DeploymentCacheCheck(step3_3ByEnv, {});
  assert.equal(out.rootCauseTable.length, 1);
  assert.equal(out.furtherAnalysisTable.length, 0);
  assert.equal(out.rootCauseTable[0].result, "restart_evidence_preempts_runtime_services_fallthrough");
  assert.equal(
    out.rootCauseTable[0].rootCause,
    "404_due_to_decision_service_restart_cache_warmup",
  );
});

test("Step3.4 fixture: runtime_services fallthrough preempted by restart_warmup reason even without restart count", () => {
  const step3_3ByEnv = {
    env1: {
      links: [
        mkLink({
          conclusion: "cache_load_failure",
          reason: "restart_warmup",
          failureEvidenceCount: 0,
          restartEvidence: { count: 0, entries: [] },
          traceErrorSummary: { category: "runtime_services_not_found", runtimeServicesCount: 2 },
          completionDistinctOriginalCount: 0,
          completionDistinctExtendCount: 0,
        }),
      ],
    },
  };
  const out = buildStep3_4DeploymentCacheCheck(step3_3ByEnv, {});
  assert.equal(out.rootCauseTable.length, 1);
  assert.equal(out.furtherAnalysisTable.length, 0);
  assert.equal(out.rootCauseTable[0].result, "restart_evidence_preempts_runtime_services_fallthrough");
  assert.equal(
    out.rootCauseTable[0].rootCause,
    "404_due_to_decision_service_restart_cache_warmup",
  );
});

test("Step3.4 fixture: runtime_services fallthrough preempted by restart evidence even when failure evidence exists", () => {
  const step3_3ByEnv = {
    env1: {
      links: [
        mkLink({
          conclusion: "cache_load_failure",
          reason: null,
          failureEvidenceCount: 2,
          restartEvidence: { count: 1, entries: [{ lokiTsNs: "1777291890000000000" }] },
          traceErrorSummary: { category: "runtime_services_not_found", runtimeServicesCount: 2 },
          completionDistinctOriginalCount: 0,
          completionDistinctExtendCount: 0,
          deploymentListCacheCheck: {
            decision: "unknown",
            reason: "no_cache_round_found",
          },
        }),
      ],
    },
  };
  const out = buildStep3_4DeploymentCacheCheck(step3_3ByEnv, {});
  assert.equal(out.rootCauseTable.length, 1);
  assert.equal(out.furtherAnalysisTable.length, 0);
  assert.equal(out.rootCauseTable[0].result, "restart_evidence_preempts_runtime_services_fallthrough");
  assert.equal(
    out.rootCauseTable[0].rootCause,
    "404_due_to_decision_service_restart_cache_warmup",
  );
});

test("Step3.4 mandatory further-analysis checks use fixed 10-minute pre-request window for restart and cache-load errors", async () => {
  const reqTsNs = 1_777_291_890_626_554_489;
  const expectedStartNs = subtractNsWithPrecisionGuard(reqTsNs, 10 * 60 * 1e9);
  const expectedEndNs = subtractNsWithPrecisionGuard(reqTsNs, 1);
  const step3_4Result = {
    rootCauseTable: [],
    furtherAnalysisTable: [
      {
        env: "etit-dev3",
        traceID: "00000000000000003dea6d26a2cd3e4f",
        pod: "authz-decision-8988f4876-kxw89",
        requestLokiTsNs: String(reqTsNs),
        url: "/v1:$3014/authorize",
      },
    ],
  };

  const observed = [];
  const mockQueryLoki = async (expr, opts = {}) => {
    observed.push({ expr, opts });
    assert.equal(Number(opts.startNs), expectedStartNs);
    assert.equal(Number(opts.endNs), expectedEndNs);
    if (expr.includes("starting decision server|starting authz decision server")) {
      return lokiResult([
        [
          String(reqTsNs - 5_000_000_000),
          JSON.stringify({
            level: "info",
            timestamp: "2026-04-27T12:06:19Z",
            message: "starting decision server with bind-addr: 0.0.0.0:8091",
          }),
        ],
      ]);
    }
    if (expr.includes("\"level\"\\s*:\\s*\"error\"")) {
      return lokiResult([
        [
          String(reqTsNs - 4_000_000_000),
          JSON.stringify({
            level: "error",
            timestamp: "2026-04-27T12:06:22Z",
            message: "failed preparing policies runtime cache",
            error: "cache warmup failure",
          }),
        ],
      ]);
    }
    return lokiResult([]);
  };

  const summary = await runMandatoryFurtherAnalysisLokiChecks(step3_4Result, {
    regionContext: "eu-frankfurt",
    queryLokiFn: mockQueryLoki,
  });

  assert.equal(observed.length, 2);
  assert.equal(summary.checkedRowCount, 1);
  assert.equal(summary.skippedRowCount, 0);
  assert.equal(summary.restartHitRowCount, 1);
  assert.equal(summary.cacheErrorHitRowCount, 1);
  assert.equal(summary.queryExecutedCount, 2);
  assert.equal(summary.queryCacheHitCount, 0);
  assert.ok(step3_4Result.mandatoryFurtherChecks);
});

test("Step3.4 mandatory further-analysis checks reuse identical Loki queries across duplicate cases", async () => {
  const reqTsNs = 1_777_291_890_626_554_489;
  const row = {
    env: "etit-dev3",
    traceID: "same-trace",
    pod: "authz-decision-8988f4876-kxw89",
    requestLokiTsNs: String(reqTsNs),
    url: "/v1:$3014/authorize",
  };
  const step3_4Result = {
    rootCauseTable: [],
    furtherAnalysisTable: [{ ...row }, { ...row }],
  };

  let queryCallCount = 0;
  const mockQueryLoki = async () => {
    queryCallCount += 1;
    return lokiResult([]);
  };

  const summary = await runMandatoryFurtherAnalysisLokiChecks(step3_4Result, {
    regionContext: "eu-frankfurt",
    queryLokiFn: mockQueryLoki,
  });

  // Two unique queries (restart + cache-error) should execute once each.
  assert.equal(queryCallCount, 2);
  assert.equal(summary.queryExecutedCount, 2);
  assert.equal(summary.queryCacheHitCount, 2);
  assert.equal(summary.checkedRowCount, 2);
});

test("Step3.4 fixture: step2 Loki query failure is excluded from full-analysis-only further table", () => {
  const out = buildStep3_4DeploymentCacheCheck(
    {},
    {},
    { step2ByEnv: { envx: { error: "Failed to fetch" } } },
  );
  assert.equal(out.furtherAnalysisTable.length, 0);
});

test("Step3.4 fixture: trace/root-cause mismatch is downgraded to further analysis", () => {
  const step3_3ByEnv = {
    env1: {
      links: [
        mkLink({
          conclusion: "cache_load_failure",
          traceErrorSummary: {
            category: "deployment_list_not_found",
            deploymentListCount: 1,
            runtimeServicesCount: 0,
          },
        }),
      ],
    },
  };
  const out = buildStep3_4DeploymentCacheCheck(step3_3ByEnv, {});
  assert.equal(out.rootCauseTable.length, 0);
  assert.equal(out.furtherAnalysisTable.length, 1);
  assert.equal(out.furtherAnalysisTable[0].result, "trace_pattern_root_cause_mismatch");
});

test("Step3.4 fixture: explicit deployment missing from runtime cache", () => {
  const step3_3ByEnv = {
    env1: {
      links: [
        mkLink({
          request: { url: "/v1:$57/authorize" },
          traceErrorSummary: { category: "runtime_services_not_found", runtimeServicesCount: 1 },
          successfulDeploymentsAll: [{ deploymentID: "1001" }, { deploymentID: "1002" }],
          deploymentListCacheCheck: { decision: "target_present", usedRoundTargetHitKind: "deployment" },
          deploymentStateCheck: { found: true, isServingState: true, servingTransitionAfterCacheHitBeforeRequest: false },
        }),
      ],
    },
  };
  const out = buildStep3_4DeploymentCacheCheck(step3_3ByEnv, {});
  assert.equal(out.rootCauseTable.length, 1);
  assert.equal(out.rootCauseTable[0].result, "requested_deployment_not_in_runtime_cache");
  assert.equal(out.rootCauseTable[0].rootCause, "404_due_to_deployment_not_in_top_3_runtime_cache");
});

test("Step3.4 fixture: explicit deployment present in runtime cache -> further analysis", () => {
  const step3_3ByEnv = {
    env1: {
      links: [
        mkLink({
          request: { url: "/v1:$57/authorize" },
          traceErrorSummary: { category: "runtime_services_not_found", runtimeServicesCount: 1 },
          successfulDeploymentsAll: [{ deploymentID: "57" }, { deploymentID: "1002" }],
          deploymentListCacheCheck: { decision: "target_present", usedRoundTargetHitKind: "deployment" },
          deploymentStateCheck: { found: true, isServingState: true, servingTransitionAfterCacheHitBeforeRequest: false },
        }),
      ],
    },
  };
  const out = buildStep3_4DeploymentCacheCheck(step3_3ByEnv, {});
  assert.equal(out.rootCauseTable.length, 0);
  assert.equal(out.furtherAnalysisTable.length, 1);
  assert.equal(out.furtherAnalysisTable[0].result, "requested_deployment_found_in_cache");
});

test("Step3.4 fixture: invalid URL goes to further analysis", () => {
  const step3_3ByEnv = {
    env1: {
      links: [
        mkLink({
          request: { url: "/v1:$not-number/authorize" },
          traceErrorSummary: { category: "runtime_services_not_found", runtimeServicesCount: 1 },
          deploymentListCacheCheck: { decision: "target_present", usedRoundTargetHitKind: "deployment" },
          deploymentStateCheck: { found: true, isServingState: true, servingTransitionAfterCacheHitBeforeRequest: false },
        }),
      ],
    },
  };
  const out = buildStep3_4DeploymentCacheCheck(step3_3ByEnv, {});
  assert.equal(out.rootCauseTable.length, 0);
  assert.equal(out.furtherAnalysisTable.length, 1);
  assert.equal(out.furtherAnalysisTable[0].result, "invalid_or_unexpected_url_pattern");
});

function lokiResult(values = [], stream = {}) {
  return {
    status: "success",
    data: {
      result: values.length ? [{ stream, values }] : [],
    },
  };
}

test("Step3.3 fixture: invalid request context returns cache_load_unknown", async () => {
  const out = await analyzeStep3_3ForLink({
    request: {
      env: "",
      traceID: "trace-x",
      pod: "pod-x",
      lokiTsNs: "0",
      url: "/v1:$57/authorize",
    },
    matched: true,
    previousLog: { lokiTsNs: "1" },
  });
  assert.equal(out.conclusion, "cache_load_unknown");
  assert.equal(out.reason, "invalid_request_context");
});

test("Step3.3 fixture: mocked Loki returns cache_load_success with runtime trace category", async () => {
  const reqTsNs = 2_000_000_000_000;
  const runtimeCacheStartTimeNs = 1_000_000_000_000;

  const mockQueryLoki = async (expr) => {
    if (expr.includes("SPDL-2001") || expr.includes("trace-success-1")) {
      return lokiResult([
        [
          String(reqTsNs - 1),
          JSON.stringify({
            level: "error",
            error: "SPDL-2001 Application 57 is not found",
            message: "runtime miss",
          }),
        ],
      ]);
    }

    if (expr.includes("completed preparing policies runtime cache") || expr.includes("Speedle policies")) {
      return lokiResult([
        [
          "1500000000000",
          JSON.stringify({
            deploymentID: "57",
            message: "updated cache for deployment '57' with '10' Speedle policies",
            elapsedTime: "1s",
          }),
        ],
        [
          "1501000000000",
          JSON.stringify({
            deploymentID: "58",
            message: "updated cache for deployment '58' with '10' Speedle policies",
            elapsedTime: "1s",
          }),
        ],
        [
          "1502000000000",
          JSON.stringify({
            deploymentID: "59",
            message: "updated cache for deployment '59' with '10' Speedle policies",
            elapsedTime: "1s",
          }),
        ],
      ]);
    }

    if (expr.includes("default deployment")) {
      return lokiResult([
        [
          String(reqTsNs - 5_000_000),
          JSON.stringify({
            message: "default deployment from latest records",
            defaultDeploymentID: "57",
          }),
        ],
      ]);
    }

    return lokiResult([]);
  };

  const out = await analyzeStep3_3ForLink(
    {
      request: {
        env: "env-success",
        traceID: "trace-success-1",
        pod: "pod-success",
        lokiTsNs: String(reqTsNs),
        url: "/v1:$57/authorize",
      },
      matched: true,
      previousLog: { lokiTsNs: String(runtimeCacheStartTimeNs) },
    },
    { queryLokiFn: mockQueryLoki },
  );

  assert.equal(out.conclusion, "cache_load_success");
  assert.equal(out.reason, null);
  assert.equal(out.completionDistinctExtendCount, 3);
  assert.equal(out.traceErrorSummary.category, "runtime_services_not_found");
});

test("Step3.3 fixture: restart warmup marks cache_load_failure when success evidence is missing", async () => {
  const reqTsNs = 2_000_000_000_000;
  const runtimeCacheStartTimeNs = 1_000_000_000_000;

  const mockQueryLoki = async (expr) => {
    if (expr.includes("trace-restart-1")) {
      return lokiResult([
        [
          String(reqTsNs - 1),
          JSON.stringify({
            level: "error",
            error: "SPDL-2001 Application 57 is not found",
            message: "runtime miss",
          }),
        ],
      ]);
    }

    if (expr.includes("starting decision server|starting authz decision server")) {
      return lokiResult([
        [
          String(reqTsNs - 2),
          JSON.stringify({
            level: "info",
            message: "starting decision server",
          }),
        ],
      ]);
    }

    return lokiResult([]);
  };

  const out = await analyzeStep3_3ForLink(
    {
      request: {
        env: "env-restart",
        traceID: "trace-restart-1",
        pod: "pod-restart",
        lokiTsNs: String(reqTsNs),
        url: "/v1:$57/authorize",
      },
      matched: true,
      previousLog: { lokiTsNs: String(runtimeCacheStartTimeNs) },
    },
    { queryLokiFn: mockQueryLoki },
  );

  assert.equal(out.conclusion, "cache_load_failure");
  assert.equal(out.reason, "restart_warmup");
  assert.equal(out.restartEvidence.count, 1);
});

test("Step3.3 fixture: multiple restart startup logs still classify as restart_warmup", async () => {
  const reqTsNs = 2_000_000_000_000;
  const runtimeCacheStartTimeNs = 1_000_000_000_000;

  const mockQueryLoki = async (expr) => {
    if (expr.includes("trace-restart-2logs-1")) {
      return lokiResult([
        [
          String(reqTsNs - 1),
          JSON.stringify({
            level: "error",
            error: "SPDL-2001 Application 3073 is not found",
            message: "runtime miss",
          }),
        ],
      ]);
    }

    if (expr.includes("starting decision server|starting authz decision server")) {
      return lokiResult([
        [
          String(reqTsNs - 10_000_000),
          JSON.stringify({
            level: "info",
            message: "starting decision server 0.0.0.0:8091",
          }),
        ],
        [
          String(reqTsNs - 9_000_000),
          JSON.stringify({
            level: "info",
            message:
              "starting decision server with bind-addr: 0.0.0.0:8091, sync-interval: 120",
          }),
        ],
      ]);
    }

    return lokiResult([]);
  };

  const out = await analyzeStep3_3ForLink(
    {
      request: {
        env: "env-restart-2logs",
        traceID: "trace-restart-2logs-1",
        pod: "pod-restart-2logs",
        lokiTsNs: String(reqTsNs),
        url: "/v1/authorize",
      },
      matched: true,
      previousLog: { lokiTsNs: String(runtimeCacheStartTimeNs) },
    },
    { queryLokiFn: mockQueryLoki },
  );

  assert.equal(out.conclusion, "cache_load_failure");
  assert.equal(out.reason, "restart_warmup");
  assert.equal(out.restartEvidence.count, 2);
});

test("Step3.3 fixture: restart evidence includes small pre-start buffer to catch boundary logs", async () => {
  const reqTsNs = 2_000_000_000_000;
  const runtimeCacheStartTimeNs = 1_000_000_000_000;
  const restartTsNs = runtimeCacheStartTimeNs - 500_000_000;

  const mockQueryLoki = async (expr, opts = {}) => {
    if (expr.includes("trace-restart-boundary-1")) {
      return lokiResult([
        [
          String(reqTsNs - 1),
          JSON.stringify({
            level: "error",
            error: "SPDL-2001 Application 57 is not found",
            message: "runtime miss",
          }),
        ],
      ]);
    }

    if (expr.includes("starting decision server|starting authz decision server")) {
      const s = Number(opts?.startNs || 0);
      const e = Number(opts?.endNs || 0);
      if (s <= restartTsNs && restartTsNs <= e) {
        return lokiResult([
          [
            String(restartTsNs),
            JSON.stringify({
              level: "info",
              message: "starting decision server with bind-addr: 0.0.0.0:8091",
            }),
          ],
        ]);
      }
      return lokiResult([]);
    }

    return lokiResult([]);
  };

  const out = await analyzeStep3_3ForLink(
    {
      request: {
        env: "env-restart-boundary",
        traceID: "trace-restart-boundary-1",
        pod: "pod-restart-boundary",
        lokiTsNs: String(reqTsNs),
        url: "/v1:$57/authorize",
      },
      matched: true,
      previousLog: { lokiTsNs: String(runtimeCacheStartTimeNs) },
    },
    { queryLokiFn: mockQueryLoki },
  );

  assert.equal(out.conclusion, "cache_load_failure");
  assert.equal(out.reason, "restart_warmup");
  assert.equal(out.restartEvidence.count, 1);
  assert.ok(Number(out.restartEvidence.startNs) < runtimeCacheStartTimeNs);
});

test("Step3.3 fixture: missing Step3.2 anchor uses request-relative restart fallback window", async () => {
  const reqTsNs = 2_000_000_000_000;
  const expectedStartNs = reqTsNs - 10 * 60 * 1e9;
  const restartTsNs = reqTsNs - 30 * 1e9;

  const mockQueryLoki = async (expr, opts = {}) => {
    if (expr.includes("starting decision server|starting authz decision server")) {
      const s = Number(opts?.startNs || 0);
      const e = Number(opts?.endNs || 0);
      assert.equal(s, expectedStartNs);
      assert.ok(e < reqTsNs);
      if (s <= restartTsNs && restartTsNs <= e) {
        return lokiResult([
          [
            String(restartTsNs),
            JSON.stringify({
              level: "info",
              message: "starting decision server 0.0.0.0:8091",
            }),
          ],
        ]);
      }
      return lokiResult([]);
    }
    return lokiResult([]);
  };

  const out = await analyzeStep3_3ForLink(
    {
      request: {
        env: "env-no-anchor",
        traceID: "trace-no-anchor-1",
        pod: "pod-no-anchor",
        lokiTsNs: String(reqTsNs),
        url: "/v1/authorize",
      },
      matched: false,
      previousLog: null,
    },
    { queryLokiFn: mockQueryLoki },
  );

  assert.equal(out.conclusion, "cache_load_failure");
  assert.equal(out.reason, "restart_warmup");
  assert.equal(out.restartEvidence.count, 1);
  assert.equal(out.restartEvidence.mode, "request_relative_fallback_no_step3_2_anchor");
  assert.equal(Number(out.restartEvidence.startNs), expectedStartNs);
  assert.equal(Number(out.restartEvidence.endNs), reqTsNs - 1);
});

test("Step3.3 fixture: restart query includes previous-round boundary buffer for near-adjacent rounds", async () => {
  const reqTsNs = 2_000_000_000_000;
  const runtimeCacheStartTimeNs = 1_500_000_000_000;
  const previousRoundStartTsNs = runtimeCacheStartTimeNs - 1_000_000;
  const restartTsNs = previousRoundStartTsNs - 500_000_000;
  const completionAnchorTsNs = runtimeCacheStartTimeNs - 10_000;

  const mockQueryLoki = async (expr, opts = {}) => {
    if (expr.includes("trace-restart-prev-round-1")) {
      return lokiResult([
        [
          String(reqTsNs - 1),
          JSON.stringify({
            level: "error",
            error: "SPDL-2001 Application 57 is not found",
            message: "runtime miss",
          }),
        ],
      ]);
    }

    if (expr.includes("completed preparing policies runtime cache") || expr.includes("Speedle policies")) {
      const s = Number(opts?.startNs || 0);
      const e = Number(opts?.endNs || 0);
      // Current round completion hit.
      if (s <= completionAnchorTsNs && completionAnchorTsNs <= e) {
        return lokiResult([
          [
            String(completionAnchorTsNs),
            JSON.stringify({
              deploymentID: "57",
              message: "updated cache for deployment '57' with '10' Speedle policies",
            }),
          ],
        ]);
      }
      return lokiResult([]);
    }

    if (expr.includes("start loading policies, roles, role mappings for all deployments|starting to prepare decision server cache")) {
      const s = Number(opts?.startNs || 0);
      const e = Number(opts?.endNs || 0);
      // Previous-round anchor search window.
      if (s === 0 && e === runtimeCacheStartTimeNs - 1) {
        return lokiResult([
          [
            String(previousRoundStartTsNs),
            JSON.stringify({
              level: "info",
              message: "starting to prepare decision server cache",
            }),
          ],
        ]);
      }
      return lokiResult([]);
    }

    if (expr.includes("starting decision server|starting authz decision server")) {
      const s = Number(opts?.startNs || 0);
      const e = Number(opts?.endNs || 0);
      if (s <= restartTsNs && restartTsNs <= e) {
        return lokiResult([
          [
            String(restartTsNs),
            JSON.stringify({
              level: "info",
              message: "starting decision server 0.0.0.0:8091",
            }),
          ],
        ]);
      }
      return lokiResult([]);
    }

    return lokiResult([]);
  };

  const out = await analyzeStep3_3ForLink(
    {
      request: {
        env: "env-restart-prev-round",
        traceID: "trace-restart-prev-round-1",
        pod: "pod-restart-prev-round",
        lokiTsNs: String(reqTsNs),
        url: "/v1:$57/authorize",
      },
      matched: true,
      previousLog: { lokiTsNs: String(runtimeCacheStartTimeNs) },
    },
    { queryLokiFn: mockQueryLoki },
  );

  assert.equal(out.conclusion, "cache_load_failure");
  assert.equal(out.reason, "restart_warmup");
  assert.equal(out.restartEvidence.count, 1);
  assert.ok(Number(out.restartEvidence.startNs) <= restartTsNs);
  assert.equal(Number(out.restartEvidence.previousRoundStartNs), previousRoundStartTsNs);
});

test("Step3.3 fixture: restart lookback captures startup log slightly over 2s before cache-start anchor", async () => {
  const reqTsNs = 2_000_000_000_000;
  const runtimeCacheStartTimeNs = 1_500_000_000_000;
  const restartTsNs = runtimeCacheStartTimeNs - 2_100_000_000;

  const mockQueryLoki = async (expr, opts = {}) => {
    if (expr.includes("trace-restart-over-2s-1")) {
      return lokiResult([
        [
          String(reqTsNs - 1),
          JSON.stringify({
            level: "error",
            error: "SPDL-2001 Application 3074 is not found",
            message: "runtime miss",
          }),
        ],
      ]);
    }

    if (expr.includes("starting decision server|starting authz decision server")) {
      const s = Number(opts?.startNs || 0);
      const e = Number(opts?.endNs || 0);
      if (s <= restartTsNs && restartTsNs <= e) {
        return lokiResult([
          [
            String(restartTsNs),
            JSON.stringify({
              level: "info",
              message: "starting decision server 0.0.0.0:8091",
            }),
          ],
        ]);
      }
      return lokiResult([]);
    }

    return lokiResult([]);
  };

  const out = await analyzeStep3_3ForLink(
    {
      request: {
        env: "env-restart-over-2s",
        traceID: "trace-restart-over-2s-1",
        pod: "pod-restart-over-2s",
        lokiTsNs: String(reqTsNs),
        url: "/v1/authorize",
      },
      matched: true,
      previousLog: { lokiTsNs: String(runtimeCacheStartTimeNs) },
    },
    { queryLokiFn: mockQueryLoki },
  );

  assert.equal(out.conclusion, "cache_load_failure");
  assert.equal(out.reason, "restart_warmup");
  assert.equal(out.restartEvidence.count, 1);
});
