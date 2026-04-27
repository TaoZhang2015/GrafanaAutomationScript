const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const {
  buildRequestIdentityKey,
  dedupeDecision404Records,
  parseElapsedTimeMs,
  isValidDecision404Url,
  isValidStep3_1Message,
  validateStep3_1Record,
  extractRequestedDeploymentFromUrl,
  analyzeStep3_3ForLink,
  buildStep3_4DeploymentCacheCheck,
} = require("./Decision404Analysis.js");

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

  const step3_4Roots = [];
  const step3_3Finals = [];
  const step3_4Agg = [];

  for (const line of lines) {
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

  return { step3_4Roots, step3_3Finals, step3_4Agg };
}

test("2026-04-22 run log: all processed Step3.4 case types are covered", () => {
  const logPath = path.join(__dirname, "2026-04-22", "decision404_analysis_run.log");
  const { step3_4Roots } = parseRunLogCases(logPath);

  const uniqueCasePairs = [...new Set(step3_4Roots.map(x => `${x.result}|${x.rootCause}`))].sort();
  assert.deepEqual(uniqueCasePairs, [
    "cache_prepare_completed_after_request_window|404_due_to_runtime_cache_not_ready_yet",
    "target_deployment_state_serving_transition_after_cache_round|404_due_to_deployment_not_ready_in_deployment_list_cache",
  ]);

  const uniqueTraceCategories = [...new Set(step3_4Roots.map(x => x.traceErrorCategory))].sort();
  assert.deepEqual(uniqueTraceCategories, ["deployment_list_not_found", "runtime_services_not_found"]);
});

test("2026-04-22 run log: Step3.3 final outcomes keep expected behavior", () => {
  const logPath = path.join(__dirname, "2026-04-22", "decision404_analysis_run.log");
  const { step3_3Finals } = parseRunLogCases(logPath);

  assert.equal(step3_3Finals.length, 10);
  const finalConclusions = [...new Set(step3_3Finals.map(x => x.finalConclusion))].sort();
  assert.deepEqual(finalConclusions, ["cache_load_success"]);

  const finalReasons = [...new Set(step3_3Finals.map(x => String(x.finalReason)))].sort();
  assert.deepEqual(finalReasons, ["null"]);
});

test("2026-04-22 run log: Step3.4 aggregation distribution remains stable", () => {
  const logPath = path.join(__dirname, "2026-04-22", "decision404_analysis_run.log");
  const { step3_4Roots, step3_4Agg } = parseRunLogCases(logPath);

  assert.equal(step3_4Roots.length, 16);
  assert.equal(step3_4Agg.length, 39);

  const nonZeroAgg = step3_4Agg
    .filter(x => Number(x.rootCauseCount || 0) > 0 || Number(x.furtherAnalysisCount || 0) > 0)
    .map(x => `${x.region}:${x.rootCauseCount}/${x.furtherAnalysisCount}`)
    .sort();
  assert.deepEqual(nonZeroAgg, [
    "me-jeddah:2/0",
    "uk-london:1/0",
    "us-ashburn:2/0",
    "us-phoenix:11/0",
  ]);
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

test("Step3.4 fixture: step2 Loki query failure gets further analysis row", () => {
  const out = buildStep3_4DeploymentCacheCheck(
    {},
    {},
    { step2ByEnv: { envx: { error: "Failed to fetch" } } },
  );
  assert.equal(out.furtherAnalysisTable.length, 1);
  assert.equal(out.furtherAnalysisTable[0].result, "step2_loki_query_failed");
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
  const prepTsNs = 1_000_000_000_000;

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
      previousLog: { lokiTsNs: String(prepTsNs) },
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
  const prepTsNs = 1_000_000_000_000;

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
      previousLog: { lokiTsNs: String(prepTsNs) },
    },
    { queryLokiFn: mockQueryLoki },
  );

  assert.equal(out.conclusion, "cache_load_failure");
  assert.equal(out.reason, "restart_warmup");
  assert.equal(out.restartEvidence.count, 1);
});
