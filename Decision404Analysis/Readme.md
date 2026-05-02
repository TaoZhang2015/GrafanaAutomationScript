# Decision404Analysis

`Decision404Analysis.js` is a browser-console script for Grafana that analyzes decision-service `404` traffic and builds root-cause oriented outputs per environment.

It combines:
- Mimir metrics discovery (`Step1`)
- Loki request log collection (`Step2`)
- multi-stage request/cache timeline analysis (`Step3.x`)
- CSV/log exports for follow-up and reporting

## What It Produces

The script generates:
- impacted env list from `Step1` (`EnvList.txt`)
- per-interval per-env summary CSV (`decision404_summary_by_env_<intervalLabel>.csv`)
- per-interval further-analysis CSV (`decision404_further_analysis_table_<intervalLabel>.csv`)
- run log file (`decision404_analysis_run.log`)

When run in browser, an export panel appears with save buttons for generated files.

Export rule:
- summary/further CSVs are generated only for intervals that are fully completed
- if any region in an interval has `Step1` failure or `Step2/Step3` failure, both interval CSVs are skipped

## Run Location

Run in Grafana browser DevTools Console (with access to target Mimir/Loki data sources).

The script calls Grafana datasource proxy endpoints such as:
- `/api/datasources/proxy/uid/<mimirUid>/...`
- `/api/datasources/proxy/uid/<lokiUid>/...`

## Quick Start

1. Open `Decision404Analysis.js`.
2. Update `ANALYSIS_CONFIG` for time range/regions.
3. Paste script into Grafana DevTools Console and execute.
4. Watch logs in console.
5. Save exported files via the export panel.

## Core Config

Most frequently edited settings are in `ANALYSIS_CONFIG` near the top of the file.

Key fields:
- `iterateAllRegions`: `true` = use `ALL_REGIONS`; `false` = only `regionsToRun`
- `regionsToRun`: specific regions when not iterating all
- `maxParallelRegions`: region-level parallelism (Step1 pre-discovery and Step2/Step3)
- `throttleBetweenRegionsMs`: delay between region starts
- `grafanaApiMinIntervalMs`: minimum interval between Grafana API requests
- `grafanaRetryMaxAttempts`, `grafanaRetryBaseDelayMs`: request retry policy
- `step1RangeStartPst`, `step1RangeEndPst`: fixed Step1/Step2 time window

Step3 behavior knobs:
- `step3_3ReuseWindowSeconds` (strict same-trace reuse window; current conservative mode)
- `step3_3CompletionExtend1Minutes`
- `step3_3CompletionExtend2Minutes`
- `step3_3FastTimelineEnabled`
- `step3_3FastTimelineMinRequestsPerHour`

## Execution Model (Current)

The run now uses a **two-phase flow**:

1. Step1 pre-discovery phase:
- runs `Step1` for each selected region
- runs with `maxParallelRegions` concurrency
- collects impacted env counts for all successful regions

2. Processing phase:
- freezes global env total before Step2/Step3 starts
- runs Step2/Step3 for successful Step1 regions with `maxParallelRegions` concurrency
- if a region has `Step1 impactedEnvCount = 0`, Step2/Step3 is skipped for that region

Why this matters:
- global `totalEnvCount` is stable during Step3 (no denominator jumps mid-run)
- avoids Step2/Step3 overhead for zero-impact regions

## Interval Completeness Rule

Per interval, the script tracks:
- `step1FailedRegionCount`
- `analysisFailedRegionCount`
- `isCompleteForExport`

CSV export behavior:
- when `isCompleteForExport=true`, export both summary/further CSVs for that interval
- when `isCompleteForExport=false`, skip both summary/further CSVs for that interval and keep run-log evidence

## Progress Logs: How To Read

There are two different progress views:

1. Global env progress:
- log key: `[STEP3.3] env analysis progress`
- fields: `processedEnvCount`, `totalEnvCount`, `progressPct`
- increments only after one env completes Step3.3

2. In-env link progress:
- log key: `[STEP3.3] progress`
- fields: `processed`, `total`
- emitted every 50 links while processing a heavy env

If global `processedEnvCount` looks “stuck” but `[STEP3.3] progress` keeps moving, the script is still actively processing one large env.

## Step Summary

This is a concrete sample from run log (`region=us-phoenix`):
- `env = esll-dev8`
- `pod = authz-decision-744d97b459-dqtjq`
- `traceID = 05409db5ee4a31412551ab088e62f685`
- `requestUrl = /v1:$941/authorize`
- `requestCompleteTimeNs = 1777162814802598100` (`2026-04-25 17:20:14.802 PDT`)
- `requestStartTimeNs = 1777162814801598200` (`2026-04-25 17:20:14.801 PDT`)

Step 1. Mimir env discovery:
- Query:
```promql
sum by (prd_env) (
  rate(application_processed_requests_total{
    prd_fleet="faaas-prod",
    job="authz-decision",
    statuscode=~"404"
  }[5m])
) > 0
```
- Time interval:
  - `start = ANALYSIS_CONFIG.step1RangeStartPst`
  - `end = ANALYSIS_CONFIG.step1RangeEndPst`

Step 2. Loki 404 request lines by env:
- Query:
```logql
{ container=~"decision", namespace="authz", prd_env="esll-dev8" } != "/live" != "/ready"
|~ "\"requestHTTPStatusCode\"\\s*:\\s*404|\"responseStatusCode\"\\s*:\\s*404"
```
- Time interval:
  - `startNs = step1RangeStartSec * 1e9`
  - `endNs = step1RangeEndSec * 1e9`
  - actual Loki query window applies global edge grace (`startNs = baseStartNs - 1ms`, `endNs = baseEndNs + 1ms`).

Step 3. Parse and validate request records (Step3.1):
- Parse Step2 lines and keep valid decision 404 records.
- Important values parsed from each request log entry:
  - `env`, `pod`, `lokiTsNs`, `timestamp`
  - `traceID`, `url`, `methodName`, `message`
  - `elapsedTime`, `elapsedTimeMs`
  - `requestHTTPStatusCode`, `responseStatusCode`
- Important derived values used by later steps:
  - `requestStartTimeNs = requestCompleteTimeNs - ceil(elapsedTimeMs) * 1e6`
  - `elapsedTimeRoundedMs`

Step 4. Find runtime cache starting time anchor (Step3.2):
- Goal: find `runtimeCacheStartTimeNs` for each 404 request.
- Step 4 Query (pod-level fetch):
```logql
{ container=~"decision", namespace="authz", prd_env="esll-dev8", pod="authz-decision-744d97b459-dqtjq" } != "/live" != "/ready"
|~ "start loading policies, roles, role mappings for all deployments|starting to prepare decision server cache"
```
- Time interval (for this pod fetch):
  - `queryStartNs = min(requestCompleteTimeNs in this pod) - lookbackHours * 3600 * 1e9`
  - `queryEndNs = max(requestCompleteTimeNs in this pod) - 1`
  - actual Loki query window then applies global edge grace (`-1ms/+1ms`).
- Step 4 Per-request result:
  - For each 404 request, choose:
    - `runtimeCacheStartTimeNs = latest cache-start log timestamp <= requestCompleteTimeNs`
  - If none exists, Step3.2 marks request as missing anchor.
  - Sample:
  - `requestCompleteTimeNs = 1777162814802598100` (`17:20:14.802 PDT`)
  - selected `runtimeCacheStartTimeNs = 1777162519323651600` (`17:15:19.323 PDT`)
Step 5. Resolve default deployment from Step 6 query results (Step3.3-A merged):
- No separate Loki query in this step.
- Reuse Step 6 query result entries and keep only default-kind records with:
  - `entryTsNs <= requestCompleteTimeNs - 1`
- Pick latest remaining record as `resolvedDefaultDeploymentID`.
- If no record remains, keep current fallback behavior:
  - `resolvedDefaultDeploymentID = null`

Step 6. Deployment-list cache cross-check (Step3.3-B, queryId 4277):
```logql
{ container=~"decision", namespace="authz", prd_env="esll-dev8", pod="authz-decision-744d97b459-dqtjq" } != "/live" != "/ready"
|~ "updating deployment list cache with default deploymentID|updating deployment list cache with deploymentID|new default deployment added to the cache|new deployment from latest DB records added to the cache|default deployment from latest records|default deployment from existing cached list"
```
- Interval derivation:
  - `baseEndNs = requestCompleteTimeNs + 15 * 1e9`
  - `baseStartNs = baseEndNs - 60 * 1e9`
  - actual Loki query window applies global edge grace (`startNs = baseStartNs - 1ms`, `endNs = baseEndNs + 1ms`).
- Optional post-request extended check window (only when needed):
  - `postStartNs = requestCompleteTimeNs`
  - `postEndNs = requestCompleteTimeNs + 10 * 60 * 1e9`
- Interval:
  - `startNs=1777162769801598200` (`17:19:29.801 PDT`)
  - `endNs=1777162829803598000` (`17:20:29.803 PDT`)
- Result in this case:
  - `resolvedDefaultDeploymentID=941` (resolved in Step 5 from this Step 6 result set, pre-request only)
  - `deploymentListDecision=target_present`
  - `deploymentListReason=last_round_after_request_fallback_to_second_last_found`
  - `deploymentListUsedRound=second_last`
  - `deploymentListUsedRoundHitKind=default`

Step 7. Trace error categorization (Step3.3-C, queryId 4278):
```logql
{ container=~"decision", namespace="authz", prd_env="esll-dev8", pod="authz-decision-744d97b459-dqtjq" } != "/live" != "/ready"
|~ "05409db5ee4a31412551ab088e62f685"
```
- Interval derivation:
  - `baseStartNs = requestStartTimeNs` (if valid and `<= requestCompleteTimeNs`), else `requestCompleteTimeNs`
  - `baseEndNs = requestCompleteTimeNs`
  - actual Loki query window applies global edge grace (`startNs = baseStartNs - 1ms`, `endNs = baseEndNs + 1ms`).
- Interval:
  - `startNs=1777162814800598200` (`17:20:14.800 PDT`)
  - `endNs=1777162814803598100` (`17:20:14.803 PDT`)
- Result in this case:
  - `traceCategory=runtime_services_not_found`
  - `tracePattern=SPDL-2001 Application %s is not found`

Step 8. Runtime cache completion search (Step3.3-D, queryId 4279):
```logql
{ container=~"decision", namespace="authz", prd_env="esll-dev8", pod="authz-decision-744d97b459-dqtjq" } != "/live" != "/ready"
|~ "completed preparing policies runtime cache|completed preparing role assignments runtime cache|updated cache for deployment '.*' with '[0-9]+' Speedle policies|updated cache for deployment '.*' with [0-9]+ Speedle Role policies"
```
- Base interval derivation:
  - `baseStartNs = runtimeCacheStartTimeNs`
  - `baseEndNs = requestCompleteTimeNs - 1`
  - actual Loki query window applies global edge grace (`startNs = baseStartNs - 1ms`, `endNs = baseEndNs + 1ms`).
- Decision logic (updated):
  - First check current round (`runtimeCacheStartTimeNs .. requestCompleteTimeNs-1`).
  - If `completionDistinctOriginalCount < 3`, find previous round first:
    - Previous-round anchor lookup window:
      - `previousRoundLookupEndNs = runtimeCacheStartTimeNs - 1`
      - `previousRoundLookupStartNs = previousRoundLookupEndNs - 1h`
    - Find latest cache-prep-start anchor in that window, then run the same completion query for:
      - `previousRoundStartNs .. previousRoundLookupEndNs`
  - Branching:
    - Previous round `<3` distinct deployments:
      - Stop extension and keep this request in further-analysis path.
    - Previous round `>=3` and contains requested deployment:
      - Use previous-round completion evidence and continue normal logic.
    - Previous round `>=3` but does not contain requested deployment:
      - Run post-request extension windows:
        - Extension 1: `(requestCompleteTimeNs, requestCompleteTimeNs + 15m]`
        - Extension 2 (if still `<3`): `(requestCompleteTimeNs + 15m, requestCompleteTimeNs + 30m]`
  - Any previous-round lookup/query errors are logged as `STEP3.3` warnings.
  - Tracking fields in run log/output:
    - `completionUsedPreviousRound`
    - `previousRoundCompletionCheck`
    - `completionExtensionUsed`
    - `completionWindowEndNs`
- Interval:
  - `startNs=1777162519322651600` (`17:15:19.322 PDT`)
  - `endNs=1777162814803598000` (`17:20:14.803 PDT`)
- Result in this case:
  - `completionDistinctOriginalCount=3`
  - `completionDistinctExtendCount=3`
  - `completionExtensionUsed=false`

Step 9. Restart evidence check (Step3.3-E, queryId 4280):
```logql
{ container=~"decision", namespace="authz", prd_env="esll-dev8", pod="authz-decision-744d97b459-dqtjq" } != "/live" != "/ready"
|~ "starting decision server|starting authz decision server"
```
- Interval derivation (current logic):
  - `restartLookbackNs = 10 * 60 * 1e9`
  - `restartBaseStartNs = startNs - restartLookbackNs` (`startNs` is Step 8 runtime-cache start)
  - if `previousRoundCompletionCheck.previousRoundStartNs` exists:
    - `restartFromPreviousRoundNs = previousRoundStartNs - restartLookbackNs`
    - `restartQueryStartNs = min(restartBaseStartNs, restartFromPreviousRoundNs)`
  - else:
    - `restartQueryStartNs = restartBaseStartNs`
  - `restartQueryEndNs = endNs` (`endNs = requestCompleteTimeNs - 1`)
  - actual Loki query window applies global edge grace (`startNs = restartQueryStartNs - 1ms`, `endNs = restartQueryEndNs + 1ms`).
- Result in this case: `restartEvidenceCount=0`

Step 10. Step3.3 final conclusion:
- `finalConclusion=cache_load_success`
- `traceErrorCategory=runtime_services_not_found`

Step 10.1. Step3.3 reuse behavior (current safety mode):
- Reuse is enabled only for **same `traceID`** within a short window.
- Window:
  - `reuseWindowSeconds = ANALYSIS_CONFIG.step3_3ReuseWindowSeconds` (current default: `10`)
- Scope:
  - reuse is intra-env loop only
  - no cross-trace signature-based reuse
- Log evidence:
  - `[STEP3.3] reused prior result for same traceID in short window`

Step 11. Step3.4 aggregation:
- Uses Step3.3 outputs to decide root-cause vs further-analysis row.
- For this sample lineage, result is further-analysis path:
  - `result=requested_deployment_found_in_cache`

Step 12. Step3.5 env recovery status after last 404:
- Query:
```logql
{ container=~"decision", namespace="authz", prd_env="esll-dev8" } != "/live" != "/ready"
|~ "\"requestHTTPStatusCode\"\\s*:\\s*200|\"responseStatusCode\"\\s*:\\s*200"
```
- Interval formula:
  - `startNs = last404RequestTsNs + 10s`
  - `endNs = nowNs`
  - actual Loki query window applies global edge grace (`startNs = baseStartNs - 1ms`, `endNs = baseEndNs + 1ms`).
- Rule:
  - `count200==0 => not_recovered`
  - `count200>100 && interval>12h => recovered`
  - else `not_sure`
- If query hits volume-limit error, fallback is second-half-only auto-split for that interval.

## Exports And Saving

The script supports:
- `showSaveFilePicker` when available
- fallback download links
- manual save button fallback for user-gesture restrictions (notably `EnvList.txt`)

## Troubleshooting

1. `totalEnvCount` unexpected:
- ensure Step1 pre-discovery finished
- check `[RUN] Global env total finalized before Step2/Step3`

2. Looks stuck at same `processedEnvCount`:
- check `[STEP3.3] progress` lines for in-env movement
- heavy envs can take much longer before global count increments

3. Time window confusion:
- window values are parsed from ISO strings in `ANALYSIS_CONFIG`
- `-00:00` offset means UTC-style input, not local PST/PDT offset

4. Missing file save dialog:
- use export panel buttons
- if blocked by user gesture, use the manual save button prompt in console

## Testing / Reuse

The file exports a subset of pure/helper functions via `module.exports` for local tests (`Decision404Analysis.test.js`).
