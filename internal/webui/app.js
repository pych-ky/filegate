"use strict";
let bootstrapToken = location.hash.slice(1);
history.replaceState(null, "", location.pathname);
let sessionToken = sessionStorage.getItem("filegate-session") || "";

const $ = id => document.getElementById(id);
const clean = value => String(value ?? "").replace(/[\u0000-\u001f\u007f-\u009f]/g, "");
const node = (tag, text, className) => {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = clean(text);
  if (className) element.className = className;
  return element;
};
const terminal = job => ["FINISHED", "FAILED", "CANCELLED"].includes(job.phase);
const verdicts = {PASS: "合格（規定検査）", HOLD: "保留", BLOCK: "遮断", UNDECIDED: "判定前"};
const phases = {QUEUED: "取得待ち", ACQUIRING: "取得中", QUEUED_FOR_SCAN: "検査待ち", PREPARING: "検査の準備中", INSPECTING: "検査中", FINISHED: "完了", FAILED: "処理失敗", CANCELLED: "キャンセル済み"};
const reasonLabels = {UNSAFE_ARCHIVE_PATH: "危険なアーカイブパス", ARCHIVE_NAME_COLLISION: "アーカイブ内の名前の衝突", ARCHIVE_PATH_TYPE_CONFLICT: "アーカイブの階層の衝突", MALWARE_DETECTED: "マルウェア検知", UNEXPECTED_ARTIFACT_TYPE: "期待した形式と異なります", UNSUPPORTED_FORMAT: "対応範囲外の形式", DOCX_FIELD_REQUIRES_REVIEW: "文書のフィールド機能は確認が必要です", XLSX_FORMULA_OR_CONNECTION: "数式・接続を含む表計算ファイルは確認が必要です", ACTIVE_CONTENT_REQUIRES_REVIEW: "動作を伴う内容は確認が必要です", VM_STOP_FAILED: "終了処理失敗", INCOMPLETE_REQUIRED_CHECKS: "必須検査が未完了", INTERRUPTED: "検査中断", CANCELLED: "キャンセル", SCAN_TIMEOUT: "検査期限超過", RESULT_STALE: "再検査が必要"};
const reasonText = code => reasonLabels[code] ? reasonLabels[code] + " / " + code : code;
Object.assign(reasonLabels, {REVALIDATION_REQUIRED: "再検査が必要", INPUT_MISSING: "原本を利用できません", UPDATE_CLOCK_UNCERTAIN: "時刻の確認待ち", RELEASE_ABORT_REQUESTED: "取り出し中止を要求済み", RELEASE_ALREADY_PUBLISHED: "公開済みのため中止できません", RELEASE_ABORTED: "取り出しは中止済み", RELEASE_OUTPUT_UNVERIFIED: "公開後の最終確認ができません", RECOVERY_REQUIRED: "復旧時の照合が必要"});
const sizeText = value => Number.isFinite(value) ? (value < 1024 ? value + " B" : value < 1048576 ? (value / 1024).toFixed(1) + " KiB" : (value / 1048576).toFixed(1) + " MiB") : "未確定";
const dateText = value => value && !Number.isNaN(Date.parse(value)) ? new Date(value).toLocaleString("ja-JP") : "—";
const badge = value => node("span", verdicts[value] || value, "badge " + (["PASS", "HOLD", "BLOCK"].includes(value) ? value : ""));
let jobs = [], selected = null, file = null, nextCursor = "", cursors = [""], pageIndex = 0, authenticated = false, refreshing = false;
let releaseEnabled = false, destinations = [], releaseHistory = [], releaseCursor = "", releaseNext = "";
let detailVersion = 0, listVersion = 0;
const activeIntakes = new Set();
const activeReleases = new Set();
const releaseChecks = new Map();
const releaseTerminal = receipt => ["COMMITTED", "ABORTED", "PUBLISHED_UNVERIFIED"].includes(receipt.state);

function message(text, error = false) {
  $("message").textContent = clean(text);
  $("message").className = "notice" + (error ? " error" : "");
}
function freshKey(kind) {
  const value = "intake_" + crypto.randomUUID();
  sessionStorage.setItem("filegate-" + kind + "-key", value);
  return value;
}
function keyFor(kind) { return sessionStorage.getItem("filegate-" + kind + "-key") || freshKey(kind); }

async function api(path, options = {}) {
  const response = await fetch(path, {credentials: "omit", cache: "no-store", ...options,
    headers: {"X-FileGate-UI": "1", ...(sessionToken ? {Authorization: "Bearer " + sessionToken} : {}), ...(options.headers || {})}});
  const value = await response.json();
  if (response.status === 401) {
    authenticated = false;
    sessionToken = ""; sessionStorage.removeItem("filegate-session");
    $("application").hidden = true;
    $("logout").hidden = true;
    message("認証が必要です。ターミナルで filegate ui を実行して開き直してください。", true);
  }
  if (!response.ok) {
    const error = new Error(value.error?.code || "REQUEST_FAILED");
    error.status = response.status;
    error.receipt = value.error?.receipt;
    error.releaseReceipt = value.error?.receipt?.release_id ? value.error.receipt : null;
    throw error;
  }
  return value;
}

function renderJobs() {
  $("jobs").replaceChildren();
  const visible = jobs;
  $("job-count").textContent = visible.length + " 件表示中";
  if (!visible.length) $("jobs").append(node("p", $("filter").value === "all" ? "まだ受付はありません。" : "該当するジョブはありません。", "empty"));
  for (const job of visible) {
    const row = node("button", undefined, "job-row" + (selected === job.job_id ? " selected" : ""));
    row.type = "button";
    const top = node("div", undefined, "job-top");
    top.append(node("span", (job.display_name || "ジョブ " + job.job_id.slice(-8)), "job-name"), badge(job.verdict));
    row.append(top, node("div", dateText(job.created_at) + " · " + sizeText(job.input_receipt?.byte_size) + " · " + (phases[job.phase] || job.phase), "job-meta"));
    const reasons = [...(job.reason_codes || []), ...(job.execution_errors || []), ...(job.release?.reason_codes || [])];
    if (reasons.length) row.append(node("div", [...new Set(reasons)].map(reasonText).join(" / "), "job-reason"));
    row.addEventListener("click", () => selectJob(job.job_id));
    $("jobs").append(row);
  }
  $("page").textContent = (pageIndex + 1) + " ページ";
  $("previous").disabled = pageIndex === 0;
  $("next").disabled = !nextCursor;
}

function facts(items) {
  const list = node("dl", undefined, "facts");
  for (const [name, value] of items) list.append(node("dt", name), node("dd", value));
  return list;
}
function reasons(container, title, values) {
  if (!values?.length) return;
  container.append(node("h3", title));
  const list = node("ul", undefined, "reason-list");
  for (const value of values) list.append(node("li", reasonText(value)));
  container.append(list);
}

function renderDetail(job) {
  const body = node("div", undefined, "detail-body");
  const title = node("div", undefined, "detail-title");
  title.append(node("strong", (job.display_name || "ジョブ " + job.job_id.slice(-8))), badge(job.verdict));
  body.append(title, facts([["処理状態", phases[job.phase] || job.phase], ["受付", job.intake_status], ["受付日時", dateText(job.created_at)], ["終了日時", dateText(job.finished_at)], ["入力サイズ", sizeText(job.input_receipt?.byte_size)], ["原本の保持", job.input_receipt ? (job.input_receipt.content_available ? "保持中" : "利用不可") : "未確定"], ["終了・回収", job.runtime_cleanup_complete ? "確認済み" : "確認待ち"]]));
  reasons(body, "判定の理由", job.reason_codes);
  reasons(body, "確認済みの拒否根拠", (job.confirmed_rejections || []).map(item => item.reason_code));
  reasons(body, "実行時の異常", job.execution_errors);
  const progress = job.progress;
  if (!terminal(job) && progress) {
    const stages = {format: "形式・構造解析（列挙中）", av: "AV検査", finalizing: "結果の照合・終了確認"};
    body.append(node("h3", "現在の工程"), node("p", stages[progress.stage] || "確認中"));
    if (progress.manifest_complete) body.append(node("p", "形式・構造の必須検査完了 " + progress.format_completed_count + " 件／対象 " + progress.format_target_count + " 件"), node("p", "AV対象 " + progress.av_input_count + " 件／通常結果 " + progress.av_normal_result_count + " 件"));
    else body.append(node("p", "総対象は列挙完了後に表示します。"));
  }
  const coverage = job.coverage || {};
  const inspection = job.scan_details;
  const count = value => Number.isInteger(value) ? value + " 件" : "未確定";
  const avInputs = inspection?.manifest_complete ? count(inspection.av_input_count) : "総対象未確定（記録済み " + (inspection?.av_input_count ?? coverage.required_av_input_count ?? 0) + " 件）";
  body.append(node("h3", "検査の範囲"), facts([["必須検査", coverage.required_checks_complete ? "完了" : "未完了"], ["形式・構造の対象", count(inspection?.format_target_count)], ["形式・構造の完了", count(inspection?.format_completed_count)], ["AV対象", avInputs], ["AV通常結果", (coverage.av_normal_result_count ?? 0) + " 件"], ["AV処理", coverage.av_process_status || "未提供"], ["AV結果", coverage.av_result || "未提供"], ["プロファイル", coverage.profile_id || "未提供"]]));
  reasons(body, "既知の観測限界", coverage.known_limitations);
  const versions = inspection?.versions;
  if (versions) {
    const details = node("details");
    details.append(node("summary", "検査時の構成と定義の版"), facts([["エンジン", versions.engine], ["ポリシー", versions.policy_id], ["定義の更新ID", versions.definition_update_id], ["定義の世代", versions.definition_generation], ["サービス SHA-256", versions.host_sha256], ["実行構成 SHA-256", versions.worker_sha256], ["ビルド SHA-256", versions.build_sha256], ["形式プロファイル SHA-256", versions.formats_sha256], ["AV実行ファイル SHA-256", versions.engine_sha256], ["AVビルド情報 SHA-256", versions.scanner_manifest_sha256], ["AV設定 SHA-256", versions.configuration_sha256], ["定義セット SHA-256", versions.definitions_sha256], ["観測仕様 SHA-256", versions.observations_sha256]]));
    body.append(details);
  } else body.append(node("p", "検査時の構成と定義の版は未記録です。", "detail-note"));
  body.append(node("h3", "入力の識別"), facts([["SHA-256", job.input_receipt?.sha256 || "未確定"], ["ジョブID", job.job_id], ["試行ID", job.attempt_id || "未確定"]]));
  if (job.update_id || job.wait_reason) body.append(node("h3", "更新待ち"), facts([["更新ID", job.update_id || "未提供"], ["待機理由", job.wait_reason || "—"], ["次回可能日時", job.next_allowed_at ? dateText(job.next_allowed_at) : "未確定"]]));
  const actions = node("div", undefined, "detail-actions");
  if (!terminal(job)) {
    const cancel = node("button", "キャンセル", "quiet");
    cancel.type = "button";
    cancel.addEventListener("click", () => action(job.job_id, "cancel", cancel));
    actions.append(cancel);
  }
  const rescan = node("button", "保存原本を再検査", "quiet");
  rescan.type = "button";
  rescan.disabled = !terminal(job) || !job.input_receipt?.content_available || !job.runtime_cleanup_complete;
  rescan.addEventListener("click", () => action(job.job_id, "attempts", rescan));
  actions.append(rescan);
  if (["HOLD", "BLOCK"].includes(job.verdict)) {
    const remove = node("button", "原本を削除", "quiet");
    remove.type = "button";
    remove.disabled = !terminal(job) || !job.runtime_cleanup_complete || !job.input_receipt?.content_available;
    remove.addEventListener("click", async () => {
      remove.disabled = true;
      try {
        await api("/ui/jobs/" + encodeURIComponent(job.job_id) + "/delete-original", {method: "POST"});
        message("原本を削除しました。検査結果と履歴は保持しています。");
        await refresh();
      } catch (error) { remove.disabled = false; message(reasonText(error.message), true); }
    });
    actions.append(remove);
  }
  body.append(actions);
  renderRelease(body, job);
  $("detail").replaceChildren(body);
}

function releaseKey(jobID, destination) {
  return "filegate-release-" + jobID + "-" + destination;
}
function renderRelease(body, job) {
  body.append(node("h3", "現在の取り出し可否"), node("p", releaseEnabled && job.release?.eligible ? "取り出し可能" : "取り出し不可"));
  reasons(body, "取り出しできない理由", job.release?.reason_codes);
  const actions = node("div", undefined, "detail-actions");
  const label = node("label", "設定済みの出力先");
  const destination = node("select");
  destination.setAttribute("aria-label", "取り出し先");
  for (const item of destinations) {
    const option = node("option", item.destination_id + (item.enabled ? "" : "（利用停止）"));
    option.value = item.destination_id; option.disabled = !item.enabled;
    destination.append(option);
  }
  const selectionKey = "filegate-release-destination-" + job.job_id;
  const saved = sessionStorage.getItem(selectionKey);
  if (destinations.some(item => item.destination_id === saved && item.enabled)) destination.value = saved;
  const enabled = releaseEnabled && job.release?.eligible && !activeReleases.has(job.job_id);
  destination.disabled = !enabled;
  const button = node("button", enabled ? "取り出す・同じ操作を照会" : "取り出しは無効", "quiet");
  button.type = "button";
  button.disabled = !enabled || !destinations.some(item => item.destination_id === destination.value && item.enabled);
  destination.addEventListener("change", () => {
    sessionStorage.setItem(selectionKey, destination.value);
    button.disabled = !enabled || !destinations.some(item => item.destination_id === destination.value && item.enabled);
  });
  button.addEventListener("click", () => submitRelease(job.job_id, destination.value, button));
  label.append(destination); actions.append(label, button); body.append(actions);
  body.append(node("h3", "取り出し履歴"));
  if (!releaseHistory.length) body.append(node("p", "取り出し履歴はありません。", "detail-note"));
  for (const receipt of releaseHistory) {
    const section = node("section", undefined, "release-entry");
    section.append(facts([["取り出しID", receipt.release_id], ["出力先", receipt.destination_id], ["出力名", receipt.output_name], ["状態", receipt.state], ["公開状態", receipt.publication_status], ["中止の結果", receipt.abort_outcome || "未要求"], ["資源の精算", receipt.resources_finalized ? "完了" : "未完了"], ["受付日時", dateText(receipt.created_at)], ["終了日時", dateText(receipt.finalized_at)]]));
    reasons(section, "取り出しの理由", receipt.reason_codes);
    const controls = node("div", undefined, "detail-actions");
    const check = node("button", "出力の現在状態を照合", "quiet");
    check.type = "button";
    check.addEventListener("click", async () => {
      check.disabled = true;
      try {
        const value = await api("/v1/releases/" + encodeURIComponent(receipt.release_id));
        releaseChecks.set(receipt.release_id, {receipt: value, checkedAt: new Date().toISOString()});
        if (selected === job.job_id) await loadDetail(job.job_id);
      } catch (error) { check.disabled = false; message(reasonText(error.message), true); }
    });
    controls.append(check);
    const checked = releaseChecks.get(receipt.release_id);
    if (checked) section.append(facts([["出力照合日時", dateText(checked.checkedAt)], ["照合時の出力", checked.receipt.current_output_state], ["最終検証", checked.receipt.final_validation], ["出力同期", checked.receipt.output_sync_confirmation]]));
    if (!releaseTerminal(receipt) && !receipt.abort_requested) {
      const abort = node("button", "取り出しを中止", "quiet");
      abort.type = "button"; abort.disabled = activeReleases.has(job.job_id);
      abort.addEventListener("click", () => abortRelease(job.job_id, receipt.release_id, abort));
      controls.append(abort);
    }
    if (releaseTerminal(receipt) && enabled && sessionStorage.getItem(releaseKey(job.job_id, receipt.destination_id) + "-receipt") === receipt.release_id && destinations.some(item => item.destination_id === receipt.destination_id && item.enabled)) {
      const create = node("button", "この出力先へ新しく取り出す", "quiet");
      create.type = "button";
      create.addEventListener("click", () => {
        if (activeReleases.has(job.job_id)) return;
        const storageKey = releaseKey(job.job_id, receipt.destination_id);
        sessionStorage.setItem(storageKey, "release_" + crypto.randomUUID());
        sessionStorage.removeItem(storageKey + "-receipt");
        submitRelease(job.job_id, receipt.destination_id, create);
      });
      controls.append(create);
    }
    section.append(controls); body.append(section);
  }
  const pages = node("div", undefined, "detail-actions");
  if (releaseCursor) {
    const latest = node("button", "先頭の履歴", "quiet"); latest.type = "button";
    latest.addEventListener("click", () => { releaseCursor = ""; refresh(); }); pages.append(latest);
  }
  if (releaseNext) {
    const older = node("button", "次の履歴", "quiet"); older.type = "button";
    older.addEventListener("click", () => { releaseCursor = releaseNext; refresh(); }); pages.append(older);
  }
  body.append(pages);
}
async function loadDetail(id) {
  const version = ++detailVersion;
  const parameters = new URLSearchParams({limit: "100"});
  if (releaseCursor) parameters.set("cursor", releaseCursor);
  const [job, history] = await Promise.all([api("/v1/jobs/" + encodeURIComponent(id)), api("/v1/jobs/" + encodeURIComponent(id) + "/releases?" + parameters)]);
  if (selected === id && version === detailVersion) {
    releaseHistory = history.releases; releaseNext = history.next_cursor || "";
    renderDetail(job);
  }
}
function releaseMessage(receipt) {
  return (receipt.replayed ? "同じ取り出し操作の結果です。" : "取り出し操作を受け付けました。") + " 状態: " + receipt.state + " / 公開: " + receipt.publication_status + " / 資源精算: " + (receipt.resources_finalized ? "完了" : "未完了");
}
async function submitRelease(id, destination, button) {
  if (activeReleases.has(id)) return;
  activeReleases.add(id); button.disabled = true;
  const storageKey = releaseKey(id, destination);
  let key = sessionStorage.getItem(storageKey);
  if (!key) { key = "release_" + crypto.randomUUID(); sessionStorage.setItem(storageKey, key); }
  try {
    const receipt = await api("/v1/jobs/" + encodeURIComponent(id) + "/release", {method: "POST", headers: {"Content-Type": "application/json", "Idempotency-Key": key}, body: JSON.stringify({destination_id: destination})});
    sessionStorage.setItem(storageKey + "-receipt", receipt.release_id);
    message(releaseMessage(receipt));
  } catch (error) {
    if (error.releaseReceipt) sessionStorage.setItem(storageKey + "-receipt", error.releaseReceipt.release_id);
    message(error.releaseReceipt ? releaseMessage(error.releaseReceipt) + " / " + reasonText(error.message) : "同じ操作のキーを保持しています。再試行で受付を照会します。 / " + reasonText(error.message), true);
  } finally { activeReleases.delete(id); releaseCursor = ""; await refresh(); }
}
async function abortRelease(jobID, releaseID, button) {
  if (activeReleases.has(jobID)) return;
  activeReleases.add(jobID); button.disabled = true;
  try {
    const receipt = await api("/v1/releases/" + encodeURIComponent(releaseID) + "/abort", {method: "POST"});
    message("中止の状態: " + (receipt.abort_outcome || receipt.state) + " / 資源精算: " + (receipt.resources_finalized ? "完了" : "未完了"));
  } catch (error) {
    message(error.releaseReceipt ? releaseMessage(error.releaseReceipt) + " / " + reasonText(error.message) : reasonText(error.message), true);
  } finally { activeReleases.delete(jobID); await refresh(); }
}
async function selectJob(id) {
  selected = id;
  releaseCursor = ""; releaseHistory = []; releaseNext = "";
  renderJobs();
  $("detail").replaceChildren(node("p", "読み込み中…", "empty"));
  try {
    await loadDetail(id);
  }
  catch (error) { message(reasonText(error.message), true); }
}
async function refresh() {
  if (!authenticated || refreshing) return;
  refreshing = true;
  const version = listVersion;
  $("previous").disabled = true; $("next").disabled = true;
  try {
    const parameters = new URLSearchParams({limit: "100", state: $("filter").value});
    if (cursors[pageIndex]) parameters.set("cursor", cursors[pageIndex]);
    const result = await api("/v1/jobs?" + parameters);
    if (version !== listVersion) return;
    jobs = result.jobs; nextCursor = result.next_cursor || "";
    renderJobs();
    const id = selected;
    if (id) {
      await loadDetail(id);
    }
  } catch (error) { message(reasonText(error.message), true); }
  finally {
    refreshing = false;
    if (version !== listVersion) refresh();
  }
}
async function action(id, operation, button) {
  button.disabled = true;
  try {
    const job = await api("/v1/jobs/" + encodeURIComponent(id) + "/" + operation, {method: "POST"});
    if (selected === id) renderDetail(job);
    await refresh();
    message(operation === "cancel" ? "キャンセル要求を受け付けました。終了・回収の状態をご確認ください。" : "保存原本の再検査を受け付けました。");
  } catch (error) { button.disabled = false; message(reasonText(error.message), true); }
}
function receiptMessage(receipt) {
  if (receipt.replayed) return "前回受付の結果です。今回のファイルは取り込んでいません。受付状態: " + receipt.intake_status + " / " + receipt.job_id;
  return (receipt.current_input_checked ? "原本の取込みが完了しました。" : "取得を予約しました。原本の取込みはまだ完了していません。") + "受付状態: " + receipt.intake_status + " / " + receipt.job_id;
}
function chooseFile(value) {
  if (activeIntakes.has("file")) return;
  file = value || null;
  freshKey("file");
  $("selected-file").textContent = file ? clean(file.name) + " · " + sizeText(file.size) : "内容はプレビューしません";
  $("file-submit").disabled = !file || file.size > 250 * 1048576;
  $("file-submit").textContent = "ファイルを受け付ける";
  if (file?.size > 250 * 1048576) message("ファイルは250 MiB以下にしてください。", true);
}
function encodedMetadata(metadata) {
  const bytes = new TextEncoder().encode(JSON.stringify(metadata));
  return btoa(Array.from(bytes, value => String.fromCharCode(value)).join("")).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}
async function submit(kind, button) {
  if (activeIntakes.has(kind)) return;
  activeIntakes.add(kind);
  const fields = document.querySelectorAll("#" + kind + "-form input, #" + kind + "-form select");
  for (const field of fields) field.disabled = true;
  button.disabled = true;
  button.textContent = "受付中…";
  try {
    const key = keyFor(kind);
    let path, options;
    if (kind === "file") {
      if (!file || file.size > 250 * 1048576) throw new Error("INPUT_TOO_LARGE");
      const metadata = {source_kind: "upload", idempotency_key: key, display_name: file.name};
      if (file.type) metadata.declared_media_type = file.type;
      if ($("file-type").value) metadata.expected_type = $("file-type").value;
      if ($("file-hash").value) metadata.expected_sha256 = $("file-hash").value;
      path = "/v1/jobs/file";
      options = {method: "POST", body: file, headers: {"Content-Type": "application/octet-stream", "Idempotency-Key": key, "X-FileGate-Metadata": encodedMetadata(metadata)}};
    } else {
      path = "/v1/jobs/url";
      options = {method: "POST", headers: {"Content-Type": "application/json", "Idempotency-Key": key},
        body: JSON.stringify({source_kind: "url", idempotency_key: key, url: $("source-url").value, expected_type: $("url-type").value, ...($("url-hash").value ? {expected_sha256: $("url-hash").value} : {})})};
    }
    const receipt = await api(path, options);
    $("receipt").textContent = receiptMessage(receipt);
    selected = receipt.job_id; cursors = [""]; pageIndex = 0;
    button.textContent = "同じ受付を照会";
    await refresh();
  } catch (error) {
    if (error.status === 400 && !error.receipt) {
      button.textContent = kind === "file" ? "ファイルを受け付ける" : "URLを受け付ける";
      $("receipt").textContent = "受付できませんでした。入力内容を確認してください。 / " + reasonText(error.message);
    } else {
      button.textContent = "同じ受付を再試行";
      $("receipt").textContent = error.receipt ? receiptMessage(error.receipt) + " / " + reasonText(error.message) :
        "受付を確認できませんでした。通信再試行では同じキーを使います。" + (error.name === "TypeError" ? "" : " / " + reasonText(error.message));
    }
  } finally {
    activeIntakes.delete(kind);
    for (const field of fields) field.disabled = false;
    button.disabled = kind === "file" && (!file || file.size > 250 * 1048576);
  }
}

$("file").addEventListener("change", event => chooseFile(event.target.files[0]));
$("file-type").addEventListener("change", () => { freshKey("file"); $("file-submit").textContent = "ファイルを受け付ける"; });
$("file-hash").addEventListener("input", () => { freshKey("file"); $("file-submit").textContent = "ファイルを受け付ける"; });
for (const id of ["source-url", "url-type", "url-hash"]) $(id).addEventListener("input", () => { freshKey("url"); $("url-submit").textContent = "URLを受け付ける"; });
$("file-form").addEventListener("submit", event => { event.preventDefault(); submit("file", $("file-submit")); });
$("url-form").addEventListener("submit", event => { event.preventDefault(); submit("url", $("url-submit")); });
for (const name of ["dragenter", "dragover"]) $("dropzone").addEventListener(name, event => { event.preventDefault(); $("dropzone").classList.add("dragging"); });
for (const name of ["dragleave", "drop"]) $("dropzone").addEventListener(name, event => { event.preventDefault(); $("dropzone").classList.remove("dragging"); });
$("dropzone").addEventListener("drop", event => { if (event.dataTransfer.files.length === 1) chooseFile(event.dataTransfer.files[0]); else message("ファイルを1つ選択してください。", true); });
$("filter").addEventListener("change", () => {
  listVersion++; cursors = [""]; pageIndex = 0; nextCursor = ""; jobs = [];
  renderJobs(); refresh();
});
$("refresh").addEventListener("click", refresh);
$("next").addEventListener("click", () => { if (nextCursor && !refreshing) { cursors[++pageIndex] = nextCursor; refresh(); } });
$("previous").addEventListener("click", () => { if (pageIndex && !refreshing) { pageIndex--; refresh(); } });
$("logout").addEventListener("click", async () => {
  try { await api("/ui/logout", {method: "POST"}); } catch (_) { }
  sessionToken = ""; sessionStorage.removeItem("filegate-session");
  authenticated = false; $("application").hidden = true; $("logout").hidden = true;
  message("接続を終了しました。再接続は filegate ui を実行してください。");
});

(async () => {
  try {
    if (bootstrapToken) {
      const auth = await api("/ui/session", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({token: bootstrapToken})});
      sessionToken = auth.session; sessionStorage.setItem("filegate-session", sessionToken);
    }
    bootstrapToken = "";
    const health = await api("/v1/health");
    releaseEnabled = health.release_enabled === true;
    const configured = await api("/v1/release-destinations");
    destinations = configured.destinations;
    authenticated = true; $("application").hidden = false; $("logout").hidden = false;
    message("ローカルサービスに接続しました。検査の判定と、実行・終了の状態を分けて表示します。");
    await refresh();
  } catch (_) {
    bootstrapToken = "";
    message("認証が必要です。ターミナルで filegate ui を実行して開き直してください。", true);
  }
})();
setInterval(() => { if (!document.hidden) refresh(); }, 3000);
