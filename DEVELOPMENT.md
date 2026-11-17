# ローカル開発

Go 1.27.3とCコンパイラを使う。リポジトリ内のPythonは0件で、製品・VM制御・更新・構築・検証の実行経路はGoへ切替済みである。固定AV library、FreshClamのC ABI層とnative C/Objective-C監視は保持する。検証には合成・無害・非機密の入力を使い、受入の順序と範囲は[実装状態](IMPLEMENTATION_STATUS.md)で確認する。

## 構築と検証

管理リポジトリから開発CLIを外部へ構築し、新しい専用workspaceへ同期する。`NEW` は未使用の名前に置き換える。凍結済みworkspace・登録imageへ同期しない。

```sh
verification="$HOME/Library/Application Support/FileGate/verification"
workspace="$HOME/Library/Application Support/FileGate/go-python-free-NEW"
mkdir -p -m 700 "$verification/tools"
go build -trimpath -o "$verification/tools/filegate-dev" ./cmd/filegate-dev
CGO_ENABLED=1 go build -trimpath -o "$verification/tools/filegate-verify" ./cmd/filegate-verify
dev="$verification/tools/filegate-dev"
verify="$verification/tools/filegate-verify"
"$dev" workspace --verification "$verification" --root "$workspace" sync
cd "$workspace"
mkdir -p -m 700 .product-build
CGO_ENABLED=1 go build -trimpath -o .product-build/filegate ./cmd/filegate
CGO_ENABLED=1 go build -trimpath -o .product-build/filegate-install ./cmd/filegate-install
go vet ./cmd/... ./internal/...
"$verify" --list
```

静的検査は製品の `cmd`・`internal` を対象にする。検証領域の保存sourceや停止点overlayを単独packageとして検査しない。新規試行は外部の未使用出力先を使い、入力・手順・期待値・実値・source/binary hashを保存する。build成功を実VMや受入の証拠にせず、過去の失敗を上書きしない。

固定入力とGo wrapperの構築は[AV builder](experiments/av/fixed_adapter_builder/README.md)、scan imageと監視付きrunnerは[VM手順](experiments/vm/README.md)、native proofは[ホスト手順](experiments/host/README.md)に従う。Darwin host runnerのidentity確認とLinux/arm64 muslのFreshClam adapterはCGOを使い、通常のゲストGoはCGO無効で構築する。署名付きAPK・所有・hash・ELFとbuild receiptを照合し、Pythonや未固定依存を追加しない。

`build-host`・`build-guest`・`build-inspector` でnativeを変更するときは、`--native-binary` と `--replacement-native-proof` を同時に指定する。`--native-proof` には旧baselineのproofを渡す。新binaryは所有者専用mode 0500とし、現在のnative source・binaryに対応する `launchagent_death` proofを照合する。2引数の片方だけは受け付けず、両方を省略した場合は旧nativeを使う。ゲストの固定入力も変わる場合は `build-guest` を使い、許可されたファイルとimage差分を照合する。`build-update-host` もこの2引数を併用でき、旧proofは `--parent-registration` から検証する。更新のゲスト入力が旧登録と一致するworkspaceで使い、native変更を理由にsourceやimageの照合を省略しない。

## CLI・UIの利用

検証領域の `.product-build/filegate` と、所有者だけがアクセスできる専用state・入力rootを使う。正式データをfixtureへ渡さず、既存stateの入力root IDを変更しない。以下の `filegate` は実行binaryの絶対pathへ置き換える。

```sh
filegate --data-dir /path/to/private-state serve --input-root fixture=/path/to/synthetic-inputs
filegate --data-dir /path/to/private-state submit file --metadata-fd 0
filegate --data-dir /path/to/private-state submit url --metadata-fd 0
filegate --data-dir /path/to/private-state inspect job_ID --json
filegate --data-dir /path/to/private-state wait job_ID --require-pass --json
filegate --data-dir /path/to/private-state mcp
filegate --data-dir /path/to/private-state ui
```

機密メタデータは保護したfile・pipeから指定FDへ渡し、コマンド文字列へ埋め込まない。file/urlには `source`・`idempotency_key` と任意の `expected_type`・`expected_sha256` を含むJSONを渡す。URLの期待形式は必須。`submit upload --metadata-fd N` は3以上のFDでmetadata、標準入力で本文を受ける。file名・URL・upload名の位置引数は受け付けない。`submit url --url-stdin` はURLを標準入力の1行から受ける別の受付方法である。

初回だけ本文を読み、期待SHA-256があれば照合する。同じキーの再送は元の受付を返し、file再読取り・upload再取込み・URL再取得を行わない。内容を変更する場合は新しいキーを使う。

名前は既定でjob別名だけを返す。`serve --share-names` の場合だけ受付時の末尾名を一覧・詳細へ返し、設定を外して再起動すれば別名へ戻る。共有名はCLI・MCPを通じてAIへも渡る。path・URLを返さない。

CLI/stdio MCPはmode 0600のUnix socketを使う。`ui` はMicrosoft Edgeを開き、127.0.0.1の動的portだけでセッション認証とHost/Origin照合を行う。外部interfaceへ公開しない。`wait --require-pass` の終了値は10がFINISHED/HOLD、20が終端BLOCK、30が拒否根拠のないFAILED/CANCELLED、40が待機期限切れで、待機期限だけではjobを変更しない。

## 出力先の再登録

`DESTINATION_IDENTITY_CHANGED` で新規取り出しが拒否されたときは、意図した同じフォルダーであることを確認してから再登録する。brokerを起動し、`destinations` が返す対象の `registration_sha256` を指定する。

```sh
filegate --data-dir PRIVATE_STATE destinations
filegate --data-dir PRIVATE_STATE destination-rebind outbox \
  --destination-path OUTPUT_DIRECTORY --expected-sha256 REGISTRATION_SHA256
```

同じID/pathでroot/stagingのinode・birthが変わっておらず、所有者・権限・APFSの条件を満たし、stagingが空の場合に限る。全取り出し処理・予約・未解決INTENTがなく、登録SHAが一致することも製品が確認する。旧取り出しの記録は更新しない。未完了の処理がある場合は通常の復旧を先に行い、登録やstagingを手動で書き換えない。

## VM・更新・配置

VM検査には `serve` の `--vm-runner`・`--vm-workspace`・`--vm-proof` をすべて絶対pathで指定する。省略時は原本受付までで検査をHOLDにする。固定runner・build receipt・現在のOS/native proofを照合し、sourceやimageを実行中に変更しない。停止・回収不明時は予約と新規起動禁止を保持し、intent/rawを手動削除しない。

更新imageは `filegate-dev build-update` へscan build、固定adapter bundle、native proofと `--freshclam-binary`・`--freshclam-build` を渡して新規構築する。新規登録/buildはschema 2・request_schema 2とし、旧schema 1は履歴読取りに限る。`--reuse-registration` は必須引数との併用で入力が一致する場合だけ使い、旧登録imageを上書きしない。

同じstateの登録切替は、旧処理の停止・回収後にbrokerを停止し、次の通常CLIを使う。

```sh
filegate --data-dir PRIVATE_STATE runtime-replace \
  --candidate REGISTRATION_CANDIDATE --expected-current-sha256 OLD_SHA256
```

旧登録・UUID・禁止期限・採用済み定義・原本・履歴を保持する。WAL/SHMが残る場合は旧構成で通常復旧して停止し、手動削除しない。途中停止後は同じ引数で再開する。HTTP 304再確認を新しい内容のdownloadと扱わない。切替成功だけで新構成の受入やサービス再起動を完了としない。

`state.sqlite` が112 MiBを超えて受付が止まった場合は、brokerを停止して次の通常CLIを使う。

```sh
filegate --data-dir PRIVATE_STATE state-compact
```

同じファイルをSQLiteのVACUUMで詰め、上限・しきい値・履歴・制御状態は変えない。ジャーナルの見積りが固定128 MiB枠を超える場合は、journal modeの切替とVACUUMの前に `STATE_COMPACTION_JOURNAL_BUDGET_EXCEEDED` で断る。4096バイトページでは32704ページ（127.75 MiB）以上が該当する。作業中の取込み・検査・取り出し・更新、索引のない表、整合性や外部キーの異常、WAL/SHMの残存などがあれば、圧縮せずに断る。ただし、前回の中断で残ったホットジャーナルは、断る前にSQLiteが戻すことがあり、そのときはmainファイルのバイト列が変わる。WAL/SHMが残る場合は通常のbroker起動・停止で復旧してから再実行する。中断後に残る `state.sqlite-journal` は手動削除せず、再実行かbrokerの通常起動に任せる。`STATE_COMPACTION_VERIFY_FAILED` は確定後の照合の失敗で、元のファイルには戻っていない。`outcome` が `COMPACTED_RESOURCE_STOP_UNCONFIRMED` なら、空きやジャーナルの長さの監視が停止を求めたが最後の書き戻しは止まらず、確定と照合は済んでいる。`main_file_within_limit` は、詰めた後のmainファイルが112 MiB以下かだけを示し、空き・負荷・復旧など受付のほかの条件が満たされたことは示さない。

ローカルbinaryの配置は `filegate-install --source BINARY --sha256 EXPECTED_SHA256 --prefix PRIVATE_DIRECTORY` を使う。親directoryを先に作り、prefixはリポジトリ外に置く。hashを固定して `current` を原子的に切り替え、前版を保持する。installerは稼働brokerの再起動・VM/定義更新・署名/公証を行わない。配置後の実検査・取り出し・起動し直しと保存状態は、最終host自身で確認する。

初期対象、AV限定保証、期限・資源、回収の条件は[継続指示](HANDOFF.md)に従う。検証記録と生成物は作業ツリー外に置き、設計・実装・ログを外部へ送信しない。
