# 検証の実行と記録

製品・VM制御・更新・ビルド・検証の実行経路をGoへ切り替えた。リポジトリ内のPythonは0件で、現存する旧原本と凍結証拠は上書きしない。正式に配置したC10構成のstage0/3 trueと実PASS・原本取り出し・再起動後の状態確認は、その構成だけの当時の記録である。採用構成と実証範囲は[継続指示](../HANDOFF.md)と[実装状態](../IMPLEMENTATION_STATUS.md)を参照する。

実装、契約、採用マニフェスト、検証CLIのソースはこのリポジトリで管理する。実行結果、保存ソース、生成入力、依存キャッシュ、ビルド出力は、ローカルの `~/Library/Application Support/FileGate/verification` に置く。設計・実装・ログを外部サービスへ送信しない。

## 新しい検証workspace

管理ソースを編集し、Goの `filegate-dev workspace` で新規workspaceへ同期する。下の `NEW` は未使用の名前に置き換える。既存のAV基準版、登録済みruntime、構築済み候補のworkspace・imageへは同期しない。

```sh
verification="$HOME/Library/Application Support/FileGate/verification"
workspace="$HOME/Library/Application Support/FileGate/go-python-free-NEW"
mkdir -p -m 700 "$verification/tools"
go build -trimpath -o "$verification/tools/filegate-dev" ./cmd/filegate-dev
CGO_ENABLED=1 go build -trimpath -o "$verification/tools/filegate-verify" ./cmd/filegate-verify
dev="$verification/tools/filegate-dev"
verify="$verification/tools/filegate-verify"
"$dev" workspace --verification "$verification" --root "$workspace" sync
```

同期対象からPythonコードと秘密設定を除き、所有者・mode・hashを照合する。既存の入力・キャッシュ・proofを自動取得する機能はない。必要な固定資産は、採用記録と同じ内容・相対配置で別途用意する。

`workspace path` は同期先を返す。`workspace run --cwd <相対ディレクトリ> -- <コマンド>` は同期してから実行するため、構築・凍結前の作業だけに使う。imageとbuild receiptを作成した後は、固定されたrunnerを直接実行する。VMのintentが残る場合や他の検証が動いている場合は同期しない。

構築済みソースと必要な証拠を照合する入口は次のとおり。

```sh
"$dev" --repo "$workspace" gate
"$verify" --list
```

`gate` の終了値は必須条件が未完なら1、証拠欠落などの不整合なら2となる。ファイルの移設やゲートの成功だけでruntimeを採用しない。

## 実行範囲と記録

製品の検証は `filegate-verify <suite> --root "$workspace" --out <新規出力先>` を使う。`basic`、`acquire`、`ui` は、それぞれ基本CLI/API/MCP、ローカルTLSによる取得層、loopback HTTPのUIを扱い、GUIは操作しない。実VM・URL結合・中断復旧・保持期限・起動保護・DOCX/XLSXは別のsuiteで確認する。所有不明時は容量予約を保持する。suiteごとの追加引数は実装と[開発手順](../DEVELOPMENT.md)に従う。DBの日付変更や前回bootの合成入力を、実OSの時計変更・sleep・再起動の証拠にしない。`idle` は自分が起動したbrokerとMCPの2つだけのCPUとRSSを測り、ほかのプロセスが動いていないことは示さない。

出力先には未使用の名前を指定する。保存済み `prepared.json` は当時の絶対パスを含むので、新しい起動へ再利用しない。同じ失敗試行の正式な回収は元の出力先を使い、停止証拠・プロセスとfdの終了・raw回収・予約精算を照合する。intentやrawを手動削除して次のVMへ進めない。

現在の構成と有限な主張の最終受入は、検証領域の `product-checks/os-events-real-20261116-01/final-completion-20261117.json` で確認する。`product-checks/current-evidence-index-20261109-01/evidence-index.v17.json`、`product-checks/remaining-completion-20261112-01/coordinator-final-acceptance.json` とv16は当時の記録として保持し、ソースや部品が変わらない限り、全suiteを実行し直さない。component試験や停止hook付きoverlayの結果を、通常host自身の実VM・採用・取り出し・再起動の証拠にしない。

修正前の失敗と修正後の成功は別の試行として保存し、失敗結果を書き換えない。異常入力を正しく拒否した成功試験も、実装不備による失敗と区別する。保持対象は検証領域の `retention.json` と採用記録で確認し、現在の実行資産や未解決事項の根拠を、再生成できる一時データと混同しない。

各文書の `artifacts/`・`evidence/` は、検証workspace内の同じ相対位置にある当時の保存先を指す。過去の成功は当時の構成と範囲の証拠であり、削除済みPythonや作業コピーをそのまま再実行できることは意味しない。所在を確認できないarchiveから旧原本を復元可能と扱わない。旧保存物の所在と対応結果は[実装状態の対応と限界](../IMPLEMENTATION_STATUS.md#今回の対応と限界)にまとめる。
