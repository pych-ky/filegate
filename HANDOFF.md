# FileGateの継続指示

## 採用構成と保存先

Pythonに依存していた製品・VM起動/監視/回収・更新・ビルド・検証をGoへ移行した。固定AV library、FreshClamの小さいC ABI層とnative C/Objective-C監視は保持する。旧Python143ファイル・pyc1ファイル・退役launcherは原本hashを照合して外部保存し、管理ソースと有効な実行経路から除き、リポジトリ内のPythonは0件になった。最終配置版のstage0/3はtrueで、実PASS・原本取り出し・通常のbroker再起動後の状態確認を終えた。

起動は `~/Library/Application Support/FileGate/application/FileGate.command`、取り出し先は `~/Library/Application Support/FileGate/Outbox`。正式データは同じ `FileGate/fg-final/data` を使い、UUID・禁止期限・採用済み定義・原本・履歴を初期化しない。既存キーの再送は元の受付に固定し、内容を変える場合は新しいキーを使う。

検証台帳は `~/Library/Application Support/FileGate/verification/product-checks/go-migration-current`、今回の移行記録は配下の `python-free-go-20261104` にある。採用するhost・scan workspace・更新登録・proofは最終完了台帳のpath/hashで確認し、prestage3版や過去の成功だけから選ばない。大量の旧経緯は同領域の `final-central-doc-drafts/original-docs.tar.gz` と旧採択証拠に保存し、失敗結果を成功へ書き換えない。

## 変更時に守る条件

仕様の正本は `BASIC_DESIGN.md`。受入判定は段階0→1→2→3の順に行い、source・image・OS・nativeを変えた場合は影響する契約を再実証する。旧構成の成功を自動継承せず、未取得の結果や静的buildを実VM成功と扱わない。顧客資料を使う運用は、その採用構成の段階3完了後に限る。

初期対象はパスワードなしのZIP、上限250 MiB。未対応形式・必須検査未完了・通常異常はHOLD、検出はBLOCKとし、確定済みBLOCKを保持する。形式・容量・I/O・identity/hash/size確認、定義の署名・真正性・鮮度、更新禁止期間・UNKNOWN、独立監視と停止保護を維持する。

採択済みのAV内部best effortは、PDF local-recursion、PESpin/PE allocation、LZW/signed-CVD internal-dependency classification、ELF/Mach-O internal analysis、AUTOIT/ISHIELD_MSI association classificationの5範囲に限る。独立未確認であり、観測不能の立証ではない。通知なく内部処理が止まった場合、その停止を検出する保証はない。拒否されたPDF再帰・PESpin/PE allocationの調査や境界入力作成を別経路で再試行しない。

検査300秒・更新全工程600秒、固定4 GiB raw、RAM上限とnative保護を維持する。ホスト直接スキャン、直接QEMU、TCG、NIC付き検査VMへ切り替えない。検査VMのloopbackと、公式配信先だけを許可する通常更新の通信を区別する。

## 再開と回収

編集は管理リポジトリで行い、`filegate-dev workspace` は新しいworkspaceへだけ同期する。凍結したbaseline・登録image・採択workspaceは変更しない。構築後は固定runnerを直接使い、`workspace run` による再同期をかけない。新規試行は未使用の出力先と新規prepareを使う。

停止・回収が不明ならintent/rawと予約・新規起動禁止を保持する。同じ試行の正式なrecoverでPID・起動identity・所有・fd終了・一時service不存在・raw回収・精算を照合し、手動削除やDB初期化で進めない。登録の切替は通常の `runtime-replace` を使い、旧登録と制御状態を保持する。

実機試験はorca-cliの専用terminalでエージェントが実行・監視し、本人によるファイル実行を通常工程の条件にしない。runtime denyを別手段で迂回しない。実OSのsleep・時計変更・再起動が必要なときは、対象・時間・復帰手順を事前に伝え、本人の標準操作と既存監視を組み合わせる。ユーザーの作業terminal、フォーカス、デスクトップを変更せず、実OS圧迫も行わない。

構築・検証の入口は[開発手順](DEVELOPMENT.md)と[検証手順](experiments/README.md)、現在の採否は[実装状態](IMPLEMENTATION_STATUS.md)を参照する。作業はローカルに限定し、設計・実装・ログの外部送信、Gitのstage・commit・push等は個別の明示許可なしに行わない。
