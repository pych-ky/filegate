# FileGateの継続指示

## 採用構成と保存先

Pythonに依存していた製品・VM起動/監視/回収・更新・ビルド・検証をGoへ移行した。固定AV library、FreshClamの小さいC ABI層とnative C/Objective-C監視は保持する。当時の移行文書では旧Python143ファイル・pyc1ファイル・退役launcherを原本hashの照合後に外部保存したとされる。管理ソースと有効な実行経路から除き、リポジトリ内のPythonは0件になった。正式に配置したC10構成のstage0/3 trueと、実PASS・原本取り出し・通常のbroker再起動後の状態確認は、その構成だけの当時の記録である。今のソースへは自動で引き継がない。

起動は `~/Library/Application Support/FileGate/application/FileGate.command`、取り出し先は `~/Library/Application Support/FileGate/Outbox`。正式データは同じ `FileGate/fg-final/data` を使い、UUID・禁止期限・採用済み定義・原本・履歴を初期化しない。既存キーの再送は元の受付に固定し、内容を変える場合は新しいキーを使う。

旧Go移行の記録は `~/Library/Application Support/FileGate/verification/product-checks/go-migration-current/python-free-go-20261104` 配下として案内されていた。旧保存物の所在と設計第14章の対応結果は[実装状態の対応と限界](IMPLEMENTATION_STATUS.md#今回の対応と限界)を参照する。失敗結果を成功へ書き換えない。

旧受入版D4はbroker `0438915e…` で、scanのC32と更新のC29を凍結した構成だった。採用の基にした通常候補C6b `5cd91a68…` の閉じた証拠は、変更のない処理の範囲で保持する。2026-11-11の正式な切り替えと実機確認で見つかった、旧監視ソースの保管計上と前bootの更新cacheの問題を修正し、出力先の明示的な再登録を追加した。通常のinstallerで配置したD4自身で合成ZIPの実VM/AVのPASS、同じSHA/sizeの原本の取り出し、通常の再起動後の保存状態を確かめ、既存の限定契約の範囲で受け入れた。当時の記録は `product-checks/formal-repair-20261111-03`、切り替えと先行試行は `product-checks/formal-cutover-20261110-01` と `formal-repair-20261111-01`・`02` にある。失敗した原記録は保持している。

現在の通常hostはbroker `ea84501d…`、installer `44b767e8…` である。scanは `go-reboot-device-remount-fixed-20261117-02`、更新runtimeはC29のGo sourceとゲスト入力を保ち、再起動後の回収修正4ファイルを加えた `go-reboot-device-remount-update-20261117-03` を使う。私用・正式データの更新登録は `61bb92b6…`、nativeは `7c5f446e…`、proofは `native-measurement-fix-20261112-01/iteration-02/native-qualify/results.json` に固定した。採用範囲と限界は[実装状態](IMPLEMENTATION_STATUS.md)、今回の受入と証拠の再利用範囲は `product-checks/os-events-real-20261116-01/final-completion-20261117.json` で確認する。`product-checks/current-evidence-index-20261109-01/evidence-index.v18.json` と `product-checks/native-measurement-fix-20261112-01/iteration-02/final-acceptance.json` は当時の構成の受入として保持する。

先行候補 `ce8bc25b…` の更新はnative計測失敗で停止し、失敗原本を保持した。当時の対象PIDと失敗した個別APIは原記録から特定できず、その失敗原因は未確定である。

2026-11-13の有限な追加試験に続き、2026-11-16〜17に実Macのスリープ・再起動と同じ中断試行の復旧を確認した。2026-11-13の結果は `product-checks/non-os-resume-20261113-01/aggregate-status.final.json`、現在の構成との対応と限定は `product-checks/os-events-real-20261116-01/final-completion-20261117.json` を参照する。実Mac時計、実定義採用と取り出し公開の両順序、完成image後のnative失敗と同じ試行の回復を、それぞれの実測と証拠の範囲で扱う。先行の `non-os-test-completion-20261113-01/final-status.json` と各失敗原本は当時の記録として保持し、失敗を成功へ書き換えない。

2026-11-13の検証では、私用 `pf1109/data` のgeneration 4 UNKNOWNは、元のUUID・禁止期限・失敗履歴を保つ限定的な管理復旧で回復した。その後の実更新でgeneration 6を採用し、完成image後にwatchdogを異常終了させた更新では新しい定義を採用せず、同じ試行の通常回復で停止・回収・予約0を確認した。Finalを反映した制御generation 7と旧採用定義generation 6を保持したまま通常登録 `e986fa87…` へ戻し、新しい通常host自身の真正な4 AV入力のPASS・取り出し可能判定、2,888バイトの同じSHA/sizeの原本取り出しと通常broker再起動後の保持を確認した。正式stateのgeneration 5 READYの制御行は不変である。UUID・禁止期限の初期化、別UUID・正式stateへの代替、Finalの捏造や無条件解除で進めない。

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
