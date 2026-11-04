# 実装・検証の状態

## Go移行と受入範囲

製品・VMの起動/監視/回収・通常更新・ビルド・検証の実行経路をGoへ移行し、採用構成について段階0→1→2→3の順に受け入れた。固定AV library、FreshClamの小さいC ABI層、独立native C/Objective-C監視は維持する。旧Python143ファイル・pyc1ファイル・退役launcherを外部保存し、リポジトリ内のPythonは0件、有効な実行経路のPython依存も0件になった。最終配置版の `stage0_passed`・`stage3_completed` はtrueで、製品自身の実PASS・原本取り出し・通常のbroker再起動後の状態を確認した。

最終host・runner・source・scan/update image・登録・proofのhashと受入条件は、検証領域 `product-checks/go-migration-current/completion-current-20261104.json` に記録している。個別試験の成功、旧構成の受入、prestage3版の配置だけでは完了としない。

初期対象はパスワードなしのZIP、上限250 MiBで、未対応形式はHOLDにする。対応する形式・AVの必須チェックを終え、鮮度と停止・回収を確認した原本だけがPASSと取り出しの対象になる。Go移行後もUUID・禁止期限・採用済み定義・原本・履歴を維持した。HTTP 304による再確認と新しい定義内容の取得は区別する。

起動は `~/Library/Application Support/FileGate/application/FileGate.command`、取り出し先は `~/Library/Application Support/FileGate/Outbox`。[開発手順](DEVELOPMENT.md)にCLI/API/MCP・loopback UI、[継続指示](HANDOFF.md)に変更・回収時の制約をまとめる。

## 今回の証拠と保存済み証拠

検証結果・固定source・入力・構築物は `~/Library/Application Support/FileGate/verification` に保存し、今回のGo移行は `product-checks/go-migration-current/python-free-go-20261104` に集約する。段階0の採択は `stage0-adoption-go-10.json`、Go登録とprestage3版の通常切替は `cutover-prestage3-01-0.json`・`cutover-prestage3-01-1.json` に残す。後者の `stage3_completed=false` は当時のまま保持する。

新Goによる実VM、形式の各ケース、AV各suite、FreshClam、独立死亡回収、更新・受付・保持・復旧等は、それぞれの入力・期待値・実値・source/image hashへ結び付ける。最終配置後の通常再検査による真正なPASS、同じSHA/sizeの原本の取り出し、通常の起動し直しと保存状態の確認も、最終host自身の証拠として保存した。実動作は同領域の `delivery-accepted-metadata-01`・`delivery-accepted-available-01`・`delivery-accepted-rescan-01`・`delivery-accepted-release-01`・`delivery-accepted-reopen-01` の各 `results.json` に対応し、最後の記録で `delivery_complete=true` を確認した。

旧OSイベント、固定C libraryの構築、ソース分類・有限実測は、変更のない処理との対応と適用範囲を明示して使う。合成時計・前回boot入力を実OS再起動/sleepに、診断出力を通常AV結果に、source推定を実測に読み替えない。新しい公式定義との実競合や物理媒体故障を発生させていない証拠から、その成功を主張しない。

過去の不合格は不合格のまま保持し、後続補完の成功範囲を分ける。旧凍結source・image・native proof・採択証拠と、今回退避したPython原本を上書きしない。旧中央文書の全文とhashは `python-free-go-20261104/final-central-doc-drafts/original-docs.tar.gz` に保存している。

## 保証の境界

FileGateの独立した形式・容量・読取り/書込み/同期・対象identity/hash/size確認は必須である。通常エラー・警告・制限・暗号化・不明・未完了・timeout・取消はHOLD、検出はBLOCKに正規化し、確定済みBLOCKを保持する。定義の署名・真正性・版・鮮度、更新禁止期間・UNKNOWN、固定容量と独立監視を省略しない。

採択済みのbest effortは、PDF local-recursion、PESpin/PE allocation、LZW/signed-CVD internal-dependency classification、ELF/Mach-O internal analysis、AUTOIT/ISHIELD_MSI association classificationの5内部範囲に限る。独立した完了確認は未実証であり、通知なく内部処理が止まった場合、その停止を検出する保証はない。観測不能を立証した範囲や全入力の絶対保証にはしない。拒否されたPDF再帰・PESpin/PE allocationの追加調査・境界入力作成は再試行しない。

対象OS・native・source・image・libraryの変更には影響する再実証を必要とする。旧全ClamAV factory、大容量境界入力のGo再生成、歴史的な単独probeのすべてを新CLIで提供したという意味ではない。再利用できる固定資産と未提供の操作は[検証手順](experiments/README.md)および各コンポーネントのREADMEに記載する。
