# 実装・検証の状態

## Go移行と受入範囲

製品・VMの起動/監視/回収・通常更新・ビルド・検証の実行経路をGoへ移行した。固定AV library、FreshClamの小さいC ABI層、独立native C/Objective-C監視は維持する。当時の移行文書では旧Python143ファイル・pyc1ファイル・退役launcherを外部保存したとされ、リポジトリ内のPythonは0件、有効な実行経路のPython依存も0件になった。正式に配置したC10構成の `stage0_passed`・`stage3_completed` trueと、製品自身の実PASS・原本取り出し・通常のbroker再起動後の状態確認は、その構成だけの当時の記録であり、今のソースへは自動で引き継がない。

C10のhost・runner・source・scan/update image・登録・proofのhashと受入条件は、検証領域 `product-checks/go-migration-current/completion-current-20261104.json` に記録したとされるが、このファイルは2026-11-09の時点で記載の場所に見つからない。個別試験の成功、旧構成の受入、prestage3版の配置だけでは完了としない。

初期対象はパスワードなしのZIP、上限250 MiBで、未対応形式はHOLDにする。対応する形式・AVの必須チェックを終え、鮮度と停止・回収を確認した原本だけがPASSと取り出しの対象になる。Go移行後もUUID・禁止期限・採用済み定義・原本・履歴を維持した。HTTP 304による再確認と新しい定義内容の取得は区別する。

起動は `~/Library/Application Support/FileGate/application/FileGate.command`、取り出し先は `~/Library/Application Support/FileGate/Outbox`。[開発手順](DEVELOPMENT.md)にCLI/API/MCP・loopback UI、[継続指示](HANDOFF.md)に変更・回収時の制約をまとめる。

## 今回の証拠と保存済み証拠

検証結果・固定source・入力・構築物の保存先は `~/Library/Application Support/FileGate/verification` である。旧Go移行の文書では `product-checks/go-migration-current/python-free-go-20261104` に記録を集約し、段階0の採択を `stage0-adoption-go-10.json`、Go登録とprestage3版の通常切替を `cutover-prestage3-01-0.json`・`cutover-prestage3-01-1.json` に記録したとされる。後者の `stage3_completed=false` は当時の記録である。

新Goによる実VM、形式の各ケース、AV各suite、FreshClam、独立死亡回収、更新・受付・保持・復旧等は、それぞれの入力・期待値・実値・source/image hashへ結び付ける。最終配置後の通常再検査による真正なPASS、同じSHA/sizeの原本の取り出し、通常の起動し直しと保存状態の確認も、最終host自身の証拠として保存した。実動作は同領域の `delivery-accepted-metadata-01`・`delivery-accepted-available-01`・`delivery-accepted-rescan-01`・`delivery-accepted-release-01`・`delivery-accepted-reopen-01` の各 `results.json` に対応し、最後の記録で `delivery_complete=true` を確認した。この節が挙げる `stage0-adoption-go-10.json`、`cutover-prestage3-01-*.json`、`delivery-accepted-*` の `results.json`、`original-docs.tar.gz` も2026-11-09の時点で記載の場所に見つからず、当時の文書の主張として扱う。

旧OSイベント、固定C libraryの構築、ソース分類・有限実測は、変更のない処理との対応と適用範囲を明示して使う。合成時計・前回boot入力を実OS再起動/sleepに、診断出力を通常AV結果に、source推定を実測に読み替えない。新しい公式定義との実競合や物理媒体故障を発生させていない証拠から、その成功を主張しない。

過去の不合格は不合格のまま保持し、後続補完の成功範囲を分ける。現存する旧凍結source・image・native proof・採択証拠・Python原本を上書きしない。旧中央文書の全文とhashも `python-free-go-20261104/final-central-doc-drafts/original-docs.tar.gz` に保存したとされるが、2026-11-12の探索でも見つからなかった。

## 今のソースの有限の検証

今の作業ツリーの `Stage0Passed`・`Stage3Completed` はtrueである。通常host自身のPASS・取り出し・通常再起動後の保存状態は、`final-normal-host-20261112-02` に記録した当時の構成で確認した。定数だけを受入の根拠にせず、`product-checks/formal-acceptance-candidate-20261108-01/stage0-verification-acceptance.v1.md` に記録した隔離構成の段階0受入、C6bの採用、D4の当時の有限な受入を、それぞれのsource/hashと証拠の範囲で扱う。この旧runtimeの最終受入は `product-checks/remaining-completion-20261112-01/coordinator-final-acceptance.json`、部品・binary・receiptのpath/hashと証拠の再利用範囲は `product-checks/current-evidence-index-20261109-01/evidence-index.v17.json` で確認する。v16は当時の対応表として保持する。

- 旧正式版C10: 旧版のファイルと登録の履歴を保持している。旧受入はこの構成だけに当てはまる。
- 旧受入版D4: broker `0438915e…` と、そのSHAを固定したinstaller `cab55528…`。C32とC29は凍結したまま使う。旧監視ソース `supervisor.py` の保管計上を64 KiBの上限付きで許可し、前bootの定義cacheを論理整合の検査後に「再利用しない」として通常の全量更新へ進め、出力先を同ID/pathで明示的に再登録する操作を追加した。UUID・禁止期限・原本・旧版・取り出し履歴を保持した。D3で通常の定義更新と真正PASS、D4自身で真正PASS・2,888バイトの同じSHAの取り出し・通常の再起動後の保存状態を確かめた。保存記録の照合では誤った登録SHAと別pathの拒否、旧取り出し5表の不変、再起動後の新登録の保持も確認した。原記録の最後の再起動判定は派生値の経過秒まで比較してfalseになった。原記録を残し、保存項目の一致を再計算した補正記録と独立確認で受け入れた。記録は `product-checks/formal-repair-20261111-03` にある。先行するD〜D3の停止・保留は元の記録のまま保持する。
- 採用の基にした通常候補: overlayなしで構築したC6bのbroker `5cd91a68…`、C32のscan、変更のないC29の更新。合成5件の実VM/AVのPASS、同じSHA/sizeの1回の取り出しと、検査・取り出し後の同じbrokerの待機メモリを確かめた。UIの一覧は1ページ20件に変え、履歴は既存の前後のページ送りでたどる。API・CLI・MCPの上限100件は変えていない。3秒ごとに送ったCLIの一覧（20件）は、brokerのCPUが1回29〜30.5ミリ秒だった。XMLの修正だけが違う参考の候補は、同じ時間に27.5〜28ミリ秒、別の時間に15.5〜16.5ミリ秒で、端末の状態による揺れが大きい。記録は `product-checks/ui-idle-performance-repair-20261109-01/candidate-6b` にある。統括はR5の証拠とあわせてC6bの処理を技術的に受け入れた。C6b自体は段階3がfalseで、正式には配置していない。
- 旧通常候補: `08df5fff…`。新しい私用stateで公式更新、実VM/AVのPASS、同じSHA/sizeの1回の取り出しを確かめた。通常のinstallerで隔離したステージング先にだけ置いた（段階3はfalse）。
- 試験専用: 停止hookを外部で加えた `c0cd3242…` などのbroker。取り出し契約の異常系の確認だけに使い、本番の候補にしない。CPUプロファイルを取る `42f0f279…` も診断だけに使い、候補にしない。

通常host `1ff6e200…` をinstaller `3cfb05d4…` で配置し、C32/C29を使った当時の構成ではhost自身の4 AV入力が正常完了してPASSとなり、2,888バイトの同じSHA/sizeの原本取り出しと通常再起動後の保存状態を28照合で確認した。UUID・snapshot・禁止期限・採用済み定義を保持し、両brokerは正常終了、未精算は0だった。7日を超えた既知の合成原本50バイト1件は外部退避後に通常期限削除されたため、全原本不変とは扱わない。記録は `product-checks/final-normal-host-20261112-02` にある。

先行候補 `ce8bc25b…` の更新は `RESOURCE_MONITOR_FAILED` で停止し、失敗原本と旧採用定義・禁止期限を保持した。当時の対象PIDと失敗した個別APIは原記録から特定できず、その失敗原因は未確定である。更新側に追加したnative結果による採用拒否は、6群12入力のcomponent試験（02の10入力と03のG1補完2入力）で有限に確認した。この時点のfixture skipはソース対応、完成image後の監視失敗は既存証拠との合成であり、動的なフル更新試験には数えない。記録は `product-checks/update-native-outcome-component-20261112-03/effective-result.json` にあり、先行失敗は保持した。後続のfixture skipと統合試験の実経路確認は次節に記す。

子孫の列挙中に、終了して未回収の子を生存中のgroup確認へ渡して誤判定する経路を、新規・追跡済みの両方で再現して修正した。identity不一致・計測不能・生存中のgroup不一致は引き続き拒否する。修正ソースは6組のAPI比較、native `7c5f446e…` はwatchdog死亡と4種の合成資源異常、実QEMUでのwatchdog死亡で有限に確認した。scanはN3の現行Go source、更新runtimeはC29のGo sourceとゲスト入力を保った別workspaceでnative sourceだけを変更した。固定adapterの構築原本不足で止まった先行フル構築は、失敗のまま保持した。

既存の私用stateでは同UUIDの通常更新がgeneration 2→3へ採用され、正式stateでは鮮度を操作せずgeneration 5の採用済み定義を保持した。正式stateで新しい更新は行っていない。両方で真正な4 AV入力のPASS、2,888バイトの同じSHA/sizeの取り出し、通常broker再起動後の状態保持を確認した。私用は62照合、正式は58照合が合格し、旧取り出し行・履歴・原本retentionを保護した。記録は `product-checks/native-measurement-fix-20261112-01/iteration-02`、受入と再利用範囲は同所の `final-acceptance.json` と `product-checks/current-evidence-index-20261109-01/evidence-index.v18.json` で確認する。

閉じた主張を全suiteの再実行で確かめ直さない。`retention`、`update-retention`、`idle`、`privacy`・`privacy-api` は、各記録に固定した製品ソースと構成の閉じたgateで合格した。`retention` の1回目は検証側の不備で止まり、`vm_retention.go` を直した2回目で合格した。`idle` は自分が起動したbrokerとMCPの2つだけを測り、待機時にVM・AV・専用watchdogが動いていないことは示さない。これは通常経路とnativeの回収の証拠で別に扱う。

性能確認の条件のうち、4種のZIP（小さい文書・約50 MiB・入力上限付近・9,500件のファイル）と、初回・定義の採用後・フル更新ありの検査は、旧通常候補 `08df5fff…` で1回ずつ測った。9,500件のZIPは、AVの1対象あたりの検査時間の上限120秒を元のZIPが超えてHOLDになった。これは運用上の上限で、変えない。件数の安全上限は、PASSの処理量を保証しない。資源と残留は、FileGateが所有するプロセス群の測定で確かめ、端末全体の値は条件にしない。AVと形式の段階の時間は、含む処理の上限として扱う。UIが見えている600秒の待機は、第3候補 `0ca0cba5…` でCPUが1.40%となり、1%未満の目標を満たさなかった。C4では有効な可視600秒の窓が取れず、見えていた区間だけのCPUは1.25〜1.36%だった。C6bではUIを表示した600秒の待機で、自分が起動したbrokerとMCPのCPUが1コアの0.92%、RSSの最大が54 MiBとなり、目標を満たした。ページの側は読み取り専用のDOMの確認点178点で表示・1ページ目・20件を確かめたが、68秒の間は観測できておらず、600秒すべてを表示し続けた証明ではない。20件のページ送り、ページ外の詳細と履歴の保持は、既存のEdgeを画面操作して確かめた。記録は `candidate-6b` の `runs-ui-5` と `runs-ui` にある。作業領域の内訳は、計測専用の候補（本番には選ばない）で入力上限付近のZIPを1回測り、rootの差分とAVの一時ファイルの、標本で測った最大を分けて得た。通常の差分更新は、C6bで2026-11-10に1回観測した。検査を1件送ると通常の更新が走り、dailyは基準の `daily.cvd` から内容の違う `daily.cld` に替わって採用され、mainとbytecodeはHTTP 304、その検査はPASSになった。CDIFFのURL・件数・転送量は測っていない。記録は `product-checks/normal-delta-20261110-01` にある。UIを表示したときのブラウザの増分は、同じ既存のEdgeでUIを閉じる・開く・閉じるの順に、各区間を30秒以上測った。Edge全体のCPUは、開いた区間で1コアの3.41%、閉じた区間で0.11〜0.14%だった。開いた区間との差はCPUが3.28〜3.30ポイント、RSSの合計が195〜221 MBである。閉じた区間どうしの差は、CPUが0.03ポイント、RSSが25 MBだった。同じEdgeのほかのタブや裏の処理を含み、RSSの合計は共有のページを重ねて数え、ページを開くときの山は測っていない。数値の合格基準は置いていない。記録は `candidate-6b/runs-browser-1` にあり、区間の境界を直した値は同じ場所の `coordinator-browser-audit.json` にある。単独の段階の時間は測っておらず、含む処理の上限として扱う。統括はこれらの限界を記録したうえで、R5の性能確認を技術的に受け入れた。形式とコーパスでは必須の性質を任意にせず、同じ拒否の判定と代表の事例で確かめる。実OSの再起動・時計・sleep・電源断は合成の場面と分け、行ったことにしない。新しい通常hostを正式に選んだときは、[開発手順](DEVELOPMENT.md)の配置と結び付けで、合成のPASS、同じSHA/sizeの取り出し、通常の起動し直しと保存状態をそのhostで確かめる。

## 今回の対応と限界

2026-11-13の有限な追加試験は、本人が延期した実OSのスリープ・再起動を除いて完了した。結果と証拠の再利用範囲は `product-checks/non-os-resume-20261113-01/aggregate-status.final.json` に集約した。先行の `non-os-test-completion-20261113-01/final-status.json` は当時の未完記録として保持する。既存の成功・失敗・受入記録は書き換えず、顧客資料を扱う運用は採用構成の段階3受入後に限る。

- 更新の期限・禁止期間は、既存76件との対応に加え、合成時計12件と、実ゲスト時計を前後10日ずらす6条件・計12回のVMで確認した。後者の1条件は固定ABIによる待機期限の保守的な変換と照合して試験のSHA期待を補正し、元のnative不合格を保持した。6条件すべてで通常native完了したとは扱わない。実Macでは本人の標準操作による前進・復帰をJ3、後退・復帰と元の600秒期限でのtimeoutをJ4で確認した。J3全体の失敗は保持し、別試行で得た性質を対応させたもので、1回の4操作完了とは扱わない。管理権限による自動操作のdenyも保持する。実OSのスリープ・再起動は2026-11-16〜17の実測と同じ中断試行の復旧で確認した。電源断は未実施の耐久性上の限界として残し、合成時計や実ゲスト時計をこれらの実証に読み替えない。
- 第13章の停止点・中止・精算は、既存の共通処理と後続28採用ケースへ対応させた。記録は `product-checks/remaining-release-matrix-20261112-01/effective-cases-result.json` にある。追加試験では、取り出しのコピー中に再検査し、明示的なAbortを先に送らず再開しても `REVALIDATION_REQUIRED` となり、公開されないことを確認した。更新中でも現在の定義が有効なら取り出しは許可され、実際にCOMMITTEDとなった。拒否を期待した試験側の誤りは保持し、その後の通常更新で、取り出し公開が先の順序と定義採用が先の順序を同じAV bindingの条件で確認した。原本のSHA/sizeと同一キー再送を保った有限の2順序であり、全競合順序の保証ではない。S03の所有不明残存も保持する。同じ正常原本が後日の公式定義でBLOCKへ変わった後の中止は、既存のBLOCK保持・非PASS拒否・中止の証拠と共通ソースによる有限な対応に限り、統合実行していない。旧取り出し5件の照合と通常timerの保持・削除も確認したが、後者は合成年齢の私用stateに限る。
- 管理側の書込み予算は、既存の有限証拠に加え、新しい試験専用DBでSHM上限と実SQLiteコミット失敗の4条件・100照合を確認した。削除intentのコミット失敗では原本を削除せず、削除後の終端コミット失敗では永続intentから通常回収して精算した。後者を原本保持とは扱わない。`state-compact` のjournal見積りが固定128 MiBを超える場合の拒否も通常CLIで確認済みである。全書き手の普遍的な割当上限を実証したとは扱わない。
- 実HTTP/2通信の5条件で、再送・競合・処理中・容量拒否・取消時にサーバーが要求本文を読まないことを42照合で確認した。実 `av.Run` では正常なscanner対照1件と、制御した子プロセスの異常応答9件を確認した。異常応答を実ClamAV内部で発生させた証拠にはしない。OOXMLは正常なDOCX/XLSXと、field begin欠落・名前定義を経由する外部URLの2拒否条件を実 `Inspect` で確認した。fixture skipも現行の `finishRuntime` を通る実VM経路で、fixture条件ではnative失敗による通常採用拒否へ入らないことを確認した。
- 旧段階0台帳 `experiments/stage0-gates.json` は2026-11-12にも107参照中104参照が存在せず、旧台帳の状態だけでは現在の完了を示せない。現在の必須性質は現存する受入根拠と共通ソースへ対応させた。同日、旧 `completion-current-20261104.json`、`stage0-adoption-go-10.json`、`original-docs.tar.gz`、`python-before-removal.tar.gz`・`python-removal-receipt.json` も記載先に見つからなかった。旧原本を復元可能と断定せず、所在を確認できないものは当時の文書の主張として扱う。旧保存物を探す作業は本人判断で見送った。

私用stateのgeneration 4 UNKNOWNは、元の失敗試行・UUID・旧採用定義・禁止期限・履歴を保つ限定的な管理復旧で回復した。完成した実Final・定義imageの後にwatchdogを異常終了させた更新では新しい定義を採用せず、停止済み4 identityの集合を受け取るStoreとの不整合を修正した。原Final・証拠を用いた同じ試行の通常回復で、停止・回収・予約0を確認した。元の試行と回復の証拠を対応させた有限の受入であり、各失敗原本は保持する。その後、制御generation 7・旧採用定義generation 6を保って通常登録へ戻し、broker `8e69dd55…` とinstaller `a38d8b83…` の通常配置、host自身の真正な4 AV入力のPASS・取り出し可能判定、2,888バイトの同じSHA/sizeの原本取り出し、通常broker再起動後の保持を確認した。正式stateのgeneration 5 READYの制御行、launcher・両通常登録・v18と旧通常版を保持している。

2026-11-16〜17に実Macのスリープ・再起動を確認した。スリープはnative `7c5f446e…` と無害な子プロセスを使い、実行前に固定した180秒の試験期限を197秒の実スリープで跨いだ。約195.685秒の監視記録の空白をOS記録と照合し、復帰時の期限切れによる停止開始と、約2.249秒での停止・回収を確認した。製品の更新期限600秒は変えず、実QEMUで600秒の期限をスリープ中に跨いだ試験とは扱わない。同じ試験用UUID・世代・snapshotを保ち、スリープ中を含む経過時間だけ待機が減ることも確認した。

NICなしの実QEMU更新fixtureの途中の再起動では、`producer.lock` と共有VM枠の `active-vm.json` のdevice番号が変わり、同じ試行の回収を拒否する不具合を修正した。前のOS起動世代の停止証明が成立する回収に限り、同じ試行・inode・要求と資源の結び付け、現在の所有者と開いたfd・pathを照合して、この2ファイルの過去のdevice番号との差を許容する。残存する一時ディレクトリのdevice/inode照合と、同じOS起動世代での厳密な比較は変えていない。元の試行を新しい定義の採用なしで停止・回収し、予約0を確認した。補助的な合成E2Eは正常1条件と拒否7条件・77照合で合格した。実OSの受入は `product-checks/os-events-real-20261116-01/os-acceptance-20261117.json`、修正と補助試験は `product-checks/reboot-device-remount-fix-20261116-01` に保存した。先行する製品・試験側の不合格は書き換えていない。

2026-11-17の通常host `ea84501d…` とinstaller `44b767e8…` では、同じ私用UUIDの通常更新で制御generationを7から8へ進め、新しいgeneration 8の定義を採用し、真正な4 AV入力のPASS、2,888バイトの同じSHA/sizeの原本取り出し、通常broker再起動後の保持を確認した。元の75照合と独立40照合が合格し、旧原本・取り出し・更新履歴を保ち、更新後の禁止期限も通常どおり保存した。標準launcherのscan参照と正式データの更新登録も新構成へ切り替えた。正式データでも新構成で通常起動し、出力先2件を同じID/pathのままdeviceだけ再登録した。制御状態の時計記録を現在のOS起動世代へ更新し、制御と採用済み定義のgeneration 5、UUID・snapshot・既知期限・履歴・原本を保持した。正式データで新しい更新・検査は行っていない。現在の構成と有限な受入は `product-checks/os-events-real-20261116-01/final-completion-20261117.json`、私用の原記録と独立監査は `product-checks/normal-remount-acceptance-20261117-01/execution-03` で確認する。

OOXML契約 `experiments/contracts/ooxml-v1.json` のzip欄には旧ZIP32 Profile 1の参照が残るが、実装と採択済み仕様は共通のZIP32 Profile 2を適用する。凍結済み契約のdigestを変えず、この説明上の不一致を記録する。

## 保証の境界

FileGateの独立した形式・容量・読取り/書込み/同期・対象identity/hash/size確認は必須である。通常エラー・警告・制限・暗号化・不明・未完了・timeout・取消はHOLD、検出はBLOCKに正規化し、確定済みBLOCKを保持する。定義の署名・真正性・版・鮮度、更新禁止期間・UNKNOWN、固定容量と独立監視を省略しない。

採択済みのbest effortは、PDF local-recursion、PESpin/PE allocation、LZW/signed-CVD internal-dependency classification、ELF/Mach-O internal analysis、AUTOIT/ISHIELD_MSI association classificationの5内部範囲に限る。独立した完了確認は未実証であり、通知なく内部処理が止まった場合、その停止を検出する保証はない。観測不能を立証した範囲や全入力の絶対保証にはしない。拒否されたPDF再帰・PESpin/PE allocationの追加調査・境界入力作成は再試行しない。

対象OS・native・source・image・libraryの変更には影響する再実証を必要とする。旧全ClamAV factory、大容量境界入力のGo再生成、歴史的な単独probeのすべてを新CLIで提供したという意味ではない。Word・Excelの実アプリ出力は追加互換性の確認であり、必須受入条件には数えない。`product-checks/remaining-office-20261112-04` の両入力は `ARCHIVE_PROFILE_UNSUPPORTED` でHOLDとなり、PASS互換性は確認していない。再利用できる固定資産と未提供の操作は[検証手順](experiments/README.md)および各コンポーネントのREADMEに記載する。
