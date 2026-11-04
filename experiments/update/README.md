# 更新制御と実adapterの検証

保存先・凍結規則・新Go候補の受入状態は[検証手順](../README.md)に従う。更新制御の合成検証、NICなしVMの実adapter、通常更新と公式配信元の通信を別の証拠として扱う。

## 合成制御のE2E

```sh
"$verify" update-control --root "$workspace" \
  --out "$verification/product-checks/update-control-NEW"
```

未使用の出力先でGoの専用driverを動かす。必要なら `experiments/product/update_driver` をGoで構築する。driverの使い捨てDBへ合成した構造化報告を渡し、各操作を別processのSQLiteで読み戻す。正式な製品state DBをfixtureへ渡さない。この試験はVM・通信・定義取得・採用を行わない。

WAL・FULL・fullfsyncのreadback、COOLDOWN中の重複開始、snapshot先行commit、UUID・generation、禁止期限最大値、報告欠落時のUNKNOWN、期限後の採用拒否を確認する。active IDは `stop_confirmed` まで保持する。DB再openの成功を電源断耐性や実OS sleep・再起動の証拠としない。

実FreshClam報告の受信は `internal/update` が扱う。版・library/snapshot digest・UUID・最大禁止期限を照合し、Retry-Afterのdelta/date/fallbackをhost受信時刻から正規化する。dat保存成功や終了0、COOLDOWNのFC_SUCCESSだけで更新確認成功とはしない。旧41件・55件は[段階0ゲート](../stage0-gates.json)の当時の証拠であり、新Go構成の受入を自動継承しない。

## NICなしVMとの状態往復

固定imageと現在のnative proof、採用bindingのlibrary SHA-256を先に用意する。Go fixture helper `workspace/.build/filegate-fixture-bridge` は、scan build receiptのartifact hashとの一致を必要とする。

```sh
"$verify" update-fixture --root "$workspace" --vm-workspace "$workspace" \
  --proof "$proof" --library-sha256 "$library_sha256" --case bridge \
  --out "$verification/product-checks/update-fixture-NEW"
```

`bridge` は実adapterの429-deltaに対し、初回通信前のhost同期commit、報告の永続化、COOLDOWNと追加要求なし、UUID・snapshotの維持を確認する。公式配信元や定義採用の試験ではない。ほかに `preparation-cancel`・`driver-death`・`deadline`・`invalid-final` を個別に選ぶ。600秒の制御期限は予約から計測し、scan VMの300秒と区別する。試験都合で待機期限を短縮しない。

旧手動bridgeのfirst/restore・事後guest取込みの操作CLIは提供しない。現在の `bridge` を、旧9ケースすべてのhost往復と同一範囲とは扱わない。ゲストの `freshclam-adapter` は実C libraryの9ケースと新processへのsnapshot復元を確認するが、hostの別VM復元や採用排他とは区別する。保存した報告の再生だけで、初回通信前のcommitや実VMの要求0件を実証したことにしない。

## 通常更新との境界

新しいGo更新imageは `filegate-dev build-update` で別出力先に構築する。schema 2 manifest、host runner、scan producer receiptと全source/artifactを固定し、既存登録imageへ反映しない。登録・切替の条件は[開発手順](../../DEVELOPMENT.md)と[実装状態](../../IMPLEMENTATION_STATUS.md)に従う。

製品の `update-normal`・`update-network`・`update-retention` は別suiteである。実VMの停止・回収・予約、公式配信元、定義の署名・真正性・鮮度、600秒の更新全工程と採用排他を、それぞれ対応する証拠で確認する。fixtureの時計や前回boot入力を実OSの再起動・sleepへ読み替えない。

adapter報告の `final` は同期API呼出し終了で、VM/helper終了やhost採用成功ではない。制御snapshot 4 KiB・入出力1 MiB、停止不明時のUNKNOWN・予約保持を維持する。失敗試行を保存したまま正式に回収し、結果を書き換えて受入を進めない。
