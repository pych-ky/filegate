# ホスト監視とnative proof

保存先・凍結規則・新Go候補の受入状態は[検証手順](../README.md)に従う。`integrated_watchdog.m` をuser LaunchAgentで動かし、QEMU・exchange helper・guardianを監視する。起動条件、資源上限、停止証拠、VM枠は[統合契約](INTEGRATION.md)を参照する。

## Goによる構築と死亡回収試験

新しいOS/native用proofの生成は `filegate-native-proof` を使う。固定CソースをApple clang/Foundationで構築し、一時LaunchAgent上のwatchdog本人だけを強制終了する。出力先には未使用の名前を指定する。

```sh
cd "$workspace"
CGO_ENABLED=1 go build -trimpath -o "$verification/tools/filegate-native-proof" ./cmd/filegate-native-proof
native_proof="$verification/tools/filegate-native-proof"
native_build="$verification/product-checks/native-build-NEW"
"$native_proof" build --repo "$workspace" --out "$native_build"
"$native_proof" qualify --repo "$workspace" --native-build "$native_build" \
  --out "$verification/product-checks/native-proof-NEW"
```

qualifyは通常VMと同じ排他枠・所有intentを使うが、QEMUとrawは作らない。固定のVM代替・helper・guardianとwatchdogのPID・起動時刻・UID・PGIDを照合し、guardianによる独立停止、10秒以内の全終了、一時label不存在を確認する。brokerによる子へのsignal、緊急回収、計測不能があれば合格にしない。監視や起動保護を省略する実行方法へ切り替えない。

失敗試行の回収は同じboot・source・binary・identityと元の出力先で `recover` を使う。回収成功は失敗したproofを合格に変えない。OS再起動などで前提が変わった場合に、保存intentを手動削除して進めない。

Goの構築・qualify入口は `product-checks/go-migration-current/python-free-go-20261104/native-monitor-build-01/build.json` と同じ領域の `native-launchagent-proof-01/results.json` で実行済みである。後者は独立停止2.144543250秒、全子終了・guardian・label不存在を確認した合成死亡proofで、実QEMUの試験とは別である。既存proofの再利用にはOS・UID・native source/binaryの完全一致を必要とし、Go CLIができたことだけで別nativeへ継承しない。

実QEMUを伴う死亡回収は[VM手順](../vm/README.md)の `watchdog-death` で確認する。LaunchAgentの合成proofを起動条件に使い、入力を送らずworkspace relayを継続した状態で独立停止を検証する。

## 保存済み証拠の範囲

現OSの[native資源20件](artifacts/20261028-os272-resource-01/results.json)は、合成メモリ値・pressure通知・計測失敗を注入した歴史的証拠である。新Go CLIに同じ20件を再生成する単独入口は提供していない。実OS圧迫、6 GiB割当、PID再利用の証拠にはしない。[600秒試験](../contracts/artifacts/20261028-os272-deadline-01/results.json)も合成VM/helperの期限・停止の証拠で、製品更新全工程やOS再起動・sleepの受入とは区別する。

終了確認が不完全なら `active-vm.json` と容量予約を保持して新規VMを拒否する。対象identity、プロセスとfdの終了、一時label不存在、raw回収を照合する。保存済み失敗を解決済みと記しただけで、現在の終了・回収確認を省略しない。

一次資料は採用SDKの `libproc.h`・`sys/resource.h`・`mach/mach_time.h` と、[Apple libproc](https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/libproc/libproc.h)、[continuous clock](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/mach_time.h)、[Dispatch pressure](https://developer.apple.com/documentation/dispatch/dispatch_source_memorypressure_flags_t)、[launchd.plist](https://github.com/apple-oss-distributions/launchd/blob/main/man/launchd.plist.5)。公開文書を対象OSの未実施試験の代わりにしない。
