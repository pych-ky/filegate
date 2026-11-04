# native watchdogの統合契約

入口と保存先は[ホスト手順](README.md)・[検証手順](../README.md)に従う。Goのhost runnerはlibprocのidentity確認にCGOを使う。`integrated_watchdog.m` はuser LaunchAgentの主processとして、QEMU・専用exchange helper・固定機能のlifeline guardianを直接の子に持つ。

## 起動と独立停止

`filegate-native-proof build` と `qualify` は固定Cの構築と、現在のOS・UID・source/binaryに対応する `launchagent_death` proofを生成する。合成VM役とhelperを使い、QEMUを起動しない。実際のLaunchAgent登録・4件のidentity・watchdog本人のSIGKILL・guardian結果・全終了・label不存在を検証する。期限内でもbrokerから子へsignalを送った試行を合格にしない。

`AbandonProcessGroup=false` だけを停止根拠にしない。nativeだけがlifeline pipeのwrite側を保持し、guardianへread側を渡す。VM/helperにはCLOEXECでwrite側を継承させない。guardian ready、資源監視、対象identity登録が済むまでQEMUをCONTしない。mainはPID=PGIDを必要とし、guardianは固定親PGID・UIDに属する対象だけを扱う。

guardianはTERM/INTでも回収を維持し、pipe EOF時に上限付きでgroupを列挙する。各PID・起動時刻・PGID・UIDをsignal直前にも照合し、TERMから2秒後にKILLへ進み、10秒以内の終了を確認する。列挙失敗時も登録済み対象を停止するが、未知の残存を終了済みにしない。通常停止ではnativeが先に停止意図をpipeへ送り、guardian以外の終了後にだけpipeを閉じる。owner限定64 KiB以下の `guardian-result.json` とguardian終了を確認して正常終了を確定する。

独立死亡proofでは、先行停止意図・計測失敗・未確認対象・緊急回収を拒否する。成功時に通常終端イベントを偽造しない。登録拒否も試験失敗であり、保護を変更した別の起動方式へ切り替えない。proofのOS・UID・source/binaryが異なれば新しいqualifyを必要とする。

## QEMUとの結合

監視付き実行は `workspace/.build/filegate-vm --fixture <固定名> --proof <proof> --out <新規出力先>` を使う。準備・起動・停止・回収を同じrunnerで行い、内部prepareや起動fdの引数を手動組立てしない。

fixtureの `prepared.json` schema 2と製品用schema 3を区別し、固定QEMU引数、canonical実体、kernel/initramfs/base/definitions、raw長・実確保量、build receiptとそのsource/artifactを照合する。native helper pinはrunner・bridge・fixture catalog・kernel・initramfs・base・selected definitions・build receiptの8件である。期待異常停止は固定catalogの理由と照合し、通常終了や製品PASSと区別する。

実QEMUの `watchdog-death` は有効な合成proofを先に要求し、新規rawを使う。helperはtransferの監視ACK後も入力を送らずworkspace relayを続け、通常exchangeを完了しない。watchdogだけをSIGKILLする直前に4件の生存identityを照合し、受信済み・未処理・永続イベントに `STOP_BEGIN`・`FINISHED` があれば拒否する。

結果は `qemu_watchdog_death` とし、`normal_completion_disabled=true`・`stop_events_observed=false`、10秒以内の独立停止、guardian結果、全identity終了、label不存在を必要とする。通常のterminalがないことを明示した死亡検証として保存し、`launchagent_death` の起動許可proofは置換しない。brokerの後始末で子を停止した試行は独立死亡の成功ではない。

## 排他・期限・資源

QEMU起動は検証領域の排他的file lockと `active-vm.json` に固定する。並行起動と、前回の終了証拠がない状態からの再取得を拒否する。全終了と一時label不存在を確認した試行だけintentを解放し、timeoutだけで解放しない。停止不明時は予約を保持し、同じ試行の正式なrecoverで回収する。

ホスト圧迫なしを30秒監視し、START_SUSPENDEDで作った子のidentityと資源を照合する。監視ready後にCONTし、初回workspaceとguest readyの確認後にだけhelperへACKする。30秒の事前観測を総期限へ含め、QEMU起動60秒は再開から計測する。全体scan300秒、broker/workspace欠落5秒、連続計測失敗、work空き・inode・I/O異常、raw長変更を独立に監視する。criticalは即時停止し、通常停止はTERMから2秒後にKILLへ進む。

`STOP_BEGIN`・`FINISHED` の同じ `resource_evidence` で、6 GiB判定sample、OS pressure flag、warning継続時間、連続計測失敗を区別する。warning/criticalでは直前の成功sampleも残す。nativeの停止指標はQEMU/helper/guardian/descendantのfootprintとresidentを合算し、大きい方を使う。通常のGo VM runnerはwatchdog自身とbroker自身を0.5秒ごとに別計測し、各peak・sample数・失敗数を残す。peakの和を同時点の総消費量と表示しない。

停止はDB・guest応答・ログ同期を待たない。nativeは実行中イベントを上限4 MiBのRAMとnonblocking IPCへ送り、全終了確認後にだけファイルへ保存・同期する。子の起動identityとMONITOR_READYはCONT前に保存するが、その後のTRANSFER_ALLOWEDなどは死亡時にディスクへ残らない場合がある。broker受信記録と共通イベントを照合し、socket上の監視有効証拠を保存済みdiskイベントだけで置き換えない。結果・consoleの未加工出力はログへ保存しない。

run管理予算64 MiBと実ディスク余白2 GiBを確保する。relayは1行64 KiB・全体1 MiB、nativeイベントは終端64 KiBを含む4 MiBまで。事前確保raw 4 GiBを二重予約しない。この管理予算を製品DB/WAL/SHM/journalの予算と混同しない。

保存済みの[native資源20件](artifacts/20261028-os272-resource-01/results.json)と合成600秒試験は当時の範囲に限る。新Go CLIに旧単独probeすべての再生成入口があるとは扱わない。製品のVM枠トランザクション・更新全工程・成果物採用・実OS再起動/sleepは、それぞれの受入証拠を別に必要とする。
