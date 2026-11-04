# 隔離VMの構築と検証

保存先・凍結規則・新Go候補の受入状態は[検証手順](../README.md)に従う。ここでは合成・無害なバイト列だけを扱う。`NOT_A_PRODUCT_SCAN` は製品のPASSではない。

## 新しいimageの構築

`filegate-dev build-scan` は固定baselineを読み取り、新規workspaceにGo runner、直接起動用initramfs、読取り専用base/definitionsを構築する。既存imageを上書きしない。Go 1.27.3、QEMU 11.1.2、e2fsprogs 1.47.4を照合する。Darwinホストrunnerはlibprocのidentity確認にCGOを使う。通常のLinux/arm64 v8.0ゲストGoはCGO無効で、FreshClamのGo/C ABI adapterは固定musl環境で別に構築する。

先に[FreshClam adapter](../av/fixed_adapter_builder/README.md)を構築する。`baseline`・`baseline_proof`・`proof` には、構築記録で指定した固定baselineと、その構成・現在のnativeに対応するproofの絶対パスを指定する。任意の古い成功結果で代用しない。

```sh
"$dev" --repo "$workspace" build-scan \
  --verification "$verification" --baseline "$baseline" \
  --baseline-proof "$baseline_proof" --native-proof "$proof" \
  --freshclam-binary "$freshclam_build/filegate-freshclam" \
  --freshclam-build "$freshclam_build/build.json"
```

新規stagingで開始前後のsource digestを照合し、変更があれば採用しない。initramfsはUID/GID 0のnewcとして生成する。baseはdebugfsで所有・mode・内容を読み戻し、ホストmountを使わない。新imageからPython interpreter・stdlib・旧Pythonコードを除く。固定corpus、Go fixture runner、必要な読取り専用C診断ソースを組み込み、build receipt schema 4のsource/artifact/installed-file hashへ結び付ける。

AVの固定APKは新image内でroot所有の読取り専用入力にし、minirootfs付属apkと鍵で `--no-network` の署名検証・導入を行う。FreshClam wrapper用のコンパイラ閉包は16 APK、ゲストC診断用はlibxml2-devを含む24 APKで、旧109 APKを一括導入しない。署名・固定hashの不一致は中止する。固定4系統のAV libraryは `/opt/filegate-av` に置き、ゲスト内でClamAV本体を再構築しない。

## 監視付き実行

現在のOS・UID・native source/binaryに一致するLaunchAgent死亡回収proofを[ホスト手順](../host/README.md)で先に用意する。proof取得前にQEMUを起動せず、監視を省略する方法も提供しない。

```sh
"$workspace/.build/filegate-vm" --fixture transfer \
  --proof "$proof" --out "$verification/product-checks/transfer-NEW"
"$workspace/.build/filegate-vm" --fixture watchdog-death \
  --proof "$proof" --out "$verification/product-checks/death-NEW"
```

runnerはowner 0700の新規run directoryと、全量事前確保した4,294,967,296 bytesのrawを作る。fixtureの `prepared.json` はschema 2であり、QEMU引数・実体・kernel/initramfs・base/definitions・rawの実長と確保量を検証する。製品用schema 3と混同しない。build receiptと全source/artifact、固定8件のnative helper pinも起動前に照合する。

停止確認が不完全な同じ試行を正式に回収するときは、元と同じfixture・proof・outへ `--recover` を加える。新しい出力先へ切り替えたり、残るintent/rawを手動削除したりしない。

## 隔離と観測の条件

ready前に既知の3 block・容量・read-only属性、mount許可表、rootと全作業先のwrite/fsync先、root copy-upとlower不変を確認する。全ディスク書込みを同じext4 workとroot OverlayFSへ収容し、`/dev/shm` だけ64 MiB/4096 inodeのRAM例外にする。swap/coreを無効化し、mkfsのnodiscardとQEMUのdiscard=ignoreで事前確保をTRIM解放しない。

trusted initでuser.max_user_namespaces=0を固定し、非rootのmount・user namespace・block直接操作を拒否する。全Go workerはBusyBox `setpriv --no-new-privs` からexecし、Go runtime作成前に継承する。単一スレッドのBusyBox `unshare -U` の終了1とEPERM/ENOSPC完全一致だけを拒否の証拠とし、多重スレッド由来のEINVALを成功にしない。

独立ゲスト監視子は初回と毎秒の空きblock・inodeを専用チャネルへ送る。helperのmount/block検証と初回work状態をnativeへ渡し、監視有効ACK後にだけ入力を送る。入力SHA-256・サイズは受信側と非root workerで再確認する。

`watchdog-death` だけはtransferを選び、ACK後も入力を送らずworkspace relayを続ける。通常exchangeの完了を禁止し、4件のidentityが生存している間にwatchdog本人だけをSIGKILLする。guardianによる独立停止を10秒以内に確認し、brokerが子へ停止signalを送った試行は成功にしない。偽の `FINISHED` を作らず、通常終了と独立死亡proofを別に検証する。

fixtureは[固定catalog](fixtures.json)を使う。圧迫先別・同時書込み、inode、境界外write、監視子SIGSTOP、statfs失敗、5 GiB累積writeとtruncate再利用を新規VMごとに測る。sync-EIOは明示したfault injectionで、実媒体の同期障害ではない。期待異常もnative停止理由とPID終了証拠の両方を必要とする。

危険な操作の選択frameはhostが `fixture-observation.json` schema 2へ同期保存し、ACKを返してから実行する。`started` は操作完了・容量到達の証拠ではない。後続の実観測とnativeのworkspace・停止結果を照合する。受信は累積4 MiB、JSONは深さ32・値20,000・文字列64 KiB、保存reportは32 MiB、relayは各64 KiB/全体1 MiBまで。これらの試作予算だけで製品レポート受理を実証済みにしない。

AVは `av-observation`・`av-limits`・`av-hard`・`av-io`・`av-internal`・`av-remaining`、FreshClamは `freshclam-adapter`、形式検査は `format-contract` を同じ監視付きrunnerで選ぶ。詳しい範囲は[AV手順](../av/README.md)と[形式契約](../contracts/README.md)に従う。ゲスト非rootでmanifest・所有・ELF・hash・loader結合を確認し、自前libraryとAlpineの別ClamAV libraryを混用しない。

scan VMは外部NICなしとし、ready前にloのUP/LOOPBACK・127.0.0.1/8、任意の::1/128以外のアドレス不在を再確認する。scan300秒・固定4 GiB work・全processの資源監視を維持する。構築成功や設定の存在をfixture実測の成功としない。

終了後はプロセスとfdの終了、base/definitions不変、所有の確認できたraw・socketの回収、予約精算を読み戻す。OS・native・source/image変更後は影響する試験を再実行し、別構成の成功を自動継承しない。

構築方式の一次資料は[QEMU ARM virt/HVF](https://www.qemu.org/docs/master/system/arm/virt.html)、[QEMU 11.1.2 block定義](https://raw.githubusercontent.com/qemu/qemu/v11.1.2/qapi/block-core.json)、[OverlayFS](https://docs.kernel.org/filesystems/overlayfs.html)、[mke2fs 1.47.4](https://raw.githubusercontent.com/tytso/e2fsprogs/v1.47.4/misc/mke2fs.8.in)、[newc形式](https://docs.kernel.org/driver-api/early-userspace/buffer-format.html)。公開文書は固定binaryの実測を代替しない。
