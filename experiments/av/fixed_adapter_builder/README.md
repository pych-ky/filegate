# 固定adapterの再利用とGo wrapper構築

保存先・凍結規則・新Go候補の受入状態は[検証手順](../../README.md)に従う。旧PythonのClamAV全source factoryは退役対象であり、source取得・patch再生成・C++/Rustの全build/ctestを再提供するGo CLIはない。旧launcherを実行せず、原本・入力manifest・採択証拠を移行archiveに保持する。

採用済みbundleには、同時構築したlibfreshclam・libclamav・unrar関連の固定4 library系統と相対symlinkを保持する。source/config/ABI ID・ELF ARM64・依存・hashを照合し、Alpineの別libclamavとの混用でABI一致を推定しない。顧客入力をbuilderへ渡さない。

## 既存bundleの照合

```sh
adapter_build="$verification/experiments/av/fixed_adapter_builder/artifacts/20261028-preparation-04"
"$dev" --repo "$workspace" verify-adapter --bundle "$adapter_build"
```

Go consumerは採択済みinputs manifest・build結果・artifact manifest全体のhash、source生成情報、source tree、library一覧・ELF・hashを検証する。実体を読む固定入力は4 script/rootfsと109 APKの113件である。旧 `entry.sh`・container用Pythonは外部bundle内の歴史的入力としてhashを維持するが、実行しない。

旧 `source.tar` はinputs manifest内の記録hashを維持する。採択済みconsumerが実体を要求しなかったarchiveを、新たな実行依存として追加しない。欠損したarchiveを復元済みと扱わず、入力検査を省略してlibraryを採用することもしない。Goの照合範囲は元consumerと現在の固定library利用に合わせる。

## 新しいGo/C ABI wrapper

`filegate-dev build-freshclam` は既存4 libraryを再buildせず、現在のGo/C ABI wrapperだけを新しい出力先へ構築する。

```sh
freshclam_build="$verification/product-checks/freshclam-build-NEW"
"$dev" --repo "$workspace" build-freshclam \
  --verification "$verification" --out "$freshclam_build"
```

`--inputs-only` は固定rootfs・109 APKのhashと、compiler用16件・scan C診断用24件の依存閉包を確認し、containerを起動しない。実buildはcompiler用16件だけを信頼済みapk/keysで署名検証・導入し、Python packageを使わない。

実buildは固定ローカルOrbStack Unix socketへ接続し、global contextを変更しない。base pull・ログイン・外部接続を行わず、network none、Linux/arm64、2 CPU、RAM4 GiB、swapなし、PID上限256、入力readonly、出力は新規専用directory、総期限480秒で実行する。ホーム全体やsocketをcontainerへ渡さない。所有containerの停止・削除を確認し、失敗先へ再実行せず新しい出力先を使う。制御失敗時も未確認containerを残したまま次へ進めない。

旧C++/Rust factoryの1,800秒・上流test結果は当時のbuild証拠であり、新wrapperの480秒や製品のscan300秒/update600秒と混同しない。containerのwritable layerは固定raw相当の4 GiB硬上限を持たず、製品の容量・監視ゲートへ流用しない。

## 新imageへの結合

成果物の存在だけで既存runtimeへ反映しない。新scan imageのbuild receipt schema 4と新update imageのmanifest schema 2へ、Go wrapper・source・固定library・host runner・producer receiptを結び付ける。固定baseline・登録済みimage・凍結workspaceは変更しない。

VMの非root起動前にmanifest・所有・mode・ELF・hash・loader結合を確認し、新imageでFreshClam9件を実測する。host永続化・別VM復元・公式取得・定義採用は別に検証する。libraryやsourceが変わった場合は対応するprovenanceと試験を取り直し、過去のbuild/ctest成功を自動継承しない。製品の固定raw、RAM、native監視、scan300秒・更新全体600秒を延長しない。
