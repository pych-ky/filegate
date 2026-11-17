# 形式・容量契約と固定corpus

保存先・凍結規則・新Go候補の受入状態は[検証手順](../README.md)に従う。必須チェック、試験入力、期待結果を先に固定し、生成・検査・製品受入を別の証拠として扱う。

`zip32-v1.json` はZIP32 Profile 2（`filegate-zip32-v2`）のヘッダー・物理配置・CRC・Deflate終端・種別・階層・AV対象・上限の責務を定義する。extra fieldは0x5455と0x7875だけを契約の長さ・flags・重複・local/central一致の条件で許可し、その他はHOLDにする。名前比較はGo 1.27.3、golang.org/x/text v0.43.0、Unicode 17.0.0のNFCとdefault full case foldingに固定し、互換正規化を使わない。`txt-v1.json` はUTF-8・型申告・空ファイルのAV対象維持を定義する。

`image-v1.json` と `ooxml-v1.json` はPNG/JPEG・DOCX/XLSXの限定profileを定義する。構造が通常でも、AV未完了ならHOLDを維持する。HOLDの一致だけで個々の必須チェックを実証済みにしない。

## 固定入力の再利用

旧generatorの348入力と3 manifestを、検証領域の `fixtures/contracts-v1.tar.gz` にbyte単位で固定した。管理側の `corpus-v1.json` にarchive SHA-256・全351 fileのhash/size・期待manifest・4契約のhashを記録する。archiveは199,180 bytes、展開量11,462,934 bytesで、Pythonコードを含まない。新しい実行時に旧generatorを呼び出さない。

Goは件数・展開量・path・hashを制限してcorpusを準備する。既知の信頼済みfixtureをhost側で準備する処理と、未信頼の顧客入力を解析する処理を区別し、後者の形式解析・展開・AVは隔離VMで行う。

```sh
"$workspace/.build/filegate-vm" --fixture format-contract \
  --proof "$proof" --out "$verification/product-checks/format-contract-NEW"
```

ZIP108・TXT14・画像73・OOXML153の348件にGo製品用6件を加え、354件を実workerで検証する。元のcase ID・入力・期待値を維持し、現在のdecoder結果を模擬しない。有限caseの成功だけで未実証の形式や新Go構成全体を受け入れない。

名前比較だけの小規模probeはGoのまま利用できる。

```sh
cd "$workspace/experiments/contracts"
go run -trimpath -buildvcs=false . --out "$verification/product-checks/normalization-NEW"
```

## 大容量・管理I/Oの証拠

[大容量6件](artifacts/20261027-large-inputs-01/results.json)は250 MiB、展開単一100 MiB、累積1 GiBの境界と超過を実byteで生成した当時の記録である。生成時の値を受信・展開時の実カウンターへ読み替えない。Goの `filegate-verify capacity-boundaries` は保存済み6入力を `--inputs` で受けてVM検証するが、その大容量入力を再生成するGo CLIは未提供である。元のrecipe・size・hashと原本archiveを保持し、必要入力がない場合は実行可能と扱わない。

[管理側I/O 13件](artifacts/20261027-budget-02/results.json)と[制御process回収5件](artifacts/20261027-driver-cleanup-04/results.json)は、当時のSQLite・ファイルI/O・OS processの証拠である。同じ単独prototypeを再生成するGo入口はなく、現在の製品pressure・startup・recovery検証と区別する。小容量SQLite、合成terminal、子と孫の終了を、製品上限やLaunchAgent/QEMU全体の実証にしない。

`host-budgets.json` はDB/WAL/SHM/journal・保守一時領域・report・log・runtimeの予算と終端余白を定義する。固定rawや書込み済みpartialを未書込み予約へ二重計上しない。readerがsnapshotを保持すると、journal_size_limitを設定してもWALはその値を超える。PRAGMAのreadbackだけを容量強制の証拠にせず、checkpoint不能時の新規書込み停止と終端用余白を維持する。

一次資料は[PKWARE APPNOTE](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)、[Unicode normalization](https://www.unicode.org/reports/tr15/)、[Go normalization](https://pkg.go.dev/golang.org/x/text@v0.43.0/unicode/norm)、[Go full folding](https://pkg.go.dev/golang.org/x/text@v0.43.0/cases)、[Windowsの名前規則](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file)、[SQLite WAL](https://sqlite.org/wal.html)。製品の受付・判定・取り出しの現状は[実装状態](../../IMPLEMENTATION_STATUS.md)を参照する。
