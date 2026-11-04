# AVの観測範囲と再検証

保存先・凍結規則・新Go候補の受入状態は[検証手順](../README.md)に従う。保証範囲は `observation-specification.json`、固定版は[採用binding](adopted-bindings.json)で確認する。`runtime-observations.json`、旧125実測、catalog・matrixは当時の証拠として保持し、新Go候補の合格に書き換えない。

固定版はAlpine 3.24 ARM64のClamAV 1.4.6-r0 LTS、PCRE2 10.49-r0。上流source、APK、実行binary、library、設定、定義、worker imageの同一性を別々に固定する。source確認だけで実binaryの挙動を確定しない。

## 必須検査と限定保証

検出はBLOCK、通常エラー・警告・制限・暗号化・不明・未完了・異常終了・timeout・取消はHOLDにする。確定済みBLOCKは保持する。FileGate自身の形式、入力size、entry数、深さ、比率、読取り・書込み・同期、検査対象のidentity/hash/size確認は常に必須である。debugの不在や通常OKだけで内部処理完了を推定しない。

利用者が採択した限定保証は、次の明示した未確認内部経路だけを標準engineのbest effortとして扱う。

- PDF local-recursion
- PESpin/PE allocation
- LZW/signed-CVD internal-dependency classification
- ELF/Mach-O internal analysis
- AUTOIT/ISHIELD_MSI association classification

この5範囲は独立した完了確認が未実証であり、「観測不能と証明した」という意味ではない。内部処理が通知なく止まった場合、その停止を検出する保証はない。parser無効化、ほかの未知経路の除外、通常異常の無視、定義の署名・真正性・鮮度、COOLDOWN/UNKNOWN、VM保護の免除は含まない。signed-CVDの内部依存分類も署名検証の免除ではない。

拒否されたPDF local-recursionとPESpin/PE allocationの境界入力生成・追加調査は、Goや別経路で再試行しない。source確認や入力未生成を実測成功にしない。許可済みPDF filter/object等の有限caseとは区別する。製品profileで未対応のPDFをHOLDにする規則も維持する。

## Goによる監視付き観測

準備は既存の固定入力・署名付きAPK・固定corpusを再利用する。旧source取得・patch生成・全ClamAV factoryをGo CLIで再提供したものではない。固定入力が欠けた場合は、検査を省略せず構築を止める。

AVをhostで起動せず、[監視付きVM runner](../vm/README.md)から固定fixtureを選ぶ。

```sh
"$workspace/.build/filegate-vm" --fixture av-observation \
  --proof "$proof" --out "$verification/product-checks/av-observation-NEW"
```

`av-observation`・`av-limits`・`av-hard`・`av-io`・`av-internal`・`av-remaining` を個別に選べる。Goで生成した無害入力またはbyte固定corpusを、ARM64 Linux・非root・外部NICなし/loopback確認済みVMで実行する。入力hash、固定引数、設定digest、期待値、終了状態、通常結果、制限診断の件数とdigestを残し、未加工stdout/stderrは保存しない。suiteごとの受信上限をstreamingで強制し、各engine実行30秒とVM全体300秒を別々に維持する。未実施項目を成功にしない。

`profile.json` は既定parserとarchive解析を有効に保つ。原本250 MiBへ展開単一100 MiBを誤適用せず、AV設定を独立形式・容量検査の代用にしない。`classification-catalog.json` の型分岐・DCONF・名前付きC定義は、全内部境界を網羅した証明ではない。直接書かれた数値、外部decoder/parser、定義で変わるDCONF、未準備fixtureの残件を未完了として残す。OLE summaryの上限は既定offのmetadata収集、ZIP検索request上限10は固定callerの最大4件に対するもので、sampleのentry数ではない。

## 観測結果の読み方

codec/LZMAの保存済み20件では、XZ property異常は終了0でも通常エラーとしてHOLD、`Heuristics.XZ.DicSizeLimit` はマルウェア検出と分けてHOLDへ正規化した。ARJの固有debugで到達を観測したguard、入力とsourceから推定した7z/XZ/LZMA経路、共通の成功正規化だけを確認した条件を分ける。

GZip/BZipの異常・未終端、CABの250 MiB保存上限、CHM部分出力では、不完全な展開や打切りでも通常OKとなる観測がある。CAB/CHM保存量は別の診断runで測っており、通常結果と区別する。TAR原本とmemberもhash/sizeで分け、途中終端の1,112 byte部分出力は別DB診断での観測とする。Deflate64の小さいmethod9入力はMAXD guard到達の証明ではない。

limitsの19件は再帰・時間、PCRE対象size、HTML/script/埋込みPE/ZIP種別/partition、MIME、PDF object数、画像decoder予約、ALZ件数、bytecode timeoutを扱う。通常結果とdebugによる制限到達を別に照合する。画像crateの512 MiBはbest-effortの予約上限で、processのメモリ上限ではない。unsigned bytecode許可・interpreter・短期限は無害fixtureだけに限り、通常設定のunsigned禁止を維持する。

hardのXML/PDF・ZIP overlap・MIME長pattern・署名付きbytecodeは、拒否されたPDF recursion caseを除いた範囲で扱う。署名付き `bytecode.cvd` の信頼済みloadとinterpreter timeout専用warningを必要とし、genericなfailed-to-runだけでtimeoutを実証しない。

固定libxml2 2.13.9-r2のarchiveと2 patchのSHA-512、調査source hashは保存済み記録へ結び付ける。読取り専用C observerは診断runだけに用い、通常結果・終了・警告・エラーが変われば到達証拠に採用しない。本文・path・未加工errorは出力しない。dictionary設定10,000,000はpool成長判定で超過を許し、厳密な割当合計上限ではない。`xml_dict_probe.c` の比較用dict試験は依存APIの挙動で、ClamAVの非公開contextを観測したものではない。

I/O fixtureはUID65534の実chmodで読取り拒否・temp作成失敗を起こす。temp失敗でもexit0/OKになる場合があるため、AV前のinput読取り・temp作成/書込み/同期と通常エラーを独立に確認する。fixtureで失敗後にもengineを動かした観測を、製品が必須検査失敗を許可する意味にしない。全内部I/O・ENOSPC・製品判定永続化は別の実証である。

## FreshClamと固定library

FreshClamには429/403後のdat保存返値を無視する経路、COOLDOWNのFC_SUCCESS、429の成功正規化が残る。datと終了値だけで最新状態・更新確認成功を確定しない。

固定 `filegate_control.c` ABIをGoの `internal/freshclamadapter`・`cmd/filegate-freshclam` から呼ぶ。最終メモリ状態、UUID、禁止期限最大値、Retry-After/Date、定義別確認結果を返し、全送信箇所の送信前guardで403/429受信後の追加要求を止める。snapshotを初期化前に復元し、古い・破損したdatへfallbackしない。datの短いwrite・同期・close失敗時も最新メモリ状態を別報告する。旧Python adapterを呼び出さない。

`filegate-dev build-freshclam` は採用済みの固定4 libraryを再構築せず、Go/C ABI wrapperを新規構築する。[固定builderの扱い](fixed_adapter_builder/README.md)に従い、署名付きcompiler依存16 APKだけを使う。scan imageのC診断用はlibxml2-devを含む24 APKであり、旧109 APK全体やPythonを導入しない。

```sh
freshclam_build="$verification/product-checks/freshclam-build-NEW"
"$dev" --repo "$workspace" build-freshclam \
  --verification "$verification" --out "$freshclam_build"
```

監視付きVMの `freshclam-adapter` は、loopbackだけで無害署名、429/403、delta/date/fallback、長い禁止期間、dat保存失敗、古いdat、成功後429を起こす9ケースを扱う。429 header後の本文切断は以前の応答完了情報を流用せずUNKNOWNにする。新processへsnapshotを復元し、追加要求・再試行0件を実libraryで確認する。呼出しはstdout/stderr合計1 MiB・30秒を受信中に強制し、超過はkill後waitして失敗にする。

固定libraryの過去build・上流test成功、VM内9件、host永続化・別VM復元、公式定義取得と採用は別の証拠である。更新制御のgeneration・時計正規化・UNKNOWN・600秒全工程・採用排他は[更新手順](../update/README.md)に従う。`final` は同期API終了で、VM/helper終了や採用成功ではない。snapshot 4 KiB・入出力1 MiB、製品scan300秒・update600秒、固定raw・RAM・native watchdogを維持する。

一次資料は[公式サポート方針](https://docs.clamav.net/faq/faq-eol.html)、[固定ClamAVソース](https://github.com/Cisco-Talos/clamav/tree/5853e1396777bae4d909cd3dd44f58352e7cf9b3)、[固定Alpine定義](https://github.com/alpinelinux/aports/blob/c84b05967ca68847882204bc14ab80ecc7b38c57/community/clamav/APKBUILD)、[固定libxml2定義](https://github.com/alpinelinux/aports/blob/f1bd5b6767a0e7fdda380c95138a1c938eb6e102/main/libxml2/APKBUILD)。source上の推定と対象binaryの実測を区別する。
