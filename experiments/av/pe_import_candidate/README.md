# PE import境界の観測

旧Pythonによる `av-pe-import` の保存済み観測である。Python実行器は退役し、この単独probeを再生成するGo suiteは提供していない。以下の有限な観測範囲を新Goで再実行済みとは扱わない。採用した8ケースのsource・image・入力・DB・通常結果は検証領域の `experiments/av/runtime-observations.json`で照合する。実行条件は[AV試作](../README.md)に従う。

入力は読取り専用 `.data` sectionだけを持つPE32 DLL形式で、entrypointとSizeOfCodeは0、実行コードを含まない。ロード・実行せず、ClamAVの読取り入力として使う。`.imp` の無害署名がimport hashの入口を成立させるため、NDBだけへ置き換えない。

- descriptor 1024/1025件は、先頭1024件までの収集を観測する。関数個数の上限とは区別する。
- DLL名とhintに続く関数名の256/257 bytesは、256 bytesでの切詰めを区別する。DLL名は拡張子除去の影響を避けるため英字だけを使う。
- 関数1024/1025件は両方で全関数のhashを検知する。固定ソースの `num_fns` は増分されず、1025件を上限到達の証拠にしない。

固定ソースのPE32+はimport hash処理より前に戻るため、結果を64-bit枝や別callerへ一般化しない。通常結果とdebugの `IMP: hash:size` を別に照合し、採用profileの上限overrideやparser無効化は行わない。
