# HFS・VBA内部境界の観測

現在の実行はGoの `internal/fixtures/av_internal.go` を使い、監視付きVMの `av-internal` で行う。旧Pythonの生成器・実行器は退役した。採用した7ケースは検証領域の `experiments/av/runtime-observations.json`に結合し、実行条件は[AV試作](../README.md)に従う。

- HFSカタログはMBRの単一partitionから到達させる。1001/1002個の空leafを比較し、両方の1001 fetch、後者だけのlimit診断、前者のend-of-leavesを区別する。強制file type指定は使わない。
- HFS属性のlimit側は、固定ソースが同じleafを1001回読む条件を使う。1001個の異なる属性ノードを処理した実証ではない。合成ディスクをmount可能なファイルシステムとは扱わない。
- VBAは単一 `_VBA_PROJECT` streamのrecord_count 0/1000/1001を比較する。1000側は次の空名で停止する不完全なprojectで、1000個のmacro処理を実証しない。実行可能なmacroは含めず、`alert-macros=yes` を維持する。

通常結果とdebugの入口・回数・guardを別に照合する。通常cleanと上限診断がそろっても全内部処理の完了を意味せず、通常warning/error/limit notificationはHOLD対象のままとする。
