# POSIX regexと証明書raw保存の観測範囲

旧Pythonによる `av-regex` の保存済み観測である。Python実行器は退役し、この単独probeを再生成するGo suiteは提供していない。以下の有限な観測範囲を新Goで再実行済みとは扱わない。CDBの6ケースは検証領域の `experiments/av/runtime-observations.json`、固定ソースの分類は検証領域の `experiments/av/classification-catalog.json`を参照する。実行条件は[AV試作](../README.md)に従う。

採用clamscan/libclamavのPOSIX regex callerはERE指定であり、数字escapeは文字として扱われる。CDBの対照入力はその解釈を観測したもので、BREだけが生成する空backref opcodeのguard到達試験ではない。milterのBRE callerとPCRE2は対象外とし、EREをBREへ変更して採用経路の実証にしない。

CDBの入口診断は、無害marker検知時はcentral headerの1回、非検知時はlocal headerを含む2回になる。対象filenameを含む `CDBNAME` 全体で照合し、`ZMDNAME` の部分一致を入口回数へ数えない。

証明書のraw_subject/raw_issuer/raw_serialは診断用に先頭63 bytesを保存する一方、照合用SHA1には同じASN.1内容の全長を渡す。これは固定ソースの保存先・参照先の分類であり、全長read失敗、他のASN.1上限、証明書検証全体の完全性を実測したものではない。raw参照先、hash順序、regex callerや採用workerを変更した場合は分類を再確認する。
