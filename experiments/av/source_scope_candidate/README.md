# POSIX callerと証明書raw保存の分類

固定ClamAV 1.4.6の原本archive・展開済みsource・adapter v5の23ファイルを照合した。C/Hのregex caller/raw field参照に加え、Rust全体のraw field参照も調べ、生成FFIの配列宣言3件のみであることを確認した。採用APKの実scannerと11依存は新OS basicのloader照合へ結び、CDB ERE対照6件の成功を別の実測証拠にした。

空backrefの `OBACK_` はBRE parserだけが生成する。採用clamscan/libclamavのcompile入口はEREを指定し、wrapperもEREを外さない。したがって固定callerの範囲では空backref guardは非活性である。CDB実測は数字escapeのERE解釈を確認したもので、guard到達の証明ではない。milterのBREやPCRE2にはこの分類を適用しない。

証明書のraw subject/issuer/serialは63 bytesのprefixを保存・コピー・診断表示する。一方、照合用のsubject/issuer/serialはASN.1内容の全長をhashする。63 bytesは検査打切り上限ではなく診断用保存の制限と分類する。証明書の新たな対象fixtureは実行しておらず、他のASN.1制限や証明書検証全般の完全性は主張しない。

`proposed.patch` はclassification_catalog生成元の該当2行、関連source evidenceと2定数の分類だけを変える。他のsource行の生成結果が不変であることを確認する。sourceやworker入口が変わった場合は本分類を再確認する。

旧Python検証器は退役し、原本を外部archiveに保持する。同じ分類probeを再生成するGo CLIは未提供であり、保存済みsource/hash・分類の証拠を参照する。

上記は当時の分類候補の範囲であり、現在の採否は[実装状態](../../../IMPLEMENTATION_STATUS.md)に従う。sourceやcallerの変更時は影響する分類を再確認し、この候補だけで製品profile・段階0の合格を有効化しない。
