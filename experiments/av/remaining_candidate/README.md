# XML・HTML・HWP3・XLM境界の観測

現在の実行はGoの `internal/fixtures/av_remaining.go` と読取り専用の `boundary_observer.c` を使い、監視付きVMの `av-remaining` で行う。旧Pythonの生成器・実行器は退役した。4経路8ケースの採用結果は検証領域の `experiments/av/runtime-observations.json`、実行条件は[AV試作](../README.md)を参照する。

- XML属性はmetadata offのHWPML BinDataを使い、20/21属性の末尾にある `Encoding=Base64` が処理対象に入るかを区別する。metadata収集を有効化すると先行走査がreader位置を消費するため、同じ比較にはならない。
- HTML tokenは未引用hrefの1024/1025 bytesを比較する。引用符を加えると境界が変わる。無害署名はnotags出力だけに成立させ、元HTMLや小文字化nocommentの検知と混同しない。
- HWP3はhidden description内のparagraph listを15/16段にする。段落数ではなく再帰深さの比較であり、CL_EMAXRECの成功正規化と通常結果を分ける。
- XLMは単一Workbook streamのMSODRAWINGGROUP recordを8228/8229 bytesにし、image経路からBIFF parserへ到達させる。macro recordを含めず、`alert-macros` を維持する。

診断observerは元の依存API・返値を変更せず、通常結果が変わらない場合だけ到達証拠に使う。通常OKを内部処理の完了保証にせず、警告・エラー・上限通知は既存契約どおり扱う。PDF object抽出再帰はこの8ケースに含まれず、[HANDOFF.md](../../../HANDOFF.md)の停止scopeに従う。
