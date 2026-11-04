# Codec定数への実測参照

`runtime.patch` は既存runtime overlayのartifact・profile・入力・定義・case対応の検証が全件終わった後に、小さい結合関数を呼ぶ。codec定数11件へ既存の参照を関連付けるだけで、新しい観測caseやmapped source rowを追加しない。

`HEADERSIZE_MAX` だけを名前付きguardの直接実測とする。`COMMENT_MAX` / `FNAME_MAX` は合成header上限の構成要素で、独立した文字列上限ではない。7z/XZ propertyはsourceから推定した分岐、PPMd/LZMA2は同じwrapperの通常結果、NSIS bzip2は共通のCL_EFORMAT正規化だけを関連付ける。参照元のARJ guardが実測されても、NSIS固有guardの実測にはしない。Deflate64とLZW 3定数など、対応する実測を持たない行は変更しない。

既存VM試験の成功だけでは、参照の結合時に未実測guardを実測済みと書く誤りを検出できない。保存artifactの再照合に加え、guard証拠欠落、source行の未検証状態、定数inventoryの欠落/重複を与え、部分更新せず拒否することを検証する。入力や対象環境を変えたVM再実行は行わない。
