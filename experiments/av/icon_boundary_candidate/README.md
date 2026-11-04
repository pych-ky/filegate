# MaxIconsPEの観測範囲

旧Pythonによる `av-icons` の保存済み観測である。Python実行器は退役し、この単独probeを再生成するGo suiteは提供していない。以下の有限な観測範囲を新Goで再実行済みとは扱わない。99/100/101個の3ケースの採用結果は検証領域の `experiments/av/runtime-observations.json`、実行条件は[AV試作](../README.md)を参照する。

入力はentrypoint 0、非実行の読取り専用 `.rsrc` だけを持つPE32形式で、実行コードを含まない。IconGroup付きlogical署名と両groupのIDBが入口条件となるため、NDBだけへ置き換えない。16px BMPに対して24pxの不一致metricを使い、早期検知で走査を打ち切らせずicon個数の停止を観測する。

固定 `max-iconspe=100` ではicon走査後にcountを増やして停止する。99個ではlimitなし、100個でもlimitあり、101個では最後の1個を処理しない。通常OKとdebugの有効BMP読取数・limit診断を別に扱い、metricの検出精度や全PE検査の完了保証にはしない。parserや上限、broken/exceeds通知の設定は維持する。
