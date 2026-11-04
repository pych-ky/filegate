# Codec/archive境界の検証

保存済みの分類は28定数を個別に整理している。旧Pythonの準備CLIと単独probeは退役し、以下は当時の有限な分類・観測範囲である。符号化幅・Huffman table・頻度の再尺度化・未使用定義を、入力拒否guardや処理量上限と混同しない。LZW 3定数のcaller側は未解消のまま残す。固定sourceの原本archive/v5同一性、採用APKの実測binding、各判定箇所を照合する。外部liblzma/bzip2等の全境界を調べた証拠にはしない。

`av-codec-bounds` は13件で、ARJ main/file headerの2600/2601 bytes、7z coder32/33とin/out stream32/33、XZ filter property長1/20/21、XZ辞書要求1.5GiBを扱う。入力は最大2669 bytes。圧縮payloadを持つのは正常XZの無害な30 bytesだけで、7zはheaderのみ、ARJは空fileである。1.5GiBは申告値であり、固定XZ allocatorの1GiB超guardが実割当前に拒否する。上限ちょうどの大容量割当は試さない。

ARJは固有debugでheader guardを観測する。7z/XZの内部関数は採用APKからexportされないため、CRCを含む小入力の構造と固定source、通常/debug結果を照合する。これはsourceから推定した分岐であり、内部branchの直接観測と記録しない。XZ property長20はheader guardを通過して後段LZMA2の長さ1要求で失敗し、21はheader guardで拒否される。どちらも通常errorをHOLDへ扱う。辞書上限の `Heuristics.XZ.DicSizeLimit` はマルウェア検知と区別してHOLDへ扱う。

他のPPMd/NSIS等の形式domain拒否は、sourceで返値からwrapper・通常出力まで対応を示し、同じ正規化経路の実測を共用する。定数ごとの追加fixtureを一律の必須条件にはしない。直接guardを試す案は任意の補足であり、共用する証拠からそのguard自体の実測成功を推定しない。未実証の通常挙動、別wrapper、採用DBでのDCONF変更は別に残る。段階0の通過や内部全評価完了を主張しない。

旧準備CLIの原本は外部archiveに保持する。同じ単独probeを再生成するGo suiteは未提供であり、保存済み入力・期待値・実測のhashを対応付けて参照する。

当時のゲスト実行はNICなし・非root・ARM64・300秒監視付きVMに限定しており、RAM4GiB/work raw4GiBと候補profileを変えない。各プロセスは既存観測器の30秒・受信行1MiB制限を使い、通常結果とdebug結果を別記録する。入力生成・準備検証は対象実測の成功ではない。

実測との結合は `runtime-observations.json` で行い、定数分類だけで観測case数やmapped row数を増やさない。

[対象実測](../../artifacts/20261028-codec-lzma-orca-01/02-av-codec-bounds/exchange.json)は13件すべて期待一致し、[停止・raw回収](../../artifacts/20261028-codec-lzma-orca-01/02-av-codec-bounds/result.json)も成功した。XZ property20/21は通常errorを伴うexit0、辞書上限通知はexit1であり、いずれもHOLDである。
