# HTTP framingと取得層の検証

保存先・凍結規則・新Go候補の受入状態は[検証手順](../README.md)に従う。framing prototypeはGo 1.27.3の標準libraryを使い、TLS検証を有効にしたloopbackの動的portだけで合成fixtureを送受信する。

```sh
cd "$workspace/experiments/http"
go run -trimpath -buildvcs=false . --out "$verification/product-checks/http-NEW"
go vet ./...
```

出力先には未作成のdirectoryを指定する。`results.json` に期待値・実値・エラー・Go版・source/binary SHA-256、`inputs/` にHTTP/1応答とHTTP/2入力条件を残す。実行sourceも保存し、TLS秘密鍵は記録しない。

[保存済み31件](artifacts/20261027-framing-05/results.json)では、HOLDだけでなく予定した拒否・読取りエラー経路も照合した。`RECEIVED_COMPLETE` はHTTP本文完了を表し、FileGateのPASSではない。

固定Go TransportがTEとCLの併記を受け入れてCLを削除する挙動は、[採用ソース](https://github.com/golang/go/blob/go1.27.3/src/net/http/transfer.go#L725-L728)と `baseline_te_cl_normalized` の実測で区別した。`headerGuard` はTLS復号後、HTTP parserより前に各header blockを64 KiB以内で確認して併記を拒否し、103後の最終応答にも適用する。

正常CL/chunked、長さ不足・矛盾、不正chunk、close-delimited、非200、Content-Range、非identity圧縮、過大headerと、HTTP/2の正常終端・RST・長さ不足を扱う。close-delimitedの拒否根拠は[RFC 9112 §6.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3)。HTTP/2は通常GoクライアントとTLSサーバーで交渉protocolも照合する。prototypeの5秒timeoutを製品期限の試験にしない。

製品の `internal/acquire` はGoの取得E2Eで別に検証する。

```sh
"$verify" acquire --root "$workspace" --out "$verification/product-checks/acquire-NEW"
```

実TLS通信をローカルfixtureへ割り当て、単一TransportのHTTP/1・HTTP/2、DNS全回答検査とIP固定、redirect、証明書検証、接続30秒・本文無通信30秒・全体120秒、実本文250 MiB境界を確認する。宛先を試験用に割り当てても、製品のTLS・判定・宛先制約は維持する。保存済みの `product-checks/acquire-path`・`acquire-total-deadline`・`acquire-idle-deadline` は当時の構成の証拠として扱う。

URL受付の予約・再送・取消・再起動は `basic`、URL取得から原本確定・VM検査までの結合は `url` として分ける。取得層だけの成功で、VM停止・永続判定・回収までの受入を代用しない。
