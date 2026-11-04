# filegate

受け取ったファイルを隔離VMで検査し、条件を満たした原本を取り出すローカルツールです。

製品・VM制御・更新・ビルド・検証の実行経路をGoへ移行しました。固定AV library、FreshClamの小さいC呼出し層、native監視は維持しています。リポジトリ内のPythonは0件で、旧ソースと証拠は作業ツリー外に保存しています。最終配置版で実PASS、同じ原本の取り出し、通常のbroker再起動後の状態を確認しました。受入範囲は[実装・検証の状態](IMPLEMENTATION_STATUS.md)を参照してください。

起動は `~/Library/Application Support/FileGate/application/FileGate.command`、取り出し先は `~/Library/Application Support/FileGate/Outbox` です。初期対象はパスワードなしのZIP、上限250 MiBで、未対応形式はHOLDにします。AV内部の未確認5範囲は採択済みのbest effortで扱い、通知なしの内部停止を検出する保証はありません。

[開発手順](DEVELOPMENT.md)・[継続時の制約](HANDOFF.md)・[設計の正本](BASIC_DESIGN.md)
