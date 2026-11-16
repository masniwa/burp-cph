# Custom Parameter Handler -re v0.3

Burp Suite用のCustom Parameter Handlerです。レスポンスから値を抽出し、リクエスト・レスポンスの指定した位置へ置換します。管理APIの認証、CPH設定の順序とキャッシュ参照の保持、動的値の文字列としての置換に対応しています。

拡張表示名は **Custom Parameter Handler -re v0.3**、タブ名は **CPH Config -re** です。配置互換性のため、ロードするファイル名は `CustomParamHandler_marged_api_v0.2.py` のままです。

## 配置

新しいWindows PCでの取得・Claude Code接続・通常／動的の初回能力確認と登録は、MCP側の[INSTALL-WINDOWS.md](https://github.com/masniwa/mcp-server/blob/main/INSTALL-WINDOWS.md)に従います。開発PCのruntimeや資格情報はコピーしません。CPH single抽出を使うローカルfixtureの合格と、実対象のMacro・cached抽出・認証の合格は区別します。CPHコードはv0.3のままで、今回の更新は導入案内だけです。

管理方式では、対応する[MCP Server](https://github.com/masniwa/mcp-server)と本リポジトリを同じ親フォルダーへ配置します。

```text
installation/
├─ mcp-server/
│  ├─ build/libs/burp-mcp-all.jar
│  └─ runtime/                    # 初回ロード時にローカル生成
└─ burp-cph/
   ├─ CustomParamHandler_marged_api_v0.2.py
   ├─ CPH_API_v0_2.py
   ├─ CPH_Managed.py
   └─ runtime/cph-connection.json
```

`runtime/cph-connection.json`は `../../mcp-server/runtime` を参照します。フォルダー名や配置を変える場合は、この相対パスを実際のMCP runtimeへ合わせてください。資格情報そのものをこのファイルに記述しないでください。

## ロード

1. BurpでJython standalone JARの場所を設定します。
2. MCP側の手順に従い、`mcp-server/build/libs/burp-mcp-all.jar` を先にロードします。MCPがローカルに生成する `runtime/settings.json` と `runtime/operator-secrets.json` を使用します。
3. ExtensionsからPython拡張として `CustomParamHandler_marged_api_v0.2.py` を追加します。3つのPythonファイルは同じフォルダーに置いてください。
4. 表示名v0.3、CPH Config -reタブ、`127.0.0.1:17866` のAPI起動ログを確認します。MCPの `get_cph_config` で `success=true` と `managed=true` を確認してください。
5. 通常の管理運用はMCPの **REVIEW** モードを使用します。設定適用・検証送信・Scan・回復は公開MCPの `diagnostic_job` を使用します。

CPHは同じAPIポートを使うため1つだけロードします。管理設定が生成される前にCPHだけをロードした状態を、管理運用の準備完了とは扱わないでください。MCP runtimeの秘密情報、Project、通信履歴はGitへ追加しません。

## 使用時の確認

抽出正規表現の名前付きグループはPython形式 `(?P<name>...)` を使用します。CPHの適用にはBurp Target scope、Tool scope、トリガー、置換先、抽出元の設定がそれぞれ必要です。設定のImport成功だけで実際の置換成功とは判断せず、対象別のMacro・Rule・CPH構成を通常の診断手順で検証してください。

共有キャッシュを利用するフローは逐次送信を前提とします。同じCPH・Cookie・アカウントを使う別テストを並行して実行しないでください。

## 更新

実行中のScan・補助通信と未完了の設定回復がないことを確認し、現在のProject・履歴・設定を保存してから更新します。CPHソースの更新時やUnload後は、Burpプロセスを終了してから再起動し、保存済みProjectを開き直してロードしてください。設定Importだけの場合は再起動不要です。

## ライセンス

MIT License。元のCustom Parameter Handlerの著作権表示と条件は [LICENSE](LICENSE) を参照してください。
