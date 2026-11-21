# Custom Parameter Handler -re v0.3

元の`../burp-cph`を保持した改修コピーです。値の抽出・置換とnative通信処理を再利用し、管理API認証、設定Import時の参照・順序保持、ローカル認証プロファイルの読み込みを追加しています。

ExtensionsでPythonとして`CustomParamHandler_marged_api_v0.2.py`を選びます。表示名は`Custom Parameter Handler -re v0.3`、タブ名は`CPH Config -re`です。v0.3でも既存の配置との互換性のためファイル名・API形式は維持しています。同じAPIポートを使うので、従来CPHとの同時ロードは行いません。

ロード前に、MCP側の`configure-runtime.ps1 -McpJar <実際のJAR> -CphRoot <このフォルダー>`で参照先を確認します。既定は読取り専用で、`-Configure -BurpStopped`を加えると停止保守中に`runtime/cph-connection.json`の参照を実配置から生成します。フォルダー名を固定せず、親フォルダー全体の移動は相対参照で維持します。片方だけの改名・移動時は再実行してください。明示した接続先が存在しなければ`CPH_RUNTIME_PROFILE_MISSING`で停止し、管理認証なしでは起動しません。MCPを先にロードしてruntimeを生成してからCPHをロードします。

認証済みのAPI取得結果の`connection`は、CPHが起動時に選んだ参照元とruntimeを秘密値なしで返します。新しいMCPの`get_cph_config`は`connectionDiagnostics.runtimeMatches`で比較します。ファイル変更だけでは起動中の認証情報は更新されません。診断中に再ロードせず、許可された保守へ分けてください。詳細な選択ロード、再起動条件、従来MCPとの組合せは[`../mcp-server -re/LOAD.md`](<../mcp-server -re/LOAD.md>)へ集約しています。

`tests`には通信を発生させないCPython/Jython/実Swingの回帰検証があります。再配置後も元CPHとの互換処理を比較します。
