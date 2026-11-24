# Google read-only setup

## Current restriction

Phase 3Aではread-only取得codeをsynthetic fixtureとmockだけで検証します。現時点では次を実行しないでください。

- `authorize-google-readonly`
- `fetch-google-snapshot`
- OAuth browser flow
- Access tokenまたはrefresh token取得
- Google Calendar API call
- Production Calendarまたはtest Calendarへの接続

実行には、Phase 3Aとは別の明示的なユーザー承認が必要です。

## Future prerequisites

将来の明示承認前に、次を別途準備・確認する必要があります。Phase 3Aではこれらの作成・変更を行いません。

- 専用Google Cloud project
- そのprojectでGoogle Calendar APIがenabledであること
- Desktop application typeのOAuth client
- Read-only authorization専用のlocal secret保存場所
- 明示承認されたtest targetと、その期待fingerprint・summary・owner role・timezone

OAuth consent、API enablement、client作成はGoogle Cloud上のstate変更です。別のユーザー許可なしに実行しません。

## Least privilege contract

許可するOAuth scopeは次の1件だけです。

```text
https://www.googleapis.com/auth/calendar.events.owned.readonly
```

Broad read scope、write scope、追加scope、重複scopeは拒否します。Read tokenを将来のwrite処理へ転用しません。OAuth client typeはDesktop application、redirectはlocalhost loopbackだけです。Service accountはこの既存owner Calendar向け初期方式として使用しません。

## Sensitive files

将来の明示承認時にも、次はすべてGit repository・worktree・cloud-synced public folderの外へ置きます。

- Desktop OAuth client JSON
- Authorized-user read token JSON
- Private target TOML
- Sanitized Google snapshot JSON

通常のlocal absolute pathだけを使用し、relative path、HTTP(S)、`file://`、UNC、symbolic linkを使用しません。既存tokenとsnapshotはdefaultで上書きされません。File名、path、内容をlog、issue、Pull Request、CI artifactへ載せないでください。

POSIX環境ではsecretとsnapshotをowner-only mode `0600`で保存します。Windowsでは専用のuser-private directoryを使用します。Sensitive writerはtokenをcurrent-userのprotected DACL付きでcreation時から作成し、loaderはcredential/tokenのeffective ACLをhandleから検証します。他のnon-admin local userにwrite/deleteを許すparentやreadを許すsecret fileは拒否され、旧unsafe tokenは自動修復されません。GitignoreはOS file permissionの代替ではありません。詳細は[Windows sensitive filesystem security](windows-sensitive-filesystem-security.md)を参照してください。

Sanitized snapshotはcredentialsを含みませんが、event title、description、opaque event IDを含むためsensitive runtime dataとして扱います。

### POSIXでのread token新規保存

`authorize-google-readonly` で新規保存する場合は、認可前にrepository外へ専用ディレクトリと未使用のファイル名を用意してください。保存先の直上の親は、実効ユーザー所有でmodeが正確に `0700` の既存ディレクトリである必要があります。祖先はrootまたは実効ユーザー所有とし、root所有でsticky bitが設定された祖先を除き、group/otherに書込み権限を付与できません。symbolic linkや `.git` マーカーを含む経路は拒否します。

認可前に保存先が未作成だった場合は、`--overwrite-token` を指定していても新規作成専用です。OAuthフローの前に保存条件を検査し、保存時にもう一度検査します。認可中に同名のファイルが作られた場合、そのファイルを保持して保存に失敗します。認可前から存在する通常ファイルは、`--overwrite-token` を指定した場合に従来の上書き経路で保存できます。この上書きでは、認可開始時と同じファイルに対する置換は保証されません。元のファイルがなくなった場合は、同じ名前で保存されることがあります。

OAuth後に保存に失敗した場合、資格情報が発行済みの可能性があります。最終名での保存を試みた、または試行状態が不明と表示された場合は、再認可・再試行・ファイル削除の前に保存先の状態を確認してください。

### POSIXでのread token更新

有効なtokenの読込みには、通常ファイルが実効ユーザー所有・単一リンクで、group/otherに権限がないことなど、従来の読込み条件を適用します。読込みだけでは更新用の権限検査、OAuth更新、保存は行いません。

読込み時に期限が切れている場合と、`fetch-google-snapshot` がHTTP 401を受けて明示的に更新する場合は、OAuth更新要求の前に保存先を検査します。直上の親が実効ユーザー所有・正確な `0700` で、上記の祖先条件を満たし、保存先が同じ実効ユーザー所有・正確な `0600`・単一リンクの既存通常ファイルである必要があります。更新要求の前と保存時にファイルの内容も照合します。

最初の比較基準は、安全な読込みとJSON検証に使った元のバイト列です。保存を確認できた場合だけ、実際に保存したバイト列を同じ実行の次の更新に引き継ぎます。異なる内容を照合時に検出した場合は、置換せずに停止します。同じ内容の別ファイルは区別できない場合があり、最終照合と置換は別操作なので、同時更新を完全には防げません。

失敗時は、OAuth更新要求前に停止した場合、要求自体が失敗した場合、OAuth更新後にローカル保存を確認できなかった場合を区別します。保存を確認できなければ、期限切れ更新ではCalendar取得を開始せず、401経路では次の取得要求とsnapshot保存を行いません。置換前の失敗は、この呼出しでは最終名の置換を試みなかったことを示します。置換を試みた場合や試行の有無が不明な場合は、再試行・再認可・復元・削除の前に、内容を表示せず保存先を確認してください。自動復旧は行いません。

## Private target contract

Target TOMLは次のclosed structureを使用します。値はすべてplaceholderであり、repositoryへ保存してはいけません。

```toml
schema_version = 1
target_label = "private-local-label"
calendar_id = "<private Calendar ID>"
expected_target_fingerprint = "<64 lowercase hexadecimal characters>"
expected_summary = "<exact expected calendar name>"
expected_access_role = "owner"
expected_time_zone = "<expected timezone>"
```

Calendar IDはAPI client構築前にdomain-separated SHA-256 fingerprintと照合します。API responseのcalendar summary、owner access role、timezoneも完全一致しなければsnapshotを作成しません。Human outputでは`T-<12 hexadecimal characters>`だけを表示します。

## Future approved sequence

以下は将来、別指示でauthorizationとread-only callが明示承認された場合の順序です。Phase 3Aでは実行しません。

1. Repository外の絶対pathとfile permissionを確認する
2. Desktop client configとprivate target configをoffline validationする
3. Exact scopeを再確認する
4. 明示的なonline flag付きでdesktop authorizationを1回実行する
5. Token fileがowner-onlyか確認する
6. Target fingerprintをAPI call前に照合する
7. `events.list`だけでfull paginationを取得する
8. Allowlist sanitizerを通し、repository外へno-overwrite atomic writeする
9. Offline `diff-snapshot`で内容をreviewする

Fetcherは`singleEvents=false`、`showDeleted=true`、`maxResults=2500`と限定field maskを固定し、write methodを持ちません。429・一部5xxだけをbounded exponential backoffでretryし、permission、shape、target mismatchはretryしません。

## Incident handling

Secretを誤ってrepository、issue、logへ出した場合は、file削除だけで済ませずcredentialを直ちに失効・rotationしてください。秘密値そのものをsecurity reportへ貼らないでください。
