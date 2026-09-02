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
