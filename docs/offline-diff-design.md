# Offline diff design

Phase 2は、検証済みAccepted HTML ICSとsanitized Google snapshot JSONをmemory上で比較する純粋なoffline処理です。Google API、OAuth、HTTP client、Calendar ID、token、runtime stateを必要としません。

## Inputs

- Source：Accepted profileでSHA-256、件数、UID一意性、日付範囲を検証した`SourceCalendarInspection`
- Target：closed schemaで検証した`sanitized-google-calendar-v1` snapshot
- Managed scope：任意のin-memory ownership evidence。省略時は空で、Google側だけのeventをunmanagedとします

Snapshotのtarget identityにはCalendar IDではなくSHA-256 fingerprintを使います。Production snapshotはrepositoryへ保存せず、tracked JSONは架空fixtureだけに限定します。

## Identity and comparison

Identityは`Source UID → Google iCalUID`です。Google event IDはopaqueな内部addressとしてのみ保持し、UIDと混同しません。比較対象はexact decoded `summary`、`description`、終日`start.date`、exclusive `end.date`です。trim、Unicode normalization、HTML整形、URL変更は行いません。

同一identityが一件ずつ存在すれば、managed fieldが同じ場合は`unchanged`、異なる場合は`update`です。Sourceだけなら`add`です。Googleだけのeventは、明確なownership evidenceがあれば`delete_candidate`、なければ`unmanaged_google_event`です。

重複UID、重複iCalUID、cancelled、recurrence、非default event type、時刻付きevent、欠落identityは自動補正せず、duplicate、ambiguous、invalid、fatal分類へ送ります。Event-specific colorは内容差分にせず警告します。

## Managed scope and delete safety

Managed scopeはtrusted source UID、trusted Google event ID、または指定された`extendedProperties.private` markerをownership evidenceとして受け取れます。専用Calendar内の全eventを暗黙にmanagedとはみなしません。

`delete_candidate`はdry-run分類だけです。Phase 2にはdelete、apply、operation plan、API write codeがありません。

## Reports and privacy

Human/JSON reportは決定的な順序とcontent hashを持ちます。Raw UID、iCalUID、Google event ID、summary、description、local absolute pathは出力せず、domain-separated SHA-256から得た`U-…`と`G-…`のsafe referenceだけを表示します。Field差分はfield名、presence、length、hashだけで表します。

CLIのdefaultはstdoutへのoffline reportです。`--output`を明示しない限りfileを作成せず、入力Sourceやsnapshotを変更しません。
