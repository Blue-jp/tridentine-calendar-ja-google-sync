# 1960年ローマ典礼暦・日本語版 Google Calendar差分同期ツール

`Google Calendar Differential Sync Tool for the 1960 Roman Liturgical Calendar – Japanese Edition`

Accepted Japanese Roman liturgical calendarを、将来Google Calendarと安全に差分同期するための専用tool repositoryです。

## Phase 6D.0の範囲

Phase 6D.0はPhase 6Cのmock-only transportをlive patchへ接続せず、専用Production write-token authorizationと、そのtokenを使うread-only rehearsalのcode foundationだけを追加します。Token role、exact `calendar.events.owned` scope、repository外storage、opaque generation、full snapshotとTrusted Baselineのcross-binding、Accepted Sourceとのzero diff、決定的なfresh getをmock OAuth・fake service・synthetic dataだけで検証します。

AuthorizationとrehearsalのCLI surfaceはPhase 6D.0ではlive hard-offです。実OAuth、token作成、browser authorization、Calendar API、Production Calendar access、ARM / EXECUTE運用、patchは実行できません。既存Production write hard lock、default-off kill switch、Add / Delete unavailableも維持されます。Phase 6Bのartifact境界は[Production single-update planning foundation](docs/production-single-update-planning-foundation.md)、Phase 6Cのmock execution semanticsは[Production single-update transport foundation](docs/production-single-update-transport-foundation.md)、Phase 6D.0の境界は[Production write-token read-only rehearsal foundation](docs/production-write-token-readonly-rehearsal-foundation.md)を参照してください。Repository-wide Deep security scanはmerge後かつProduction OAuth前に必須です。Repository-wide Deep security scan required after merge and before Production OAuth.

### Implemented

- raw bytesのSHA-256をparse前に検証
- RFC準拠parserによるVEVENT解析
- Accepted source profileに対する件数・UID・日付範囲・property構造の検証
- 内容を秘匿したhuman-readable reportとJSON report
- sanitized snapshotのclosed-schema validationとcanonical Google event model
- Source UIDとGoogle `iCalUID`による決定的な差分分類
- `unchanged`、`add`、`update`、`delete_candidate`、duplicate、ambiguous、unmanaged、fatal guardの集計
- raw UID、Google event ID、title、descriptionを含まないdiff report
- optional `google-read` dependency extraと完全に分離されたbase install
- `calendar.events.owned.readonly`だけを許可するdesktop OAuth境界
- `events.list`専用client、full pagination、bounded retry、target identity guard
- raw API responseをallowlistでsanitized snapshotへ変換する処理
- repository外へのprivate atomic snapshot writeとno-overwrite default
- exact zero-difference auditからのcandidate baseline作成
- exact confirmation phraseによるcandidate→trusted transition
- trusted baselineだけをownership evidenceに使うoffline diff
- threshold・mass-change・ambiguity・unmanaged guardを持つnon-executable sync plan
- Add/updateだけを含むintegrity-pinned private apply bundle
- Exact test-only approval challengeとstale plan hash guard
- Bounded abstract retryを持つfake mutation simulation
- Partial failureとskipped tailを記録するhash-chain journal
- Redacted bundle/simulation/journal reports
- Production dataを含まないsynthetic fixture test
- `calendar.events.owned`だけを許可する、Production read tokenと分離されたTest write認証境界
- Test target config、Production hard lock、exact approvalに結び付く1-operation run spec
- Add用`events.import`とUpdate用`events.patch`だけに限定したGoogle adapter
- Source UID / Google `iCalUID`維持、fresh event ID / ETag、exact `If-Match`
- post-write read-back、uncertain outcomeのread-after-check、mutation blind retry禁止
- raw identity・ETag・本文を除外したTest write journal / report
- Productionへ到達不可能なmock-only Test write safety test
- Test write tokenを使い`events.list`だけを公開する専用prewrite inspection境界
- Empty Test Calendarのwrite-readiness検証
- Sanitized Test prewrite snapshotとno-mutation Human / JSON report
- Non-empty Calendarの自動delete / clearを行わないfatal guard
- Empty Test Calendarとsynthetic one-event SourceだけのTest-only bootstrap add planning
- 通常Sync Plan guardを変更しない専用Bootstrap Plan
- 初回Test addだけbaseline不要の専用Bootstrap Run Spec
- Production hard lock、add 1件固定、update / delete到達不可能policy
- Trusted Test Baselineを必須とするTest-only single-update planning
- 管理済みsynthetic event 1件・DESCRIPTION-only update 1件に固定した専用Plan
- 通常global guardを変更せずoriginal guard evidenceを保持するpolicy
- Current Test snapshot由来のevent ID / ETagにbindする専用single-update Run Spec
- Add / Deleteへ到達できないProduction-locked update境界
- Accepted Production Source Manifestによるrepository/tag/commit/ICS/source aggregateのexact pin
- Full Production source・Trusted Baseline・full sanitized snapshotからのDESCRIPTION-only update 1件planning
- Unrelated eventを最低1件unchangedとして要求し、add/delete/update 0件・2件以上を拒否するProduction Plan
- raw UID・SUMMARY・DESCRIPTION・Calendar ID・Google event ID・ETagを持たないProduction Run Spec
- UTC-aware `issued_at`から最大24時間だけ有効なRun Specと、承認対象bit全体をbindするapproval material hash
- Production planning artifactのclosed schema、domain-separated hash、repository-external atomic/no-overwrite I/O、redacted inspection report
- Production full-snapshot reader / fresh-event reader / Description-only mutatorの分離capabilityとdeterministic fake transport
- Full pre-snapshot drift STOP、fresh get / ETag / exact non-wildcard `If-Match`、mutation 1 attempt / retry 0
- Immediate read-back、post-write full snapshot、Accepted Sourceとのcanonical zero-diff verification
- 最大10分のARM receiptからone-time EXECUTE permitへ進むclosed approval-state model
- repository外のatomic permit consumption、replay prevention、default-off kill-switch、switch/token generation binding
- patch前fsyncを必須とするappend-only hash-chain journalとredacted public execution report
- raw API call hard max 10、no rollback、Production Add / Delete到達不可、live Production execution hard-off
- `google-production-write`へ隔離した専用Production write-token authorization foundation
- `production_read` / `test_write` / `production_write`の3-role分離、exact owned-events scope、opaque token-generation state
- repository外no-overwrite token storageと、scope / role / generationを再検証するbounded refresh foundation
- Production write-token rehearsalのlist/get-only capability、full snapshot / Baseline cross-binding、Source zero-diff、one deterministic fresh get
- Event ID / ETag memory-only、redacted rehearsal report、raw Calendar API call hard max 5、live patch hard-off

### Not implemented

- Test write OAuthの実行、browser authorization、token取得
- Test Calendar live prewrite readの実行
- Test Calendar APIの実接続とadd/update実行
- Test Calendar single updateの実行
- Production Calendar write
- Production OAuthの実行、Production write token作成、browser authorization
- Production Calendar read-only rehearsalの実行、live ARM / EXECUTE operational flow
- live Production patch、real Production execution adapter
- automatic rollback、Production Add、Production Delete
- Delete operation model・payload・transport method
- `syncToken`、incremental state、automation

Phase 4Bのbundle/simulationもGoogle Calendarへ接続せず、Google Calendarを書き換えません。Private bundleは将来の安全検討用payloadを保持しますが、execution enabledは常にfalseで、method・endpoint・Authorization headerを持ちません。

Production ICS、Production snapshot、runtime stateをrepositoryへcommitしないでください。入力はrepository外のローカルfileとして明示的に渡します。

## 必要環境

- Python `>=3.12,<3.13`
- 対応platform：WindowsおよびLinux

Base runtime dependencyは`icalendar`と`pydantic`だけです。Google公式Python packageはoptional `google-read`、`google-test-write`、`google-production-write` extraに隔離され、base installには入りません。3つのGoogle extraは同じ既存dependency setを再利用し、installだけでOAuthやAPI callを開始しません。

## セットアップ

### uv

```powershell
uv sync --extra dev --frozen
uv run tridentine-calendar-google-sync --help
```

### Windows標準のvenvとpip

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
tridentine-calendar-google-sync --help
```

Mock-only Google read layerを開発時に検証する場合だけ、optional extraを追加します。このinstall自体は認証やAPI callを開始しません。

```powershell
uv sync --extra dev --extra google-read --frozen
uv run pytest -m google_read
```

Windows標準venvとpipでmock layerも検証する場合は次のoptional extrasを使用できます。

```powershell
python -m pip install -e ".[dev,google-read]"
python -m pytest -m google_read
```

Test write mock layerを検証する場合だけ、分離されたoptional extraを使います。InstallだけでOAuthやAPI callは始まりません。

```powershell
uv sync --extra dev --extra google-test-write --frozen
uv run pytest -m google_test_write
```

Production write-token authorization / read-only rehearsal foundationをmockだけで検証する場合は、専用extraを使います。Phase 6D.0のCLI handlerはlive hard-offで、installやtestによるOAuth・browser・Calendar API利用はありません。

```powershell
uv sync --extra dev --extra google-production-write --frozen
uv run pytest -m google_production_write
uv run tridentine-calendar-google-sync authorize-production-write-token --help
uv run tridentine-calendar-google-sync rehearse-production-write-token-readonly --help
```

## CLI

入力には通常のローカルfilesystem pathだけを使用できます。HTTP(S) URL、`file://` URL、symbolic linkは拒否され、file size上限は64 MiBです。入力fileは変更・コピー・再出力されません。

### Source構造の確認

```powershell
tridentine-calendar-google-sync inspect-source `
  --source "<repository外のAccepted HTML ICS path>" `
  --profile accepted-20260814
```

### Accepted profileによるstrict validation

```powershell
tridentine-calendar-google-sync validate-source `
  --source "<repository外のAccepted HTML ICS path>" `
  --profile accepted-20260814
```

両commandは`--format text`または`--format json`を受け付けます。`--output <path>`を指定しない場合は標準出力へ書き、reportをrepository内へ自動保存しません。通常reportにlocal absolute path、raw UID、SUMMARY一覧、DESCRIPTION本文は含まれません。

### Sanitized snapshotとの差分確認

```powershell
tridentine-calendar-google-sync diff-snapshot `
  --source "<repository外のAccepted HTML ICS path>" `
  --profile accepted-20260814 `
  --google-snapshot "<repository外のsanitized snapshot JSON path>" `
  --format text
```

`diff-snapshot`はローカルfileだけを読み、networkへ接続しません。snapshotは`sanitized-google-calendar-v1`形式で、targetは秘密のCalendar IDではなくSHA-256 fingerprintで識別します。通常reportにはraw `iCalUID`、Google event ID、event title、description、local pathを含めません。

### Candidate baselineの作成とinspection

```powershell
tridentine-calendar-google-sync create-baseline-candidate `
  --source "<repository外のAccepted HTML ICS path>" `
  --profile accepted-20260814 `
  --google-snapshot "<repository外のsanitized snapshot path>" `
  --output "<repository外のcandidate baseline path>"

tridentine-calendar-google-sync inspect-baseline `
  --baseline "<repository外のbaseline path>" `
  --format text
```

Candidateはexact zero-difference、全件unchanged、warning 0、snapshot safety counter 0の場合だけ作れます。Baseline fileはraw Source UID inventoryを含むsensitive runtime dataです。`inspect-baseline`はraw UIDを表示しません。

### Explicit trust transition

```powershell
tridentine-calendar-google-sync trust-baseline `
  --candidate "<repository外のcandidate baseline path>" `
  --output "<repository外のtrusted baseline path>" `
  --confirmation "<candidate専用のexact confirmation phrase>"
```

Candidateはownership evidenceになりません。Hash検証済みcandidateと、表示されたexact confirmation phraseが一致した場合だけ、新しいtrusted baseline fileをno-overwriteで作成します。

### Non-executable sync plan

```powershell
tridentine-calendar-google-sync plan-sync `
  --source "<repository外のAccepted HTML ICS path>" `
  --profile accepted-20260814 `
  --google-snapshot "<repository外のsanitized snapshot path>" `
  --trusted-baseline "<repository外のtrusted baseline path>" `
  --output "<repository外のsync plan path>" `
  --format json
```

Threshold defaultはadd/update/deleteすべて`0`です。Plan stateは`draft`、`review_required`、`blocked`のいずれかですが、全stateで`executable=false`です。Delete candidateは常にdestructiveかつseparate approval requiredとして表示されます。

### Offline apply safety

Phase 4Bのcommandは`build-apply-bundle`、`inspect-apply-bundle`、`simulate-apply`、`inspect-operation-journal`です。

Apply bundleを作れるのは、trusted baselineに基づく`draft` zero-action plan、またはfatal guardのない`review_required` add/update planだけです。Delete countが1件でもあるplan、blocked plan、warning付きplan、stale planは拒否されます。

Nonzero test bundleはexact challengeとcurrent plan hashの再照合後にだけ`approved_for_simulation`へ遷移できます。Simulationは`FakeMutationTransport`だけを受け付け、add/updateを順番にmemory内で処理します。Retryはdefault最大5 attemptsで、実時間のsleepは行いません。Failure、uncertain outcome、ETag conflictでは即停止し、後続operationを`skipped`としてjournalへ記録します。Rollbackは提供しません。

Bundle作成時は明示的なtest target labelが必要です。Production environment、Production label、既知のProduction target safe referenceはoperation countが0でもbundle生成前に拒否されます。Production bundle file write、approval、simulation、journal作成も常に拒否されます。詳細は[Offline apply safety](docs/offline-apply-safety.md)を参照してください。

### Test Calendar write foundation

Phase 5Aのcommandは`authorize-test-google-write`、`build-test-write-run-spec`、`inspect-test-write-run-spec`、`run-test-calendar-write`です。OAuthとwrite runnerは`--online`、repository外の専用token / target config、Test targetのexact policy、exact approval phraseを要求します。

Run specはaddまたはupdateを1件だけ含みます。AddはSource UIDを`iCalUID`として保持する`events.import`、updateはchanged fieldsだけをexact ETagの`If-Match`付きで変更する`events.patch`に限定されます。Mutationは1 attemptだけで自動retryせず、read-backまたはread-after-uncertainで確認します。Delete、batch、rollbackはありません。

Phase 5Aではこれらのlive commandを実行していません。将来のTest Calendar利用には、別の明示的なOAuth / API / event-change承認が必要です。詳細は[Test Calendar write transport foundation](docs/test-calendar-write-foundation.md)を参照してください。

### Test Calendar read-only prewrite inspection

`inspect-test-calendar-prewrite`はrepository外のTest target configと分離されたTest write tokenを使い、`events.list`だけでmetadata・event countを取得します。Sanitized snapshot、Human report、JSON reportの3出力をrepository外へno-overwriteで保存し、event count 0の場合だけwrite-readyとします。

```powershell
# REFERENCE ONLY — REQUIRES SEPARATE ONLINE APPROVAL
tridentine-calendar-google-sync inspect-test-calendar-prewrite `
  --online `
  --target-config "<repository外のTest target TOML path>" `
  --token-file "<repository外のTest write token path>" `
  --production-read-token-file "<repository外のProduction read token path>" `
  --snapshot-output "<repository外のprewrite snapshot path>" `
  --human-report-output "<repository外のHuman report path>" `
  --json-report-output "<repository外のJSON report path>"
```

Non-empty Calendarはsafe aggregate countだけを報告してfatal guardで停止し、event本文をconsoleへ出さず、delete・clear・import・patchは行いません。このcommandはmutation approvalやRun Specを要求しませんが、network境界として`--online`は必須です。Phase 5A.1開発中にlive commandは実行していません。

Snapshot outputはprivate `test-calendar-prewrite-snapshot-v1`包装です。後続でcanonical Google snapshotを使う場合は、strict loaderで包装を検証した後の内部`snapshot`を使い、包装fileを通常の`google-snapshot-v1`として直接読み込みません。

### Test-only bootstrap add planning

`build-test-bootstrap-add-plan`は、strictに検証した空のTest prewrite snapshotと`.invalid` UID・Test markerを持つsynthetic Source 1件から、non-executableの専用Bootstrap Planをoffline生成します。通常planが報告する`zero_google_event_count`、`all_events_add`、`mass_change_guard`は抑制せず、許可されたoriginal guard codesとして専用planへ記録します。

`inspect-test-bootstrap-add-plan`はraw UIDやevent本文を出さず、safe reference・aggregate count・hashだけを表示します。`build-test-bootstrap-add-run-spec`はそのplanからadd 1 / update 0 / delete 0の専用private Run Specを作ります。Trusted Baselineが不要なのは完全に空のTest Calendarへの初回addだけです。

Bootstrap成功後はこの経路を再利用せず、Source 1 / Google 1の一致状態から通常のTest baselineを作る予定です。Phase 5C.0ではGoogle APIやTest Calendar writeを実行しません。

### Test-only single-update planning

`build-test-single-update-plan`は、strictに検証したnon-Production Test snapshot、Trusted Test Baseline、synthetic Source 1件から、DESCRIPTIONだけのupdate 1件を表すnon-executable Planをoffline生成します。通常`plan-sync`は同じ1 / 1 diffを引き続き`all_events_update`と`mass_change_guard`でblockし、専用Planはその2件を消去せずoriginal guard evidenceとして保持します。

`inspect-test-single-update-plan`はsafe reference、固定count、changed field、guard evidence、hashだけを表示します。Planはraw UID、本文、Calendar ID、Google event ID、ETag、request payloadを持ちません。

`build-test-single-update-run-spec`は、Trusted Test Baselineとcurrent snapshotに再bindしたprivate Run Specを作ります。Run Specはplanning mode、DESCRIPTION-only、add 0 / update 1 / delete 0に固定され、event IDとexact ETagはcurrent snapshotからだけ取得します。Add、Delete、Productionは到達不能です。実際のpatchには別Stageのexact approvalが必要で、Phase 5D.0ではGoogle APIを呼び出しません。

### Production single-update planning foundation

`inspect-accepted-production-source-manifest`は、別途作成されたAccepted Production Source Manifestをstrictに検証し、repository/tag/commit/ICS/profile/source hashをsafe referenceへ変換して表示します。Manifestは`production=true`、`acceptance_state=accepted`、`synthetic=false`で、cleanなAccepted sourceのexact provenanceとaggregateだけを認めます。

`build-production-single-update-plan`はmanifest、Accepted source/profile、Trusted Production Baseline、同baseline snapshot hashに一致するfull sanitized snapshot、明示的Production target configをofflineで再検証します。全件のうちexactly 1件だけがDESCRIPTION update、少なくとも1件がunrelated unchanged、add/delete/duplicate/ambiguous/unmanaged/fatal/warningがすべて0の場合だけ、non-executable Planを作ります。

`build-production-single-update-run-spec`は同じ入力とPlanを再bindし、UTC-aware `issued_at <= now < expires_at`かつ最大24時間の短命Run Specを作ります。Run Specはsafe UID reference、canonical pre-image hash、Description patch hashを保持しますが、raw UID、SUMMARY、DESCRIPTION、current/desired body、Calendar ID、Google event ID、ETag、payload、endpoint、HTTP methodを保持しません。実際のidentity/content解決とETag取得は、将来の別Phaseがfresh inputをmemory上で再検証した後にだけ行います。

Inspection commandは次の5つです。すべてofflineで、build outputと任意のinspection outputはrepository外へatomic/no-overwriteで保存します。

```powershell
tridentine-calendar-google-sync inspect-accepted-production-source-manifest `
  --manifest "<repository外のAccepted Production manifest path>" `
  --format json

tridentine-calendar-google-sync build-production-single-update-plan `
  --manifest "<repository外のmanifest path>" `
  --source "<repository外のAccepted ICS path>" `
  --profile "<accepted profile id>" `
  --profiles-dir "<repository外のprofile directory>" `
  --google-snapshot "<repository外のfull sanitized snapshot path>" `
  --trusted-baseline "<repository外のtrusted baseline path>" `
  --target-config "<repository外のProduction target TOML path>" `
  --output "<repository外のProduction Plan path>"

tridentine-calendar-google-sync inspect-production-single-update-plan `
  --plan "<repository外のProduction Plan path>" `
  --format text

tridentine-calendar-google-sync build-production-single-update-run-spec `
  --manifest "<repository外のmanifest path>" `
  --source "<repository外のAccepted ICS path>" `
  --profile "<accepted profile id>" `
  --profiles-dir "<repository外のprofile directory>" `
  --google-snapshot "<repository外のfull sanitized snapshot path>" `
  --production-plan "<repository外のProduction Plan path>" `
  --trusted-baseline "<repository外のtrusted baseline path>" `
  --target-config "<repository外のProduction target TOML path>" `
  --output "<repository外のProduction Run Spec path>"

tridentine-calendar-google-sync inspect-production-single-update-run-spec `
  --run-spec "<repository外のProduction Run Spec path>" `
  --format json
```

これらのcommandに`--online`、token、credential、approval phrase、apply/execute optionはありません。Phase 6BはGoogle clientをconstructせず、既存`run-test-calendar-write`へProduction Run Specをdispatchしません。

### Google read-only commands

`authorize-google-readonly`と`fetch-google-snapshot`はPhase 3Aで追加された明示的online commandです。両commandは`--online`を要求し、別途承認されたread-only workflowでだけ利用します。Phase 4Aのbaseline/plan commandから呼び出されることはありません。準備要件とsecret配置方針は[Google read-only setup](docs/google-readonly-setup.md)を参照してください。

将来承認後のcommand syntaxは次の形です。以下はreferenceであり、Phase 3Aでは実行しません。

```powershell
# REFERENCE ONLY — REQUIRES SEPARATE ONLINE APPROVAL
tridentine-calendar-google-sync authorize-google-readonly `
  --online `
  --credentials-file "<repository外のDesktop OAuth client JSON path>" `
  --token-file "<repository外のread-only token JSON path>"

# REFERENCE ONLY — REQUIRES SEPARATE ONLINE APPROVAL
tridentine-calendar-google-sync fetch-google-snapshot `
  --online `
  --token-file "<repository外のread-only token JSON path>" `
  --target-config "<repository外のprivate target TOML path>" `
  --output "<repository外のsanitized snapshot JSON path>"
```

## Accepted asset integration test

Full Accepted HTML ICSはtracked fixtureにしません。検証済みassetをrepository外へ用意し、次の環境変数を明示したときだけintegration testが実行されます。

```powershell
$env:TRIDENTINE_ACCEPTED_HTML_ICS_PATH = "<repository外の検証済みAccepted HTML ICS path>"
uv run pytest tests/test_accepted_asset_integration.py `
  tests/test_offline_diff_accepted_integration.py
```

環境変数が未設定ならtestはskipされ、offline unit test suiteは成功します。環境変数の値はreportやtest failureへ表示しません。CIはこの環境変数を設定せず、Production assetをdownloadしません。

Phase 2のopt-in integration testはAccepted sourceをmemory上のsynthetic Google eventへ変換してdiff engineを検証します。生成したsnapshotをfileへ保存せず、Google APIも呼び出しません。

Phase 4AのProduction candidate integrationは次の2環境変数が明示された場合だけ実行されます。

- `TRIDENTINE_ACCEPTED_HTML_ICS_PATH`
- `TRIDENTINE_PRODUCTION_GOOGLE_SNAPSHOT_PATH`

このtestはcandidateをmemory内で検証するだけで、trust transitionやbaseline/plan file writeを行いません。

Phase 4BのProduction lock integrationは次の4環境変数が明示された場合だけ実行されます。

- `TRIDENTINE_ACCEPTED_HTML_ICS_PATH`
- `TRIDENTINE_PRODUCTION_GOOGLE_SNAPSHOT_PATH`
- `TRIDENTINE_PRODUCTION_TRUSTED_BASELINE_PATH`
- `TRIDENTINE_PRODUCTION_SYNC_PLAN_PATH`

このtestは4入力をstrict loadしてzero-difference planをmemory内で再構築し、Production bundle生成がoperation count 0でも拒否されることと入力byte preservationを検証します。Production bundle、journal、simulation resultを作成・保存しません。

## Exit code

| Code | 意味 |
|---:|---|
| `0` | Sourceはprofileに対してvalid |
| `1` | 安全に分類されたoffline差分あり |
| `2` | CLI引数または設定error |
| `3` | Source parse・validation error |
| `4` | Sanitized snapshotの入力・schema error |
| `5` | SHA・UID・件数・日付範囲などのfatal guard |
| `6` | Google read-only取得・認証のsafe error |
| `8` | 予期しないinternal error |

Validation mismatchは通常の利用時にPython tracebackやfile本文を表示しません。

## 安全性とprivacy

- Credentials、token、Calendar ID、private iCal URL、Google event ID、Production snapshot、stateをcommit・log・issue・Pull Requestへ載せないでください。
- Accepted HTML ICSおよびPlain ICSをcommitしないでください。repository内のICSは架空データだけを使ったsynthetic test fixtureに限定します。
- Repository内のGoogle snapshot fixtureは架空UID・架空event ID・架空fingerprintだけを使い、URLや個人情報を含めません。
- UIDは内部解析時だけ正確に保持し、reportではdomain-separated SHA-256から作る`U-<12 hexadecimal characters>`形式のsafe referenceを使用します。
- Google event IDも内部比較時だけ保持し、reportでは別domainの`G-<12 hexadecimal characters>`形式を使用します。
- SUMMARYとDESCRIPTIONにはtrim、Unicode normalization、HTML整形、URL変更、改行削除を行いません。RFC parserによるline unfoldingとICS escape decodeだけをtransport処理として行います。
- runtime dataはrepository外に保存します。
- OAuth client JSON、authorized-user token、target config、sanitized Production snapshotはすべてrepositoryとGit worktreeの外へ置きます。
- Snapshotはsanitized後もevent本文とopaque IDを含むsensitive runtime dataです。公開artifactやCI artifactにしません。
- Candidate/trusted baselineはraw Source UID inventoryを含むためprivate dataです。Repository、CI artifact、issue、Pull Requestへ載せません。
- Sync plan reportはsafe referencesだけを使用し、raw UID、Google event ID、ETag、event本文、payload、method、endpointを含めません。
- Private apply bundleはraw UID、Google event ID、ETag、managed field payloadを含むため、baselineやsnapshotと同等のsensitive dataです。
- Public apply reportとoperation journalはsafe references・hash・allowlisted outcome codeだけを使用します。
- Test write tokenはProduction read-only tokenと別fileに保存し、scope追加・上書き・再利用を拒否します。
- Test Write Run Specはprivate artifactです。Public report / journalはraw UID、Google event ID、ETag、SUMMARY、DESCRIPTION、payloadを含みません。
- Accepted Production manifest、Production target config、source、snapshot、baseline、Plan、Run Specはrepository外のprivate runtime artifactです。Production Plan/Run Spec inspectionはsafe reference・aggregate・hash・lifetimeだけを表示します。
- Production Run Specにはraw UID、SUMMARY、DESCRIPTION、Calendar ID、Google event ID、ETag、current/desired bodyを保存しません。

詳細は[Security Policy](SECURITY.md)も参照してください。

## 開発時の検証

```powershell
uv run ruff check .
uv run ruff format --check .
uv run mypy --strict src
uv run pytest
uv run python -m build
```

Test実行時もnetwork socketを無効化します。CIはLinux/Windowsそれぞれでbase、optional `google-read`、optional `google-test-write`、optional `google-production-write` mock layerを分離し、credentialsやProduction dataを使用しません。

## Roadmap

Phase 6Cまでに、offline diff、trusted baseline、non-executable plan、fake-only apply safety simulation、Test Calendar write transport、Test-only planning、Accepted Production manifest、Production single-update Plan/Run Spec、mock-only approval state・list/get/patch transport・write-ahead journal / report foundationを実装しました。以下は未実施または未承認です。

1. 分離されたProduction write OAuth / token作成とread-only rehearsal
2. real Production target / scope / token identity検証とGoogle client adapter
3. 自然に発生した正当なDescription-only変更1件の明示承認live update
4. Production Addの別Phase設計・security review・acceptance
5. Production Delete、rollback、syncToken、batch、automationの独立review

## Provenanceとlicense

典礼暦の生成元は[Blue-jp/tridentine_calendar](https://github.com/Blue-jp/tridentine_calendar)、正式配布元は[Blue-jp/tridentine-calendar-ja](https://github.com/Blue-jp/tridentine-calendar-ja)です。本toolはAccepted sourceを入力として扱い、典礼data自体を生成・補正しません。

このrepositoryは[MIT License](LICENSE)で公開します。
