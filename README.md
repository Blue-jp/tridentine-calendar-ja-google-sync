# 1960年ローマ典礼暦・日本語版 Google Calendar差分同期ツール

`Google Calendar Differential Sync Tool for the 1960 Roman Liturgical Calendar – Japanese Edition`

Accepted Japanese Roman liturgical calendarを、将来Google Calendarと安全に差分同期するための専用tool repositoryです。

## Phase 4Bの範囲

Phase 4Bはtrusted baselineとnon-executable planに、test環境限定のprivate apply bundle、fake-only mutation simulation、tamper-evident operation journalを追加します。すべてoffline処理であり、Google API mutation clientは存在しません。

Phase 4Bの開発・testはOAuth、Google API、browser、networkを使用しません。Fake transportはmemory内の架空inventoryだけを変更し、外部Calendarへ接続しません。

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

### Not implemented

- Google Calendar write scopeおよびwrite method
- Test Calendar / Production Calendarへのapply
- add/update/delete executionとexecutable plan
- Google mutation transport、HTTP request、live executor
- Delete operation model・payload・transport method
- `syncToken`、incremental state、automation

Phase 4Bのbundle/simulationもGoogle Calendarへ接続せず、Google Calendarを書き換えません。Private bundleは将来の安全検討用payloadを保持しますが、execution enabledは常にfalseで、method・endpoint・Authorization headerを持ちません。

Production ICS、Production snapshot、runtime stateをrepositoryへcommitしないでください。入力はrepository外のローカルfileとして明示的に渡します。

## 必要環境

- Python `>=3.12,<3.13`
- 対応platform：WindowsおよびLinux

Base runtime dependencyは`icalendar`と`pydantic`だけです。Google公式Python packageはoptional `google-read` extraに隔離され、base installには入りません。

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

Nonzero test bundleはexact challengeとcurrent plan hashの再照合後にだけ`approved_for_simulation`へ遷移できます。Simulationは`FakeMutationTransport`だけを受け付け、add/updateを順番にmemory内で処理します。Failure、uncertain outcome、ETag conflictでは即停止し、後続operationを`skipped`としてjournalへ記録します。Rollbackは提供しません。

Productionではzero-operation bundleをmemory内で検証できるだけです。Production bundle file write、approval、simulation、journal作成は常に拒否されます。詳細は[Offline apply safety](docs/offline-apply-safety.md)を参照してください。

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

Phase 4BのProduction zero-bundle integrationは次の4環境変数が明示された場合だけ実行されます。

- `TRIDENTINE_ACCEPTED_HTML_ICS_PATH`
- `TRIDENTINE_PRODUCTION_GOOGLE_SNAPSHOT_PATH`
- `TRIDENTINE_PRODUCTION_TRUSTED_BASELINE_PATH`
- `TRIDENTINE_PRODUCTION_SYNC_PLAN_PATH`

このtestは4入力をstrict loadし、memory内zero bundleと入力byte preservationを検証します。Production bundle、journal、simulation resultを保存しません。

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

詳細は[Security Policy](SECURITY.md)も参照してください。

## 開発時の検証

```powershell
uv run ruff check .
uv run ruff format --check .
uv run mypy --strict src
uv run pytest
uv run python -m build
```

Test実行時もnetwork socketを無効化します。CIはLinux/Windowsそれぞれでbase layerとoptional `google-read` mock layerを分離し、credentialsやProduction dataを使用しません。

## Roadmap

Phase 4Bまでに、offline diff、trusted baseline、non-executable plan、fake-only apply safety simulationを実装しました。以下は未実装または未承認です。

1. Production baseline candidateの別承認によるtrusted化
2. Live request payload生成とconditional request検証
3. 専用test Calendarに限定したwrite検証
4. Production apply、delete、syncToken、automation

## Provenanceとlicense

典礼暦の生成元は[Blue-jp/tridentine_calendar](https://github.com/Blue-jp/tridentine_calendar)、正式配布元は[Blue-jp/tridentine-calendar-ja](https://github.com/Blue-jp/tridentine-calendar-ja)です。本toolはAccepted sourceを入力として扱い、典礼data自体を生成・補正しません。

このrepositoryは[MIT License](LICENSE)で公開します。
