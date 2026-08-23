# 1960年ローマ典礼暦・日本語版 Google Calendar差分同期ツール

`Google Calendar Differential Sync Tool for the 1960 Roman Liturgical Calendar – Japanese Edition`

Accepted Japanese Roman liturgical calendarを、将来Google Calendarと安全に差分同期するための専用tool repositoryです。

## Phase 3Aの範囲

Phase 3AはPhase 2のoffline比較機能に、最小権限Google read-only取得の安全なcode foundationを追加します。OAuth、API、browser、networkを使うtestはなく、公式client境界はすべてmockで検証します。

**現時点ではonline commandを実行しないでください。Phase 3A中のOAuth認証開始およびGoogle Calendar API呼出しは未承認です。**

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
- Production dataを含まないsynthetic fixture test

### Not implemented

- 実際のOAuth認証、browser起動、Google Calendar API call、Production接続
- `syncToken`、state persistence
- applyおよびadd/update/delete execution
- Production synchronization

Phase 3Aの開発・testではGoogle Calendarへ接続せず、Google Calendarを読み取りも書き換えもしません。`delete_candidate`は分類名にすぎず、削除操作を生成・実行しません。

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

### Google read-only commands

`authorize-google-readonly`と`fetch-google-snapshot`はPhase 3Aの安全設計・mock test対象として追加されています。両commandは明示的な`--online`を要求しますが、**現時点では実行禁止**です。将来の別承認後にだけ利用します。準備要件とsecret配置方針は[Google read-only setup](docs/google-readonly-setup.md)を参照してください。

将来承認後のcommand syntaxは次の形です。以下はreferenceであり、Phase 3Aでは実行しません。

```powershell
# DO NOT RUN IN PHASE 3A
tridentine-calendar-google-sync authorize-google-readonly `
  --online `
  --credentials-file "<repository外のDesktop OAuth client JSON path>" `
  --token-file "<repository外のread-only token JSON path>"

# DO NOT RUN IN PHASE 3A
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

Phase 3Aまでに、offline diffとmock検証済みread-only取得foundationを実装しました。以下は未実装または未承認であり、別のreviewと明示的な許可が必要です。

1. 実accountでの最小権限OAuth authorization
2. 明示承認されたtest targetに対する初回read-only fetch
3. 専用test Calendarに限定したwrite検証
4. Production apply、delete、syncToken、automation

## Provenanceとlicense

典礼暦の生成元は[Blue-jp/tridentine_calendar](https://github.com/Blue-jp/tridentine_calendar)、正式配布元は[Blue-jp/tridentine-calendar-ja](https://github.com/Blue-jp/tridentine-calendar-ja)です。本toolはAccepted sourceを入力として扱い、典礼data自体を生成・補正しません。

このrepositoryは[MIT License](LICENSE)で公開します。
