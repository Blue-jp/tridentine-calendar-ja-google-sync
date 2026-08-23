# Trusted baseline and non-executable plan

## Purpose

Phase 4Aは、過去に人間がexact一致を確認したSource UID inventoryだけをownership evidenceとして保存し、現在のAccepted sourceとsanitized Google snapshotからreview用planを作ります。Baseline・diff・planはoffline処理であり、Google APIやOAuthを呼び出しません。

## Candidate baseline

Candidateを作れるのは次がすべて成立するときだけです。

- Accepted profile、source SHA、event count、UID uniquenessがvalid
- Snapshotがcompleteで、event countとsafety counterが期待どおり
- Source UIDとGoogle iCalUIDが全件一対一
- 全eventが`unchanged`
- Add、update、delete candidate、duplicate、ambiguous、unmanaged、fatalが0
- Warningが0

Candidate fileはsource/snapshot/diff provenance、target fingerprint、raw managed UID inventory、domain-separated content hashを保持します。Google event ID、ETag、summary、description、locationは保存しません。

Candidateはownership evidenceではありません。誤って作成したcandidateからdelete candidateを導出できません。

## Trust transition

Trustはcandidateとは別fileを作る明示的なstate transitionです。Candidate hashとshort target referenceから生成された次の形のconfirmation phraseを完全一致で入力する必要があります。

```text
TRUST BASELINE T-<12 hex> <candidate hash first 12 hex>
```

Trust後はstateを含めてcontent hashを再計算します。Candidate fileをin-placeで上書きしません。Trusted baselineもrepository外へ置き、public reportにはraw UID inventoryを出しません。

## Ownership and current diff

Verified `trusted` baselineだけが`trusted_baseline` evidenceを提供します。現在sourceに存在せずGoogle側だけに残ったiCalUIDがbaseline inventoryに存在する場合に限り、`delete_candidate`になり得ます。

- Baseline inventory外：`unmanaged_google_event`
- Candidate state：planning拒否
- Baseline hash不一致：planning拒否
- Target fingerprint不一致：planning拒否
- Duplicate、recurrence、cancelled、special shape：ambiguousまたはfatal

Accepted tagは将来更新できます。Current source自体が新しいprofileでvalidで、targetとbaseline hashが一致する限り、baseline tagとcurrent tagが異なる遷移をplan provenanceへ記録します。

## Plan states

Plan formatは`non-executable-sync-plan-v1`で、`executable`は常に`false`です。

- `draft`：action 0、fatal guard 0、approval不要
- `review_required`：actionあり、fatal guardなし、人間review必須
- `blocked`：fatal guardあり、処理停止

Default thresholdはadd/update/deleteすべて0です。Threshold超過、全件add/update/delete、1%超または50件超のmass change、ambiguous、duplicate、unmanaged、invalid sourceはplanをblockします。

Delete candidate actionは常に次を持ちます。

- `destructive=true`
- `separate_approval_required=true`
- `trusted_baseline` ownership evidence

Phase 4Aにはapproval command、apply command、Google request body、HTTP method、endpoint、Authorization header、If-Match処理がありません。

## Privacy and storage

Baselineはraw UIDを含むprivate runtime dataです。Planはraw UIDを含みませんが、運用provenanceを含むためrepository外へ保存します。

Human/JSON plan reportが表示できるidentityはdomain-separated `U-…`と`G-…` safe referenceだけです。Event title、description、Google event ID、ETag、Calendar ID、local absolute pathを含めません。Human reportはtargetを`T-…`短縮形で表示します。

次はGitignore対象です。

- `baselines/`
- `plans/`
- `*.baseline.json`
- `*.sync-plan.json`

GitignoreはOS permissionの代替ではありません。Baselineとplanはuser-private directoryへno-overwrite atomic writeし、誤公開時は内容を削除するだけでなく運用影響を再監査してください。
