# Offline apply safety

## Scope

Phase 4BはGoogle Calendarへ書き込む機能ではありません。Trusted baselineとnon-executable planからprivate apply bundleを作り、fake transportだけでadd/updateの順序・retry・partial failure・journalを検証します。

Google mutation client、live transport、HTTP method・endpoint、delete operation、Production simulation、rollback executorは存在しません。

## Apply bundle

BundleはSource、snapshot、trusted baseline、planのhash/provenanceを再計算して固定します。Planをそのまま信用せず、同じinputsから再構築したplan hashと一致しなければ拒否します。

Operation kindは`add`と`update`だけです。Add payloadはSource UID、summary、description、start、exclusive endを、update payloadはGoogle event ID、ETag、changed fieldだけを含みます。Raw valueはprivate bundle内部だけに保存され、public inspection reportにはsafe refsとshort hashしか出しません。

Bundleは`production_locked=true`、`execution_enabled=false`です。Test nonzero bundleは`approval_required`、test zero bundleは`draft`になります。Production environment、Production label、既知のProduction target safe referenceはoperation countにかかわらずbundle生成前に拒否されます。

## Approval

Approvalはtest bundleだけが対象です。Challengeはtarget short reference、current plan hash、add/update countに結び付けられます。Approval時にcurrent plan hashを再指定し、stored/recalculated plan hashの両方へ一致させます。

Confirmation mismatch、stale plan、zero bundle、Production bundleは拒否します。Approvalはsimulation stateへ進めるだけで、execution authorityを与えません。

## Fake simulation

`FakeMutationTransport`はmemory内inventoryだけを保持し、`simulate_add`と`simulate_update`だけを提供します。

Retryable outcomeは`rate_limit`、`server_500`、`server_502`、`server_503`です。それ以外のvalidation、permission、target missing、ETag conflict、ambiguous、uncertain、duplicate、permanent failureはretryしません。

Retryはdefault最大5 attemptsです。Delayはabstract unitとしてjournalへ記録し、sleepやnetworkを行いません。Permanent failure、uncertain outcome、ETag conflictでは直ちに停止します。先行successは明示的に残し、後続operationは`skipped`です。Rollbackは`not_available`です。

## Operation journal

Journal entryはoperation ordinal/key、safe refs、attempt、allowlisted outcome、payload hash、expected ETag hash、safe response hash、result state hashだけを保持します。Raw UID、event ID、ETag、payload本文は保持しません。

各entryはprevious hashとentry hashでchainされ、journal全体にもcontent hashがあります。Start markerとstate対応completion markerを必須とし、retry sequence、terminal status、skipped tail、entry orderをsemantic verifierで検査します。

## Production lock

Production inputはactions 0・guards 0・thresholds 0のdraft planとしてoffline inspectionできますが、zero-operationの場合もapply bundle生成を拒否します。Production environment、大小文字を問わないProduction label、既知のProduction target safe referenceを独立したguardで判定します。Production bundle write、approval、simulation、journalも常に拒否します。

Production integration testは4入力fileをstrict loadしてzero-difference planを再構築し、bundle生成拒否とbefore/after hash一致を確認します。Bundle、journal、simulation resultは作成・保存しません。

## Storage and privacy

Private bundleとjournalはrepository外のuser-private directoryへno-overwrite atomic writeします。Public reportsにもCalendar ID、raw identity、ETag、payload、absolute pathを含めません。

Runtime artifactsは`apply-bundles/`、`journals/`、`simulations/`、`*.apply-bundle.json`、`*.operation-journal.json`、`*.simulation.json`としてGitignoreします。
