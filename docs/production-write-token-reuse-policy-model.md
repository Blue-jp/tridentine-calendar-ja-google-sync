# Production write-token 再利用拒否ポリシーの独立モデル

## 目的と今回の境界

このモデルは、認証情報の保存について「失敗した、途中で止まった、完了したか確かめられない」という履歴が与えられたとき、見た目が正常でも、その問題を忘れないための設計を検証するものです。実際の認証情報や保存先は調べません。合成した入力をメモリ上で分類し、どの状態でも `reuse_authorized=False` を返します。

例えば、前回の保存が完了した後、同じ世代の認証情報を更新する別操作が失敗したとします。その後「内容が一致する」「期限内である」「保存関数が2回とも戻った」という観測を追加しても、今回の失敗は解消しません。反対に、失敗していない同じ操作が開始・進行・完了の順に進む様子は表せます。その完了状態も、実際に使ってよいという承認ではありません。

今回の変更は、この仕様書、標準ライブラリだけを使う独立した純粋判定module、合成入力のテストの3ファイルに限定します。新しいUnit番号は確定しません。既存のsession、writer、inspector、CLIには接続せず、それらのruntime moduleを新モデルからimportしません。

## 既存実装・歴史的説明・今回の提案の区別

既存の境界は、[POSIX private-artifact security](posix-private-artifact-security.md) のUnit 4I、4J、4L、4N、4O、4Pと、[read-only rehearsal foundation](production-write-token-readonly-rehearsal-foundation.md) のgeneration、refresh、Linux serializationの各節に基づきます。

| 区分 | この文書での扱い |
| --- | --- |
| 既存のUnit 4P inspector | 内容の一致や期限を観測しても常に再利用未承認。過去の失敗履歴や永続markerは参照しない。今回も未接続のまま。 |
| 既存のrefresh | 同じ認証identityのrefreshではgenerationは変わらない。現在のコードは4Jの再読込検査後に4Lの専用保存経路へ元tokenを期待値として渡す。 |
| 既存のbundle | state、tokenの順に保存し、後続checkpointの失敗もエラー。writerの正常return数はcommit証拠ではない。 |
| 既存のLinux lock | 同じdirectory inodeとprotocolに参加するcaller間の協調型排他。Windowsに同じserializationがあるとは扱わない。 |
| 増分ごとの歴史的説明 | 4I/Jの旧保存経路、4K/Mの未接続、4Nのnew-pair未参加などは各段階の記録。後続の4L/4O統合を取り消した現況説明にしない。 |
| 今回の新しい規則 | 与えられた合成履歴を検査し、未解決の負の証拠を優先するmemory-onlyの状態・拒否理由モデル。既存runtimeがこの規則を強制しているとは主張しない。 |

固定された既存treeのLinux/Python 3.12 CIはrun `35499634580` で成功済みです。既存資料に残る当時のCI未実施の記述を、現在の未実施という判断へ戻しません。その過去の結果を今回の新しい3ファイルの検証結果にも流用しません。

DS-04はPARTIAL、Historical Deep Security ScanはINCOMPLETE、`47194b0` 対象の別scan reportはFAIL、Production gateはBLOCKEDのままです。

## 入力の定義

入口は `evaluate_reuse_policy(value: object)` です。期待する入力は次のfrozen dataclassで組み立てた `PolicyInput` です。入力オブジェクトのフィールドはreprから隠します。任意の入力文字列を分類、理由、例外文、診断へコピーしません。

| 型 | フィールドと意味 |
| --- | --- |
| `SyntheticBinding` | `storage_ref` は管理対象の保存領域、`pair_ref` はtoken/stateの組を指す合成参照。実パスやファイル内容ではない。 |
| `OperationDefinition` | `binding`、今回の `operation_id`、`kind`、`generation_ref`、必要に応じた `predecessor_id`。generationとoperation IDは別の比較軸。 |
| `OperationEvent` | `operation`、1から始まる整数 `ordinal`、固定分類 `kind`。ordinalは同一操作内の申告された段階順であり、実時刻ではない。 |
| `AppearanceObservations` | 正常らしく見える付帯観測。下記の固定フィールドだけを持ち、これだけで状態を完了や承認へ進めない。 |
| `PolicyInput` | 今回評価する `target`、イベントの `history` tuple、`history_status`、`registered`、`observations`。省略時は履歴状態COMPLETE、登録済み、付帯観測は未主張。履歴や登録の信頼性を証明する既定値ではない。 |

参照文字列はASCII英数字と `.`、`_`、`-` だけ、長さ1〜96文字です。`generation_ref` も合成参照で、実tokenの内容・ハッシュ・generation schemaを入力するAPIではありません。秘密、実Calendar ID、個人情報、実パスを入力してはいけません。ラベルの一致は現実のidentity、実ファイルとのbinding、入力者のauthorityを証明しません。

`OperationKind` は `NEW_PAIR` と `REFRESH` の2種類です。同一generationの複数refreshは異なる `operation_id` を持つ別操作として扱います。IDの生成や管理領域の登録方法は実装しません。

`HistoryStatus` は次の閉じた分類です。

| 値 | 合成入力が主張する状態 |
| --- | --- |
| `COMPLETE` | 履歴を検査対象としてすべて渡したという仮定。実際の完全性や認証を証明しない。 |
| `ABSENT` | 履歴がない、または履歴不明。問題なしとは扱わない。 |
| `MISSING` | 必要な履歴の欠落がある。 |
| `CORRUPT` | 履歴が壊れている。 |
| `UNREADABLE` | 履歴を読み取れなかったという入力。モデル自身が読み取りを試すわけではない。 |

付帯観測は `content_matches`、`token_unexpired`、`generation_matches`、`publication_possible`、`completed_output_count`、`time_elapsed`、`previous_process_absent`、`copied_to_other_storage`、`completion_record_visible` です。boolean観測の既定値Falseは「このモデルで肯定されていない」を表し、現実の否定事実ではありません。publicationとcountのNoneも不明であり、不在・無変更ではありません。countは0、1、2の合成値です。

モデルは現在時刻、乱数、環境変数、processの存否、ファイル内容、providerへ問い合わせません。時間経過やprocess不在も、callerが合成入力として渡すだけです。

## 出力と状態の定義

`ReusePolicyDecision` は固定分類だけを返します。`state`、固定理由enumのtuple `reasons`、未解決証拠のboolean `unresolved_failure`、`unresolved_interruption`、`unresolved_commit`、遷移検査のboolean `transitions_valid`、常にFalseの `reuse_authorized` から成ります。

`reuse_authorized` は `Literal[False]`、`init=False` のfrozen fieldであり、通常のコンストラクター引数でTrueを指定できません。credentials、usable session、実行permit、復旧許可は返しません。`transitions_valid=True` は合成イベントがこの規則に従っているという意味だけで、実行承認や現実の証拠の検証成功ではありません。

| `PolicyState` | 意味 |
| --- | --- |
| `UNREGISTERED_OR_UNKNOWN` | 管理状態が未登録、または履歴がなく不明。 |
| `INPUT_UNVERIFIABLE` | 入力型、参照、履歴の内容・つながり・順序などを検証できない。 |
| `START_RECORDED` | 必要な開始記録の成立を合成データ上で仮定した。実保存ではない。 |
| `IN_PROGRESS` | 同じ操作が正常な順序で進行中だが、完了証拠はまだない。 |
| `RECONCILIATION_REQUIRED` | 明示的な失敗または中断があり、このモデルでは解除しない。 |
| `COMMIT_UNCERTAIN` | commitの成立や保存確認・終了処理に未解決の不確実性がある。 |
| `COMPLETION_OBSERVED` | 同一操作の必要な完了証拠が合成入力として成立した。再利用は未承認。 |

正常進行中の未完了と、失敗後の要reconciliationは区別します。前者は、同一操作の次の正常イベントを検査できます。後者を通常のPROGRESSやCOMPLETION_EVIDENCEで正常状態へ戻すことはできません。単なる情報不足を失敗の推定で埋めることも、明示的な失敗を情報不足へ置き換えることもしません。

`RefusalReason` は次の22値です。複数ある場合はenumの定義順で返し、入力配列の並び順や任意文字列を診断順序へ反映しません。

| 固定理由 | 意味 |
| --- | --- |
| `POLICY_NEVER_AUTHORIZES` | このモデル自体に再利用を承認する権限がない。全結果に含む。 |
| `UNREGISTERED` | 管理対象の登録が成立したという入力がない。 |
| `HISTORY_ABSENT` | 履歴が空、またはABSENTという入力。 |
| `HISTORY_MISSING` | 履歴欠落という入力。 |
| `HISTORY_CORRUPT` | 履歴破損という入力。 |
| `HISTORY_UNREADABLE` | 履歴読取不能という入力。 |
| `INVALID_INPUT` | 型、参照、enum、付帯観測などが不正、または入力の主張が矛盾。 |
| `BINDING_MISMATCH` | 操作の保存領域・pair参照がtargetと不一致。 |
| `CONFLICTING_OPERATION` | 同じoperation IDに矛盾する操作定義がある。 |
| `MISSING_CURRENT_OPERATION` | 今回のoperationのイベントがない。 |
| `MISSING_PREDECESSOR` | 指定された前操作の定義・イベントがない。 |
| `INVALID_OPERATION_CHAIN` | 操作のつながりに循環・切断などがある。 |
| `PREDECESSOR_NOT_COMPLETED` | 前操作が有効に完了した履歴になっていない。 |
| `INVALID_EVENT_SEQUENCE` | ordinalが1始まりの連続した一意な番号になっていない。 |
| `MISSING_START` | 最初のイベントが必要な開始証拠ではない。 |
| `INVALID_TRANSITION` | 定義された状態遷移に違反する。 |
| `UNRESOLVED_FAILURE` | 明示的な失敗証拠を保持している。 |
| `UNRESOLVED_INTERRUPTION` | 明示的な中断証拠を保持している。 |
| `UNRESOLVED_COMMIT` | commit不確実性・保存確認失敗・終了処理失敗を保持している。 |
| `START_ONLY` | 開始記録だけで、その後の進行・完了証拠がない。 |
| `OPERATION_INCOMPLETE` | 操作は進行中で、完了証拠がない。 |
| `COMPLETION_NOT_AUTHORIZATION` | 完了証拠を観測しても再利用承認ではない。 |

入口は既知の正確な型だけを検査します。未知オブジェクトの文字列化・比較・反復を診断のために呼び出しません。結果のコンストラクターもstate/reasons/flagの型を検査し、不正なら入力を含まない固定文の `ValueError` を出します。

## イベントと状態遷移

`EventKind` は `START_RECORDED`、`PROGRESS`、`COMPLETION_EVIDENCE`、`FAILED`、`INTERRUPTED`、`COMMIT_UNCERTAIN`、`SAVE_CONFIRMATION_FAILED`、`FINALIZATION_FAILED` の8種類です。

`COMPLETION_EVIDENCE` は、保存確認と終了処理を含む必要な完了証拠が成立したという強い合成仮定です。実際にそれを取得・認証する処理はありません。writerの正常return、count=2、`completion_record_visible=True` だけから、このイベントをモデルが生成することはありません。

同一操作のordinalは1から連続し、各番号にイベントは1つだけです。イベント配列の並び順は正当性や最新性の根拠にしません。申告されたordinalを使って順序を検査し、番号の重複、欠落、開始証拠の欠落、矛盾を正常状態へ補正しません。

| 直前の同一操作の状態 | 次のイベント | 結果 |
| --- | --- | --- |
| 開始証拠なし | ordinal=1の `START_RECORDED` | `START_RECORDED`。 |
| 開始証拠なし | その他 | 遷移不正。認識可能な負の証拠は保持。 |
| `START_RECORDED` | `PROGRESS` | `IN_PROGRESS`。 |
| `IN_PROGRESS` | `COMPLETION_EVIDENCE` | `COMPLETION_OBSERVED`。 |
| `START_RECORDED` または `IN_PROGRESS` | `FAILED` / `INTERRUPTED` | `RECONCILIATION_REQUIRED`。 |
| `START_RECORDED` / `IN_PROGRESS` / `COMPLETION_OBSERVED` | `COMMIT_UNCERTAIN` / `SAVE_CONFIRMATION_FAILED` / `FINALIZATION_FAILED` | `COMMIT_UNCERTAIN`。完了証拠が見えても不確実性を優先。 |
| `RECONCILIATION_REQUIRED` / `COMMIT_UNCERTAIN` | 追加の負の証拠 | 未解決フラグを保持・追加し、必要ならcommit不確実へ強化。 |
| `RECONCILIATION_REQUIRED` / `COMMIT_UNCERTAIN` | 開始・進行・通常の完了 | 遷移不正。未解決の状態・フラグを維持。 |
| `COMPLETION_OBSERVED` | `FAILED` / `INTERRUPTED` | 矛盾した遷移として拒否し、負の証拠も保持。 |
| 上記以外 | 重複開始、段階の飛越し、段階の反復など | 遷移不正。正常状態へ補正しない。 |

解除、recovery、retry、再認証による解決イベントは定義しません。開始なしの進行・完了、STARTから完了への飛越し、失敗後の通常完了、完了後の再開始も許可しません。

## 操作・管理対象・履歴の対応

同じoperation IDのイベントは、binding、種類、generation参照、直前operation IDが同じである必要があります。同じIDを別操作の定義に再利用する入力は矛盾として拒否します。同じordinalの重複も、内容が同じでも拒否します。

複数操作を与える場合、今回のtargetから `predecessor_id` をたどって全操作がつながる必要があります。前操作には有効な完了証拠が必要です。循環、参照先の欠落、切断された操作、別bindingの混入は拒否します。配列の最後にあるイベントや最大のgenerationを「最新」と推測しません。

以前の完了は以前のoperationの証拠だけです。現在の操作が未完了なら完了へ進めず、失敗していれば解除しません。未解決の前操作に新しいIDを付けた操作をつなぐことも、retryやrecoveryとして許可しません。別保存領域へのコピーという付帯観測は、登録・binding・履歴を新しく正当化しません。

## 競合する証拠の優先規則

判定の優先順位は次の通りです。すべての結果の `reuse_authorized` はFalseです。

1. 認識可能なcommit不確実性があれば `COMMIT_UNCERTAIN`。
2. 明示的な失敗または中断があれば `RECONCILIATION_REQUIRED`。
3. 型、参照、履歴状態、binding、重複、順序、predecessor対応などが不正なら `INPUT_UNVERIFIABLE`。
4. 未登録または履歴なしなら `UNREGISTERED_OR_UNKNOWN`。
5. それ以外で、今回の操作の正常な合成段階を返す。

負イベントは、その他の入力検証による拒否へ置き換える前に認識します。同じbatchに不正イベント、不一致binding、壊れた履歴状態が混入しても、認識できた失敗・中断・commit不確実性のフラグを消しません。historyはtupleが必要ですが、不正なlistに認識可能な負イベントが含まれる場合も、その負の証拠を保持して拒否します。この保守的扱いは、不正なbatchを信頼済み履歴へ格上げしたり、別bindingの現実の所有関係を証明したりするものではありません。

拒否理由は、優先された1つの状態とは別に保持します。例えば失敗と不正bindingが競合しても、失敗を「入力不明」に忘れず、不一致という拒否理由も失いません。理由は閉じたenumの固定値に限定し、入力の任意文字列を埋め込みません。

次の情報はいずれも未解決履歴を解除しません。

- token/stateの内容一致、期限内、同一generation。
- 以前の操作や別対象の完了。
- writerが2件とも正常returnしたという観測。
- `publication_possible=False`。
- 時間経過、前processの不在。
- 同じ内容を別保存領域へコピーしたという観測。
- 完了記録が見えること、失敗後に追加された通常の完了イベント。

## 例外の限定的な意味

既存例外の `publication_possible` はFalse、True、Noneの限定的な保存証拠です。Falseはその呼出し自身による最終名への公開試行を行っていないという意味で、providerが何も変えていない、他processが何も保存していない、古い認証情報が使える、ファイルがない、という意味ではありません。Trueも完全なpairの成立ではなく、Noneは不明です。

`completed_output_count` は正常returnしたwriter数です。2であっても、その後のcheckpointやcontext終了に失敗すればbundle成功ではありません。両者は永続したtransaction記録、retry許可、削除許可、復旧承認ではありません。

完了記録の可視性と保存確認・終了失敗が競合する場合、commit不確実性を優先します。正常終了の証拠がないとき、正常終了を推定して埋めません。`completion_record_visible` だけでは `COMPLETION_OBSERVED` にも進めません。

## 合成入力と将来必要な実証拠

このモデルでは、参照・段階番号・履歴状態・登録状態・イベント分類をcallerが渡すものとして仮定しています。dataclassの形やラベル一致の検査は、入力者の権限、記録の真正性、全履歴の取得、現実の保存領域や認証identityの検証ではありません。

将来接続を検討する場合は、開始記録をどこで実際に成立させるか、operation IDをどう生成して重複を防ぐか、誰が記録を認証するか、履歴の欠落・巻戻しをどう検出するか、実ファイルと対象をどう結び付けるか、保存確認と終了処理のどの証拠を完了に必要とするかを別途定義する必要があります。今回の入力形式を、そのまま永続schemaや認証されたjournalに採用したとは扱いません。

新しいオブジェクトへ同じ未解決履歴を渡した判定でも拒否を維持します。判定は入力だけで決まり、module globalへ一時保存した失敗に依存しません。ただし、これはmemory上の再構成テストです。process再起動、crash、電源断後にも履歴が残るという実証ではありません。

## 仕様とテストの対応

新規テストは `tests/test_token_reuse_policy_phase6d1h.py` に置き、実運用データやGoogle関連extraを使わず、既存conftestとsocket制限の下で実行します。表内の名前は同ファイルのテスト関数です。parameterizedな組合せの内容はテスト本体で確認できます。

| 規則 | 対応テスト |
| --- | --- |
| 全7状態、すべて未承認 | `test_every_observed_state_is_a_refusal` |
| NEW_PAIR/REFRESHの開始・進行・完了 | `test_normal_progress_finishes_without_authorization` |
| 許可・拒否するイベント遷移、開始欠落 | `test_exhaustive_core_event_transitions`、`test_missing_start_never_becomes_normal_progress` |
| 失敗・中断・commit不確実性を正常らしい観測で解除しない。内容一致、期限内、同generation、publication=False、count=2、時間経過、process不在、コピー、完了可視性を個別・同時に確認 | `test_normal_looking_observations_never_clear_unresolved_history` |
| 負の状態の後の通常完了を拒否 | `test_later_completion_cannot_release_negative_state` |
| 前回完了と今回失敗、同generationの別refresh | `test_previous_completion_and_same_generation_refresh_are_distinct_operations` |
| 未解決の前操作を後続操作の完了で解除しない | `test_old_failure_dominates_a_later_operations_completion` |
| 別保存領域・別pairの完了で失敗を解除しない | `test_other_target_completion_cannot_clear_failure` |
| 同じoperation IDの定義矛盾 | `test_conflicting_operation_definition_is_rejected` |
| ordinal重複・欠落・不正順序 | `test_explicit_ordinals_reject_duplicate_missing_or_contradictory_order` |
| predecessor欠落・切断・循環・今回操作欠落・未完了前操作 | `test_predecessor_chain_is_explicit_and_required` |
| 配列順を権威にしない | `test_history_permutations_preserve_unresolved_failure_and_explicit_progress` |
| module globalに依存しないmemory再構成 | `test_memory_reconstruction_uses_supplied_history_not_module_global_state` |
| 完了可視性・count=2・publication=Falseと保存確認／終了失敗の競合 | `test_visible_completion_plus_failed_commit_confirmation_is_uncertain` |
| 履歴なし・欠落・破損・読取不能は成功ではない | `test_missing_corrupt_unreadable_history_never_means_success` |
| 未知オブジェクトを拒否し、任意のrepr等を呼び出さない | `test_unknown_objects_are_rejected_without_invoking_untrusted_hooks` |
| 不正型・不正binding・不正ordinal・list履歴・未知隣接イベント等が負の証拠を消さない | `test_malformed_input_cannot_erase_recognized_negative_evidence` |
| 失敗・中断・commit不確実性をすべて保持し、commit不確実性を優先 | `test_competing_negative_classifications_are_all_retained` |
| 固定分類だけを返し、入力任意文字列をrepr・診断へ流さない | `test_result_and_input_repr_never_expose_arbitrary_input_strings` |
| 通常コンストラクター・代入で承認をTrueにできない | `test_authorization_cannot_be_enabled_by_normal_constructor_or_assignment` |
| 不正な結果コンストラクターの例外も固定文で入力を含まない | `test_invalid_result_constructor_has_a_fixed_non_secret_exception` |
| 完了記録の可視性だけでは開始・進行から完了へ進めない | `test_visible_completion_without_completion_evidence_does_not_advance` |
| 空・パス形式・非ASCII・長すぎる合成参照を拒否 | `test_invalid_reference_strings_are_refused_without_rendering` |
| booleanと整数の混同、不正publication値、不正countを変換して受け入れない | `test_invalid_observation_types_and_counts_are_not_coerced` |
| enumに似た文字列を信頼済みラベルとして受け入れない | `test_enum_value_strings_are_unknown_input_not_trusted_labels` |
| 不正な先行イベント・未登録状態を通常イベントで補正しない | `test_invalid_prefix_and_unregistered_status_cannot_be_corrected_by_normal_events` |
| 不正履歴の並べ替えでも固定診断を維持 | `test_invalid_history_permutations_have_the_same_fixed_diagnostics` |
| 全22固定拒否理由に対応する証拠を確認 | `test_every_fixed_refusal_reason_has_corresponding_evidence` |
| runtime未接続、標準ライブラリ限定、I/O・network・permit経路なし | `test_model_has_only_pure_standard_library_dependencies_and_no_runtime_consumer` |

テストによるrepositoryソースの読み取りは、独立モデル本体によるI/Oと区別します。既存inspectorが他runtime moduleから未参照であるという既存テストも維持します。検証時にはPython 3.12、既存workflowと同じmarker条件のbase回帰、Ruff checkとformat check、新moduleのstrict mypyを使います。OSごとの未実施項目、passed、failed、skipped、deselectedを分け、今回の実行結果は作業報告へ記録します。

## 今回未実装の範囲

- 永続記録、journal、marker、開始記録の実保存。
- 記録の信頼の根拠、実ファイルとのbinding、履歴の完全性・認証・巻戻し対策。
- 管理領域の実登録、operation ID生成、本番schema変更、既存token移行、JSON等への永続化API。
- Windows/Linuxの実保存、実lock取得、排他制御、他writerの参加。
- 既存session、writer、inspector、CLIへの接続と、実sessionの再利用拒否。
- controlled reconciliationによる解除、recovery、retry、再認証による解決。
- 実認証、provider側の有効性確認、OAuth、token refresh、Calendar read/write。
- process再起動耐性、crash durability、電源断耐性、実ファイルやproviderの状態の証明。
- Production利用承認、実行permit、復旧許可、セキュリティscan判定の更新。

モデルはファイルの読み書き・置換・削除・権限変更、lock file作成、process起動、network通信を行いません。今回の範囲を終えた後、永続化や実sessionへの接続へ自動的に進みません。
