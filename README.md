# Intel macOS HVF on personal GitHub Actions

A small harness for comparing NeverD's Intel Hypervisor.framework recovery on a personal repository and the organization repository. No Intel Mac is needed locally to dispatch this workflow.

The separate [independent finite Intel HVF API lifecycle control](native/README.md)
has its own manual workflow and eleven-language scope notes. It compares vCPU
and VM recreation using a small real-mode guest with checked finite calls.

Open **Actions → Personal Intel HVF recovery diagnosis → Run workflow**. Defaults:

| Input | Value |
| --- | --- |
| Intel image | `macos-26-intel` (`macos-15-intel` is also available) |
| Tested NeverD source | `bd284894c60427cf4e6a60e661a1fa0df8a070f5` |
| Repetitions | `1000` in one native process; `100` is an optional shorter diagnosis |
| Diagnostic implementation | `5488132130f41822e9f4b3dc41220bc708cc7af4`, pinned in the workflow |

The workflow requires native `x86_64`, a working signed HVF VM/vCPU probe, and `NEVERD_REQUIRE_HVF=1`. It builds only `NeverDHvfTests` with Release and HVF enabled, then uses the original `HvfExecutor.Native*` command, deadlines and assertions. It does not retry failed iterations. NeverD dependency submodule revisions and Actions implementations are pinned. The workflow has read-only repository permissions and does not retain checkout credentials.

Before running the guest, it uploads `provenance.json`, the execution plan, inventory and initial host state. While the original loop runs continuously, it uploads bounded progress copies. A reachable runner also uploads the final raw output, status and child-process retirement records. All artifact names include the run attempt. The legacy `controller_commit` in the diagnostic plan means **this workflow's commit**; `provenance.json` separately identifies the pinned NeverD diagnostic implementation and tested source.

Compare with [organization run 37159724276](https://github.com/NeverSight/NeverD/actions/runs/37159724276): the same tested source and 1,000-loop command, using macOS 26 Intel. That run used diagnostic revision `e4a8169e69eb668ed3795efe4bd5f42cf4f287c2`; this harness uses its updated controller, which additionally reports cancellation during final collection, records each uploader process outcome and collects matching uploader crash reports after failure. NeverD's guest execution code and test deadlines are unchanged between these diagnostic controllers. Queue time and runtime stability are separate observations. A last uploaded iteration is only a persisted prefix, not proof of the failure location. One passing recovery loop does not prove full CPU, macOS or iOS coverage, and a repository change alone does not establish the cause of a lost runner.

The adapted workflow is from [NeverD](https://github.com/NeverSight/NeverD) under **AGPL-3.0-only**. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Modifications dated **2026-10-04** add the personal repository wrapper, fixed upstream checkouts and independent provenance. The runtime source is checked out directly from NeverD.

The separate **Intel artifact uploader control** workflow uploads 16 synthetic snapshots with the same Node 24 runtime and pinned official uploader, without creating a VM or running NeverD. It isolates the upload path; a successful control is not a passing HVF recovery test. Its manifests explicitly record `native_execution=false`.


Observed results from **2026-10-04** are retained with original test-output prefixes and artifact SHA-256 digests in [the evidence summary](results/2026-10-04/summary.json). The full guides below include these results in all eleven languages.

| Run | Purpose | Final result | Retained native evidence |
| --- | --- | --- | --- |
| [37175472452](https://github.com/gmh5225/test_mac_intel/actions/runs/37175472452) | macOS 26 baseline | Upload subprocess failed; native child cancelled and retired | 3 complete / 4 started |
| [37175511460](https://github.com/gmh5225/test_mac_intel/actions/runs/37175511460) | macOS 15 baseline | Upload subprocess failed; native child cancelled and retired | 105 complete / 106 started |
| [37176652285](https://github.com/gmh5225/test_mac_intel/actions/runs/37176652285) | Diagnostic contract check | Fixture readiness race; fixed upstream | No native execution |
| [37176652027](https://github.com/gmh5225/test_mac_intel/actions/runs/37176652027) | macOS 26 with enhanced diagnostics | Hosted runner lost communication | Last snapshot: 175 complete / 176 started |
| [37176990174](https://github.com/gmh5225/test_mac_intel/actions/runs/37176990174) | macOS 15 with corrected fixture | Hosted runner lost communication | Last snapshot: 326 complete / 327 started |
| [37177383621](https://github.com/gmh5225/test_mac_intel/actions/runs/37177383621) | Uploader-only control | 16/16 uploads passed | No native execution |

The native command requested 1,000 repetitions in each recovery run. None of the retained prefixes proves that gate passed or identifies the eventual fault location. The first personal jobs started in 8 and 5 seconds; the earlier organization control also started in 5 seconds. These observations do not establish a repository-level queue-speed improvement. GitHub documents nested virtualization as [experimental and unsupported](https://docs.github.com/en/actions/concepts/runners/github-hosted-runners); that policy alone does not establish this failure's cause.

After the recovery gates pass, **Personal Intel HVF complete validation** runs the upstream transport and CR8 checks, all sixteen CPU shards with independent reconciliation, and the separate Darwin workload gate. `source-ref` pins NeverD, while wrapper and controller revisions are recorded separately. It preserves the original inventories and failure rules; partial recovery results cannot replace full acceptance.

## Native boundary experiments

**Independent upstream Intel HVF control** builds [HVF edge cases](https://gitlab.com/pmdj/hvf-edge-cases/-/tree/f150b38bfff419fe19907b7a6a2d743a63b46a49) at the pinned revision with its unchanged Makefile and real-mode guest. It observes 100000 random interrupt **attempts**, a fixed 900-second limit, PTY output, immutable live snapshots and child retirement. Upstream ignores the random-call return codes and its completion can race the final interrupt, so timeout alone does not identify an HVF fault. This control neither measures NeverD performance nor replaces its recovery, CPU or Darwin gates.

The separate [Intel HVF native boundary experiments](.github/workflows/intel-native-boundary.yml) workflow isolates these paths: `lifecycle` creates and retires the VM/vCPU and mappings without guest execution; `instruction` runs the real startup probe and ordinary checked steps; `finite-deadline` observes finite, expired and short `hv_vcpu_run_until` calls through the original long-mode preparation. It records a fresh native store witness and per-call time, RIP, register and exit-reason observations. Setup and retry use the existing transport; the finite calls themselves bypass the asynchronous watchdog. Unsupported timers and unexpected exits fail the experiment. A successful diagnostic is **not** full native acceptance or evidence that runner disconnects are fixed.

Each dispatch selects one experiment, one of `macos-15-intel` / `macos-26-intel`, and `100` / `1000` repetitions. Source and diagnostic revisions are independently pinned; all three repository identities remain in provenance. Live evidence uploads retain the original whole-process deadline. The opt-in probes require `NEVERD_HVF_INTEL_PROBE=1` and do not change production guest execution.

```sh
gh workflow run intel-native-boundary.yml -R gmh5225/test_mac_intel --ref main \
  -f experiment=finite-deadline -f intel-image=macos-15-intel -f repetitions=100
```

`instruction-reuse` runs the same ordinary-instruction test while retaining one Executor across iterations. VM, vCPU, owner/watchdog threads and native state survive together; each fixture still retires its mappings. The controller isolates diagnostic environment switches. This compares executor lifetimes and cannot attribute a difference solely to VM destruction.

`recovery-reuse` retains the Executor around the original `HvfExecutor.Native*` recovery test, including its actual vCPU destruction/recreation after cancellation. Both reuse modes require exactly one native retention marker in every iteration and reject older source without that evidence. Default `recovery` is unchanged; reuse is diagnostic evidence only. Finite probes keep one fixed overall witness budget across short slices that may expire before guest execution.

## 中文（简体）

**Independent upstream Intel HVF control** 固定公开 HVF 测试程序的版本，保留原 Makefile 与实模式 guest，观察 100000 次随机中断调用尝试。单进程期限固定为 900 秒，保留 PTY 原始输出、实时快照和进程回收记录。上游未检查随机调用的返回码，结束逻辑也可能与最后一次中断竞争，因此超时本身不能证明 HVF 故障；它不代表 NeverD 性能，也不替代恢复、CPU 或 Darwin 验收。

在 Actions 中选择 **Personal Intel HVF recovery diagnosis** 并手动运行，无需本地 Intel Mac。默认使用 `macos-26-intel`，对固定的 NeverD 源码在同一进程连续测试 1,000 轮；也可选择 `macos-15-intel` 或 100 轮诊断。产物保留版本、计划、实时进度和最终结果。排队时间与运行稳定性分别判断；单次恢复测试通过不能代表完整 CPU、macOS 或 iOS 覆盖。[完整指南](https://github.com/NeverSight/NeverD/blob/dev/docs/zh-CN/macos-hvf.md)。

另有 `Intel artifact uploader control` 工作流：连续上传 16 份模拟快照，不启动 VM；它只用于排查上传器，成功不代表 HVF 测试通过。

新增 `Intel HVF native boundary experiments` 工作流：`lifecycle` 只创建和回收 VM/vCPU 与映射，不运行客体；`instruction` 验证真实启动探针和普通指令；`finite-deadline` 使用原有长模式准备，记录有限、过期和短期限调用的原生写入见证、时间、RIP、寄存器和退出原因。有限调用不使用异步 watchdog，准备和重试仍使用原有执行路径。不支持计时器或出现意外退出会失败。每次运行只选一个实验和一个镜像，可选 100/1000 轮；三个仓库版本分别留档。诊断通过不代表完整验收，也不代表失联已经修复。

`instruction-reuse` 执行相同的普通指令测试，跨轮次保留一个执行器，其中 VM、vCPU、工作线程、watchdog 线程和原生状态一同保留；每轮映射仍会回收。控制器隔离诊断环境开关。此对照研究执行器寿命，不能仅据差异归因于 VM 销毁。

`recovery-reuse` 在原有 `HvfExecutor.Native*` 恢复测试外保留执行器，取消后仍真实销毁和重建 vCPU。两个复用模式都要求每轮恰好一个原生保留标记，旧源码缺少证据会失败。默认 `recovery` 不变，复用仅属诊断。有限期限探针对尚未执行客体就到期的短分段继续观察，共用固定总期限。

恢复关卡通过后，**Personal Intel HVF complete validation** 执行上游原有 transport、CR8、16 个 CPU 分片及独立汇总，以及单独的 Darwin 工作负载关卡。`source-ref` 固定 NeverD 源码，入口 workflow 和控制器版本分别记录。保留原始清单与失败规则；部分恢复结果不能替代完整验收。

## 中文（繁體）

**Independent upstream Intel HVF control** 固定公開 HVF 測試程式的版本，保留原 Makefile 與實模式 guest，觀察 100000 次隨機中斷呼叫嘗試。單程序期限固定為 900 秒，保留 PTY 原始輸出、即時快照和程序回收紀錄。上游未檢查隨機呼叫的回傳碼，結束邏輯也可能與最後一次中斷競爭，因此逾時本身不能證明 HVF 故障；它不代表 NeverD 效能，也不取代復原、CPU 或 Darwin 驗收。

在 Actions 選擇 **Personal Intel HVF recovery diagnosis** 手動執行，不需要本機 Intel Mac。預設以 `macos-26-intel` 對固定的 NeverD 原始碼，在同一程序連續測試 1,000 輪；亦可選擇 `macos-15-intel` 或 100 輪診斷。產物保留版本、計畫、即時進度及最終結果。排隊時間與執行穩定性須分別判斷；單次恢復測試通過不代表完整 CPU、macOS 或 iOS 覆蓋。[完整指南](https://github.com/NeverSight/NeverD/blob/dev/docs/zh-TW/macos-hvf.md)。

另有 `Intel artifact uploader control` 工作流程：連續上傳 16 份模擬快照，不啟動 VM；它只用於診斷上傳器，成功不代表 HVF 測試通過。

新增 `Intel HVF native boundary experiments` 工作流程：`lifecycle` 僅建立和回收 VM/vCPU 與映射，不執行客體；`instruction` 驗證真實啟動探針與一般指令；`finite-deadline` 使用原有長模式準備，記錄有限、過期及短期限呼叫的原生寫入見證、時間、RIP、暫存器和退出原因。有限呼叫不使用非同步 watchdog，準備與重試仍使用原有路徑。不支援計時器或意外退出皆失敗。每次只選一個實驗與鏡像，可選 100/1000 輪；三個儲存庫版本分別留存。診斷通過不代表完整驗收或失聯已修復。

`instruction-reuse` 執行相同的一般指令測試，跨輪次保留同一執行器，包含 VM、vCPU、工作執行緒、watchdog 執行緒與原生狀態；每輪仍回收映射。控制器隔離診斷環境開關。此對照研究執行器生命週期，不能僅憑差異歸因於 VM 銷毀。

`recovery-reuse` 在原有 `HvfExecutor.Native*` 復原測試外保留執行器，取消後仍實際銷毀並重建 vCPU。兩種復用模式每輪均須恰有一個原生保留標記，舊原始碼缺少證據即失敗。預設 `recovery` 不變，復用僅屬診斷。有限期限探針對尚未執行客體就到期的短分段繼續觀察，共用固定總期限。

恢復關卡通過後，**Personal Intel HVF complete validation** 執行上游原有 transport、CR8、16 個 CPU 分片及獨立彙總，以及單獨的 Darwin 工作負載關卡。`source-ref` 固定 NeverD 原始碼，入口 workflow 和控制器版本分別記錄。保留原始清單與失敗規則；部分恢復結果不能替代完整驗收。

## 日本語

**Independent upstream Intel HVF control** は公開 HVF テストの版を固定し、元の Makefile と実モード guest を変更せず、100000 回のランダム割り込み呼び出しを試みます。単一プロセスの制限は 900 秒で、PTY 生出力、ライブスナップショット、終了確認を保存します。上流はランダム呼び出しの戻り値を確認せず、終了処理と最後の割り込みにも競合があるため、タイムアウトだけでは HVF 障害を特定できません。NeverD の性能測定や復旧・CPU・Darwin 検証の代わりにはなりません。

Actions で **Personal Intel HVF recovery diagnosis** を手動実行します。手元に Intel Mac は不要です。既定では `macos-26-intel` と固定した NeverD ソースを使い、同じプロセスで 1,000 回連続実行します。`macos-15-intel` と 100 回の診断も選択できます。成果物にはリビジョン、計画、進捗、最終結果を保存します。待ち時間と実行の安定性は別々に評価し、この復旧テストの成功を CPU・macOS・iOS 全体の検証とは扱いません。[詳細ガイド](https://github.com/NeverSight/NeverD/blob/dev/docs/ja/macos-hvf.md)。

`Intel artifact uploader control` は VM を起動せず、合成スナップショットを 16 回アップロードします。アップローダーの診断専用であり、成功しても HVF の検証完了を意味しません。

新しい `Intel HVF native boundary experiments` は、ゲストを実行せず VM/vCPU とマッピングを生成・破棄する `lifecycle`、実際の起動プローブと通常命令を検証する `instruction`、元のロングモード準備を使う `finite-deadline` を分離します。有限・期限切れ・短期限の呼出しごとにネイティブ書込みの証拠、時間、RIP、レジスタ、終了理由を記録します。有限呼出しは非同期 watchdog を使わず、準備と再試行は既存経路です。タイマー非対応や想定外の終了は失敗です。各実行は実験とイメージを一つずつ選び、100/1000回を指定し、三つのリポジトリの版を個別に保存します。診断成功は完全検証や接続喪失の修正を意味しません。

`instruction-reuse` は同じ通常命令テストで一つの Executor を反復間に保持します。VM、vCPU、実行・watchdog スレッドとネイティブ状態を一緒に保持し、各回のマッピングは解放します。診断用環境変数はコントローラーが分離します。実行器の寿命を比較するための対照であり、差異を VM の破棄だけに帰属できません。

`recovery-reuse` は元の `HvfExecutor.Native*` 回復テストの周囲で Executor を保持し、キャンセル後の vCPU の破棄・再生成はそのまま実行します。両方の再利用モードは各回にネイティブ保持マーカーを一つだけ要求し、証拠のない旧ソースを拒否します。既定の `recovery` は変更せず、再利用は診断専用です。有限期限プローブは、ゲスト実行前に短い区間が期限切れになっても、固定された全体期限の中で観測を続けます。

復旧ゲートの合格後、**Personal Intel HVF complete validation** は上流の transport、CR8、全 16 CPU シャードと独立照合、別個の Darwin ワークロードを実行します。`source-ref` は NeverD ソースを固定し、入口 workflow とコントローラーの版は別々に記録します。元の一覧と失敗条件を維持し、部分的な復旧結果を完全な合格の代わりにはしません。

## 한국어

**Independent upstream Intel HVF control**은 공개 HVF 테스트 버전을 고정하고 원래 Makefile과 real mode guest를 그대로 사용하여 임의 인터럽트 호출 100000회를 시도합니다. 한 프로세스의 제한은 900초이며 PTY 원본 출력, 실시간 스냅샷, 프로세스 종료 기록을 보존합니다. 상위 코드는 임의 호출의 반환 코드를 검사하지 않고 마지막 인터럽트와 종료 처리가 경쟁할 수 있으므로 시간 초과만으로 HVF 결함을 단정할 수 없습니다. NeverD 성능 측정이나 복구·CPU·Darwin 검증을 대신하지 않습니다.

Actions에서 **Personal Intel HVF recovery diagnosis**를 수동 실행합니다. 로컬 Intel Mac은 필요하지 않습니다. 기본값은 `macos-26-intel`이며, 고정된 NeverD 소스를 같은 프로세스에서 1,000회 연속 테스트합니다. `macos-15-intel` 또는 100회 진단도 선택할 수 있습니다. 산출물에는 버전, 계획, 진행 상황과 최종 결과가 보존됩니다. 대기 시간과 실행 안정성은 따로 평가해야 하며, 복구 테스트 한 번의 성공이 전체 CPU·macOS·iOS 검증을 의미하지는 않습니다. [전체 안내](https://github.com/NeverSight/NeverD/blob/dev/docs/ko/macos-hvf.md).

`Intel artifact uploader control`은 VM 없이 합성 스냅샷 16개를 업로드합니다. 업로더 진단용이며, 성공해도 HVF 검증 완료를 뜻하지 않습니다.

새 `Intel HVF native boundary experiments`는 게스트 실행 없이 VM/vCPU와 매핑을 생성·회수하는 `lifecycle`, 실제 시작 프로브와 일반 명령을 검증하는 `instruction`, 기존 long mode 준비를 사용하는 `finite-deadline`을 분리합니다. 유한·만료·짧은 기한 호출마다 네이티브 쓰기 증거, 시간, RIP, 레지스터와 종료 이유를 기록합니다. 유한 호출은 비동기 watchdog을 사용하지 않으며 준비와 재시도는 기존 경로입니다. 타이머 미지원과 예기치 않은 종료는 실패입니다. 실행마다 실험과 이미지를 하나씩 선택하고 100/1000회를 지정하며 세 저장소 버전을 독립적으로 보존합니다. 진단 통과는 전체 검증이나 연결 끊김 수정의 증거가 아닙니다.

`instruction-reuse`는 같은 일반 명령 테스트에서 반복 간 하나의 Executor를 유지합니다. VM, vCPU, 실행·watchdog 스레드와 네이티브 상태가 함께 유지되고 매핑은 매회 해제됩니다. 컨트롤러는 진단 환경 변수를 격리합니다. 실행기 수명을 비교하는 대조이므로 차이를 VM 파괴만의 영향으로 단정할 수 없습니다.

`recovery-reuse`는 기존 `HvfExecutor.Native*` 복구 테스트 주위에 Executor를 유지하며 취소 후 실제 vCPU 해제·재생성은 그대로 수행합니다. 두 재사용 모드는 매회 하나의 네이티브 유지 표시를 요구하고, 증거가 없는 이전 소스는 거부합니다. 기본 `recovery`는 변경하지 않으며 재사용은 진단 전용입니다. 유한 기한 프로브는 게스트 실행 전에 짧은 구간이 만료되어도 고정된 전체 기한 내에서 관찰을 이어 갑니다.

복구 관문 통과 후 **Personal Intel HVF complete validation**은 원래 transport 및 CR8 검사, CPU 분할 16개 전체와 독립 대조, 별도 Darwin 작업 부하를 실행합니다. `source-ref`는 NeverD 소스를 고정하며 진입 workflow와 컨트롤러 버전은 따로 기록합니다. 원래 목록과 실패 규칙을 유지하므로 일부 복구 결과는 전체 검증을 대신할 수 없습니다.

## Français

**Independent upstream Intel HVF control** fixe la version d’un test HVF public et conserve son Makefile et son invité en mode réel : 100000 tentatives d’interruption aléatoires, limite fixe de 900 secondes, sortie PTY brute, instantanés en direct et confirmation de fin du processus. Le programme amont ignore les codes de retour des appels aléatoires et sa fin peut entrer en concurrence avec la dernière interruption ; un délai dépassé ne suffit donc pas à identifier une panne HVF. Ce contrôle ne mesure pas les performances de NeverD et ne remplace pas les validations de récupération, CPU ou Darwin.

Lancez **Personal Intel HVF recovery diagnosis** dans Actions, sans Mac Intel local. Par défaut, `macos-26-intel` exécute 1 000 répétitions dans un seul processus avec une révision fixe de NeverD. Vous pouvez aussi choisir `macos-15-intel` ou un diagnostic de 100 répétitions. Les artefacts conservent les révisions, le plan, la progression et le résultat final. Évaluez séparément l'attente et la stabilité ; réussir ce test de récupération ne valide pas toute la couverture CPU, macOS ou iOS. [Guide complet](https://github.com/NeverSight/NeverD/blob/dev/docs/fr/macos-hvf.md).

`Intel artifact uploader control` téléverse 16 instantanés synthétiques sans lancer de VM. Ce contrôle de l’outil de téléversement ne valide pas HVF.

Le nouveau workflow `Intel HVF native boundary experiments` sépare `lifecycle` (création et destruction VM/vCPU et mappings sans invité), `instruction` (sonde initiale réelle et instructions normales) et `finite-deadline` (préparation long mode originale). Les appels à échéance finie, expirée ou courte enregistrent écriture native témoin, temps, RIP, registres et motif de sortie. Les appels finis évitent le watchdog asynchrone ; préparation et reprise gardent le transport existant. Un timer indisponible ou une sortie inattendue fait échouer l’expérience. Chaque lancement choisit une expérience, une image et 100/1000 répétitions ; les trois révisions restent distinctes. Un succès ne prouve ni validation complète ni correction des déconnexions.

`instruction-reuse` exécute le même test d’instructions en conservant un Executor entre les répétitions. VM, vCPU, threads d’exécution et watchdog, ainsi que l’état natif, sont conservés ensemble ; les mappings sont libérés à chaque fois. Le contrôleur isole les variables de diagnostic. Ce contrôle compare la durée de vie de l’exécuteur sans attribuer une différence à la seule destruction de VM.

`recovery-reuse` conserve l’Executor autour du test original `HvfExecutor.Native*`, qui détruit et recrée toujours le vCPU après annulation. Les deux modes de réutilisation exigent un unique marqueur natif par répétition et rejettent les anciennes sources sans cette preuve. Le mode `recovery` par défaut reste inchangé ; la réutilisation sert uniquement au diagnostic. Les sondes finies gardent un budget global fixe lorsque des tranches courtes expirent avant l’exécution de l’invité.

Après les contrôles de récupération, **Personal Intel HVF complete validation** exécute les vérifications amont transport et CR8, les seize lots CPU avec rapprochement indépendant et le contrôle Darwin distinct. `source-ref` fixe NeverD ; les révisions du workflow et du contrôleur sont consignées séparément. Les inventaires et règles d’échec d’origine sont conservés ; une récupération partielle ne remplace pas la validation complète.

## Deutsch

**Independent upstream Intel HVF control** verwendet eine feste Version eines öffentlichen HVF-Tests mit unverändertem Makefile und Real-Mode-Gast: 100000 zufällige Interrupt-Aufrufversuche, feste 900-Sekunden-Frist, rohe PTY-Ausgabe, laufende Momentaufnahmen und bestätigtes Prozessende. Der Ursprungscode prüft die Rückgabewerte der zufälligen Aufrufe nicht; zudem kann sein Abschluss mit dem letzten Interrupt konkurrieren. Ein Zeitablauf allein belegt daher keinen HVF-Fehler. Der Kontrolllauf misst keine NeverD-Leistung und ersetzt keine Wiederherstellungs-, CPU- oder Darwin-Abnahme.

Starten Sie **Personal Intel HVF recovery diagnosis** manuell unter Actions; ein eigener Intel-Mac ist nicht erforderlich. Standardmäßig führt `macos-26-intel` mit einer festgelegten NeverD-Revision 1.000 Wiederholungen in einem Prozess aus. Alternativ sind `macos-15-intel` oder 100 Wiederholungen möglich. Artefakte sichern Revisionen, Plan, Fortschritt und Endergebnis. Wartezeit und Laufzeitstabilität werden getrennt bewertet. Ein erfolgreicher Wiederherstellungstest bestätigt keine vollständige CPU-, macOS- oder iOS-Abdeckung. [Vollständige Anleitung](https://github.com/NeverSight/NeverD/blob/dev/docs/de/macos-hvf.md).

`Intel artifact uploader control` lädt 16 synthetische Snapshots ohne VM hoch. Dieser Upload-Test bestätigt bei Erfolg keine HVF-Funktionalität.

Der neue Workflow `Intel HVF native boundary experiments` trennt `lifecycle` (VM/vCPU und Mappings erzeugen und beenden, ohne Gast), `instruction` (echte Startprobe und normale Instruktionen) und `finite-deadline` (ursprüngliche Long-Mode-Vorbereitung). Aufrufe mit endlicher, abgelaufener oder kurzer Frist protokollieren native Schreibmarker, Zeit, RIP, Register und Austrittsgrund. Endliche Aufrufe umgehen den asynchronen Watchdog; Vorbereitung und Wiederholung behalten den bestehenden Transport. Fehlender Timer oder unerwarteter Austritt bedeutet Fehler. Jeder Start wählt eine Untersuchung, ein Image und 100/1000 Wiederholungen; drei Revisionen bleiben getrennt. Erfolg belegt weder vollständige Abnahme noch behobene Verbindungsabbrüche.

`instruction-reuse` führt denselben Instruktionstest aus und behält einen Executor zwischen den Wiederholungen. VM, vCPU, Ausführungs- und Watchdog-Threads sowie nativer Zustand bleiben gemeinsam bestehen; die Mappings werden jeweils freigegeben. Der Controller isoliert die Diagnose-Umgebungsvariablen. Der Vergleich untersucht die Executor-Lebensdauer und kann Unterschiede nicht allein der VM-Zerstörung zuordnen.

`recovery-reuse` behält den Executor um den ursprünglichen Test `HvfExecutor.Native*`; nach Abbruch wird die vCPU weiterhin tatsächlich zerstört und neu erstellt. Beide Wiederverwendungsmodi verlangen genau einen nativen Marker pro Runde und lehnen ältere Quellen ohne diesen Nachweis ab. Das normale `recovery` bleibt unverändert; Wiederverwendung ist nur Diagnose. Endliche Proben behalten eine feste Gesamtfrist, auch wenn kurze Abschnitte vor der Gastausführung ablaufen.

Nach bestandenen Wiederherstellungstests führt **Personal Intel HVF complete validation** die ursprünglichen Transport- und CR8-Prüfungen, alle sechzehn CPU-Teile mit unabhängigem Abgleich sowie die separate Darwin-Prüfung aus. `source-ref` fixiert NeverD; Workflow- und Controller-Version werden getrennt erfasst. Ursprüngliche Inventare und Fehlerregeln bleiben erhalten; Teilergebnisse ersetzen keine vollständige Abnahme.

## Español

**Independent upstream Intel HVF control** fija una versión de un test HVF público y conserva su Makefile y huésped en modo real: 100000 intentos de interrupción aleatoria, límite fijo de 900 segundos, salida PTY original, instantáneas en directo y confirmación de finalización del proceso. El programa original no comprueba los códigos de retorno aleatorios y su finalización puede competir con la última interrupción; un tiempo agotado no identifica por sí solo un fallo de HVF. No mide el rendimiento de NeverD ni sustituye las validaciones de recuperación, CPU o Darwin.

Ejecute manualmente **Personal Intel HVF recovery diagnosis** en Actions; no necesita un Mac Intel local. Por defecto, `macos-26-intel` ejecuta 1.000 repeticiones en un solo proceso con una revisión fija de NeverD. También puede elegir `macos-15-intel` o un diagnóstico de 100 repeticiones. Los artefactos conservan las revisiones, el plan, el progreso y el resultado final. Evalúe por separado la espera y la estabilidad: superar esta prueba de recuperación no valida toda la cobertura de CPU, macOS o iOS. [Guía completa](https://github.com/NeverSight/NeverD/blob/dev/docs/es/macos-hvf.md).

`Intel artifact uploader control` carga 16 instantáneas sintéticas sin iniciar una VM. Este diagnóstico de carga no valida HVF aunque termine correctamente.

El nuevo workflow `Intel HVF native boundary experiments` separa `lifecycle` (crear y retirar VM/vCPU y mapeos sin huésped), `instruction` (sondeo inicial real e instrucciones normales) y `finite-deadline` (preparación original en long mode). Las llamadas con plazo finito, vencido o corto registran escritura nativa testigo, tiempo, RIP, registros y motivo de salida. Las llamadas finitas evitan el watchdog asíncrono; preparación y reintento conservan el transporte original. Un temporizador no compatible o una salida inesperada hace fallar el experimento. Cada ejecución elige un experimento, una imagen y 100/1000 repeticiones; se conservan tres revisiones independientes. El éxito no demuestra aceptación completa ni desconexiones corregidas.

`instruction-reuse` ejecuta la misma prueba de instrucciones conservando un Executor entre repeticiones. VM, vCPU, hilos de ejecución y watchdog y estado nativo se conservan juntos; los mapeos se liberan cada vez. El controlador aísla las variables de diagnóstico. Esta comparación estudia la vida del ejecutor y no permite atribuir diferencias únicamente a la destrucción de VM.

`recovery-reuse` conserva el Executor durante la prueba original `HvfExecutor.Native*`, que sigue destruyendo y recreando la vCPU tras la cancelación. Ambos modos de reutilización exigen un único marcador nativo por repetición y rechazan fuentes antiguas sin esa prueba. El modo `recovery` predeterminado no cambia; la reutilización es solo diagnóstica. Los sondeos finitos conservan un plazo total fijo cuando intervalos cortos vencen antes de ejecutar el huésped.

Tras superar la recuperación, **Personal Intel HVF complete validation** ejecuta las comprobaciones originales de transport y CR8, los dieciséis fragmentos CPU con conciliación independiente y la comprobación Darwin separada. `source-ref` fija NeverD; las revisiones del workflow y del controlador se registran por separado. Conserva los inventarios y las reglas de fallo originales; la recuperación parcial no sustituye la aceptación completa.

## Italiano

**Independent upstream Intel HVF control** fissa la versione di un test HVF pubblico, mantenendone Makefile e guest in modalità reale: 100000 tentativi di interruzione casuale, limite fisso di 900 secondi, output PTY originale, istantanee in tempo reale e conferma della terminazione del processo. Il codice originale ignora i valori restituiti dalle chiamate casuali e la conclusione può concorrere con l’ultima interruzione; un timeout da solo non identifica quindi un guasto HVF. Il controllo non misura le prestazioni di NeverD né sostituisce le verifiche di ripristino, CPU o Darwin.

Avviare manualmente **Personal Intel HVF recovery diagnosis** da Actions; non serve un Mac Intel locale. Per impostazione predefinita, `macos-26-intel` esegue 1.000 ripetizioni in un unico processo su una revisione fissa di NeverD. Sono disponibili anche `macos-15-intel` e una diagnosi di 100 ripetizioni. Gli artefatti conservano revisioni, piano, avanzamento e risultato finale. Valutare separatamente l'attesa e la stabilità: il successo di questo test di recupero non convalida l'intera copertura CPU, macOS o iOS. [Guida completa](https://github.com/NeverSight/NeverD/blob/dev/docs/it/macos-hvf.md).

`Intel artifact uploader control` carica 16 istantanee sintetiche senza avviare una VM. Il successo di questa diagnosi del caricamento non convalida HVF.

Il nuovo workflow `Intel HVF native boundary experiments` separa `lifecycle` (creazione e ritiro di VM/vCPU e mapping senza guest), `instruction` (sonda iniziale reale e istruzioni normali) e `finite-deadline` (preparazione originale in long mode). Le chiamate con scadenza finita, scaduta o breve registrano scrittura nativa di riscontro, tempi, RIP, registri e motivo di uscita. Le chiamate finite evitano il watchdog asincrono; preparazione e ripetizione mantengono il trasporto originale. Timer non supportato o uscita inattesa fanno fallire l’esperimento. Ogni avvio sceglie un esperimento, un’immagine e 100/1000 ripetizioni; tre revisioni restano distinte. Il successo non dimostra accettazione completa o disconnessioni risolte.

`instruction-reuse` esegue lo stesso test di istruzioni mantenendo un Executor tra le ripetizioni. VM, vCPU, thread di esecuzione e watchdog e stato nativo rimangono insieme; i mapping sono liberati ogni volta. Il controller isola le variabili diagnostiche. Il confronto riguarda la durata dell’esecutore e non attribuisce eventuali differenze alla sola distruzione della VM.

`recovery-reuse` mantiene l’Executor intorno al test originale `HvfExecutor.Native*`, che continua a distruggere e ricreare la vCPU dopo l’annullamento. Entrambe le modalità di riuso richiedono esattamente un marcatore nativo per ripetizione e rifiutano sorgenti precedenti senza tale prova. Il normale `recovery` non cambia; il riuso è soltanto diagnostico. Le sonde finite conservano una scadenza complessiva fissa quando intervalli brevi scadono prima dell’esecuzione guest.

Dopo il superamento dei controlli di recupero, **Personal Intel HVF complete validation** esegue i controlli originali transport e CR8, tutti i sedici gruppi CPU con riconciliazione indipendente e il controllo Darwin separato. `source-ref` fissa NeverD; le revisioni di workflow e controller sono registrate separatamente. Mantiene inventari e regole di errore originali; il recupero parziale non sostituisce l’accettazione completa.

## Русский

**Independent upstream Intel HVF control** фиксирует версию общедоступного теста HVF, сохраняя исходные Makefile и гостя в реальном режиме: 100000 попыток случайного прерывания, единый предел 900 секунд, исходный вывод PTY, текущие снимки и подтверждение завершения процесса. Исходный код не проверяет результаты случайных вызовов; завершение может конкурировать с последним прерыванием. Поэтому один тайм-аут не доказывает сбой HVF. Этот контроль не измеряет производительность NeverD и не заменяет проверки восстановления, CPU или Darwin.

Запустите **Personal Intel HVF recovery diagnosis** вручную в Actions; собственный Intel Mac не нужен. По умолчанию `macos-26-intel` выполняет 1 000 повторений в одном процессе для фиксированной ревизии NeverD. Можно выбрать `macos-15-intel` или диагностику из 100 повторений. Артефакты сохраняют ревизии, план, ход выполнения и итог. Время ожидания и стабильность выполнения оцениваются отдельно: успешный тест восстановления не подтверждает полное покрытие CPU, macOS или iOS. [Полное руководство](https://github.com/NeverSight/NeverD/blob/dev/docs/ru/macos-hvf.md).

`Intel artifact uploader control` загружает 16 синтетических снимков без запуска VM. Успех этой проверки загрузчика не означает успешную проверку HVF.

Новый workflow `Intel HVF native boundary experiments` разделяет `lifecycle` (создание и освобождение VM/vCPU и отображений без гостя), `instruction` (реальная стартовая проба и обычные инструкции) и `finite-deadline` (исходная подготовка long mode). Вызовы с конечным, истёкшим и коротким сроком записывают нативную запись-маркер, время, RIP, регистры и причину выхода. Конечные вызовы обходят асинхронный watchdog; подготовка и повтор используют прежний транспорт. Неподдерживаемый таймер или неожиданный выход означает ошибку. Каждый запуск выбирает один опыт, образ и 100/1000 повторов; три ревизии сохраняются отдельно. Успех не доказывает полную приёмку или исправление потери связи.

`instruction-reuse` выполняет тот же тест инструкций, сохраняя один Executor между повторами. VM, vCPU, рабочий поток, watchdog и нативное состояние сохраняются вместе; отображения освобождаются каждый раз. Контроллер изолирует диагностические переменные среды. Этот опыт сравнивает время жизни исполнителя и не позволяет приписать различие только уничтожению VM.

`recovery-reuse` сохраняет Executor вокруг исходного теста `HvfExecutor.Native*`, который по-прежнему уничтожает и создаёт vCPU после отмены. Оба режима повторного использования требуют ровно один нативный маркер в каждом повторе и отклоняют старый код без такого доказательства. Обычный `recovery` не меняется; повторное использование служит только диагностике. Конечные пробы сохраняют общий неизменный срок, даже когда короткий интервал истекает до выполнения гостя.

После прохождения проверок восстановления **Personal Intel HVF complete validation** выполняет исходные проверки transport и CR8, все шестнадцать частей CPU с независимой сверкой и отдельную проверку Darwin. `source-ref` фиксирует NeverD; версии workflow и контроллера записываются отдельно. Исходные списки и правила ошибок сохранены; частичное восстановление не заменяет полную приёмку.

## العربية

يثبّت **Independent upstream Intel HVF control** إصدار اختبار HVF عام ويحافظ على Makefile والضيف في الوضع الحقيقي دون تعديل: 100000 محاولة استدعاء مقاطعة عشوائية، ومهلة ثابتة قدرها 900 ثانية، ومخرجات PTY الأصلية، ولقطات مباشرة، وتأكيد انتهاء العملية. لا يفحص البرنامج الأصلي قيم إرجاع الاستدعاءات العشوائية، وقد يتسابق الإنهاء مع آخر مقاطعة؛ لذلك لا يثبت انتهاء المهلة وحده خللًا في HVF. لا يقيس هذا الاختبار أداء NeverD ولا يحل محل اختبارات الاستعادة أو CPU أو Darwin.

شغّل **Personal Intel HVF recovery diagnosis** يدوياً من Actions؛ لا تحتاج إلى جهاز Mac بمعالج Intel محلياً. يستخدم الإعداد الافتراضي `macos-26-intel` لتنفيذ 1,000 تكرار متتالٍ في عملية واحدة على إصدار محدد من NeverD. ويمكن اختيار `macos-15-intel` أو تشخيص من 100 تكرار. تحفظ ملفات النتائج الإصدارات والخطة والتقدم والنتيجة النهائية. يُقيّم وقت الانتظار واستقرار التنفيذ كلٌّ على حدة؛ نجاح اختبار الاستعادة هذا لا يثبت اكتمال تغطية CPU أو macOS أو iOS. [الدليل الكامل](https://github.com/NeverSight/NeverD/blob/dev/docs/ar/macos-hvf.md).

يرفع `Intel artifact uploader control` ست عشرة لقطة اصطناعية دون تشغيل VM. هذا فحص لأداة الرفع فقط، ولا يعني نجاحه اجتياز اختبارات HVF.

يفصل workflow الجديد `Intel HVF native boundary experiments` بين `lifecycle` لإنشاء VM/vCPU والتعيينات وتحريرها دون تشغيل ضيف، و`instruction` لمجس البدء الحقيقي والتعليمات العادية، و`finite-deadline` مع إعداد long mode الأصلي. تسجل الاستدعاءات ذات الموعد المحدد أو المنتهي أو القصير شاهد كتابة أصلية والوقت وRIP والسجلات وسبب الخروج. تتجاوز الاستدعاءات المحددة watchdog غير المتزامن، بينما يبقى الإعداد وإعادة المحاولة على المسار الأصلي. يفشل الاختبار عند عدم دعم المؤقت أو الخروج غير المتوقع. يختار كل تشغيل تجربة وصورة واحدة و100/1000 تكرار، مع حفظ إصدارات المستودعات الثلاثة مستقلة. النجاح لا يثبت قبولًا كاملًا أو إصلاح انقطاع الاتصال.

English: [full NeverD guide](https://github.com/NeverSight/NeverD/blob/dev/docs/macos-hvf.md).

يشغّل `instruction-reuse` اختبار التعليمات نفسه مع الاحتفاظ بكائن Executor واحد بين التكرارات. تُحفظ VM وvCPU وخيوط التنفيذ وwatchdog والحالة الأصلية معًا، بينما تُحرَّر التعيينات في كل مرة. يعزل المتحكم متغيرات التشخيص. تقارن التجربة عمر المنفّذ ولا تسمح بإرجاع أي فرق إلى تدمير VM وحده.

يحتفظ `recovery-reuse` بكائن Executor حول اختبار الاستعادة الأصلي `HvfExecutor.Native*`، مع استمرار تدمير vCPU وإعادة إنشائه بعد الإلغاء. يتطلب وضعا إعادة الاستخدام علامة أصلية واحدة بالضبط في كل تكرار، ويرفضان الشيفرة القديمة التي تفتقر إلى هذا الدليل. يبقى وضع `recovery` الافتراضي دون تغيير، وإعادة الاستخدام للتشخيص فقط. تحافظ المجسات المحددة زمنيًا على موعد إجمالي ثابت حتى عندما تنتهي فترة قصيرة قبل تنفيذ الضيف.

بعد اجتياز فحوص الاستعادة، يشغّل **Personal Intel HVF complete validation** فحوص transport وCR8 الأصلية، وجميع أجزاء CPU الستة عشر مع مطابقة مستقلة، وفحص Darwin المنفصل. يثبت `source-ref` مصدر NeverD، وتُسجَّل إصدارات workflow والمتحكم بصورة مستقلة. تبقى القوائم وقواعد الفشل الأصلية؛ ولا تحل نتائج الاستعادة الجزئية محل القبول الكامل.

[2026-10-04: independently audited Intel boundary and upstream results, all 11 languages](results/2026-10-04-investigation.md).

### vCPU recreation control

`experiment=instruction-vcpu-recreate` · `source-ref=74e3b59a1fceec59e8190b1280216b63c89c9dea` · `repetitions=1000` · `intel-image=macos-15-intel` / `macos-26-intel`

**en.** The same `909672ca6` candidate passed instruction-reuse1000 on both images, with complete native logs and retirement (37194478425, 37194538616). The next opt-in `instruction-vcpu-recreate` diagnostic retains VM and owner thread but recreates the vCPU after every original startup/32-NOP workload. It requires four ordered native lifecycle markers per iteration with continuous generation and the same owner, plus final Executor retirement and process exit. 1000 iterations mean 1000 recreations and 1001 vCPU generations; the final unused generation is destroyed on exit. This compares lifetimes and does not change production acceptance.

**zh-CN.** 同一 `909672ca6` 候选在两个镜像上均通过 instruction-reuse1000，完整原生日志和回收记录已核验（37194478425、37194538616）。下一项显式诊断 `instruction-vcpu-recreate` 保留 VM 和 owner 线程，在每轮原始启动探针及 32 条 NOP 后重建 vCPU。每轮必须有四个有序的原生生命周期标记、连续代际和同一 owner，最后还须证明 Executor 销毁及进程退出。1000 轮对应 1000 次重建、1001 代 vCPU，最后未执行 guest 的一代在退出时销毁。这是生命周期对照，不改变生产验收。

**zh-TW.** 同一 `909672ca6` 候選在兩個映像上均通過 instruction-reuse1000，完整原生紀錄與程序回收已核驗（37194478425、37194538616）。下一項明確啟用的診斷 `instruction-vcpu-recreate` 保留 VM 與 owner 執行緒，每輪原始啟動探針及 32 條 NOP 後重建 vCPU。每輪必須有四個有序原生生命週期標記、連續世代及相同 owner，最後須證明 Executor 銷毀與程序結束。1000 輪對應 1000 次重建、1001 代 vCPU；最後未執行 guest 的一代在結束時銷毀。此為生命週期對照，不改變正式驗收。

**ja.** 同じ候補 `909672ca6` は両イメージで instruction-reuse1000 に合格し、完全なログとプロセス回収を確認しました（37194478425、37194538616）。次の任意診断 `instruction-vcpu-recreate` は VM と所有スレッドを保持し、元の起動プローブと 32 個の NOP ごとに vCPU を再生成します。各回に順序どおりの 4 個のネイティブライフサイクル記録、連続した世代、同じ owner が必要で、最後に Executor の破棄とプロセス終了も要求します。1000 回は 1000 回の再生成、1001 世代を意味し、最後の未実行世代は終了時に破棄します。製品の合格条件は変更しません。

**ko.** 동일한 후보 `909672ca6`이 두 이미지의 instruction-reuse1000을 통과했고 전체 로그와 프로세스 회수를 검증했습니다（37194478425, 37194538616）. 다음 선택 진단 `instruction-vcpu-recreate`는 VM과 소유 스레드를 유지하고 원래 시작 프로브와 32개 NOP 작업마다 vCPU를 다시 만듭니다. 매회 순서가 맞는 네 개의 네이티브 수명 표시, 연속 세대와 동일 owner가 필요하며 마지막 Executor 소멸과 프로세스 종료도 확인합니다. 1000회는 재생성 1000회와 vCPU 1001세대를 뜻하며, 실행하지 않은 마지막 세대는 종료 시 소멸합니다. 제품 승인 조건은 바꾸지 않습니다.

**fr.** Le même candidat `909672ca6` a réussi instruction-reuse1000 sur les deux images, avec journaux complets et processus récupérés (37194478425, 37194538616). Le diagnostic facultatif suivant, `instruction-vcpu-recreate`, conserve VM et thread propriétaire, mais recrée le vCPU après chaque sonde de démarrage originale et 32 NOP. Il exige quatre marqueurs natifs ordonnés par itération, des générations continues, le même owner et la destruction finale de l’Executor suivie de la sortie du processus. 1000 itérations représentent 1000 recréations et 1001 générations ; la dernière, non exécutée, est détruite à la sortie. Les critères d’acceptation du produit restent inchangés.

**de.** Derselbe Kandidat `909672ca6` bestand instruction-reuse1000 auf beiden Images mit vollständigen Logs und eingesammelten Prozessen (37194478425, 37194538616). Die nächste optionale Diagnose `instruction-vcpu-recreate` behält VM und Besitzerthread bei, erstellt die vCPU aber nach ursprünglicher Startprobe und 32 NOPs jedes Durchlaufs neu. Sie verlangt vier geordnete native Lebenszyklusmarkierungen pro Durchlauf, lückenlose Generationen, denselben owner sowie abschließende Executor-Zerstörung und Prozessende. 1000 Durchläufe ergeben 1000 Neuerstellungen und 1001 Generationen; die letzte, unbenutzte Generation wird beim Beenden zerstört. Die Produktabnahme bleibt unverändert.

**es.** El mismo candidato `909672ca6` superó instruction-reuse1000 en ambas imágenes, con registros completos y procesos recogidos (37194478425, 37194538616). El siguiente diagnóstico opcional, `instruction-vcpu-recreate`, conserva VM e hilo propietario y recrea la vCPU tras cada sonda de inicio original y 32 NOP. Exige cuatro marcadores nativos ordenados por iteración, generaciones continuas, el mismo owner, destrucción final de Executor y salida del proceso. 1000 iteraciones equivalen a 1000 recreaciones y 1001 generaciones; la última no ejecutada se destruye al salir. Los criterios de aceptación del producto no cambian.

**it.** Lo stesso candidato `909672ca6` ha superato instruction-reuse1000 su entrambe le immagini, con log completi e processi raccolti (37194478425, 37194538616). Il prossimo diagnostico facoltativo, `instruction-vcpu-recreate`, mantiene VM e thread proprietario, ricreando la vCPU dopo ogni sonda iniziale originale e 32 NOP. Richiede quattro marcatori nativi ordinati per iterazione, generazioni continue, lo stesso owner, distruzione finale di Executor e uscita del processo. 1000 iterazioni producono 1000 ricreazioni e 1001 generazioni; l’ultima inutilizzata viene distrutta all’uscita. I criteri di accettazione del prodotto restano invariati.

**ru.** Тот же кандидат `909672ca6` прошёл instruction-reuse1000 на обоих образах; полные журналы и сбор процессов проверены (37194478425, 37194538616). Следующая необязательная диагностика `instruction-vcpu-recreate` сохраняет VM и поток-владелец, но пересоздаёт vCPU после каждой исходной стартовой пробы и 32 NOP. Нужны четыре упорядоченных нативных события на итерацию, последовательные поколения, неизменный owner и окончательное уничтожение Executor с выходом процесса. 1000 итераций означают 1000 пересозданий и 1001 поколение; последнее неиспользованное поколение уничтожается при выходе. Критерии приёмки продукта не меняются.

**ar.** نجح المرشح نفسه `909672ca6` في instruction-reuse1000 على الصورتين، مع تدقيق السجلات الكاملة وجمع العمليات (37194478425، 37194538616). يحتفظ التشخيص الاختياري التالي `instruction-vcpu-recreate` بالـVM والخيط المالك، ويعيد إنشاء vCPU بعد كل مجس بدء أصلي و32 تعليمة NOP. يشترط أربع علامات أصلية مرتبة لكل تكرار وأجيالًا متتابعة وowner ثابتًا، ثم تدمير Executor النهائي وخروج العملية. تعني 1000 دورة 1000 إعادة إنشاء و1001 جيل؛ ويُدمَّر الجيل الأخير الذي لم ينفذ الضيف عند الخروج. لا تتغير شروط قبول المنتج.

### VM recreation control

`experiment=instruction-vm-recreate` · `source-ref=9eccca62dc22b5df7a1d2d15f01488d35821f1ba` · `repetitions=1000` · `intel-image=macos-15-intel` / `macos-26-intel`

**en.** Both lifecycle controls now passed 1000/1000 on both Intel images: vCPU recreation (37195529270, 37195554929) and VM plus vCPU recreation on one retained owner (37196504453, 37196535787). The latter has 8000 ordered native events and final generation 1001 retirement per run; all 24/27 artifact digests, zero native/controller exits and child retirement were verified. This narrows the comparison with full Executor turnover but neither identifies the cause nor proves a production fix. The next diagnostic will retain the VM while replacing the vCPU and owner thread; original recovery and full CPU/Darwin acceptance remain required.

**zh-CN.** 两项生命周期对照现已在两套 Intel 镜像上均通过 1000/1000 轮：仅重建 vCPU（37195529270、37195554929），以及保留同一 owner、重建 VM 和 vCPU（37196504453、37196535787）。后一项每次运行均包含 8000 个有序原生事件及第 1001 代的最终销毁；24/27 个产物摘要、原生与控制器正常退出、子进程回收均已核验。这缩小了与完整 Executor 周转的比较范围，但尚未定位原因或证明生产修复。下一项诊断将保留 VM、更换 vCPU 和 owner 线程；原始恢复及完整 CPU/Darwin 验收仍须通过。

**zh-TW.** 兩項生命週期對照現已在兩套 Intel 映像上均通過 1000/1000 輪：僅重建 vCPU（37195529270、37195554929），以及保留相同 owner、重建 VM 與 vCPU（37196504453、37196535787）。後者每次執行均包含 8000 個有序原生事件及第 1001 代的最終銷毀；24/27 個產物摘要、原生與控制器正常退出、子程序回收均已核驗。這縮小了與完整 Executor 更替的比較範圍，但尚未定位原因或證明正式修復。下一項診斷將保留 VM、更換 vCPU 與 owner 執行緒；原始恢復及完整 CPU/Darwin 驗收仍須通過。

**ja.** 両 Intel イメージで、vCPU 再生成（37195529270、37195554929）と同じ owner 上での VM・vCPU 再生成（37196504453、37196535787）が、それぞれ 1000/1000 回に合格しました。後者では各実行の 8000 個のネイティブイベントの順序と最終第 1001 世代の破棄、24/27 個の成果物ハッシュ、ネイティブ処理・制御側の終了コード 0、子プロセス回収を確認しました。Executor 全体の再生成との差を絞る証拠であり、原因や製品修正の証明ではありません。次は VM を保持して vCPU と owner スレッドを交換します。元の回復試験と完全な CPU/Darwin 検証は引き続き必要です。

**ko.** 두 Intel 이미지에서 vCPU 재생성(37195529270, 37195554929)과 같은 owner에서 VM 및 vCPU 재생성(37196504453, 37196535787)이 각각 1000/1000회를 통과했습니다. 후자는 실행마다 네이티브 이벤트 8000개의 순서, 마지막 1001세대 소멸, 산출물 해시 24/27개, 네이티브·제어기 종료 코드 0과 자식 프로세스 회수를 검증했습니다. 전체 Executor 교체와의 차이를 좁히는 근거이며 원인이나 제품 수정의 증명은 아닙니다. 다음 진단은 VM을 유지하고 vCPU와 owner 스레드를 교체합니다. 원래 복구 시험과 전체 CPU/Darwin 검증은 여전히 필요합니다.

**fr.** Les deux contrôles ont désormais réussi 1000/1000 fois sur les deux images Intel : recréation du vCPU (37195529270, 37195554929), puis de la VM et du vCPU avec le même owner (37196504453, 37196535787). Ce dernier comprend 8000 événements natifs ordonnés et la destruction finale de la génération 1001 par exécution ; les 24/27 empreintes, les sorties natives et du contrôleur à zéro et la collecte des processus ont été vérifiées. Cela précise la comparaison avec le renouvellement complet d’Executor sans identifier la cause ni prouver une correction. Le prochain diagnostic conservera la VM et remplacera le vCPU et son thread propriétaire. La récupération originale et la validation CPU/Darwin complète restent nécessaires.

**de.** Beide Lebenszyklusvergleiche bestanden jetzt auf beiden Intel-Images jeweils 1000/1000 Durchläufe: vCPU-Neuerstellung (37195529270, 37195554929) sowie VM- und vCPU-Neuerstellung bei gleichem owner (37196504453, 37196535787). Letztere belegt je Lauf 8000 geordnete native Ereignisse und die abschließende Zerstörung von Generation 1001; alle 24/27 Artefakt-Hashes, Rückgabecodes null und das Einsammeln der Kindprozesse wurden geprüft. Das grenzt den Vergleich mit vollständigem Executor-Wechsel ein, beweist aber weder Ursache noch Produktkorrektur. Als Nächstes bleiben die VM erhalten und werden vCPU und Besitzer-Thread ersetzt. Originaler Wiederherstellungstest und vollständige CPU/Darwin-Abnahme bleiben erforderlich.

**es.** Ambos controles de ciclo de vida superaron ya 1000/1000 iteraciones en las dos imágenes Intel: recreación de vCPU (37195529270, 37195554929) y de VM más vCPU conservando el mismo owner (37196504453, 37196535787). El segundo acredita 8000 eventos nativos ordenados y la destrucción final de la generación 1001 por ejecución; se verificaron las 24/27 huellas, las salidas nativas y del controlador a cero y la recogida de los procesos. Esto acota la comparación con la sustitución completa de Executor, pero no identifica la causa ni demuestra una corrección. El siguiente diagnóstico conservará la VM y sustituirá vCPU e hilo propietario. Siguen pendientes la recuperación original y la validación CPU/Darwin completa.

**it.** Entrambi i controlli hanno ora superato 1000/1000 iterazioni sulle due immagini Intel: ricreazione della vCPU (37195529270, 37195554929) e di VM più vCPU con lo stesso owner (37196504453, 37196535787). Il secondo documenta 8000 eventi nativi ordinati e la distruzione finale della generazione 1001 per esecuzione; sono stati verificati tutti i 24/27 hash, le uscite native e del controllore a zero e la raccolta dei processi. Ciò restringe il confronto con il rinnovo completo di Executor, senza identificare la causa o dimostrare una correzione. Il prossimo diagnostico manterrà la VM e sostituirà vCPU e thread proprietario. Restano necessari il recupero originale e la validazione CPU/Darwin completa.

**ru.** Оба сравнения жизненного цикла прошли по 1000/1000 итераций на обоих образах Intel: пересоздание vCPU (37195529270, 37195554929) и VM вместе с vCPU при сохранении owner (37196504453, 37196535787). Во втором проверены 8000 упорядоченных нативных событий и окончательное уничтожение поколения 1001 на запуск, все 24/27 хешей артефактов, нулевые коды выхода и сбор дочерних процессов. Это сужает сравнение с полной заменой Executor, но не устанавливает причину и не доказывает исправление. Следующая диагностика сохранит VM, заменяя vCPU и поток-владелец. Исходный тест восстановления и полная приёмка CPU/Darwin по-прежнему необходимы.

**ar.** نجح الآن ضابطا دورة الحياة في 1000/1000 تكرار على صورتي Intel: إعادة إنشاء vCPU ‏(37195529270، 37195554929)، ثم VM وvCPU مع الاحتفاظ بالمالك نفسه (37196504453، 37196535787). يثبت الثاني 8000 حدث أصلي مرتب وتدمير الجيل 1001 النهائي في كل تشغيل؛ ودُققت بصمات الملفات الـ24/27، ورموز الخروج الصفرية، وجمع العمليات الفرعية. يضيّق ذلك المقارنة مع تبديل Executor بالكامل، لكنه لا يحدد السبب ولا يثبت إصلاح المنتج. سيحتفظ التشخيص التالي بالـVM ويستبدل vCPU والخيط المالك. يبقى اختبار الاسترداد الأصلي والتحقق الكامل لـCPU/Darwin مطلوبين.

### Owner-thread recreation control

`source-ref=9e74b172a3b9eb391d24af09a086a337f8fd88c9` · `owner-failure-controls: repetitions=100` · `instruction-owner-recreate: repetitions=1000` · `macos-15-intel` / `macos-26-intel`

**en.** The next diagnostic is `instruction-owner-recreate`: retain VM, replace the vCPU and owner after each unchanged instruction workload. First run `owner-failure-controls` with 100 repetitions (300 injected checks, real HVF calls but no guest execution); require verified cleanup before the 1000-round guest experiment. Neither mode replaces original acceptance.

**zh-CN.** 下一项诊断为 `instruction-owner-recreate`：保留 VM，在每轮不变的指令负载后更换 vCPU 和 owner。先运行 100 轮 `owner-failure-controls`（300 项注入检查，调用真实 HVF，但不执行 guest），核验清理完成后再跑 1000 轮指令实验。两者均不替代原始验收。

**zh-TW.** 下一項診斷為 `instruction-owner-recreate`：保留 VM，在每輪不變的指令負載後更換 vCPU 與 owner。先執行 100 輪 `owner-failure-controls`（300 項注入檢查，呼叫真實 HVF，但不執行 guest），核驗清理完成後再跑 1000 輪指令實驗。兩者均不取代原始驗收。

**ja.** 次の診断 `instruction-owner-recreate` は VM を保持し、元の指令負荷ごとに vCPU と owner を交換します。先に `owner-failure-controls` を100回実施し（300件の障害注入確認、実際のHVF呼び出し、guest実行なし）、後処理を検証してから1000回の指令実験を行います。元の受け入れ試験の代わりにはなりません。

**ko.** 다음 진단 `instruction-owner-recreate`는 VM을 유지하고 기존 명령 부하마다 vCPU와 owner를 교체합니다. 먼저 `owner-failure-controls`를 100회 실행합니다(300개 오류 주입 검사, 실제 HVF 호출, guest 실행 없음). 정리를 검증한 뒤 1000회 명령 실험을 진행하며 원래 승인 시험을 대체하지 않습니다.

**fr.** Le prochain diagnostic `instruction-owner-recreate` conserve la VM et remplace vCPU et owner après chaque charge inchangée. Exécuter d’abord 100 tours de `owner-failure-controls` (300 vérifications injectées, appels HVF réels sans guest), vérifier le nettoyage puis lancer les 1000 tours avec guest. Aucun mode ne remplace la validation originale.

**de.** Der nächste Vergleich `instruction-owner-recreate` behält die VM und ersetzt vCPU und owner nach jeder unveränderten Instruktionslast. Zuerst laufen 100 Wiederholungen von `owner-failure-controls` (300 injizierte Prüfungen, echte HVF-Aufrufe ohne Gast). Erst nach bestätigter Bereinigung folgen 1000 Gastdurchläufe. Die ursprüngliche Abnahme bleibt erforderlich.

**es.** El siguiente diagnóstico `instruction-owner-recreate` conserva VM y sustituye vCPU y owner tras cada carga original. Primero se ejecutan 100 rondas de `owner-failure-controls` (300 comprobaciones con fallos inyectados, llamadas HVF reales sin guest); tras verificar la limpieza, se realizan 1000 rondas con guest. No sustituyen la aceptación original.

**it.** Il prossimo diagnostico `instruction-owner-recreate` mantiene VM e sostituisce vCPU e owner dopo ogni carico originale. Prima eseguire 100 cicli di `owner-failure-controls` (300 verifiche con errori iniettati, chiamate HVF reali senza guest); verificata la pulizia, eseguire 1000 cicli con guest. Non sostituiscono la validazione originale.

**ru.** Следующая диагностика `instruction-owner-recreate` сохраняет VM и заменяет vCPU и owner после каждой исходной нагрузки. Сначала выполняются 100 повторений `owner-failure-controls` (300 проверок внедрённых ошибок, реальные вызовы HVF без гостя). После проверки очистки запускаются 1000 повторений с гостем. Исходная приёмка остаётся обязательной.

**ar.** يحتفظ التشخيص التالي `instruction-owner-recreate` بالـVM ويبدّل vCPU والمالك بعد كل حمل تعليمات أصلي. يُشغّل أولًا `owner-failure-controls` مئة مرة (300 فحص بأخطاء محقونة، واستدعاءات HVF حقيقية دون تنفيذ الضيف)، ثم يُتحقق من التنظيف قبل تجربة الضيف ذات 1000 تكرار. لا يحل أي منهما محل القبول الأصلي.

**en.** Owner turnover did not complete its 1000-round experiment: the uploader crashed on macOS 15 with SIGTRAP in V8 string parsing (37198629082), and on macOS 26 with SIGSEGV in V8 scope lookup (37198630903). The controller then cancelled and reaped the native processes; the saved logs show 24/25 and 467/468 completed/started iterations, without a native assertion or final native result. Both runners stayed reachable and supplied matched crash reports. These are observer-triggered interruptions, not verified native passes or confirmed runner losses. The cause remains unknown; compare upload-only controls before changing the backend.

**zh-CN.** 线程更换实验未完成 1000 轮：macOS 15 上传器在 V8 字符串解析中触发 SIGTRAP（37198629082），macOS 26 上传器在 V8 作用域查找中触发 SIGSEGV（37198630903）。控制器随后取消并回收原生进程；保存的日志分别显示 24/25、467/468 轮完成/开始，没有原生断言或最终原生结果。两台 runner 均保持在线并提供匹配的崩溃报告。这属于观察器触发的中断，既不是已验证的原生通过，也不是已确认的 runner 失联。原因仍未知；先用纯上传对照比较，再决定后端变更。

**zh-TW.** 執行緒更換實驗未完成 1000 輪：macOS 15 上傳器在 V8 字串解析中觸發 SIGTRAP（37198629082），macOS 26 上傳器在 V8 作用域查找中觸發 SIGSEGV（37198630903）。控制器隨後取消並回收原生程序；保存的日誌分別顯示 24/25、467/468 輪完成/開始，沒有原生斷言或最終原生結果。兩台 runner 均保持連線並提供匹配的崩潰報告。這屬於觀察器觸發的中斷，既不是已驗證的原生通過，也不是已確認的 runner 失聯。原因仍未知；先以純上傳對照比較，再決定後端變更。

**ja.** owner 交代の1000回実験は未完了です。macOS 15のアップローダーはV8文字列解析中にSIGTRAP（37198629082）、macOS 26はV8スコープ検索中にSIGSEGV（37198630903）で停止し、制御側がネイティブ処理を中止・回収しました。保存記録は完了/開始24/25、467/468回で、ネイティブのアサーションや最終結果はありません。両runnerは接続を保ち、一致するクラッシュ報告を提供しました。観測側による中断であり、ネイティブ合格やrunner切断の証明ではありません。原因は未確定で、バックエンド変更前にアップロードのみの対照と比較します。

**ko.** owner 교체 1000회 실험은 완료되지 않았습니다. macOS 15 업로더는 V8 문자열 구문 분석에서 SIGTRAP(37198629082), macOS 26은 V8 범위 검색에서 SIGSEGV(37198630903)로 중단됐고 제어기가 네이티브 프로세스를 취소·회수했습니다. 보존 로그는 완료/시작 24/25회와 467/468회이며 네이티브 단언 실패나 최종 결과는 없습니다. 두 runner 모두 연결을 유지하며 일치하는 충돌 보고서를 제공했습니다. 관찰기 때문에 중단된 것으로 네이티브 통과나 runner 연결 단절의 증거가 아닙니다. 원인은 미확정이며 백엔드를 바꾸기 전에 업로드 전용 대조와 비교합니다.

**fr.** Les 1000 tours de changement d’owner sont incomplets : l’uploader a subi SIGTRAP dans l’analyse de chaînes V8 sur macOS 15 (37198629082) et SIGSEGV dans la recherche de portée V8 sur macOS 26 (37198630903). Le contrôleur a alors annulé et collecté les processus natifs. Les journaux montrent 24/25 et 467/468 tours terminés/commencés, sans assertion native ni résultat final. Les runners sont restés joignables avec des rapports de crash concordants. Ce sont des interruptions par l’observateur, pas des validations natives ni des pertes de runner confirmées. La cause reste inconnue ; comparer les contrôles sans VM avant de modifier le backend.

**de.** Der owner-Wechsel beendete die 1000 Runden nicht: Der Uploader erlitt SIGTRAP beim V8-Stringparsen auf macOS 15 (37198629082) und SIGSEGV bei der V8-Scope-Suche auf macOS 26 (37198630903). Der Controller brach daraufhin die nativen Prozesse ab und sammelte sie ein. Gesichert sind 24/25 bzw. 467/468 beendete/gestartete Runden ohne native Assertion oder Endergebnis. Beide Runner blieben erreichbar und lieferten passende Crashberichte. Das sind vom Beobachter ausgelöste Abbrüche, keine nativen Erfolge oder bestätigten Runner-Verluste. Die Ursache ist offen; vor Backend-Änderungen werden reine Upload-Kontrollen verglichen.

**es.** El cambio de owner no completó 1000 rondas: el uploader sufrió SIGTRAP al analizar cadenas V8 en macOS 15 (37198629082) y SIGSEGV al buscar ámbitos V8 en macOS 26 (37198630903). El controlador canceló y recogió los procesos nativos. Los registros conservan 24/25 y 467/468 rondas completadas/iniciadas, sin aserción nativa ni resultado final. Ambos runners siguieron accesibles y entregaron informes coincidentes. Son interrupciones del observador, no aprobaciones nativas ni pérdidas confirmadas del runner. La causa sigue abierta; se compararán controles de solo subida antes de cambiar el backend.

**it.** Il cambio di owner non ha completato 1000 cicli: l’uploader ha subito SIGTRAP nell’analisi delle stringhe V8 su macOS 15 (37198629082) e SIGSEGV nella ricerca degli scope V8 su macOS 26 (37198630903). Il controllore ha annullato e raccolto i processi nativi. I log conservano 24/25 e 467/468 cicli completati/avviati, senza asserzione nativa o risultato finale. Entrambi i runner sono rimasti raggiungibili con rapporti di crash corrispondenti. Sono interruzioni dell’osservatore, non successi nativi o perdite confermate del runner. La causa resta ignota; confrontare controlli di solo caricamento prima di modificare il backend.

**ru.** Эксперимент смены owner не завершил 1000 повторений: загрузчик получил SIGTRAP при разборе строк V8 на macOS 15 (37198629082) и SIGSEGV при поиске области видимости V8 на macOS 26 (37198630903). Контроллер остановил и собрал нативные процессы. Сохранены 24/25 и 467/468 завершённых/начатых итераций без нативной ошибки проверки или итогового результата. Оба runner остались доступны и предоставили соответствующие отчёты о сбое. Это прерывания наблюдателем, а не нативные успехи или подтверждённая потеря runner. Причина не установлена; до изменения backend нужны сравнения с контролем только загрузки.

**ar.** لم تكتمل تجربة تبديل المالك ذات 1000 دورة: تعطل الرافع بإشارة SIGTRAP أثناء تحليل نصوص V8 على macOS 15 ‏(37198629082)، وبإشارة SIGSEGV أثناء بحث نطاق V8 على macOS 26 ‏(37198630903). ألغى المتحكم العمليات الأصلية وجمعها. تثبت السجلات 24/25 و467/468 دورة مكتملة/بدأت، دون فشل تحقق أصلي أو نتيجة أصلية نهائية. بقي runner متصلًا في الحالتين وقدّم تقرير تعطل مطابقًا. هذه مقاطعات سببها المراقب وليست نجاحًا أصليًا أو فقد اتصال مؤكدًا. السبب مجهول؛ تُقارن ضوابط الرفع وحده قبل تعديل الخلفية.
