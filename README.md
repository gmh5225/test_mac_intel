# Intel macOS HVF on personal GitHub Actions

A small harness for comparing NeverD's Intel Hypervisor.framework recovery on a personal repository and the organization repository. No Intel Mac is needed locally to dispatch this workflow.

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

## Native boundary experiments

The separate [Intel HVF native boundary experiments](.github/workflows/intel-native-boundary.yml) workflow isolates these paths: `lifecycle` creates and retires the VM/vCPU and mappings without guest execution; `instruction` runs the real startup probe and ordinary checked steps; `finite-deadline` observes finite, expired and short `hv_vcpu_run_until` calls through the original long-mode preparation. It records a fresh native store witness and per-call time, RIP, register and exit-reason observations. Setup and retry use the existing transport; the finite calls themselves bypass the asynchronous watchdog. Unsupported timers and unexpected exits fail the experiment. A successful diagnostic is **not** full native acceptance or evidence that runner disconnects are fixed.

Each dispatch selects one experiment, one of `macos-15-intel` / `macos-26-intel`, and `100` / `1000` repetitions. Source and diagnostic revisions are independently pinned; all three repository identities remain in provenance. Live evidence uploads retain the original whole-process deadline. The opt-in probes require `NEVERD_HVF_INTEL_PROBE=1` and do not change production guest execution.

```sh
gh workflow run intel-native-boundary.yml -R gmh5225/test_mac_intel --ref main \
  -f experiment=finite-deadline -f intel-image=macos-15-intel -f repetitions=100
```

`instruction-reuse` runs the same ordinary-instruction test while retaining one Executor across iterations. VM, vCPU, owner/watchdog threads and native state survive together; each fixture still retires its mappings. The controller isolates diagnostic environment switches. This compares executor lifetimes and cannot attribute a difference solely to VM destruction.

`recovery-reuse` retains the Executor around the original `HvfExecutor.Native*` recovery test, including its actual vCPU destruction/recreation after cancellation. Both reuse modes require exactly one native retention marker in every iteration and reject older source without that evidence. Default `recovery` is unchanged; reuse is diagnostic evidence only. Finite probes keep one fixed overall witness budget across short slices that may expire before guest execution.

## 中文（简体）

在 Actions 中选择 **Personal Intel HVF recovery diagnosis** 并手动运行，无需本地 Intel Mac。默认使用 `macos-26-intel`，对固定的 NeverD 源码在同一进程连续测试 1,000 轮；也可选择 `macos-15-intel` 或 100 轮诊断。产物保留版本、计划、实时进度和最终结果。排队时间与运行稳定性分别判断；单次恢复测试通过不能代表完整 CPU、macOS 或 iOS 覆盖。[完整指南](https://github.com/NeverSight/NeverD/blob/dev/docs/zh-CN/macos-hvf.md)。

另有 `Intel artifact uploader control` 工作流：连续上传 16 份模拟快照，不启动 VM；它只用于排查上传器，成功不代表 HVF 测试通过。

新增 `Intel HVF native boundary experiments` 工作流：`lifecycle` 只创建和回收 VM/vCPU 与映射，不运行客体；`instruction` 验证真实启动探针和普通指令；`finite-deadline` 使用原有长模式准备，记录有限、过期和短期限调用的原生写入见证、时间、RIP、寄存器和退出原因。有限调用不使用异步 watchdog，准备和重试仍使用原有执行路径。不支持计时器或出现意外退出会失败。每次运行只选一个实验和一个镜像，可选 100/1000 轮；三个仓库版本分别留档。诊断通过不代表完整验收，也不代表失联已经修复。

`instruction-reuse` 执行相同的普通指令测试，跨轮次保留一个执行器，其中 VM、vCPU、工作线程、watchdog 线程和原生状态一同保留；每轮映射仍会回收。控制器隔离诊断环境开关。此对照研究执行器寿命，不能仅据差异归因于 VM 销毁。

`recovery-reuse` 在原有 `HvfExecutor.Native*` 恢复测试外保留执行器，取消后仍真实销毁和重建 vCPU。两个复用模式都要求每轮恰好一个原生保留标记，旧源码缺少证据会失败。默认 `recovery` 不变，复用仅属诊断。有限期限探针对尚未执行客体就到期的短分段继续观察，共用固定总期限。

## 中文（繁體）

在 Actions 選擇 **Personal Intel HVF recovery diagnosis** 手動執行，不需要本機 Intel Mac。預設以 `macos-26-intel` 對固定的 NeverD 原始碼，在同一程序連續測試 1,000 輪；亦可選擇 `macos-15-intel` 或 100 輪診斷。產物保留版本、計畫、即時進度及最終結果。排隊時間與執行穩定性須分別判斷；單次恢復測試通過不代表完整 CPU、macOS 或 iOS 覆蓋。[完整指南](https://github.com/NeverSight/NeverD/blob/dev/docs/zh-TW/macos-hvf.md)。

另有 `Intel artifact uploader control` 工作流程：連續上傳 16 份模擬快照，不啟動 VM；它只用於診斷上傳器，成功不代表 HVF 測試通過。

新增 `Intel HVF native boundary experiments` 工作流程：`lifecycle` 僅建立和回收 VM/vCPU 與映射，不執行客體；`instruction` 驗證真實啟動探針與一般指令；`finite-deadline` 使用原有長模式準備，記錄有限、過期及短期限呼叫的原生寫入見證、時間、RIP、暫存器和退出原因。有限呼叫不使用非同步 watchdog，準備與重試仍使用原有路徑。不支援計時器或意外退出皆失敗。每次只選一個實驗與鏡像，可選 100/1000 輪；三個儲存庫版本分別留存。診斷通過不代表完整驗收或失聯已修復。

`instruction-reuse` 執行相同的一般指令測試，跨輪次保留同一執行器，包含 VM、vCPU、工作執行緒、watchdog 執行緒與原生狀態；每輪仍回收映射。控制器隔離診斷環境開關。此對照研究執行器生命週期，不能僅憑差異歸因於 VM 銷毀。

`recovery-reuse` 在原有 `HvfExecutor.Native*` 復原測試外保留執行器，取消後仍實際銷毀並重建 vCPU。兩種復用模式每輪均須恰有一個原生保留標記，舊原始碼缺少證據即失敗。預設 `recovery` 不變，復用僅屬診斷。有限期限探針對尚未執行客體就到期的短分段繼續觀察，共用固定總期限。

## 日本語

Actions で **Personal Intel HVF recovery diagnosis** を手動実行します。手元に Intel Mac は不要です。既定では `macos-26-intel` と固定した NeverD ソースを使い、同じプロセスで 1,000 回連続実行します。`macos-15-intel` と 100 回の診断も選択できます。成果物にはリビジョン、計画、進捗、最終結果を保存します。待ち時間と実行の安定性は別々に評価し、この復旧テストの成功を CPU・macOS・iOS 全体の検証とは扱いません。[詳細ガイド](https://github.com/NeverSight/NeverD/blob/dev/docs/ja/macos-hvf.md)。

`Intel artifact uploader control` は VM を起動せず、合成スナップショットを 16 回アップロードします。アップローダーの診断専用であり、成功しても HVF の検証完了を意味しません。

新しい `Intel HVF native boundary experiments` は、ゲストを実行せず VM/vCPU とマッピングを生成・破棄する `lifecycle`、実際の起動プローブと通常命令を検証する `instruction`、元のロングモード準備を使う `finite-deadline` を分離します。有限・期限切れ・短期限の呼出しごとにネイティブ書込みの証拠、時間、RIP、レジスタ、終了理由を記録します。有限呼出しは非同期 watchdog を使わず、準備と再試行は既存経路です。タイマー非対応や想定外の終了は失敗です。各実行は実験とイメージを一つずつ選び、100/1000回を指定し、三つのリポジトリの版を個別に保存します。診断成功は完全検証や接続喪失の修正を意味しません。

`instruction-reuse` は同じ通常命令テストで一つの Executor を反復間に保持します。VM、vCPU、実行・watchdog スレッドとネイティブ状態を一緒に保持し、各回のマッピングは解放します。診断用環境変数はコントローラーが分離します。実行器の寿命を比較するための対照であり、差異を VM の破棄だけに帰属できません。

`recovery-reuse` は元の `HvfExecutor.Native*` 回復テストの周囲で Executor を保持し、キャンセル後の vCPU の破棄・再生成はそのまま実行します。両方の再利用モードは各回にネイティブ保持マーカーを一つだけ要求し、証拠のない旧ソースを拒否します。既定の `recovery` は変更せず、再利用は診断専用です。有限期限プローブは、ゲスト実行前に短い区間が期限切れになっても、固定された全体期限の中で観測を続けます。

## 한국어

Actions에서 **Personal Intel HVF recovery diagnosis**를 수동 실행합니다. 로컬 Intel Mac은 필요하지 않습니다. 기본값은 `macos-26-intel`이며, 고정된 NeverD 소스를 같은 프로세스에서 1,000회 연속 테스트합니다. `macos-15-intel` 또는 100회 진단도 선택할 수 있습니다. 산출물에는 버전, 계획, 진행 상황과 최종 결과가 보존됩니다. 대기 시간과 실행 안정성은 따로 평가해야 하며, 복구 테스트 한 번의 성공이 전체 CPU·macOS·iOS 검증을 의미하지는 않습니다. [전체 안내](https://github.com/NeverSight/NeverD/blob/dev/docs/ko/macos-hvf.md).

`Intel artifact uploader control`은 VM 없이 합성 스냅샷 16개를 업로드합니다. 업로더 진단용이며, 성공해도 HVF 검증 완료를 뜻하지 않습니다.

새 `Intel HVF native boundary experiments`는 게스트 실행 없이 VM/vCPU와 매핑을 생성·회수하는 `lifecycle`, 실제 시작 프로브와 일반 명령을 검증하는 `instruction`, 기존 long mode 준비를 사용하는 `finite-deadline`을 분리합니다. 유한·만료·짧은 기한 호출마다 네이티브 쓰기 증거, 시간, RIP, 레지스터와 종료 이유를 기록합니다. 유한 호출은 비동기 watchdog을 사용하지 않으며 준비와 재시도는 기존 경로입니다. 타이머 미지원과 예기치 않은 종료는 실패입니다. 실행마다 실험과 이미지를 하나씩 선택하고 100/1000회를 지정하며 세 저장소 버전을 독립적으로 보존합니다. 진단 통과는 전체 검증이나 연결 끊김 수정의 증거가 아닙니다.

`instruction-reuse`는 같은 일반 명령 테스트에서 반복 간 하나의 Executor를 유지합니다. VM, vCPU, 실행·watchdog 스레드와 네이티브 상태가 함께 유지되고 매핑은 매회 해제됩니다. 컨트롤러는 진단 환경 변수를 격리합니다. 실행기 수명을 비교하는 대조이므로 차이를 VM 파괴만의 영향으로 단정할 수 없습니다.

`recovery-reuse`는 기존 `HvfExecutor.Native*` 복구 테스트 주위에 Executor를 유지하며 취소 후 실제 vCPU 해제·재생성은 그대로 수행합니다. 두 재사용 모드는 매회 하나의 네이티브 유지 표시를 요구하고, 증거가 없는 이전 소스는 거부합니다. 기본 `recovery`는 변경하지 않으며 재사용은 진단 전용입니다. 유한 기한 프로브는 게스트 실행 전에 짧은 구간이 만료되어도 고정된 전체 기한 내에서 관찰을 이어 갑니다.

## Français

Lancez **Personal Intel HVF recovery diagnosis** dans Actions, sans Mac Intel local. Par défaut, `macos-26-intel` exécute 1 000 répétitions dans un seul processus avec une révision fixe de NeverD. Vous pouvez aussi choisir `macos-15-intel` ou un diagnostic de 100 répétitions. Les artefacts conservent les révisions, le plan, la progression et le résultat final. Évaluez séparément l'attente et la stabilité ; réussir ce test de récupération ne valide pas toute la couverture CPU, macOS ou iOS. [Guide complet](https://github.com/NeverSight/NeverD/blob/dev/docs/fr/macos-hvf.md).

`Intel artifact uploader control` téléverse 16 instantanés synthétiques sans lancer de VM. Ce contrôle de l’outil de téléversement ne valide pas HVF.

Le nouveau workflow `Intel HVF native boundary experiments` sépare `lifecycle` (création et destruction VM/vCPU et mappings sans invité), `instruction` (sonde initiale réelle et instructions normales) et `finite-deadline` (préparation long mode originale). Les appels à échéance finie, expirée ou courte enregistrent écriture native témoin, temps, RIP, registres et motif de sortie. Les appels finis évitent le watchdog asynchrone ; préparation et reprise gardent le transport existant. Un timer indisponible ou une sortie inattendue fait échouer l’expérience. Chaque lancement choisit une expérience, une image et 100/1000 répétitions ; les trois révisions restent distinctes. Un succès ne prouve ni validation complète ni correction des déconnexions.

`instruction-reuse` exécute le même test d’instructions en conservant un Executor entre les répétitions. VM, vCPU, threads d’exécution et watchdog, ainsi que l’état natif, sont conservés ensemble ; les mappings sont libérés à chaque fois. Le contrôleur isole les variables de diagnostic. Ce contrôle compare la durée de vie de l’exécuteur sans attribuer une différence à la seule destruction de VM.

`recovery-reuse` conserve l’Executor autour du test original `HvfExecutor.Native*`, qui détruit et recrée toujours le vCPU après annulation. Les deux modes de réutilisation exigent un unique marqueur natif par répétition et rejettent les anciennes sources sans cette preuve. Le mode `recovery` par défaut reste inchangé ; la réutilisation sert uniquement au diagnostic. Les sondes finies gardent un budget global fixe lorsque des tranches courtes expirent avant l’exécution de l’invité.

## Deutsch

Starten Sie **Personal Intel HVF recovery diagnosis** manuell unter Actions; ein eigener Intel-Mac ist nicht erforderlich. Standardmäßig führt `macos-26-intel` mit einer festgelegten NeverD-Revision 1.000 Wiederholungen in einem Prozess aus. Alternativ sind `macos-15-intel` oder 100 Wiederholungen möglich. Artefakte sichern Revisionen, Plan, Fortschritt und Endergebnis. Wartezeit und Laufzeitstabilität werden getrennt bewertet. Ein erfolgreicher Wiederherstellungstest bestätigt keine vollständige CPU-, macOS- oder iOS-Abdeckung. [Vollständige Anleitung](https://github.com/NeverSight/NeverD/blob/dev/docs/de/macos-hvf.md).

`Intel artifact uploader control` lädt 16 synthetische Snapshots ohne VM hoch. Dieser Upload-Test bestätigt bei Erfolg keine HVF-Funktionalität.

Der neue Workflow `Intel HVF native boundary experiments` trennt `lifecycle` (VM/vCPU und Mappings erzeugen und beenden, ohne Gast), `instruction` (echte Startprobe und normale Instruktionen) und `finite-deadline` (ursprüngliche Long-Mode-Vorbereitung). Aufrufe mit endlicher, abgelaufener oder kurzer Frist protokollieren native Schreibmarker, Zeit, RIP, Register und Austrittsgrund. Endliche Aufrufe umgehen den asynchronen Watchdog; Vorbereitung und Wiederholung behalten den bestehenden Transport. Fehlender Timer oder unerwarteter Austritt bedeutet Fehler. Jeder Start wählt eine Untersuchung, ein Image und 100/1000 Wiederholungen; drei Revisionen bleiben getrennt. Erfolg belegt weder vollständige Abnahme noch behobene Verbindungsabbrüche.

`instruction-reuse` führt denselben Instruktionstest aus und behält einen Executor zwischen den Wiederholungen. VM, vCPU, Ausführungs- und Watchdog-Threads sowie nativer Zustand bleiben gemeinsam bestehen; die Mappings werden jeweils freigegeben. Der Controller isoliert die Diagnose-Umgebungsvariablen. Der Vergleich untersucht die Executor-Lebensdauer und kann Unterschiede nicht allein der VM-Zerstörung zuordnen.

`recovery-reuse` behält den Executor um den ursprünglichen Test `HvfExecutor.Native*`; nach Abbruch wird die vCPU weiterhin tatsächlich zerstört und neu erstellt. Beide Wiederverwendungsmodi verlangen genau einen nativen Marker pro Runde und lehnen ältere Quellen ohne diesen Nachweis ab. Das normale `recovery` bleibt unverändert; Wiederverwendung ist nur Diagnose. Endliche Proben behalten eine feste Gesamtfrist, auch wenn kurze Abschnitte vor der Gastausführung ablaufen.

## Español

Ejecute manualmente **Personal Intel HVF recovery diagnosis** en Actions; no necesita un Mac Intel local. Por defecto, `macos-26-intel` ejecuta 1.000 repeticiones en un solo proceso con una revisión fija de NeverD. También puede elegir `macos-15-intel` o un diagnóstico de 100 repeticiones. Los artefactos conservan las revisiones, el plan, el progreso y el resultado final. Evalúe por separado la espera y la estabilidad: superar esta prueba de recuperación no valida toda la cobertura de CPU, macOS o iOS. [Guía completa](https://github.com/NeverSight/NeverD/blob/dev/docs/es/macos-hvf.md).

`Intel artifact uploader control` carga 16 instantáneas sintéticas sin iniciar una VM. Este diagnóstico de carga no valida HVF aunque termine correctamente.

El nuevo workflow `Intel HVF native boundary experiments` separa `lifecycle` (crear y retirar VM/vCPU y mapeos sin huésped), `instruction` (sondeo inicial real e instrucciones normales) y `finite-deadline` (preparación original en long mode). Las llamadas con plazo finito, vencido o corto registran escritura nativa testigo, tiempo, RIP, registros y motivo de salida. Las llamadas finitas evitan el watchdog asíncrono; preparación y reintento conservan el transporte original. Un temporizador no compatible o una salida inesperada hace fallar el experimento. Cada ejecución elige un experimento, una imagen y 100/1000 repeticiones; se conservan tres revisiones independientes. El éxito no demuestra aceptación completa ni desconexiones corregidas.

`instruction-reuse` ejecuta la misma prueba de instrucciones conservando un Executor entre repeticiones. VM, vCPU, hilos de ejecución y watchdog y estado nativo se conservan juntos; los mapeos se liberan cada vez. El controlador aísla las variables de diagnóstico. Esta comparación estudia la vida del ejecutor y no permite atribuir diferencias únicamente a la destrucción de VM.

`recovery-reuse` conserva el Executor durante la prueba original `HvfExecutor.Native*`, que sigue destruyendo y recreando la vCPU tras la cancelación. Ambos modos de reutilización exigen un único marcador nativo por repetición y rechazan fuentes antiguas sin esa prueba. El modo `recovery` predeterminado no cambia; la reutilización es solo diagnóstica. Los sondeos finitos conservan un plazo total fijo cuando intervalos cortos vencen antes de ejecutar el huésped.

## Italiano

Avviare manualmente **Personal Intel HVF recovery diagnosis** da Actions; non serve un Mac Intel locale. Per impostazione predefinita, `macos-26-intel` esegue 1.000 ripetizioni in un unico processo su una revisione fissa di NeverD. Sono disponibili anche `macos-15-intel` e una diagnosi di 100 ripetizioni. Gli artefatti conservano revisioni, piano, avanzamento e risultato finale. Valutare separatamente l'attesa e la stabilità: il successo di questo test di recupero non convalida l'intera copertura CPU, macOS o iOS. [Guida completa](https://github.com/NeverSight/NeverD/blob/dev/docs/it/macos-hvf.md).

`Intel artifact uploader control` carica 16 istantanee sintetiche senza avviare una VM. Il successo di questa diagnosi del caricamento non convalida HVF.

Il nuovo workflow `Intel HVF native boundary experiments` separa `lifecycle` (creazione e ritiro di VM/vCPU e mapping senza guest), `instruction` (sonda iniziale reale e istruzioni normali) e `finite-deadline` (preparazione originale in long mode). Le chiamate con scadenza finita, scaduta o breve registrano scrittura nativa di riscontro, tempi, RIP, registri e motivo di uscita. Le chiamate finite evitano il watchdog asincrono; preparazione e ripetizione mantengono il trasporto originale. Timer non supportato o uscita inattesa fanno fallire l’esperimento. Ogni avvio sceglie un esperimento, un’immagine e 100/1000 ripetizioni; tre revisioni restano distinte. Il successo non dimostra accettazione completa o disconnessioni risolte.

`instruction-reuse` esegue lo stesso test di istruzioni mantenendo un Executor tra le ripetizioni. VM, vCPU, thread di esecuzione e watchdog e stato nativo rimangono insieme; i mapping sono liberati ogni volta. Il controller isola le variabili diagnostiche. Il confronto riguarda la durata dell’esecutore e non attribuisce eventuali differenze alla sola distruzione della VM.

`recovery-reuse` mantiene l’Executor intorno al test originale `HvfExecutor.Native*`, che continua a distruggere e ricreare la vCPU dopo l’annullamento. Entrambe le modalità di riuso richiedono esattamente un marcatore nativo per ripetizione e rifiutano sorgenti precedenti senza tale prova. Il normale `recovery` non cambia; il riuso è soltanto diagnostico. Le sonde finite conservano una scadenza complessiva fissa quando intervalli brevi scadono prima dell’esecuzione guest.

## Русский

Запустите **Personal Intel HVF recovery diagnosis** вручную в Actions; собственный Intel Mac не нужен. По умолчанию `macos-26-intel` выполняет 1 000 повторений в одном процессе для фиксированной ревизии NeverD. Можно выбрать `macos-15-intel` или диагностику из 100 повторений. Артефакты сохраняют ревизии, план, ход выполнения и итог. Время ожидания и стабильность выполнения оцениваются отдельно: успешный тест восстановления не подтверждает полное покрытие CPU, macOS или iOS. [Полное руководство](https://github.com/NeverSight/NeverD/blob/dev/docs/ru/macos-hvf.md).

`Intel artifact uploader control` загружает 16 синтетических снимков без запуска VM. Успех этой проверки загрузчика не означает успешную проверку HVF.

Новый workflow `Intel HVF native boundary experiments` разделяет `lifecycle` (создание и освобождение VM/vCPU и отображений без гостя), `instruction` (реальная стартовая проба и обычные инструкции) и `finite-deadline` (исходная подготовка long mode). Вызовы с конечным, истёкшим и коротким сроком записывают нативную запись-маркер, время, RIP, регистры и причину выхода. Конечные вызовы обходят асинхронный watchdog; подготовка и повтор используют прежний транспорт. Неподдерживаемый таймер или неожиданный выход означает ошибку. Каждый запуск выбирает один опыт, образ и 100/1000 повторов; три ревизии сохраняются отдельно. Успех не доказывает полную приёмку или исправление потери связи.

`instruction-reuse` выполняет тот же тест инструкций, сохраняя один Executor между повторами. VM, vCPU, рабочий поток, watchdog и нативное состояние сохраняются вместе; отображения освобождаются каждый раз. Контроллер изолирует диагностические переменные среды. Этот опыт сравнивает время жизни исполнителя и не позволяет приписать различие только уничтожению VM.

`recovery-reuse` сохраняет Executor вокруг исходного теста `HvfExecutor.Native*`, который по-прежнему уничтожает и создаёт vCPU после отмены. Оба режима повторного использования требуют ровно один нативный маркер в каждом повторе и отклоняют старый код без такого доказательства. Обычный `recovery` не меняется; повторное использование служит только диагностике. Конечные пробы сохраняют общий неизменный срок, даже когда короткий интервал истекает до выполнения гостя.

## العربية

شغّل **Personal Intel HVF recovery diagnosis** يدوياً من Actions؛ لا تحتاج إلى جهاز Mac بمعالج Intel محلياً. يستخدم الإعداد الافتراضي `macos-26-intel` لتنفيذ 1,000 تكرار متتالٍ في عملية واحدة على إصدار محدد من NeverD. ويمكن اختيار `macos-15-intel` أو تشخيص من 100 تكرار. تحفظ ملفات النتائج الإصدارات والخطة والتقدم والنتيجة النهائية. يُقيّم وقت الانتظار واستقرار التنفيذ كلٌّ على حدة؛ نجاح اختبار الاستعادة هذا لا يثبت اكتمال تغطية CPU أو macOS أو iOS. [الدليل الكامل](https://github.com/NeverSight/NeverD/blob/dev/docs/ar/macos-hvf.md).

يرفع `Intel artifact uploader control` ست عشرة لقطة اصطناعية دون تشغيل VM. هذا فحص لأداة الرفع فقط، ولا يعني نجاحه اجتياز اختبارات HVF.

يفصل workflow الجديد `Intel HVF native boundary experiments` بين `lifecycle` لإنشاء VM/vCPU والتعيينات وتحريرها دون تشغيل ضيف، و`instruction` لمجس البدء الحقيقي والتعليمات العادية، و`finite-deadline` مع إعداد long mode الأصلي. تسجل الاستدعاءات ذات الموعد المحدد أو المنتهي أو القصير شاهد كتابة أصلية والوقت وRIP والسجلات وسبب الخروج. تتجاوز الاستدعاءات المحددة watchdog غير المتزامن، بينما يبقى الإعداد وإعادة المحاولة على المسار الأصلي. يفشل الاختبار عند عدم دعم المؤقت أو الخروج غير المتوقع. يختار كل تشغيل تجربة وصورة واحدة و100/1000 تكرار، مع حفظ إصدارات المستودعات الثلاثة مستقلة. النجاح لا يثبت قبولًا كاملًا أو إصلاح انقطاع الاتصال.

English: [full NeverD guide](https://github.com/NeverSight/NeverD/blob/dev/docs/macos-hvf.md).

يشغّل `instruction-reuse` اختبار التعليمات نفسه مع الاحتفاظ بكائن Executor واحد بين التكرارات. تُحفظ VM وvCPU وخيوط التنفيذ وwatchdog والحالة الأصلية معًا، بينما تُحرَّر التعيينات في كل مرة. يعزل المتحكم متغيرات التشخيص. تقارن التجربة عمر المنفّذ ولا تسمح بإرجاع أي فرق إلى تدمير VM وحده.

يحتفظ `recovery-reuse` بكائن Executor حول اختبار الاستعادة الأصلي `HvfExecutor.Native*`، مع استمرار تدمير vCPU وإعادة إنشائه بعد الإلغاء. يتطلب وضعا إعادة الاستخدام علامة أصلية واحدة بالضبط في كل تكرار، ويرفضان الشيفرة القديمة التي تفتقر إلى هذا الدليل. يبقى وضع `recovery` الافتراضي دون تغيير، وإعادة الاستخدام للتشخيص فقط. تحافظ المجسات المحددة زمنيًا على موعد إجمالي ثابت حتى عندما تنتهي فترة قصيرة قبل تنفيذ الضيف.
