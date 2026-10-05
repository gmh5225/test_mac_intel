# Independent finite Intel HVF API lifecycle

[The manual workflow](../.github/workflows/intel-api-lifecycle.yml) builds an
authored derivative of the real-mode setup from
[hvf-edge-cases at f150b38bfff419fe19907b7a6a2d743a63b46a49](https://gitlab.com/pmdj/hvf-edge-cases/-/tree/f150b38bfff419fe19907b7a6a2d743a63b46a49).
The applicable hvdos copyright and BSD-2-Clause terms are retained in
[HVFDOS-LICENSE.txt](HVFDOS-LICENSE.txt). This is a different experiment from the
unchanged upstream random-interrupt control.

Use **Independent finite Intel HVF API lifecycle** in Actions. Choose either
`macos-15-intel` or `macos-26-intel` and `vcpu` or `vm`. Every native invocation
has exactly 1,000 iterations, one owner thread and one retained host allocation.
`vcpu` retains one VM and creates 1,000 vCPUs. `vm` creates 1,000 VMs and vCPUs.
Both modes map and unmap each iteration, with vCPU destruction before unmapping.
Only run the VM pair after both matching vCPU controls have complete passing
native output, successful process exit and child retirement evidence.

The five guest bytes `A3 00 02 EB FE` write a fresh 16-bit nonce and loop. Each
iteration must observe the fresh store and an actual timer exit within a fixed
two-second budget. Five-millisecond slices, a 4,096-call limit and explicit
control/state readbacks reject unsupported or unexpected behavior. The program
contains no NeverD Executor, long-mode guest, managed MSR or asynchronous guest
cancellation thread. These differences limit causal comparisons.

The native process has a 600-second timeout. Evidence includes source/helper
revisions, source and signed binary hashes, runtime identity, host observations,
ordered native JSONL, process status and retirement. The event limit is 65,536;
the output limit is 32 MiB. At most 64 progress uploads preserve 8 MiB windows
with byte offsets. Gaps, missing final records, observer failures and runner
loss are never passing native evidence. Every failed attempt must be retained.

The local checks cover parsing, failure cleanup, cancellation, reaping, observer
failure and workflow syntax. An ARM-host x86_64 cross-build proves compilation
only; it is not native Intel execution. Passing this isolated experiment does
not establish a root cause, physical Intel Mac stability, NeverD performance,
or complete NeverD recovery, CPU, macOS or iOS acceptance.

The first live pair is retained in [the evidence record](../results/2026-10-05-api-lifecycle/summary.json): macOS 26 run `37256341043` passed 1,000 rounds; macOS 15 run `37256339176` had an identity-matched Node uploader SIGSEGV. The controller killed and reaped the native child after 411 complete rounds, leaving its native outcome unknown. NeverD long-mode state and managed MSRs were absent in this reproduction; no root cause is established.

The explicit `observation` input defaults to `live`. The new `final-only` contrast keeps the native program and every limit unchanged, but omits the live snapshot loop, process probes and progress uploaders. It uploads the plan before execution and final evidence after controller completion. This removes concurrent observation as a bundle; a difference cannot be attributed to an individual component. Runner loss may leave only the plan, which cannot pass the native gate. First require complete passing `final-only` vCPU evidence on both images before the matched VM pair; retain every failed attempt.

The first `final-only` pair, macOS 15 `37257757852` and macOS 26 `37257759882`, both exited with error 1 and were reaped, without concurrent progress uploads or runner loss. The original parser rejected one CRCRLF terminator in each stream. Separately labelled LF-framing analysis verifies 501/781 completed rounds, then a budget failure in rounds 502/782 and successful cleanup. Those older 2.842/2.013-second intervals contain log writes and cannot be assigned to HVF alone. Protocol 2 parses LF records, disables PTY output processing for this control only, checks the unchanged deadline again after the begin log, and captures guest state before writing end logs. `entered` means the host instant before the API call, not proof of VM entry; the interval still includes host scheduling. All original failures remain recorded, and the VM gate stays closed until both new vCPU attempts pass.

## 中文（简体）

这是独立编写的实模式 HVF 对照，保留上游许可。`vcpu` 保留一个 VM，`vm` 每轮重建 VM；两种模式均执行 1,000 轮，要求新写入见证、有限计时器退出、成功退出和进程回收。先等待两个 Intel 镜像的 `vcpu` 完整通过，再运行对应 `vm`。失联、输出缺失或上传失败不能算通过；失败也必须留档。它不代表根因、性能或 NeverD CPU、macOS、iOS 完整验收。

首轮实时对照中，macOS 26 `37256341043` 通过 1,000 轮；macOS 15 `37256339176` 的 Node 上传器发生身份已匹配的 SIGSEGV，控制器在 411 完整轮后终止并回收原生子进程，其原生结果未知。新增 `observation=final-only` 保持程序和期限不变，只在执行前上传计划、退出后上传最终证据，取消并发扫描、进程探测和进度上传。失联可能只留下计划，不能算通过。两个镜像的新 vCPU 对照完整通过后才能运行对应 VM 对照；所有失败留档，根因仍未确定。

首组 `final-only`：macOS 15 `37257757852` 与 macOS 26 `37257759882` 均以错误码 1 退出并回收，没有并发进度上传或 runner 失联。原解析器各因一个 CRCRLF 拒绝输出；单独标注的 LF 分帧分析核对了 501/781 个完整轮次，随后在 502/782 轮超出预算且清理成功。旧的 2.842/2.013 秒区间包含日志写入，不能全归给 HVF。协议 2 修正 LF 分帧，仅对此控制关闭 PTY 输出处理，在开始日志后再次检查原期限，并先采集状态再输出结束日志。`entered` 只是 API 调用前的主机时刻，不证明 VM 已进入，区间仍含调度等待。旧失败全部保留；新 vCPU 双平台完整通过前不测 VM。

## 中文（繁體）

這是獨立編寫的實模式 HVF 對照，保留上游授權。`vcpu` 保留一個 VM，`vm` 每輪重建 VM；兩者均執行 1,000 輪，要求新的寫入見證、有限計時器退出、成功結束及程序回收。先等待兩個 Intel 映像的 `vcpu` 完整通過，再執行對應 `vm`。失聯、輸出缺失或上傳失敗不能算通過；失敗也須留存。它不代表根因、效能或 NeverD CPU、macOS、iOS 完整驗收。

首輪即時對照中，macOS 26 `37256341043` 通過 1,000 輪；macOS 15 `37256339176` 的 Node 上傳器發生身分已核對的 SIGSEGV，控制器在 411 完整輪後終止並回收原生子程序，原生結果未知。新增 `observation=final-only` 保持程式和期限不變，只在執行前上傳計畫、退出後上傳最終證據，取消並行掃描、程序探測和進度上傳。失聯可能只留下計畫，不能算通過。兩個映像的新 vCPU 對照完整通過後才能執行對應 VM 對照；所有失敗留存，根因仍未確定。

首組 `final-only`：macOS 15 `37257757852` 與 macOS 26 `37257759882` 均以錯誤碼 1 結束並回收，沒有並行進度上傳或 runner 失聯。原解析器各因一個 CRCRLF 拒絕輸出；獨立標示的 LF 分幀分析核對了 501/781 個完整輪次，隨後在 502/782 輪超出預算且清理成功。舊的 2.842/2.013 秒區間包含日誌寫入，不能全歸給 HVF。協定 2 修正 LF 分幀，僅對此控制關閉 PTY 輸出處理，在開始日誌後再次檢查原期限，先擷取狀態再輸出結束日誌。`entered` 只是 API 呼叫前的主機時刻，不證明 VM 已進入，區間仍含排程等待。舊失敗全部保留；新 vCPU 雙平台完整通過前不測 VM。

## 日本語

上流のライセンスを保持した、独自の実モード HVF 対照実験です。`vcpu` は一つの VM を保持し、`vm` は毎回 VM を再生成します。各 1,000 回で新しい書込み、有限タイマー終了、正常終了と子プロセス回収が必要です。両 Intel イメージの `vcpu` が完全に成功してから対応する `vm` を実行します。接続喪失、出力欠落、アップロード失敗は合格とせず、失敗も保存します。原因・性能や NeverD CPU、macOS、iOS の完全検証を示すものではありません。

最初のライブ対照では macOS 26 の `37256341043` が 1,000 回成功し、macOS 15 の `37256339176` では識別情報を照合した Node アップローダーが SIGSEGV で終了しました。411 回完了後にネイティブ子プロセスを停止・回収したため、ネイティブ結果は不明です。新しい `observation=final-only` はプログラムと制限を保持し、実行前の計画と終了後の最終証拠だけをアップロードします。同時スキャン・プロセス確認・進捗アップロードを一括して除く対照であり、接続喪失で計画しか残らなければ不合格です。両イメージの新しい vCPU 対照が完全に成功してから VM 対照を実行し、全失敗を保持します。原因は未特定です。

最初の `final-only` 対照 `37257757852`（macOS 15）と `37257759882`（macOS 26）は、ともに終了コード 1 で回収され、同時進捗アップロードも接続喪失もありませんでした。元の解析器は各一つの CRCRLF を拒否しました。別記の LF 解析では 501/781 回完了後、502/782 回目の予算超過と正常な解放を確認しました。旧 2.842/2.013 秒にはログ書込みが含まれ、HVF 単独の時間ではありません。プロトコル 2 は LF 区切りと出力変換を無効にした PTY を使い、開始ログ後に同じ期限を再確認し、終了ログ前に状態を取得します。`entered` は API 呼出し前のホスト時刻で、VM entry の証明ではなく、区間はスケジューリングも含みます。旧失敗を保持し、両新 vCPU 対照が成功するまで VM は実行しません。

## 한국어

상위 라이선스를 유지한 독립적인 real mode HVF 대조 실험입니다. `vcpu`는 VM 하나를 유지하고 `vm`은 매번 VM을 다시 만듭니다. 각각 1,000회 실행하며 새로운 쓰기 증거, 유한 타이머 종료, 정상 종료와 자식 프로세스 회수가 필요합니다. 두 Intel 이미지의 `vcpu`가 완전히 통과한 뒤 대응하는 `vm`을 실행합니다. 연결 손실, 출력 누락, 업로드 실패를 통과로 보지 않으며 실패도 보존합니다. 원인·성능이나 NeverD CPU, macOS, iOS 전체 검증을 증명하지 않습니다.

첫 실시간 대조에서 macOS 26 `37256341043`은 1,000회를 통과했고, macOS 15 `37256339176`에서는 신원을 확인한 Node 업로더가 SIGSEGV로 종료했습니다. 411회 완료 후 네이티브 자식 프로세스를 종료·회수했으므로 네이티브 결과는 미확인입니다. 새 `observation=final-only`는 프로그램과 제한을 유지하고 실행 전 계획과 종료 후 최종 증거만 업로드합니다. 동시 스캔·프로세스 확인·진행 업로드를 함께 제거하며, 연결 손실로 계획만 남으면 통과할 수 없습니다. 두 이미지의 새 vCPU 대조가 완전히 통과한 뒤 VM 대조를 실행하고 모든 실패를 보존합니다. 근본 원인은 아직 확인되지 않았습니다.

첫 `final-only` 대조 `37257757852`(macOS 15)와 `37257759882`(macOS 26)는 모두 코드 1로 종료·회수됐으며 동시 진행 업로드나 runner 연결 손실은 없었습니다. 원래 파서는 각 로그의 CRCRLF 하나를 거부했습니다. 별도 LF 분석은 501/781회 완료 후 502/782회의 예산 초과와 정상 정리를 확인했습니다. 기존 2.842/2.013초에는 로그 쓰기가 포함돼 HVF 시간으로만 볼 수 없습니다. 프로토콜 2는 LF 분리와 출력 처리를 끈 PTY를 사용하고, 시작 로그 뒤 같은 기한을 재확인하며 종료 로그 전에 상태를 수집합니다. `entered`는 API 호출 전 호스트 시각이며 VM 진입 증거가 아니고 구간에는 스케줄링도 포함됩니다. 기존 실패를 유지하고 새 vCPU 두 검증이 통과하기 전에는 VM을 실행하지 않습니다.

## Français

Ce contrôle HVF indépendant en mode réel conserve la licence amont. `vcpu` garde une VM ; `vm` recrée la VM à chaque tour. Chacun effectue 1 000 tours avec une nouvelle écriture vérifiée, une sortie de temporisateur bornée, une sortie normale et la récupération du processus enfant. Attendre le succès complet de `vcpu` sur les deux images Intel avant les contrôles `vm` correspondants. Une déconnexion, une sortie manquante ou un échec de téléversement ne vaut pas succès ; conserver aussi les échecs. Ce test ne prouve ni la cause, ni les performances, ni la validation complète CPU, macOS ou iOS de NeverD.

Le premier contrôle en direct `37256341043` sur macOS 26 a réussi 1 000 tours. Sur macOS 15, `37256339176` a subi un SIGSEGV de l’uploader Node identifié ; le processus natif a été arrêté et récupéré après 411 tours complets, donc son résultat reste inconnu. `observation=final-only` conserve le programme et les limites, mais ne téléverse que le plan avant exécution et les preuves finales après terminaison. Il retire ensemble scans, sondes de processus et téléversements simultanés. Une déconnexion peut ne laisser que le plan, sans succès natif. Attendre les deux nouveaux contrôles vCPU complets avant les contrôles VM ; conserver tous les échecs. La cause reste inconnue.

Les contrôles `final-only` `37257757852` (macOS 15) et `37257759882` (macOS 26) ont tous deux terminé avec le code 1 et ont été récupérés, sans téléversement de progression simultané ni déconnexion. Le parseur initial a rejeté un CRCRLF par flux. Une analyse LF distincte confirme 501/781 tours complets, puis un dépassement aux tours 502/782 avec nettoyage réussi. Les anciens intervalles de 2,842/2,013 s incluent des écritures de journal, pas seulement HVF. Le protocole 2 corrige le découpage LF, désactive le traitement de sortie PTY pour ce contrôle, revérifie la même échéance après le journal initial et capture l’état avant les journaux finaux. `entered` est l’instant hôte précédant l’appel API, sans preuve d’entrée VM ; l’intervalle inclut encore l’ordonnancement. Les échecs restent conservés ; pas de contrôle VM avant les deux nouveaux succès vCPU.

## Deutsch

Dieser eigenständige HVF-Vergleich im Real Mode behält die Upstream-Lizenz bei. `vcpu` behält eine VM, `vm` erstellt sie in jeder Runde neu. Je 1.000 Runden verlangen einen frischen Schreibnachweis, einen begrenzten Timer-Exit, erfolgreichen Prozessabschluss und das Einsammeln des Kindprozesses. Erst nach vollständigem Erfolg von `vcpu` auf beiden Intel-Images folgen die zugehörigen `vm`-Kontrollen. Verbindungsverlust, fehlende Ausgabe oder Uploadfehler gelten nicht als Erfolg; auch Fehlschläge bleiben erhalten. Das belegt weder Ursache noch Leistung oder die vollständige CPU-, macOS- und iOS-Abnahme von NeverD.

Der erste Live-Kontrolllauf `37256341043` auf macOS 26 bestand 1.000 Runden. Bei `37256339176` auf macOS 15 stürzte der identifizierte Node-Uploader mit SIGSEGV ab; nach 411 vollständigen Runden wurde der native Kindprozess beendet und eingesammelt, sein Ergebnis bleibt unbekannt. `observation=final-only` behält Programm und Grenzen bei, lädt aber nur den Plan vor Ausführung und abschließende Belege nach Prozessende hoch. Gleichzeitige Scans, Prozessabfragen und Fortschrittsuploads entfallen gemeinsam. Bei Verbindungsverlust kann nur der Plan übrig bleiben; das gilt nicht als Erfolg. Erst beide neuen vCPU-Kontrollen vollständig bestehen lassen, dann VM testen; alle Fehlschläge behalten. Die Ursache ist offen.

Die ersten `final-only`-Läufe `37257757852` (macOS 15) und `37257759882` (macOS 26) endeten beide mit Code 1 und wurden eingesammelt, ohne gleichzeitige Fortschrittsuploads oder Verbindungsverlust. Der ursprüngliche Parser wies je ein CRCRLF zurück. Eine getrennte LF-Analyse bestätigt 501/781 vollständige Runden, dann Budgetüberschreitungen in Runde 502/782 mit erfolgreicher Freigabe. Die alten 2,842/2,013 s enthalten Logausgaben und sind keine reine HVF-Zeit. Protokoll 2 korrigiert LF-Trennung, deaktiviert nur für diesen Versuch die PTY-Ausgabeverarbeitung, prüft nach dem Anfangslog dieselbe Frist erneut und erfasst Zustand vor Endlogs. `entered` ist die Hostzeit vor dem API-Aufruf, kein VM-Eintrittsnachweis; Scheduling bleibt enthalten. Alte Fehler bleiben erhalten; VM erst nach beiden neuen vCPU-Erfolgen.

## Español

Este control HVF independiente en modo real conserva la licencia original. `vcpu` mantiene una VM; `vm` la recrea en cada vuelta. Cada modo realiza 1.000 vueltas y exige una escritura nueva verificada, una salida del temporizador acotada, finalización correcta y recogida del proceso hijo. Esperar el éxito completo de `vcpu` en ambas imágenes Intel antes de ejecutar los controles `vm` correspondientes. La desconexión, la salida incompleta o el fallo de carga no cuentan como éxito; también se conservan los fallos. No demuestra la causa, el rendimiento ni la aceptación completa de CPU, macOS o iOS en NeverD.

El primer control en vivo `37256341043` en macOS 26 superó 1.000 vueltas. En macOS 15, `37256339176` sufrió un SIGSEGV del cargador Node identificado; el hijo nativo se terminó y recogió tras 411 vueltas completas, por lo que su resultado sigue desconocido. `observation=final-only` mantiene programa y límites, pero carga el plan antes de ejecutar y la evidencia final después de terminar. Retira conjuntamente el escaneo, las consultas de procesos y las cargas simultáneas. Una desconexión puede dejar solo el plan, sin éxito nativo. Exigir ambos nuevos controles vCPU completos antes de probar VM y conservar todos los fallos. La causa sigue sin determinarse.

Los controles `final-only` `37257757852` (macOS 15) y `37257759882` (macOS 26) terminaron con código 1 y fueron recogidos, sin cargas de progreso simultáneas ni desconexión. El analizador original rechazó un CRCRLF por flujo. Un análisis LF separado verifica 501/781 vueltas completas y después exceso de presupuesto en 502/782 con limpieza correcta. Los anteriores 2,842/2,013 s incluyen escritura de registros, no solo HVF. El protocolo 2 corrige la separación LF, desactiva el procesamiento de salida PTY solo para este control, vuelve a comprobar el mismo límite tras el registro inicial y captura estado antes de los registros finales. `entered` es el instante del host antes de llamar a la API, no prueba de entrada a VM; el intervalo aún incluye planificación. Se conservan los fallos; no ejecutar VM antes de ambos nuevos éxitos vCPU.

## Italiano

Questo controllo HVF indipendente in modalità reale conserva la licenza originale. `vcpu` mantiene una VM; `vm` la ricrea a ogni ciclo. Ogni modalità esegue 1.000 cicli e richiede una nuova scrittura verificata, un'uscita del timer entro il limite, la terminazione corretta e il recupero del processo figlio. Attendere il successo completo di `vcpu` su entrambe le immagini Intel prima dei controlli `vm` corrispondenti. Disconnessione, output mancante o errore di caricamento non valgono come successo; conservare anche gli insuccessi. Non dimostra la causa, le prestazioni o la convalida completa CPU, macOS e iOS di NeverD.

Il primo controllo live `37256341043` su macOS 26 ha superato 1.000 cicli. Su macOS 15, `37256339176` ha subito un SIGSEGV del processo Node di caricamento identificato; il figlio nativo è stato terminato e recuperato dopo 411 cicli completi, quindi il risultato nativo resta sconosciuto. `observation=final-only` mantiene programma e limiti, ma carica il piano prima dell’esecuzione e le prove finali dopo la terminazione. Elimina insieme scansioni, sonde dei processi e caricamenti simultanei. Una disconnessione può lasciare solo il piano, senza successo nativo. Richiedere entrambi i nuovi controlli vCPU completi prima dei controlli VM e conservare tutti gli insuccessi. La causa resta da determinare.

I controlli `final-only` `37257757852` (macOS 15) e `37257759882` (macOS 26) sono terminati con codice 1 e recuperati, senza caricamenti simultanei del progresso né disconnessioni. Il parser originale ha rifiutato un CRCRLF per flusso. Un’analisi LF separata verifica 501/781 cicli completi, poi il superamento del limite nei cicli 502/782 con pulizia riuscita. I vecchi 2,842/2,013 s includono scritture dei log, non solo HVF. Il protocollo 2 corregge la separazione LF, disattiva l’elaborazione dell’output PTY solo per questo controllo, ricontrolla lo stesso termine dopo il log iniziale e acquisisce lo stato prima dei log finali. `entered` è l’istante host prima della chiamata API, non prova dell’ingresso VM; l’intervallo include ancora la pianificazione. Conservare i fallimenti; niente VM prima di entrambi i nuovi successi vCPU.

## Русский

Этот независимый контроль HVF в реальном режиме сохраняет исходную лицензию. `vcpu` сохраняет одну VM, а `vm` создаёт её заново на каждом шаге. Каждый режим выполняет 1 000 шагов с проверкой новой записи, ограниченного выхода по таймеру, успешного завершения и освобождения дочернего процесса. Запускать соответствующие проверки `vm` только после полного успеха `vcpu` на обоих образах Intel. Потеря связи, неполный вывод или ошибка загрузки не считаются успехом; неудачи также сохраняются. Это не доказывает причину, производительность или полную приёмку CPU, macOS и iOS в NeverD.

Первый контроль с наблюдением `37256341043` на macOS 26 прошёл 1 000 шагов. На macOS 15 в `37256339176` подтверждён SIGSEGV процесса загрузки Node; после 411 завершённых шагов нативный дочерний процесс был остановлен и освобождён, поэтому его результат неизвестен. `observation=final-only` сохраняет программу и ограничения, но загружает план до запуска, а итоговые доказательства после завершения. Одновременно исключаются сканирование, опрос процессов и загрузка прогресса. При потере связи может остаться только план, что не означает успеха. Сначала должны полностью пройти обе новые проверки vCPU, затем можно проверять VM; все неудачи сохраняются. Причина не установлена.

Первые проверки `final-only` — `37257757852` (macOS 15) и `37257759882` (macOS 26) — завершились с кодом 1 и освобождением процессов, без одновременной загрузки прогресса и потери связи. Исходный анализатор отклонил по одному CRCRLF. Отдельный LF-анализ проверяет 501/781 полный шаг, затем превышение бюджета на шагах 502/782 и успешную очистку. Старые 2,842/2,013 с включают запись журналов, а не только HVF. Протокол 2 исправляет разделение LF, отключает обработку вывода PTY только для этого опыта, повторно проверяет тот же срок после начального журнала и считывает состояние до завершающих журналов. `entered` — момент хоста перед вызовом API, не доказательство входа VM; интервал по-прежнему включает планирование. Старые неудачи сохраняются; VM не запускать до обоих новых успехов vCPU.

## العربية

هذا اختبار HVF مستقل في الوضع الحقيقي مع الاحتفاظ بترخيص المصدر. يحتفظ `vcpu` بآلة افتراضية واحدة، بينما يعيد `vm` إنشاءها في كل دورة. ينفذ كل وضع 1,000 دورة مع التحقق من كتابة جديدة وخروج مؤقت ضمن المهلة ونهاية ناجحة وجمع العملية التابعة. يجب انتظار النجاح الكامل لاختبار `vcpu` على صورتي Intel قبل تشغيل اختباري `vm` المقابلين. انقطاع الاتصال أو نقص المخرجات أو فشل الرفع لا يُعد نجاحاً، وتُحفظ المحاولات الفاشلة أيضاً. لا يثبت ذلك السبب أو الأداء أو اكتمال اختبارات CPU وmacOS وiOS في NeverD.

نجح الاختبار المباشر الأول `37256341043` على macOS 26 في 1,000 دورة. أما `37256339176` على macOS 15 فقد سجل SIGSEGV في عملية رفع Node بعد مطابقة هويتها؛ أُوقفت العملية الأصلية التابعة وجُمعت بعد 411 دورة مكتملة، وتبقى نتيجتها مجهولة. يحافظ `observation=final-only` على البرنامج والحدود، لكنه يرفع الخطة قبل التنفيذ والأدلة النهائية بعد الانتهاء فقط. يزيل المسح وفحص العمليات ورفع التقدم المتزامن معاً. قد يترك انقطاع الاتصال الخطة وحدها، وهذا لا يُعد نجاحاً. يجب نجاح اختباري vCPU الجديدين بالكامل قبل اختباري VM، مع حفظ جميع الإخفاقات. السبب لم يُحدد بعد.

انتهى اختبارا `final-only`، وهما `37257757852` على macOS 15 و`37257759882` على macOS 26، بالرمز 1 مع جمع العمليتين، دون رفع تقدم متزامن أو انقطاع اتصال. رفض المحلل الأصلي CRCRLF واحدة في كل سجل. يؤكد تحليل LF منفصل اكتمال 501/781 دورة ثم تجاوز المهلة في 502/782 مع تنظيف ناجح. تتضمن الفترتان السابقتان 2.842/2.013 ثانية كتابة السجلات، ولا تمثلان وقت HVF وحده. يصحح البروتوكول 2 تقسيم LF ويعطل معالجة خرج PTY لهذا الاختبار فقط، ويعيد فحص المهلة نفسها بعد سجل البداية ويجمع الحالة قبل سجلات النهاية. `entered` هو وقت المضيف قبل استدعاء API، وليس دليلاً على دخول VM؛ ولا تزال الفترة تتضمن الجدولة. تُحفظ الإخفاقات ولا تُشغل VM قبل نجاح اختباري vCPU الجديدين.
