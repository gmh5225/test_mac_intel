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

## 中文（简体）

这是独立编写的实模式 HVF 对照，保留上游许可。`vcpu` 保留一个 VM，`vm` 每轮重建 VM；两种模式均执行 1,000 轮，要求新写入见证、有限计时器退出、成功退出和进程回收。先等待两个 Intel 镜像的 `vcpu` 完整通过，再运行对应 `vm`。失联、输出缺失或上传失败不能算通过；失败也必须留档。它不代表根因、性能或 NeverD CPU、macOS、iOS 完整验收。

## 中文（繁體）

這是獨立編寫的實模式 HVF 對照，保留上游授權。`vcpu` 保留一個 VM，`vm` 每輪重建 VM；兩者均執行 1,000 輪，要求新的寫入見證、有限計時器退出、成功結束及程序回收。先等待兩個 Intel 映像的 `vcpu` 完整通過，再執行對應 `vm`。失聯、輸出缺失或上傳失敗不能算通過；失敗也須留存。它不代表根因、效能或 NeverD CPU、macOS、iOS 完整驗收。

## 日本語

上流のライセンスを保持した、独自の実モード HVF 対照実験です。`vcpu` は一つの VM を保持し、`vm` は毎回 VM を再生成します。各 1,000 回で新しい書込み、有限タイマー終了、正常終了と子プロセス回収が必要です。両 Intel イメージの `vcpu` が完全に成功してから対応する `vm` を実行します。接続喪失、出力欠落、アップロード失敗は合格とせず、失敗も保存します。原因・性能や NeverD CPU、macOS、iOS の完全検証を示すものではありません。

## 한국어

상위 라이선스를 유지한 독립적인 real mode HVF 대조 실험입니다. `vcpu`는 VM 하나를 유지하고 `vm`은 매번 VM을 다시 만듭니다. 각각 1,000회 실행하며 새로운 쓰기 증거, 유한 타이머 종료, 정상 종료와 자식 프로세스 회수가 필요합니다. 두 Intel 이미지의 `vcpu`가 완전히 통과한 뒤 대응하는 `vm`을 실행합니다. 연결 손실, 출력 누락, 업로드 실패를 통과로 보지 않으며 실패도 보존합니다. 원인·성능이나 NeverD CPU, macOS, iOS 전체 검증을 증명하지 않습니다.

## Français

Ce contrôle HVF indépendant en mode réel conserve la licence amont. `vcpu` garde une VM ; `vm` recrée la VM à chaque tour. Chacun effectue 1 000 tours avec une nouvelle écriture vérifiée, une sortie de temporisateur bornée, une sortie normale et la récupération du processus enfant. Attendre le succès complet de `vcpu` sur les deux images Intel avant les contrôles `vm` correspondants. Une déconnexion, une sortie manquante ou un échec de téléversement ne vaut pas succès ; conserver aussi les échecs. Ce test ne prouve ni la cause, ni les performances, ni la validation complète CPU, macOS ou iOS de NeverD.

## Deutsch

Dieser eigenständige HVF-Vergleich im Real Mode behält die Upstream-Lizenz bei. `vcpu` behält eine VM, `vm` erstellt sie in jeder Runde neu. Je 1.000 Runden verlangen einen frischen Schreibnachweis, einen begrenzten Timer-Exit, erfolgreichen Prozessabschluss und das Einsammeln des Kindprozesses. Erst nach vollständigem Erfolg von `vcpu` auf beiden Intel-Images folgen die zugehörigen `vm`-Kontrollen. Verbindungsverlust, fehlende Ausgabe oder Uploadfehler gelten nicht als Erfolg; auch Fehlschläge bleiben erhalten. Das belegt weder Ursache noch Leistung oder die vollständige CPU-, macOS- und iOS-Abnahme von NeverD.

## Español

Este control HVF independiente en modo real conserva la licencia original. `vcpu` mantiene una VM; `vm` la recrea en cada vuelta. Cada modo realiza 1.000 vueltas y exige una escritura nueva verificada, una salida del temporizador acotada, finalización correcta y recogida del proceso hijo. Esperar el éxito completo de `vcpu` en ambas imágenes Intel antes de ejecutar los controles `vm` correspondientes. La desconexión, la salida incompleta o el fallo de carga no cuentan como éxito; también se conservan los fallos. No demuestra la causa, el rendimiento ni la aceptación completa de CPU, macOS o iOS en NeverD.

## Italiano

Questo controllo HVF indipendente in modalità reale conserva la licenza originale. `vcpu` mantiene una VM; `vm` la ricrea a ogni ciclo. Ogni modalità esegue 1.000 cicli e richiede una nuova scrittura verificata, un'uscita del timer entro il limite, la terminazione corretta e il recupero del processo figlio. Attendere il successo completo di `vcpu` su entrambe le immagini Intel prima dei controlli `vm` corrispondenti. Disconnessione, output mancante o errore di caricamento non valgono come successo; conservare anche gli insuccessi. Non dimostra la causa, le prestazioni o la convalida completa CPU, macOS e iOS di NeverD.

## Русский

Этот независимый контроль HVF в реальном режиме сохраняет исходную лицензию. `vcpu` сохраняет одну VM, а `vm` создаёт её заново на каждом шаге. Каждый режим выполняет 1 000 шагов с проверкой новой записи, ограниченного выхода по таймеру, успешного завершения и освобождения дочернего процесса. Запускать соответствующие проверки `vm` только после полного успеха `vcpu` на обоих образах Intel. Потеря связи, неполный вывод или ошибка загрузки не считаются успехом; неудачи также сохраняются. Это не доказывает причину, производительность или полную приёмку CPU, macOS и iOS в NeverD.

## العربية

هذا اختبار HVF مستقل في الوضع الحقيقي مع الاحتفاظ بترخيص المصدر. يحتفظ `vcpu` بآلة افتراضية واحدة، بينما يعيد `vm` إنشاءها في كل دورة. ينفذ كل وضع 1,000 دورة مع التحقق من كتابة جديدة وخروج مؤقت ضمن المهلة ونهاية ناجحة وجمع العملية التابعة. يجب انتظار النجاح الكامل لاختبار `vcpu` على صورتي Intel قبل تشغيل اختباري `vm` المقابلين. انقطاع الاتصال أو نقص المخرجات أو فشل الرفع لا يُعد نجاحاً، وتُحفظ المحاولات الفاشلة أيضاً. لا يثبت ذلك السبب أو الأداء أو اكتمال اختبارات CPU وmacOS وiOS في NeverD.
