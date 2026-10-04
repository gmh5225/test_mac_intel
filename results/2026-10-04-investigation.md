# Intel HVF investigation — 2026-10-04

## en: Intel isolation results (2026-10-04)

The finite owner-deadline candidate `909672ca6` remains experimental. The original 1000-repetition recovery test lost runner communication on both macOS 15 and 26; its last preserved prefixes contain 277/278 and 250/251 completed/started iterations. Ordinary instruction execution with the same candidate and no explicit cancellation also lost communication on macOS 15 (576/577). GitHub confirmed all three losses. None has a final native result or retirement record; a saved prefix does not locate the eventual fault. [Original evidence](https://github.com/gmh5225/test_mac_intel/tree/main/results/2026-10-04-boundaries).

An independent, unchanged `hvf-edge-cases` program at `f150b38` completed its real-mode guest and 100000 random interrupt call attempts on both images, in approximately 362 and 398 seconds. Both exited zero and their children were reaped; artifact digests, source hashes, checkpoints and guest completion were independently checked. Earlier 300-second attempts reached their observer deadline and were retired, without losing the runner. The upstream program ignores random interrupt return codes, so attempt counts do not establish one-to-one delivery. This control is not NeverD acceptance or a performance comparison. [Source, logs and audit](https://github.com/gmh5225/test_mac_intel/tree/main/results/2026-10-04-upstream).

These results narrow the investigation but establish no production fix. Retaining the VM and executor threads is a diagnostic comparison, not an accepted lifecycle change. Intel still requires the original 1000-repetition recovery test, complete CPU inventory and independent Darwin gate on the same clean candidate.

## zh-CN: Intel 隔离实验结果（2026-10-04）

有限 owner 期限候选 `909672ca6` 仍属实验方案。原始 1000 轮恢复测试在 macOS 15 和 26 上均失联；最后保存的日志分别证明 277/278、250/251 轮已完成/已开始。同一候选的普通指令测试没有主动取消操作，在 macOS 15 上也失联（576/577）。三次均有 GitHub 失联注记，均缺少最终原生结果和进程回收记录；保存的日志不能定位最终故障。[原始证据](https://github.com/gmh5225/test_mac_intel/tree/main/results/2026-10-04-boundaries)。

独立且未修改的 `hvf-edge-cases` 程序 `f150b38` 在两个镜像上完成 real-mode guest 和 100000 次随机中断调用尝试，耗时约 362、398 秒。两次均正常退出并回收子进程；产物摘要、源码哈希、进度标记和 guest 完成输出均已独立核验。先前 300 秒尝试达到观察器期限后被回收，没有 runner 失联。上游程序忽略随机中断返回值，调用次数不代表逐次成功交付。该对照不构成 NeverD 验收或性能比较。[源码、日志与审计](https://github.com/gmh5225/test_mac_intel/tree/main/results/2026-10-04-upstream)。

这些结果缩小了调查范围，但尚未证明生产修复。保留 VM 和 Executor 线程仅用于诊断对照，尚未成为接受的生命周期变更。Intel 仍须在同一个干净候选上通过原始 1000 轮恢复、完整 CPU 清单和独立 Darwin 门禁。

## zh-TW: Intel 隔離實驗結果（2026-10-04）

有限 owner 期限候選 `909672ca6` 仍屬實驗方案。原始 1000 輪恢復測試在 macOS 15 與 26 上均失聯；最後保留的紀錄分別證明 277/278、250/251 輪已完成/已開始。同一候選的普通指令測試沒有主動取消操作，在 macOS 15 上也失聯（576/577）。三次均有 GitHub 失聯註記，均缺少最終原生結果與程序回收紀錄；保留的紀錄無法定位最終故障。[原始證據](https://github.com/gmh5225/test_mac_intel/tree/main/results/2026-10-04-boundaries)。

獨立且未修改的 `hvf-edge-cases` 程式 `f150b38` 在兩個映像上完成 real-mode guest 與 100000 次隨機中斷呼叫嘗試，耗時約 362、398 秒。兩次均正常結束並回收子程序；產物摘要、原始碼雜湊、進度標記與 guest 完成輸出均已獨立核驗。先前 300 秒嘗試達到觀察器期限後被回收，沒有 runner 失聯。上游程式忽略隨機中斷回傳值，呼叫次數不代表逐次成功交付。此對照不構成 NeverD 驗收或效能比較。[原始碼、紀錄與稽核](https://github.com/gmh5225/test_mac_intel/tree/main/results/2026-10-04-upstream)。

這些結果縮小調查範圍，但尚未證明正式修復。保留 VM 與 Executor 執行緒僅用於診斷對照，尚未成為接受的生命週期變更。Intel 仍須在同一個乾淨候選上通過原始 1000 輪恢復、完整 CPU 清單與獨立 Darwin 門檻。

## ja: Intel 分離実験の結果（2026-10-04）

所有スレッドの実行期限を有限にした候補 `909672ca6` は実験段階です。元の 1000 回復旧テストは macOS 15 と 26 の両方で runner との通信を失いました。保存された末尾の完了/開始回数は 277/278 と 250/251 です。同じ候補で明示的なキャンセルを行わない通常命令テストも macOS 15 で通信を失いました（576/577）。GitHub が 3 件とも確認しています。最終ネイティブ結果とプロセス回収記録はなく、保存ログから最終的な障害箇所は特定できません。[元の証拠](https://github.com/gmh5225/test_mac_intel/tree/main/results/2026-10-04-boundaries)。

独立した未変更の `hvf-edge-cases` プログラム `f150b38` は、両イメージで real-mode guest と 100000 回のランダム割り込み呼び出し試行を約 362 秒、398 秒で完了しました。終了コードは 0 で子プロセスも回収済みです。成果物とソースのハッシュ、進捗、guest 完了を独立検証しました。先の 300 秒実行は観測期限で終了・回収され、runner の通信断はありませんでした。上流コードはランダム割り込みの戻り値を無視するため、試行数は配信成功数を意味しません。NeverD の受け入れ検証や性能比較には代用できません。[ソース・ログ・監査](https://github.com/gmh5225/test_mac_intel/tree/main/results/2026-10-04-upstream)。

調査範囲は狭まりましたが、製品修正はまだ証明されていません。VM と Executor スレッドの保持は診断用の比較であり、採用済みのライフサイクル変更ではありません。Intel では同じクリーンな候補で元の 1000 回復旧テスト、CPU 全項目、独立 Darwin ゲートを通す必要があります。

## ko: Intel 분리 실험 결과（2026-10-04）

소유 스레드의 실행 기한을 유한하게 바꾼 후보 `909672ca6`은 실험 단계입니다. 원래 1000회 복구 테스트는 macOS 15와 26 모두에서 runner 연결을 잃었습니다. 마지막 보존 기록의 완료/시작 횟수는 277/278과 250/251입니다. 같은 후보에서 명시적 취소 없는 일반 명령 테스트도 macOS 15에서 연결이 끊겼습니다（576/577）. GitHub가 세 건 모두 확인했습니다. 최종 네이티브 결과와 프로세스 회수 기록은 없으며, 저장된 로그는 최종 장애 위치를 특정하지 못합니다. [원본 증거](https://github.com/gmh5225/test_mac_intel/tree/main/results/2026-10-04-boundaries).

독립적인 원본 `hvf-edge-cases` 프로그램 `f150b38`은 두 이미지에서 real-mode guest와 100000회 무작위 인터럽트 호출 시도를 약 362초와 398초에 완료했습니다. 모두 종료 코드 0과 자식 프로세스 회수가 확인되었고, 산출물·소스 해시, 진행 표시, guest 완료도 독립 검증했습니다. 앞선 300초 실행은 관찰 기한에 도달해 회수되었으며 runner 연결은 유지되었습니다. 상류 코드는 무작위 인터럽트 반환값을 무시하므로 시도 횟수가 개별 전달 성공을 뜻하지 않습니다. NeverD 승인이나 성능 비교를 대신하지 않습니다. [소스·로그·감사](https://github.com/gmh5225/test_mac_intel/tree/main/results/2026-10-04-upstream).

조사 범위는 좁아졌지만 제품 수정이 입증되지는 않았습니다. VM과 Executor 스레드 유지는 진단 비교이며 채택된 수명 변경이 아닙니다. Intel은 동일한 깨끗한 후보에서 원래 1000회 복구 테스트, 전체 CPU 목록 및 독립 Darwin 관문을 통과해야 합니다.

## fr: Résultats des expériences Intel isolées (2026-10-04)

Le candidat `909672ca6`, qui impose une échéance finie au thread propriétaire, reste expérimental. Le test original de 1000 récupérations a perdu la communication avec le runner sur macOS 15 et 26 : les derniers préfixes conservés montrent 277/278 et 250/251 répétitions terminées/démarrées. Le test d’instructions ordinaires du même candidat, sans annulation explicite, a aussi perdu la communication sur macOS 15 (576/577). GitHub confirme les trois pertes. Aucun résultat natif final ni relevé de récupération du processus n’est disponible ; les préfixes ne localisent pas la panne finale. [Preuves originales](https://github.com/gmh5225/test_mac_intel/tree/main/results/2026-10-04-boundaries).

Le programme indépendant et inchangé `hvf-edge-cases`, révision `f150b38`, a terminé son invité en mode réel et 100000 tentatives d’appel d’interruption aléatoire sur les deux images, en environ 362 et 398 secondes. Les deux sorties valent zéro et les processus enfants ont été récupérés ; empreintes, progression et fin de l’invité ont été vérifiées indépendamment. Les essais précédents à 300 secondes ont atteint la limite d’observation et ont été arrêtés puis récupérés, sans perte du runner. Le programme ignore les codes de retour des interruptions aléatoires : les tentatives ne prouvent pas leur livraison individuelle. Ce contrôle ne vaut ni validation NeverD ni comparaison de performances. [Sources, journaux et audit](https://github.com/gmh5225/test_mac_intel/tree/main/results/2026-10-04-upstream).

Ces résultats réduisent le champ d’investigation sans établir de correction. Conserver VM et threads Executor est un contrôle diagnostique, pas un changement de cycle de vie accepté. Intel exige encore les 1000 récupérations originales, l’inventaire CPU complet et le contrôle Darwin indépendant sur un même candidat propre.

## de: Ergebnisse isolierter Intel-Versuche (2026-10-04)

Der Kandidat `909672ca6` mit endlicher Frist im besitzenden Thread bleibt experimentell. Der ursprüngliche Test mit 1000 Wiederherstellungen verlor unter macOS 15 und 26 die Verbindung zum Runner. Die letzten gespeicherten Ausschnitte zeigen 277/278 und 250/251 beendete/gestartete Durchläufe. Auch gewöhnliche Anweisungen desselben Kandidaten ohne ausdrücklichen Abbruch verloren unter macOS 15 die Verbindung (576/577). GitHub bestätigte alle drei Verluste. Native Endergebnisse und Nachweise der Prozessbeendigung fehlen; die Ausschnitte bestimmen nicht den späteren Fehlerort. [Originalbelege](https://github.com/gmh5225/test_mac_intel/tree/main/results/2026-10-04-boundaries).

Das unabhängige, unveränderte Programm `hvf-edge-cases` bei `f150b38` beendete seinen Real-Mode-Gast und 100000 zufällige Interrupt-Aufrufversuche auf beiden Images nach etwa 362 und 398 Sekunden. Beide Exitcodes waren null, die Kindprozesse wurden eingesammelt. Artefakt- und Quellhashes, Fortschritt und Gastabschluss wurden unabhängig geprüft. Frühere Versuche erreichten die Beobachtungsgrenze von 300 Sekunden und wurden beendet und eingesammelt, ohne Runner-Verlust. Das Original ignoriert Rückgabecodes zufälliger Interrupts; Aufrufzahlen belegen keine einzelne Zustellung. Der Vergleich ersetzt weder NeverD-Abnahme noch Leistungsmessung. [Quellen, Protokolle und Prüfung](https://github.com/gmh5225/test_mac_intel/tree/main/results/2026-10-04-upstream).

Die Ergebnisse grenzen die Untersuchung ein, belegen aber keine Produktkorrektur. VM und Executor-Threads beizubehalten ist ein Diagnosevergleich, keine akzeptierte Lebenszyklusänderung. Intel benötigt weiterhin den ursprünglichen 1000-fachen Wiederherstellungstest, das vollständige CPU-Inventar und die unabhängige Darwin-Prüfung am selben sauberen Kandidaten.

## es: Resultados de experimentos Intel aislados (2026-10-04)

El candidato `909672ca6`, con plazo finito en el hilo propietario, sigue siendo experimental. La prueba original de 1000 recuperaciones perdió la comunicación con el runner en macOS 15 y 26; los últimos prefijos conservados muestran 277/278 y 250/251 iteraciones completadas/iniciadas. Las instrucciones ordinarias del mismo candidato, sin cancelación explícita, también perdieron la comunicación en macOS 15 (576/577). GitHub confirmó las tres pérdidas. Faltan el resultado nativo final y el registro de recogida del proceso; los prefijos no localizan el fallo final. [Pruebas originales](https://github.com/gmh5225/test_mac_intel/tree/main/results/2026-10-04-boundaries).

El programa independiente y sin modificar `hvf-edge-cases`, revisión `f150b38`, completó su invitado en modo real y 100000 intentos de llamada de interrupción aleatoria en ambas imágenes, en unos 362 y 398 segundos. Ambos terminaron con código cero y se recogieron sus procesos hijos; hashes, progreso y finalización del invitado se verificaron de forma independiente. Los intentos anteriores de 300 segundos alcanzaron el plazo del observador y fueron terminados y recogidos, sin pérdida del runner. El programa ignora los códigos de retorno de las interrupciones aleatorias: el número de intentos no demuestra entregas individuales. No sustituye la aceptación de NeverD ni una comparación de rendimiento. [Código, registros y auditoría](https://github.com/gmh5225/test_mac_intel/tree/main/results/2026-10-04-upstream).

Estos resultados acotan la investigación, pero no establecen una corrección de producción. Conservar VM e hilos Executor es una comparación diagnóstica, no un cambio de ciclo de vida aceptado. Intel aún debe superar las 1000 recuperaciones originales, el inventario CPU completo y la prueba Darwin independiente con el mismo candidato limpio.

## it: Risultati degli esperimenti Intel isolati (2026-10-04)

Il candidato `909672ca6`, con scadenza finita sul thread proprietario, resta sperimentale. Il test originale di 1000 recuperi ha perso la comunicazione con il runner sia su macOS 15 sia su 26; gli ultimi prefissi salvati mostrano 277/278 e 250/251 iterazioni completate/avviate. Anche le istruzioni ordinarie dello stesso candidato, senza annullamento esplicito, hanno perso la comunicazione su macOS 15 (576/577). GitHub ha confermato tutte e tre le perdite. Mancano il risultato nativo finale e il registro di raccolta del processo; i prefissi non localizzano il guasto finale. [Prove originali](https://github.com/gmh5225/test_mac_intel/tree/main/results/2026-10-04-boundaries).

Il programma indipendente e invariato `hvf-edge-cases`, revisione `f150b38`, ha completato il guest in modalità reale e 100000 tentativi di chiamata di interrupt casuale su entrambe le immagini, in circa 362 e 398 secondi. Entrambi sono terminati con codice zero e i processi figli sono stati raccolti; hash, avanzamento e completamento del guest sono stati verificati indipendentemente. I precedenti tentativi di 300 secondi hanno raggiunto la scadenza dell’osservatore e sono stati terminati e raccolti, senza perdita del runner. Il programma ignora i codici di ritorno degli interrupt casuali: il numero di tentativi non prova la consegna individuale. Non sostituisce l’accettazione NeverD né un confronto prestazionale. [Sorgenti, log e verifica](https://github.com/gmh5225/test_mac_intel/tree/main/results/2026-10-04-upstream).

Questi risultati restringono l’indagine, ma non dimostrano una correzione di produzione. Conservare VM e thread Executor è un confronto diagnostico, non una modifica del ciclo di vita accettata. Intel richiede ancora i 1000 recuperi originali, l’intero inventario CPU e il controllo Darwin indipendente sul medesimo candidato pulito.

## ru: Результаты изолированных экспериментов Intel (2026-10-04)

Кандидат `909672ca6` с конечным сроком выполнения в потоке-владельце остаётся экспериментальным. Исходный тест 1000 восстановлений потерял связь с runner на macOS 15 и 26; последние сохранённые фрагменты содержат 277/278 и 250/251 завершённых/начатых итераций. Обычные инструкции того же кандидата без явной отмены также потеряли связь на macOS 15 (576/577). GitHub подтвердил все три случая. Итоговых нативных результатов и записей о сборе дочернего процесса нет; фрагменты не определяют место последующего сбоя. [Исходные доказательства](https://github.com/gmh5225/test_mac_intel/tree/main/results/2026-10-04-boundaries).

Независимая неизменённая программа `hvf-edge-cases`, версия `f150b38`, завершила гостя в реальном режиме и 100000 попыток вызова случайных прерываний на обоих образах примерно за 362 и 398 секунд. Оба кода выхода равны нулю, дочерние процессы собраны; хеши, ход выполнения и завершение гостя проверены независимо. Предыдущие попытки достигли предела наблюдения 300 секунд и были остановлены и собраны без потери runner. Программа игнорирует коды возврата случайных прерываний, поэтому число попыток не доказывает доставку каждого вызова. Это не приёмка NeverD и не сравнение производительности. [Код, журналы и аудит](https://github.com/gmh5225/test_mac_intel/tree/main/results/2026-10-04-upstream).

Результаты сужают область поиска, но не доказывают исправление продукта. Сохранение VM и потоков Executor — диагностическое сравнение, а не принятая смена жизненного цикла. Intel по-прежнему требует исходные 1000 восстановлений, полный набор CPU и отдельную проверку Darwin на одном чистом кандидате.

## ar: نتائج تجارب Intel المعزولة (2026-10-04)

يبقى المرشح `909672ca6`، الذي يفرض مهلة محدودة على الخيط المالك، تجريبيًا. فقد اختبار الاسترداد الأصلي ذو 1000 تكرار اتصال runner على macOS 15 و26؛ وتثبت آخر الأجزاء المحفوظة 277/278 و250/251 تكرارًا مكتملًا/بدأ. وفقد اختبار التعليمات العادية للمرشح نفسه، بلا إلغاء صريح، الاتصال أيضًا على macOS 15 (576/577). أكد GitHub الحالات الثلاث. لا توجد نتيجة أصلية نهائية أو سجلات جمع العملية؛ ولا تحدد الأجزاء المحفوظة موقع العطل النهائي. [الأدلة الأصلية](https://github.com/gmh5225/test_mac_intel/tree/main/results/2026-10-04-boundaries).

أكمل البرنامج المستقل وغير المعدّل `hvf-edge-cases` بالإصدار `f150b38` الضيف في النمط الحقيقي و100000 محاولة استدعاء مقاطعة عشوائية على الصورتين، خلال نحو 362 و398 ثانية. انتهت العمليتان برمز صفر وجُمعت العمليتان الفرعيتان؛ ودُققت بصمات المصدر والملفات والتقدم واكتمال الضيف بصورة مستقلة. بلغت المحاولتان السابقتان حد المراقبة البالغ 300 ثانية وأُنهِيتا وجُمعتا دون فقدان runner. يتجاهل البرنامج رموز إرجاع المقاطعات العشوائية، لذا لا يثبت عدد المحاولات تسليم كل مقاطعة. لا يُعد هذا قبولًا لـNeverD أو مقارنة أداء. [المصدر والسجلات والتدقيق](https://github.com/gmh5225/test_mac_intel/tree/main/results/2026-10-04-upstream).

تضيّق النتائج نطاق التحقيق لكنها لا تثبت إصلاح المنتج. الاحتفاظ بالـVM وخيوط Executor مقارنة تشخيصية وليس تغييرًا معتمدًا لدورة الحياة. ما زال Intel يتطلب نجاح 1000 تكرار الاسترداد الأصلي وكامل قائمة CPU واختبار Darwin المستقل على المرشح النظيف نفسه.
