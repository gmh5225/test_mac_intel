# Intel macOS HVF on personal GitHub Actions

A small harness for comparing NeverD's Intel Hypervisor.framework recovery on a personal repository and the organization repository. No Intel Mac is needed locally to dispatch this workflow.

Open **Actions → Personal Intel HVF recovery diagnosis → Run workflow**. Defaults:

| Input | Value |
| --- | --- |
| Intel image | `macos-26-intel` (`macos-15-intel` is also available) |
| Tested NeverD source | `bd284894c60427cf4e6a60e661a1fa0df8a070f5` |
| Repetitions | `1000` in one native process; `100` is an optional shorter diagnosis |
| Diagnostic implementation | `a3a620b63a34c81a1cd1131c9905a8087b96c723`, pinned in the workflow |

The workflow requires native `x86_64`, a working signed HVF VM/vCPU probe, and `NEVERD_REQUIRE_HVF=1`. It builds only `NeverDHvfTests` with Release and HVF enabled, then uses the original `HvfExecutor.Native*` command, deadlines and assertions. It does not retry failed iterations. NeverD dependency submodule revisions and Actions implementations are pinned. The workflow has read-only repository permissions and does not retain checkout credentials.

Before running the guest, it uploads `provenance.json`, the execution plan, inventory and initial host state. While the original loop runs continuously, it uploads bounded progress copies. A reachable runner also uploads the final raw output, status and child-process retirement records. All artifact names include the run attempt. The legacy `controller_commit` in the diagnostic plan means **this workflow's commit**; `provenance.json` separately identifies the pinned NeverD diagnostic implementation and tested source.

Compare with [organization run 37159724276](https://github.com/NeverSight/NeverD/actions/runs/37159724276): the same tested source and 1,000-loop command, using macOS 26 Intel. That run used diagnostic revision `e4a8169e69eb668ed3795efe4bd5f42cf4f287c2`; this harness uses its updated controller, which additionally reports cancellation during final collection, records each uploader process outcome and collects matching uploader crash reports after failure. NeverD's guest execution code and test deadlines are unchanged between these diagnostic controllers. Queue time and runtime stability are separate observations. A last uploaded iteration is only a persisted prefix, not proof of the failure location. One passing recovery loop does not prove full CPU, macOS or iOS coverage, and a repository change alone does not establish the cause of a lost runner.

The adapted workflow is from [NeverD](https://github.com/NeverSight/NeverD) under **AGPL-3.0-only**. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Modifications dated **2026-10-04** add the personal repository wrapper, fixed upstream checkouts and independent provenance. The runtime source is checked out directly from NeverD.

The separate **Intel artifact uploader control** workflow uploads 16 synthetic snapshots with the same Node 24 runtime and pinned official uploader, without creating a VM or running NeverD. It isolates the upload path; a successful control is not a passing HVF recovery test. Its manifests explicitly record `native_execution=false`.

## 中文（简体）

在 Actions 中选择 **Personal Intel HVF recovery diagnosis** 并手动运行，无需本地 Intel Mac。默认使用 `macos-26-intel`，对固定的 NeverD 源码在同一进程连续测试 1,000 轮；也可选择 `macos-15-intel` 或 100 轮诊断。产物保留版本、计划、实时进度和最终结果。排队时间与运行稳定性分别判断；单次恢复测试通过不能代表完整 CPU、macOS 或 iOS 覆盖。[完整指南](https://github.com/NeverSight/NeverD/blob/dev/docs/zh-CN/macos-hvf.md)。

另有 `Intel artifact uploader control` 工作流：连续上传 16 份模拟快照，不启动 VM；它只用于排查上传器，成功不代表 HVF 测试通过。

## 中文（繁體）

在 Actions 選擇 **Personal Intel HVF recovery diagnosis** 手動執行，不需要本機 Intel Mac。預設以 `macos-26-intel` 對固定的 NeverD 原始碼，在同一程序連續測試 1,000 輪；亦可選擇 `macos-15-intel` 或 100 輪診斷。產物保留版本、計畫、即時進度及最終結果。排隊時間與執行穩定性須分別判斷；單次恢復測試通過不代表完整 CPU、macOS 或 iOS 覆蓋。[完整指南](https://github.com/NeverSight/NeverD/blob/dev/docs/zh-TW/macos-hvf.md)。

另有 `Intel artifact uploader control` 工作流程：連續上傳 16 份模擬快照，不啟動 VM；它只用於診斷上傳器，成功不代表 HVF 測試通過。

## 日本語

Actions で **Personal Intel HVF recovery diagnosis** を手動実行します。手元に Intel Mac は不要です。既定では `macos-26-intel` と固定した NeverD ソースを使い、同じプロセスで 1,000 回連続実行します。`macos-15-intel` と 100 回の診断も選択できます。成果物にはリビジョン、計画、進捗、最終結果を保存します。待ち時間と実行の安定性は別々に評価し、この復旧テストの成功を CPU・macOS・iOS 全体の検証とは扱いません。[詳細ガイド](https://github.com/NeverSight/NeverD/blob/dev/docs/ja/macos-hvf.md)。

`Intel artifact uploader control` は VM を起動せず、合成スナップショットを 16 回アップロードします。アップローダーの診断専用であり、成功しても HVF の検証完了を意味しません。

## 한국어

Actions에서 **Personal Intel HVF recovery diagnosis**를 수동 실행합니다. 로컬 Intel Mac은 필요하지 않습니다. 기본값은 `macos-26-intel`이며, 고정된 NeverD 소스를 같은 프로세스에서 1,000회 연속 테스트합니다. `macos-15-intel` 또는 100회 진단도 선택할 수 있습니다. 산출물에는 버전, 계획, 진행 상황과 최종 결과가 보존됩니다. 대기 시간과 실행 안정성은 따로 평가해야 하며, 복구 테스트 한 번의 성공이 전체 CPU·macOS·iOS 검증을 의미하지는 않습니다. [전체 안내](https://github.com/NeverSight/NeverD/blob/dev/docs/ko/macos-hvf.md).

`Intel artifact uploader control`은 VM 없이 합성 스냅샷 16개를 업로드합니다. 업로더 진단용이며, 성공해도 HVF 검증 완료를 뜻하지 않습니다.

## Français

Lancez **Personal Intel HVF recovery diagnosis** dans Actions, sans Mac Intel local. Par défaut, `macos-26-intel` exécute 1 000 répétitions dans un seul processus avec une révision fixe de NeverD. Vous pouvez aussi choisir `macos-15-intel` ou un diagnostic de 100 répétitions. Les artefacts conservent les révisions, le plan, la progression et le résultat final. Évaluez séparément l'attente et la stabilité ; réussir ce test de récupération ne valide pas toute la couverture CPU, macOS ou iOS. [Guide complet](https://github.com/NeverSight/NeverD/blob/dev/docs/fr/macos-hvf.md).

`Intel artifact uploader control` téléverse 16 instantanés synthétiques sans lancer de VM. Ce contrôle de l’outil de téléversement ne valide pas HVF.

## Deutsch

Starten Sie **Personal Intel HVF recovery diagnosis** manuell unter Actions; ein eigener Intel-Mac ist nicht erforderlich. Standardmäßig führt `macos-26-intel` mit einer festgelegten NeverD-Revision 1.000 Wiederholungen in einem Prozess aus. Alternativ sind `macos-15-intel` oder 100 Wiederholungen möglich. Artefakte sichern Revisionen, Plan, Fortschritt und Endergebnis. Wartezeit und Laufzeitstabilität werden getrennt bewertet. Ein erfolgreicher Wiederherstellungstest bestätigt keine vollständige CPU-, macOS- oder iOS-Abdeckung. [Vollständige Anleitung](https://github.com/NeverSight/NeverD/blob/dev/docs/de/macos-hvf.md).

`Intel artifact uploader control` lädt 16 synthetische Snapshots ohne VM hoch. Dieser Upload-Test bestätigt bei Erfolg keine HVF-Funktionalität.

## Español

Ejecute manualmente **Personal Intel HVF recovery diagnosis** en Actions; no necesita un Mac Intel local. Por defecto, `macos-26-intel` ejecuta 1.000 repeticiones en un solo proceso con una revisión fija de NeverD. También puede elegir `macos-15-intel` o un diagnóstico de 100 repeticiones. Los artefactos conservan las revisiones, el plan, el progreso y el resultado final. Evalúe por separado la espera y la estabilidad: superar esta prueba de recuperación no valida toda la cobertura de CPU, macOS o iOS. [Guía completa](https://github.com/NeverSight/NeverD/blob/dev/docs/es/macos-hvf.md).

`Intel artifact uploader control` carga 16 instantáneas sintéticas sin iniciar una VM. Este diagnóstico de carga no valida HVF aunque termine correctamente.

## Italiano

Avviare manualmente **Personal Intel HVF recovery diagnosis** da Actions; non serve un Mac Intel locale. Per impostazione predefinita, `macos-26-intel` esegue 1.000 ripetizioni in un unico processo su una revisione fissa di NeverD. Sono disponibili anche `macos-15-intel` e una diagnosi di 100 ripetizioni. Gli artefatti conservano revisioni, piano, avanzamento e risultato finale. Valutare separatamente l'attesa e la stabilità: il successo di questo test di recupero non convalida l'intera copertura CPU, macOS o iOS. [Guida completa](https://github.com/NeverSight/NeverD/blob/dev/docs/it/macos-hvf.md).

`Intel artifact uploader control` carica 16 istantanee sintetiche senza avviare una VM. Il successo di questa diagnosi del caricamento non convalida HVF.

## Русский

Запустите **Personal Intel HVF recovery diagnosis** вручную в Actions; собственный Intel Mac не нужен. По умолчанию `macos-26-intel` выполняет 1 000 повторений в одном процессе для фиксированной ревизии NeverD. Можно выбрать `macos-15-intel` или диагностику из 100 повторений. Артефакты сохраняют ревизии, план, ход выполнения и итог. Время ожидания и стабильность выполнения оцениваются отдельно: успешный тест восстановления не подтверждает полное покрытие CPU, macOS или iOS. [Полное руководство](https://github.com/NeverSight/NeverD/blob/dev/docs/ru/macos-hvf.md).

`Intel artifact uploader control` загружает 16 синтетических снимков без запуска VM. Успех этой проверки загрузчика не означает успешную проверку HVF.

## العربية

شغّل **Personal Intel HVF recovery diagnosis** يدوياً من Actions؛ لا تحتاج إلى جهاز Mac بمعالج Intel محلياً. يستخدم الإعداد الافتراضي `macos-26-intel` لتنفيذ 1,000 تكرار متتالٍ في عملية واحدة على إصدار محدد من NeverD. ويمكن اختيار `macos-15-intel` أو تشخيص من 100 تكرار. تحفظ ملفات النتائج الإصدارات والخطة والتقدم والنتيجة النهائية. يُقيّم وقت الانتظار واستقرار التنفيذ كلٌّ على حدة؛ نجاح اختبار الاستعادة هذا لا يثبت اكتمال تغطية CPU أو macOS أو iOS. [الدليل الكامل](https://github.com/NeverSight/NeverD/blob/dev/docs/ar/macos-hvf.md).

يرفع `Intel artifact uploader control` ست عشرة لقطة اصطناعية دون تشغيل VM. هذا فحص لأداة الرفع فقط، ولا يعني نجاحه اجتياز اختبارات HVF.

English: [full NeverD guide](https://github.com/NeverSight/NeverD/blob/dev/docs/macos-hvf.md).
