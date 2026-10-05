# Intel HVF API — retained evidence

## en: English — Intel HVF API evidence

All attempts are retained. Counts come from validated native logs; — means unknown, not zero. Reaping confirms process retirement, not complete guest resource correctness. Runner loss requires a matching GitHub check-run annotation. These authored real-mode controls do not establish NeverD Intel acceptance, physical-Mac stability or a performance ranking.

[JSON](summary.json) · `files.json` = SHA-256 · `audit.json` = evidence audit

| Image | Guest / observation | Source | Verified complete rounds | Native result | Child reaped | Run |
| --- | --- | --- | --- | --- | --- | --- |
| macos-15-intel | `timer` / `live` | [d61a491](https://github.com/gmh5225/test_mac_intel/commit/d61a4910cf6a05041786c979ef570ac29a054636) | 411 | uploader crash; native unknown | yes | [37256339176](https://github.com/gmh5225/test_mac_intel/actions/runs/37256339176) · [JSON](37256339176/audit.json) |
| macos-26-intel | `timer` / `live` | [d61a491](https://github.com/gmh5225/test_mac_intel/commit/d61a4910cf6a05041786c979ef570ac29a054636) | 1000 | pass | yes | [37256341043](https://github.com/gmh5225/test_mac_intel/actions/runs/37256341043) · [JSON](37256341043/audit.json) |
| macos-15-intel | `timer` / `final-only` | [4e4350e](https://github.com/gmh5225/test_mac_intel/commit/4e4350ee23348c4fe9e0902ff8fb1791570086c6) | 501 | failure | yes | [37257757852](https://github.com/gmh5225/test_mac_intel/actions/runs/37257757852) · [JSON](37257757852/audit.json) |
| macos-26-intel | `timer` / `final-only` | [4e4350e](https://github.com/gmh5225/test_mac_intel/commit/4e4350ee23348c4fe9e0902ff8fb1791570086c6) | 781 | failure | yes | [37257759882](https://github.com/gmh5225/test_mac_intel/actions/runs/37257759882) · [JSON](37257759882/audit.json) |
| macos-15-intel | `timer` / `final-only` | [ac717e4](https://github.com/gmh5225/test_mac_intel/commit/ac717e4288a5ff1e6ce7c93d73568e2739b9c58b) | 1000 | pass | yes | [37259797988](https://github.com/gmh5225/test_mac_intel/actions/runs/37259797988) · [JSON](37259797988/audit.json) |
| macos-26-intel | `timer` / `final-only` | [ac717e4](https://github.com/gmh5225/test_mac_intel/commit/ac717e4288a5ff1e6ce7c93d73568e2739b9c58b) | 571 | failure | yes | [37259800022](https://github.com/gmh5225/test_mac_intel/actions/runs/37259800022) · [JSON](37259800022/audit.json) |
| macos-15-intel | `timer` / `final-only` | [fb7a9d2](https://github.com/gmh5225/test_mac_intel/commit/fb7a9d2c9cf0bb5294daf3611c74cdff54f7858b) | 781 | failure | yes | [37262095705](https://github.com/gmh5225/test_mac_intel/actions/runs/37262095705) · [JSON](37262095705/audit.json) |
| macos-26-intel | `timer` / `final-only` | [fb7a9d2](https://github.com/gmh5225/test_mac_intel/commit/fb7a9d2c9cf0bb5294daf3611c74cdff54f7858b) | 396 | failure | yes | [37262097389](https://github.com/gmh5225/test_mac_intel/actions/runs/37262097389) · [JSON](37262097389/audit.json) |
| macos-15-intel | `halt` / `final-only` | [ca8da7d](https://github.com/gmh5225/test_mac_intel/commit/ca8da7d2045bd7b1186acfe4c3e7b1f63a66ac12) | — | job time limit; native unknown | unknown | [37263893167](https://github.com/gmh5225/test_mac_intel/actions/runs/37263893167) · [JSON](37263893167/audit.json) |
| macos-26-intel | `halt` / `final-only` | [ca8da7d](https://github.com/gmh5225/test_mac_intel/commit/ca8da7d2045bd7b1186acfe4c3e7b1f63a66ac12) | — | job time limit; native unknown | unknown | [37263895410](https://github.com/gmh5225/test_mac_intel/actions/runs/37263895410) · [JSON](37263895410/audit.json) |

Run from the repository root with the reviewed commit history available locally:

```sh
python3 scripts/verify_api_evidence.py
python3 -m unittest discover -s scripts -p 'test_verify_api_evidence.py' -q
```

## zh-CN: 简体中文 — Intel HVF API 证据

保留全部尝试。轮数来自核验过的原生日志；— 表示未知，不是零。进程回收不等同于 guest 资源已完全正确清理。runner 失联需匹配本次 GitHub check-run 的注记。这些自编实模式对照不能代表 NeverD Intel 完整验收、Intel Mac 真机稳定性或性能排名。

[JSON](summary.json) · `files.json` = SHA-256 · `audit.json` = evidence audit

| 镜像 | Guest / 观察方式 | 源码 | 已验证完成轮数 | 原生结果 | 子进程已回收 | 运行 |
| --- | --- | --- | --- | --- | --- | --- |
| macos-15-intel | `timer` / `live` | [d61a491](https://github.com/gmh5225/test_mac_intel/commit/d61a4910cf6a05041786c979ef570ac29a054636) | 411 | 上传器崩溃；原生未知 | 是 | [37256339176](https://github.com/gmh5225/test_mac_intel/actions/runs/37256339176) · [JSON](37256339176/audit.json) |
| macos-26-intel | `timer` / `live` | [d61a491](https://github.com/gmh5225/test_mac_intel/commit/d61a4910cf6a05041786c979ef570ac29a054636) | 1000 | 通过 | 是 | [37256341043](https://github.com/gmh5225/test_mac_intel/actions/runs/37256341043) · [JSON](37256341043/audit.json) |
| macos-15-intel | `timer` / `final-only` | [4e4350e](https://github.com/gmh5225/test_mac_intel/commit/4e4350ee23348c4fe9e0902ff8fb1791570086c6) | 501 | 失败 | 是 | [37257757852](https://github.com/gmh5225/test_mac_intel/actions/runs/37257757852) · [JSON](37257757852/audit.json) |
| macos-26-intel | `timer` / `final-only` | [4e4350e](https://github.com/gmh5225/test_mac_intel/commit/4e4350ee23348c4fe9e0902ff8fb1791570086c6) | 781 | 失败 | 是 | [37257759882](https://github.com/gmh5225/test_mac_intel/actions/runs/37257759882) · [JSON](37257759882/audit.json) |
| macos-15-intel | `timer` / `final-only` | [ac717e4](https://github.com/gmh5225/test_mac_intel/commit/ac717e4288a5ff1e6ce7c93d73568e2739b9c58b) | 1000 | 通过 | 是 | [37259797988](https://github.com/gmh5225/test_mac_intel/actions/runs/37259797988) · [JSON](37259797988/audit.json) |
| macos-26-intel | `timer` / `final-only` | [ac717e4](https://github.com/gmh5225/test_mac_intel/commit/ac717e4288a5ff1e6ce7c93d73568e2739b9c58b) | 571 | 失败 | 是 | [37259800022](https://github.com/gmh5225/test_mac_intel/actions/runs/37259800022) · [JSON](37259800022/audit.json) |
| macos-15-intel | `timer` / `final-only` | [fb7a9d2](https://github.com/gmh5225/test_mac_intel/commit/fb7a9d2c9cf0bb5294daf3611c74cdff54f7858b) | 781 | 失败 | 是 | [37262095705](https://github.com/gmh5225/test_mac_intel/actions/runs/37262095705) · [JSON](37262095705/audit.json) |
| macos-26-intel | `timer` / `final-only` | [fb7a9d2](https://github.com/gmh5225/test_mac_intel/commit/fb7a9d2c9cf0bb5294daf3611c74cdff54f7858b) | 396 | 失败 | 是 | [37262097389](https://github.com/gmh5225/test_mac_intel/actions/runs/37262097389) · [JSON](37262097389/audit.json) |
| macos-15-intel | `halt` / `final-only` | [ca8da7d](https://github.com/gmh5225/test_mac_intel/commit/ca8da7d2045bd7b1186acfe4c3e7b1f63a66ac12) | — | 作业超时；原生未知 | 未知 | [37263893167](https://github.com/gmh5225/test_mac_intel/actions/runs/37263893167) · [JSON](37263893167/audit.json) |
| macos-26-intel | `halt` / `final-only` | [ca8da7d](https://github.com/gmh5225/test_mac_intel/commit/ca8da7d2045bd7b1186acfe4c3e7b1f63a66ac12) | — | 作业超时；原生未知 | 未知 | [37263895410](https://github.com/gmh5225/test_mac_intel/actions/runs/37263895410) · [JSON](37263895410/audit.json) |

在仓库根目录运行，需在本地保留已复核提交的历史：

```sh
python3 scripts/verify_api_evidence.py
python3 -m unittest discover -s scripts -p 'test_verify_api_evidence.py' -q
```

## zh-TW: 繁體中文 — Intel HVF API 證據

保留全部嘗試。輪數來自核驗過的原生日誌；— 表示未知，不是零。程序回收不等同於 guest 資源已完全正確清理。runner 失聯需符合本次 GitHub check-run 的註記。這些自編實模式對照不能代表 NeverD Intel 完整驗收、Intel Mac 實機穩定性或效能排名。

[JSON](summary.json) · `files.json` = SHA-256 · `audit.json` = evidence audit

| 映像 | Guest / 觀察方式 | 原始碼 | 已驗證完成輪數 | 原生結果 | 子程序已回收 | 執行 |
| --- | --- | --- | --- | --- | --- | --- |
| macos-15-intel | `timer` / `live` | [d61a491](https://github.com/gmh5225/test_mac_intel/commit/d61a4910cf6a05041786c979ef570ac29a054636) | 411 | 上傳器崩潰；原生未知 | 是 | [37256339176](https://github.com/gmh5225/test_mac_intel/actions/runs/37256339176) · [JSON](37256339176/audit.json) |
| macos-26-intel | `timer` / `live` | [d61a491](https://github.com/gmh5225/test_mac_intel/commit/d61a4910cf6a05041786c979ef570ac29a054636) | 1000 | 通過 | 是 | [37256341043](https://github.com/gmh5225/test_mac_intel/actions/runs/37256341043) · [JSON](37256341043/audit.json) |
| macos-15-intel | `timer` / `final-only` | [4e4350e](https://github.com/gmh5225/test_mac_intel/commit/4e4350ee23348c4fe9e0902ff8fb1791570086c6) | 501 | 失敗 | 是 | [37257757852](https://github.com/gmh5225/test_mac_intel/actions/runs/37257757852) · [JSON](37257757852/audit.json) |
| macos-26-intel | `timer` / `final-only` | [4e4350e](https://github.com/gmh5225/test_mac_intel/commit/4e4350ee23348c4fe9e0902ff8fb1791570086c6) | 781 | 失敗 | 是 | [37257759882](https://github.com/gmh5225/test_mac_intel/actions/runs/37257759882) · [JSON](37257759882/audit.json) |
| macos-15-intel | `timer` / `final-only` | [ac717e4](https://github.com/gmh5225/test_mac_intel/commit/ac717e4288a5ff1e6ce7c93d73568e2739b9c58b) | 1000 | 通過 | 是 | [37259797988](https://github.com/gmh5225/test_mac_intel/actions/runs/37259797988) · [JSON](37259797988/audit.json) |
| macos-26-intel | `timer` / `final-only` | [ac717e4](https://github.com/gmh5225/test_mac_intel/commit/ac717e4288a5ff1e6ce7c93d73568e2739b9c58b) | 571 | 失敗 | 是 | [37259800022](https://github.com/gmh5225/test_mac_intel/actions/runs/37259800022) · [JSON](37259800022/audit.json) |
| macos-15-intel | `timer` / `final-only` | [fb7a9d2](https://github.com/gmh5225/test_mac_intel/commit/fb7a9d2c9cf0bb5294daf3611c74cdff54f7858b) | 781 | 失敗 | 是 | [37262095705](https://github.com/gmh5225/test_mac_intel/actions/runs/37262095705) · [JSON](37262095705/audit.json) |
| macos-26-intel | `timer` / `final-only` | [fb7a9d2](https://github.com/gmh5225/test_mac_intel/commit/fb7a9d2c9cf0bb5294daf3611c74cdff54f7858b) | 396 | 失敗 | 是 | [37262097389](https://github.com/gmh5225/test_mac_intel/actions/runs/37262097389) · [JSON](37262097389/audit.json) |
| macos-15-intel | `halt` / `final-only` | [ca8da7d](https://github.com/gmh5225/test_mac_intel/commit/ca8da7d2045bd7b1186acfe4c3e7b1f63a66ac12) | — | 作業逾時；原生未知 | 未知 | [37263893167](https://github.com/gmh5225/test_mac_intel/actions/runs/37263893167) · [JSON](37263893167/audit.json) |
| macos-26-intel | `halt` / `final-only` | [ca8da7d](https://github.com/gmh5225/test_mac_intel/commit/ca8da7d2045bd7b1186acfe4c3e7b1f63a66ac12) | — | 作業逾時；原生未知 | 未知 | [37263895410](https://github.com/gmh5225/test_mac_intel/actions/runs/37263895410) · [JSON](37263895410/audit.json) |

在儲存庫根目錄執行，需在本機保留已複核提交的歷史：

```sh
python3 scripts/verify_api_evidence.py
python3 -m unittest discover -s scripts -p 'test_verify_api_evidence.py' -q
```

## ja: 日本語 — Intel HVF API の証拠

すべての試行を保持しています。回数は検証済みのネイティブログに基づき、— はゼロではなく不明です。プロセス回収は guest 資源の完全な正常解放を保証しません。接続喪失は該当 GitHub check-run の注記で確認します。独自のリアルモード対照は NeverD Intel 全体の検証、実機の安定性、性能順位を示しません。

[JSON](summary.json) · `files.json` = SHA-256 · `audit.json` = evidence audit

| イメージ | Guest / 観測方式 | ソース | 検証済み完了回数 | ネイティブ結果 | 子プロセス回収 | 実行 |
| --- | --- | --- | --- | --- | --- | --- |
| macos-15-intel | `timer` / `live` | [d61a491](https://github.com/gmh5225/test_mac_intel/commit/d61a4910cf6a05041786c979ef570ac29a054636) | 411 | アップローダー異常終了・ネイティブ不明 | 済 | [37256339176](https://github.com/gmh5225/test_mac_intel/actions/runs/37256339176) · [JSON](37256339176/audit.json) |
| macos-26-intel | `timer` / `live` | [d61a491](https://github.com/gmh5225/test_mac_intel/commit/d61a4910cf6a05041786c979ef570ac29a054636) | 1000 | 成功 | 済 | [37256341043](https://github.com/gmh5225/test_mac_intel/actions/runs/37256341043) · [JSON](37256341043/audit.json) |
| macos-15-intel | `timer` / `final-only` | [4e4350e](https://github.com/gmh5225/test_mac_intel/commit/4e4350ee23348c4fe9e0902ff8fb1791570086c6) | 501 | 失敗 | 済 | [37257757852](https://github.com/gmh5225/test_mac_intel/actions/runs/37257757852) · [JSON](37257757852/audit.json) |
| macos-26-intel | `timer` / `final-only` | [4e4350e](https://github.com/gmh5225/test_mac_intel/commit/4e4350ee23348c4fe9e0902ff8fb1791570086c6) | 781 | 失敗 | 済 | [37257759882](https://github.com/gmh5225/test_mac_intel/actions/runs/37257759882) · [JSON](37257759882/audit.json) |
| macos-15-intel | `timer` / `final-only` | [ac717e4](https://github.com/gmh5225/test_mac_intel/commit/ac717e4288a5ff1e6ce7c93d73568e2739b9c58b) | 1000 | 成功 | 済 | [37259797988](https://github.com/gmh5225/test_mac_intel/actions/runs/37259797988) · [JSON](37259797988/audit.json) |
| macos-26-intel | `timer` / `final-only` | [ac717e4](https://github.com/gmh5225/test_mac_intel/commit/ac717e4288a5ff1e6ce7c93d73568e2739b9c58b) | 571 | 失敗 | 済 | [37259800022](https://github.com/gmh5225/test_mac_intel/actions/runs/37259800022) · [JSON](37259800022/audit.json) |
| macos-15-intel | `timer` / `final-only` | [fb7a9d2](https://github.com/gmh5225/test_mac_intel/commit/fb7a9d2c9cf0bb5294daf3611c74cdff54f7858b) | 781 | 失敗 | 済 | [37262095705](https://github.com/gmh5225/test_mac_intel/actions/runs/37262095705) · [JSON](37262095705/audit.json) |
| macos-26-intel | `timer` / `final-only` | [fb7a9d2](https://github.com/gmh5225/test_mac_intel/commit/fb7a9d2c9cf0bb5294daf3611c74cdff54f7858b) | 396 | 失敗 | 済 | [37262097389](https://github.com/gmh5225/test_mac_intel/actions/runs/37262097389) · [JSON](37262097389/audit.json) |
| macos-15-intel | `halt` / `final-only` | [ca8da7d](https://github.com/gmh5225/test_mac_intel/commit/ca8da7d2045bd7b1186acfe4c3e7b1f63a66ac12) | — | ジョブ時間制限・ネイティブ不明 | 不明 | [37263893167](https://github.com/gmh5225/test_mac_intel/actions/runs/37263893167) · [JSON](37263893167/audit.json) |
| macos-26-intel | `halt` / `final-only` | [ca8da7d](https://github.com/gmh5225/test_mac_intel/commit/ca8da7d2045bd7b1186acfe4c3e7b1f63a66ac12) | — | ジョブ時間制限・ネイティブ不明 | 不明 | [37263895410](https://github.com/gmh5225/test_mac_intel/actions/runs/37263895410) · [JSON](37263895410/audit.json) |

検証済みコミット履歴をローカルに保持し、リポジトリのルートから実行します：

```sh
python3 scripts/verify_api_evidence.py
python3 -m unittest discover -s scripts -p 'test_verify_api_evidence.py' -q
```

## ko: 한국어 — Intel HVF API 증거

모든 시도를 보존합니다. 횟수는 검증한 네이티브 로그에서 가져오며 — 는 0이 아니라 알 수 없음을 뜻합니다. 프로세스 회수는 guest 자원의 완전한 정리를 보장하지 않습니다. 연결 손실에는 해당 GitHub check-run 주석이 필요합니다. 자체 실모드 대조는 NeverD Intel 전체 검증, 실제 Mac 안정성 또는 성능 순위를 입증하지 않습니다.

[JSON](summary.json) · `files.json` = SHA-256 · `audit.json` = evidence audit

| 이미지 | Guest / 관측 방식 | 소스 | 검증된 완료 횟수 | 네이티브 결과 | 자식 회수 | 실행 |
| --- | --- | --- | --- | --- | --- | --- |
| macos-15-intel | `timer` / `live` | [d61a491](https://github.com/gmh5225/test_mac_intel/commit/d61a4910cf6a05041786c979ef570ac29a054636) | 411 | 업로더 충돌; 네이티브 불명 | 예 | [37256339176](https://github.com/gmh5225/test_mac_intel/actions/runs/37256339176) · [JSON](37256339176/audit.json) |
| macos-26-intel | `timer` / `live` | [d61a491](https://github.com/gmh5225/test_mac_intel/commit/d61a4910cf6a05041786c979ef570ac29a054636) | 1000 | 통과 | 예 | [37256341043](https://github.com/gmh5225/test_mac_intel/actions/runs/37256341043) · [JSON](37256341043/audit.json) |
| macos-15-intel | `timer` / `final-only` | [4e4350e](https://github.com/gmh5225/test_mac_intel/commit/4e4350ee23348c4fe9e0902ff8fb1791570086c6) | 501 | 실패 | 예 | [37257757852](https://github.com/gmh5225/test_mac_intel/actions/runs/37257757852) · [JSON](37257757852/audit.json) |
| macos-26-intel | `timer` / `final-only` | [4e4350e](https://github.com/gmh5225/test_mac_intel/commit/4e4350ee23348c4fe9e0902ff8fb1791570086c6) | 781 | 실패 | 예 | [37257759882](https://github.com/gmh5225/test_mac_intel/actions/runs/37257759882) · [JSON](37257759882/audit.json) |
| macos-15-intel | `timer` / `final-only` | [ac717e4](https://github.com/gmh5225/test_mac_intel/commit/ac717e4288a5ff1e6ce7c93d73568e2739b9c58b) | 1000 | 통과 | 예 | [37259797988](https://github.com/gmh5225/test_mac_intel/actions/runs/37259797988) · [JSON](37259797988/audit.json) |
| macos-26-intel | `timer` / `final-only` | [ac717e4](https://github.com/gmh5225/test_mac_intel/commit/ac717e4288a5ff1e6ce7c93d73568e2739b9c58b) | 571 | 실패 | 예 | [37259800022](https://github.com/gmh5225/test_mac_intel/actions/runs/37259800022) · [JSON](37259800022/audit.json) |
| macos-15-intel | `timer` / `final-only` | [fb7a9d2](https://github.com/gmh5225/test_mac_intel/commit/fb7a9d2c9cf0bb5294daf3611c74cdff54f7858b) | 781 | 실패 | 예 | [37262095705](https://github.com/gmh5225/test_mac_intel/actions/runs/37262095705) · [JSON](37262095705/audit.json) |
| macos-26-intel | `timer` / `final-only` | [fb7a9d2](https://github.com/gmh5225/test_mac_intel/commit/fb7a9d2c9cf0bb5294daf3611c74cdff54f7858b) | 396 | 실패 | 예 | [37262097389](https://github.com/gmh5225/test_mac_intel/actions/runs/37262097389) · [JSON](37262097389/audit.json) |
| macos-15-intel | `halt` / `final-only` | [ca8da7d](https://github.com/gmh5225/test_mac_intel/commit/ca8da7d2045bd7b1186acfe4c3e7b1f63a66ac12) | — | 작업 시간 초과; 네이티브 불명 | 알 수 없음 | [37263893167](https://github.com/gmh5225/test_mac_intel/actions/runs/37263893167) · [JSON](37263893167/audit.json) |
| macos-26-intel | `halt` / `final-only` | [ca8da7d](https://github.com/gmh5225/test_mac_intel/commit/ca8da7d2045bd7b1186acfe4c3e7b1f63a66ac12) | — | 작업 시간 초과; 네이티브 불명 | 알 수 없음 | [37263895410](https://github.com/gmh5225/test_mac_intel/actions/runs/37263895410) · [JSON](37263895410/audit.json) |

검토된 커밋 기록을 로컬에 보존하고 저장소 루트에서 실행합니다:

```sh
python3 scripts/verify_api_evidence.py
python3 -m unittest discover -s scripts -p 'test_verify_api_evidence.py' -q
```

## fr: Français — Preuves API Intel HVF

Toutes les tentatives sont conservées. Les nombres proviennent des journaux natifs validés ; — signifie inconnu, pas zéro. La récupération du processus ne garantit pas la libération correcte de toutes les ressources du guest. Une déconnexion exige une annotation du check-run GitHub correspondant. Ces contrôles écrits en mode réel ne prouvent ni la validation complète de NeverD Intel, ni la stabilité sur Mac physique, ni un classement de performances.

[JSON](summary.json) · `files.json` = SHA-256 · `audit.json` = evidence audit

| Image | Guest / observation | Source | Cycles complets vérifiés | Résultat natif | Processus récupéré | Exécution |
| --- | --- | --- | --- | --- | --- | --- |
| macos-15-intel | `timer` / `live` | [d61a491](https://github.com/gmh5225/test_mac_intel/commit/d61a4910cf6a05041786c979ef570ac29a054636) | 411 | plantage du téléverseur ; natif inconnu | oui | [37256339176](https://github.com/gmh5225/test_mac_intel/actions/runs/37256339176) · [JSON](37256339176/audit.json) |
| macos-26-intel | `timer` / `live` | [d61a491](https://github.com/gmh5225/test_mac_intel/commit/d61a4910cf6a05041786c979ef570ac29a054636) | 1000 | réussite | oui | [37256341043](https://github.com/gmh5225/test_mac_intel/actions/runs/37256341043) · [JSON](37256341043/audit.json) |
| macos-15-intel | `timer` / `final-only` | [4e4350e](https://github.com/gmh5225/test_mac_intel/commit/4e4350ee23348c4fe9e0902ff8fb1791570086c6) | 501 | échec | oui | [37257757852](https://github.com/gmh5225/test_mac_intel/actions/runs/37257757852) · [JSON](37257757852/audit.json) |
| macos-26-intel | `timer` / `final-only` | [4e4350e](https://github.com/gmh5225/test_mac_intel/commit/4e4350ee23348c4fe9e0902ff8fb1791570086c6) | 781 | échec | oui | [37257759882](https://github.com/gmh5225/test_mac_intel/actions/runs/37257759882) · [JSON](37257759882/audit.json) |
| macos-15-intel | `timer` / `final-only` | [ac717e4](https://github.com/gmh5225/test_mac_intel/commit/ac717e4288a5ff1e6ce7c93d73568e2739b9c58b) | 1000 | réussite | oui | [37259797988](https://github.com/gmh5225/test_mac_intel/actions/runs/37259797988) · [JSON](37259797988/audit.json) |
| macos-26-intel | `timer` / `final-only` | [ac717e4](https://github.com/gmh5225/test_mac_intel/commit/ac717e4288a5ff1e6ce7c93d73568e2739b9c58b) | 571 | échec | oui | [37259800022](https://github.com/gmh5225/test_mac_intel/actions/runs/37259800022) · [JSON](37259800022/audit.json) |
| macos-15-intel | `timer` / `final-only` | [fb7a9d2](https://github.com/gmh5225/test_mac_intel/commit/fb7a9d2c9cf0bb5294daf3611c74cdff54f7858b) | 781 | échec | oui | [37262095705](https://github.com/gmh5225/test_mac_intel/actions/runs/37262095705) · [JSON](37262095705/audit.json) |
| macos-26-intel | `timer` / `final-only` | [fb7a9d2](https://github.com/gmh5225/test_mac_intel/commit/fb7a9d2c9cf0bb5294daf3611c74cdff54f7858b) | 396 | échec | oui | [37262097389](https://github.com/gmh5225/test_mac_intel/actions/runs/37262097389) · [JSON](37262097389/audit.json) |
| macos-15-intel | `halt` / `final-only` | [ca8da7d](https://github.com/gmh5225/test_mac_intel/commit/ca8da7d2045bd7b1186acfe4c3e7b1f63a66ac12) | — | limite du travail ; natif inconnu | inconnu | [37263893167](https://github.com/gmh5225/test_mac_intel/actions/runs/37263893167) · [JSON](37263893167/audit.json) |
| macos-26-intel | `halt` / `final-only` | [ca8da7d](https://github.com/gmh5225/test_mac_intel/commit/ca8da7d2045bd7b1186acfe4c3e7b1f63a66ac12) | — | limite du travail ; natif inconnu | inconnu | [37263895410](https://github.com/gmh5225/test_mac_intel/actions/runs/37263895410) · [JSON](37263895410/audit.json) |

Depuis la racine du dépôt, avec les commits examinés disponibles localement :

```sh
python3 scripts/verify_api_evidence.py
python3 -m unittest discover -s scripts -p 'test_verify_api_evidence.py' -q
```

## de: Deutsch — Intel-HVF-API-Belege

Alle Versuche bleiben erhalten. Die Zahlen stammen aus geprüften nativen Logs; — bedeutet unbekannt, nicht null. Die Prozessrückholung beweist keine vollständige korrekte Guest-Ressourcenfreigabe. Ein Verbindungsverlust erfordert eine passende GitHub-Check-Run-Anmerkung. Diese selbst geschriebenen Real-Mode-Kontrollen belegen weder vollständige NeverD-Intel-Abnahme noch physische Mac-Stabilität oder eine Leistungsrangfolge.

[JSON](summary.json) · `files.json` = SHA-256 · `audit.json` = evidence audit

| Image | Guest / Beobachtung | Quellstand | Geprüfte vollständige Runden | Natives Ergebnis | Kindprozess abgeholt | Lauf |
| --- | --- | --- | --- | --- | --- | --- |
| macos-15-intel | `timer` / `live` | [d61a491](https://github.com/gmh5225/test_mac_intel/commit/d61a4910cf6a05041786c979ef570ac29a054636) | 411 | Uploader-Absturz; nativ unbekannt | ja | [37256339176](https://github.com/gmh5225/test_mac_intel/actions/runs/37256339176) · [JSON](37256339176/audit.json) |
| macos-26-intel | `timer` / `live` | [d61a491](https://github.com/gmh5225/test_mac_intel/commit/d61a4910cf6a05041786c979ef570ac29a054636) | 1000 | bestanden | ja | [37256341043](https://github.com/gmh5225/test_mac_intel/actions/runs/37256341043) · [JSON](37256341043/audit.json) |
| macos-15-intel | `timer` / `final-only` | [4e4350e](https://github.com/gmh5225/test_mac_intel/commit/4e4350ee23348c4fe9e0902ff8fb1791570086c6) | 501 | fehlgeschlagen | ja | [37257757852](https://github.com/gmh5225/test_mac_intel/actions/runs/37257757852) · [JSON](37257757852/audit.json) |
| macos-26-intel | `timer` / `final-only` | [4e4350e](https://github.com/gmh5225/test_mac_intel/commit/4e4350ee23348c4fe9e0902ff8fb1791570086c6) | 781 | fehlgeschlagen | ja | [37257759882](https://github.com/gmh5225/test_mac_intel/actions/runs/37257759882) · [JSON](37257759882/audit.json) |
| macos-15-intel | `timer` / `final-only` | [ac717e4](https://github.com/gmh5225/test_mac_intel/commit/ac717e4288a5ff1e6ce7c93d73568e2739b9c58b) | 1000 | bestanden | ja | [37259797988](https://github.com/gmh5225/test_mac_intel/actions/runs/37259797988) · [JSON](37259797988/audit.json) |
| macos-26-intel | `timer` / `final-only` | [ac717e4](https://github.com/gmh5225/test_mac_intel/commit/ac717e4288a5ff1e6ce7c93d73568e2739b9c58b) | 571 | fehlgeschlagen | ja | [37259800022](https://github.com/gmh5225/test_mac_intel/actions/runs/37259800022) · [JSON](37259800022/audit.json) |
| macos-15-intel | `timer` / `final-only` | [fb7a9d2](https://github.com/gmh5225/test_mac_intel/commit/fb7a9d2c9cf0bb5294daf3611c74cdff54f7858b) | 781 | fehlgeschlagen | ja | [37262095705](https://github.com/gmh5225/test_mac_intel/actions/runs/37262095705) · [JSON](37262095705/audit.json) |
| macos-26-intel | `timer` / `final-only` | [fb7a9d2](https://github.com/gmh5225/test_mac_intel/commit/fb7a9d2c9cf0bb5294daf3611c74cdff54f7858b) | 396 | fehlgeschlagen | ja | [37262097389](https://github.com/gmh5225/test_mac_intel/actions/runs/37262097389) · [JSON](37262097389/audit.json) |
| macos-15-intel | `halt` / `final-only` | [ca8da7d](https://github.com/gmh5225/test_mac_intel/commit/ca8da7d2045bd7b1186acfe4c3e7b1f63a66ac12) | — | Job-Zeitlimit; nativ unbekannt | unbekannt | [37263893167](https://github.com/gmh5225/test_mac_intel/actions/runs/37263893167) · [JSON](37263893167/audit.json) |
| macos-26-intel | `halt` / `final-only` | [ca8da7d](https://github.com/gmh5225/test_mac_intel/commit/ca8da7d2045bd7b1186acfe4c3e7b1f63a66ac12) | — | Job-Zeitlimit; nativ unbekannt | unbekannt | [37263895410](https://github.com/gmh5225/test_mac_intel/actions/runs/37263895410) · [JSON](37263895410/audit.json) |

Im Repository-Stamm mit lokal vorhandener geprüfter Commit-Historie ausführen:

```sh
python3 scripts/verify_api_evidence.py
python3 -m unittest discover -s scripts -p 'test_verify_api_evidence.py' -q
```

## es: Español — Pruebas de la API Intel HVF

Se conservan todos los intentos. Los recuentos proceden de registros nativos validados; — significa desconocido, no cero. Recoger el proceso no garantiza la liberación correcta de todos los recursos del guest. Una desconexión exige una anotación del check-run de GitHub correspondiente. Estos controles propios en modo real no prueban la aceptación completa de NeverD Intel, estabilidad de un Mac físico ni una clasificación de rendimiento.

[JSON](summary.json) · `files.json` = SHA-256 · `audit.json` = evidence audit

| Imagen | Guest / observación | Código | Ciclos completos verificados | Resultado nativo | Proceso recogido | Ejecución |
| --- | --- | --- | --- | --- | --- | --- |
| macos-15-intel | `timer` / `live` | [d61a491](https://github.com/gmh5225/test_mac_intel/commit/d61a4910cf6a05041786c979ef570ac29a054636) | 411 | fallo del cargador; nativo desconocido | sí | [37256339176](https://github.com/gmh5225/test_mac_intel/actions/runs/37256339176) · [JSON](37256339176/audit.json) |
| macos-26-intel | `timer` / `live` | [d61a491](https://github.com/gmh5225/test_mac_intel/commit/d61a4910cf6a05041786c979ef570ac29a054636) | 1000 | aprobado | sí | [37256341043](https://github.com/gmh5225/test_mac_intel/actions/runs/37256341043) · [JSON](37256341043/audit.json) |
| macos-15-intel | `timer` / `final-only` | [4e4350e](https://github.com/gmh5225/test_mac_intel/commit/4e4350ee23348c4fe9e0902ff8fb1791570086c6) | 501 | fallo | sí | [37257757852](https://github.com/gmh5225/test_mac_intel/actions/runs/37257757852) · [JSON](37257757852/audit.json) |
| macos-26-intel | `timer` / `final-only` | [4e4350e](https://github.com/gmh5225/test_mac_intel/commit/4e4350ee23348c4fe9e0902ff8fb1791570086c6) | 781 | fallo | sí | [37257759882](https://github.com/gmh5225/test_mac_intel/actions/runs/37257759882) · [JSON](37257759882/audit.json) |
| macos-15-intel | `timer` / `final-only` | [ac717e4](https://github.com/gmh5225/test_mac_intel/commit/ac717e4288a5ff1e6ce7c93d73568e2739b9c58b) | 1000 | aprobado | sí | [37259797988](https://github.com/gmh5225/test_mac_intel/actions/runs/37259797988) · [JSON](37259797988/audit.json) |
| macos-26-intel | `timer` / `final-only` | [ac717e4](https://github.com/gmh5225/test_mac_intel/commit/ac717e4288a5ff1e6ce7c93d73568e2739b9c58b) | 571 | fallo | sí | [37259800022](https://github.com/gmh5225/test_mac_intel/actions/runs/37259800022) · [JSON](37259800022/audit.json) |
| macos-15-intel | `timer` / `final-only` | [fb7a9d2](https://github.com/gmh5225/test_mac_intel/commit/fb7a9d2c9cf0bb5294daf3611c74cdff54f7858b) | 781 | fallo | sí | [37262095705](https://github.com/gmh5225/test_mac_intel/actions/runs/37262095705) · [JSON](37262095705/audit.json) |
| macos-26-intel | `timer` / `final-only` | [fb7a9d2](https://github.com/gmh5225/test_mac_intel/commit/fb7a9d2c9cf0bb5294daf3611c74cdff54f7858b) | 396 | fallo | sí | [37262097389](https://github.com/gmh5225/test_mac_intel/actions/runs/37262097389) · [JSON](37262097389/audit.json) |
| macos-15-intel | `halt` / `final-only` | [ca8da7d](https://github.com/gmh5225/test_mac_intel/commit/ca8da7d2045bd7b1186acfe4c3e7b1f63a66ac12) | — | límite del trabajo; nativo desconocido | desconocido | [37263893167](https://github.com/gmh5225/test_mac_intel/actions/runs/37263893167) · [JSON](37263893167/audit.json) |
| macos-26-intel | `halt` / `final-only` | [ca8da7d](https://github.com/gmh5225/test_mac_intel/commit/ca8da7d2045bd7b1186acfe4c3e7b1f63a66ac12) | — | límite del trabajo; nativo desconocido | desconocido | [37263895410](https://github.com/gmh5225/test_mac_intel/actions/runs/37263895410) · [JSON](37263895410/audit.json) |

Desde la raíz del repositorio, con los commits revisados disponibles localmente:

```sh
python3 scripts/verify_api_evidence.py
python3 -m unittest discover -s scripts -p 'test_verify_api_evidence.py' -q
```

## it: Italiano — Prove API Intel HVF

Tutti i tentativi sono conservati. I conteggi derivano da log nativi validati; — significa ignoto, non zero. Il recupero del processo non garantisce il corretto rilascio di tutte le risorse guest. Una disconnessione richiede una nota del check-run GitHub corrispondente. Questi controlli originali in modalità reale non dimostrano la convalida completa NeverD Intel, la stabilità su Mac fisici o una classifica di prestazioni.

[JSON](summary.json) · `files.json` = SHA-256 · `audit.json` = evidence audit

| Immagine | Guest / osservazione | Sorgente | Cicli completi verificati | Esito nativo | Processo recuperato | Esecuzione |
| --- | --- | --- | --- | --- | --- | --- |
| macos-15-intel | `timer` / `live` | [d61a491](https://github.com/gmh5225/test_mac_intel/commit/d61a4910cf6a05041786c979ef570ac29a054636) | 411 | crash del caricatore; nativo ignoto | sì | [37256339176](https://github.com/gmh5225/test_mac_intel/actions/runs/37256339176) · [JSON](37256339176/audit.json) |
| macos-26-intel | `timer` / `live` | [d61a491](https://github.com/gmh5225/test_mac_intel/commit/d61a4910cf6a05041786c979ef570ac29a054636) | 1000 | superato | sì | [37256341043](https://github.com/gmh5225/test_mac_intel/actions/runs/37256341043) · [JSON](37256341043/audit.json) |
| macos-15-intel | `timer` / `final-only` | [4e4350e](https://github.com/gmh5225/test_mac_intel/commit/4e4350ee23348c4fe9e0902ff8fb1791570086c6) | 501 | fallito | sì | [37257757852](https://github.com/gmh5225/test_mac_intel/actions/runs/37257757852) · [JSON](37257757852/audit.json) |
| macos-26-intel | `timer` / `final-only` | [4e4350e](https://github.com/gmh5225/test_mac_intel/commit/4e4350ee23348c4fe9e0902ff8fb1791570086c6) | 781 | fallito | sì | [37257759882](https://github.com/gmh5225/test_mac_intel/actions/runs/37257759882) · [JSON](37257759882/audit.json) |
| macos-15-intel | `timer` / `final-only` | [ac717e4](https://github.com/gmh5225/test_mac_intel/commit/ac717e4288a5ff1e6ce7c93d73568e2739b9c58b) | 1000 | superato | sì | [37259797988](https://github.com/gmh5225/test_mac_intel/actions/runs/37259797988) · [JSON](37259797988/audit.json) |
| macos-26-intel | `timer` / `final-only` | [ac717e4](https://github.com/gmh5225/test_mac_intel/commit/ac717e4288a5ff1e6ce7c93d73568e2739b9c58b) | 571 | fallito | sì | [37259800022](https://github.com/gmh5225/test_mac_intel/actions/runs/37259800022) · [JSON](37259800022/audit.json) |
| macos-15-intel | `timer` / `final-only` | [fb7a9d2](https://github.com/gmh5225/test_mac_intel/commit/fb7a9d2c9cf0bb5294daf3611c74cdff54f7858b) | 781 | fallito | sì | [37262095705](https://github.com/gmh5225/test_mac_intel/actions/runs/37262095705) · [JSON](37262095705/audit.json) |
| macos-26-intel | `timer` / `final-only` | [fb7a9d2](https://github.com/gmh5225/test_mac_intel/commit/fb7a9d2c9cf0bb5294daf3611c74cdff54f7858b) | 396 | fallito | sì | [37262097389](https://github.com/gmh5225/test_mac_intel/actions/runs/37262097389) · [JSON](37262097389/audit.json) |
| macos-15-intel | `halt` / `final-only` | [ca8da7d](https://github.com/gmh5225/test_mac_intel/commit/ca8da7d2045bd7b1186acfe4c3e7b1f63a66ac12) | — | limite del job; nativo ignoto | ignoto | [37263893167](https://github.com/gmh5225/test_mac_intel/actions/runs/37263893167) · [JSON](37263893167/audit.json) |
| macos-26-intel | `halt` / `final-only` | [ca8da7d](https://github.com/gmh5225/test_mac_intel/commit/ca8da7d2045bd7b1186acfe4c3e7b1f63a66ac12) | — | limite del job; nativo ignoto | ignoto | [37263895410](https://github.com/gmh5225/test_mac_intel/actions/runs/37263895410) · [JSON](37263895410/audit.json) |

Dalla radice del repository, con la cronologia dei commit esaminati disponibile localmente:

```sh
python3 scripts/verify_api_evidence.py
python3 -m unittest discover -s scripts -p 'test_verify_api_evidence.py' -q
```

## ru: Русский — Доказательства API Intel HVF

Сохранены все попытки. Числа взяты из проверенных нативных журналов; — означает неизвестность, а не ноль. Сбор процесса не гарантирует правильного освобождения всех ресурсов guest. Потеря связи требует примечания соответствующего GitHub check-run. Эти собственные тесты реального режима не доказывают полной приёмки NeverD Intel, стабильности физического Mac или превосходства в производительности.

[JSON](summary.json) · `files.json` = SHA-256 · `audit.json` = evidence audit

| Образ | Guest / наблюдение | Исходный код | Проверенные завершённые циклы | Нативный результат | Процесс собран | Запуск |
| --- | --- | --- | --- | --- | --- | --- |
| macos-15-intel | `timer` / `live` | [d61a491](https://github.com/gmh5225/test_mac_intel/commit/d61a4910cf6a05041786c979ef570ac29a054636) | 411 | сбой загрузчика; нативный итог неизвестен | да | [37256339176](https://github.com/gmh5225/test_mac_intel/actions/runs/37256339176) · [JSON](37256339176/audit.json) |
| macos-26-intel | `timer` / `live` | [d61a491](https://github.com/gmh5225/test_mac_intel/commit/d61a4910cf6a05041786c979ef570ac29a054636) | 1000 | успех | да | [37256341043](https://github.com/gmh5225/test_mac_intel/actions/runs/37256341043) · [JSON](37256341043/audit.json) |
| macos-15-intel | `timer` / `final-only` | [4e4350e](https://github.com/gmh5225/test_mac_intel/commit/4e4350ee23348c4fe9e0902ff8fb1791570086c6) | 501 | сбой | да | [37257757852](https://github.com/gmh5225/test_mac_intel/actions/runs/37257757852) · [JSON](37257757852/audit.json) |
| macos-26-intel | `timer` / `final-only` | [4e4350e](https://github.com/gmh5225/test_mac_intel/commit/4e4350ee23348c4fe9e0902ff8fb1791570086c6) | 781 | сбой | да | [37257759882](https://github.com/gmh5225/test_mac_intel/actions/runs/37257759882) · [JSON](37257759882/audit.json) |
| macos-15-intel | `timer` / `final-only` | [ac717e4](https://github.com/gmh5225/test_mac_intel/commit/ac717e4288a5ff1e6ce7c93d73568e2739b9c58b) | 1000 | успех | да | [37259797988](https://github.com/gmh5225/test_mac_intel/actions/runs/37259797988) · [JSON](37259797988/audit.json) |
| macos-26-intel | `timer` / `final-only` | [ac717e4](https://github.com/gmh5225/test_mac_intel/commit/ac717e4288a5ff1e6ce7c93d73568e2739b9c58b) | 571 | сбой | да | [37259800022](https://github.com/gmh5225/test_mac_intel/actions/runs/37259800022) · [JSON](37259800022/audit.json) |
| macos-15-intel | `timer` / `final-only` | [fb7a9d2](https://github.com/gmh5225/test_mac_intel/commit/fb7a9d2c9cf0bb5294daf3611c74cdff54f7858b) | 781 | сбой | да | [37262095705](https://github.com/gmh5225/test_mac_intel/actions/runs/37262095705) · [JSON](37262095705/audit.json) |
| macos-26-intel | `timer` / `final-only` | [fb7a9d2](https://github.com/gmh5225/test_mac_intel/commit/fb7a9d2c9cf0bb5294daf3611c74cdff54f7858b) | 396 | сбой | да | [37262097389](https://github.com/gmh5225/test_mac_intel/actions/runs/37262097389) · [JSON](37262097389/audit.json) |
| macos-15-intel | `halt` / `final-only` | [ca8da7d](https://github.com/gmh5225/test_mac_intel/commit/ca8da7d2045bd7b1186acfe4c3e7b1f63a66ac12) | — | лимит времени задания; нативный итог неизвестен | неизвестно | [37263893167](https://github.com/gmh5225/test_mac_intel/actions/runs/37263893167) · [JSON](37263893167/audit.json) |
| macos-26-intel | `halt` / `final-only` | [ca8da7d](https://github.com/gmh5225/test_mac_intel/commit/ca8da7d2045bd7b1186acfe4c3e7b1f63a66ac12) | — | лимит времени задания; нативный итог неизвестен | неизвестно | [37263895410](https://github.com/gmh5225/test_mac_intel/actions/runs/37263895410) · [JSON](37263895410/audit.json) |

Запускайте из корня репозитория с проверенными коммитами в локальной истории:

```sh
python3 scripts/verify_api_evidence.py
python3 -m unittest discover -s scripts -p 'test_verify_api_evidence.py' -q
```

## ar: العربية — أدلة واجهة Intel HVF

حُفظت جميع المحاولات. الأعداد مأخوذة من سجلات أصلية متحقق منها؛ وتعني — أن العدد مجهول، وليس صفراً. جمع العملية لا يضمن تحرير جميع موارد guest بشكل صحيح. يتطلب فقدان الاتصال ملاحظة من check-run المطابق في GitHub. لا تثبت هذه الاختبارات المؤلفة للوضع الحقيقي قبول NeverD Intel الكامل أو استقرار Mac فعلي أو ترتيباً للأداء.

[JSON](summary.json) · `files.json` = SHA-256 · `audit.json` = evidence audit

| الصورة | Guest / المراقبة | المصدر | الدورات المكتملة المتحقق منها | النتيجة الأصلية | جُمعت العملية | التشغيل |
| --- | --- | --- | --- | --- | --- | --- |
| macos-15-intel | `timer` / `live` | [d61a491](https://github.com/gmh5225/test_mac_intel/commit/d61a4910cf6a05041786c979ef570ac29a054636) | 411 | تعطل الرفع؛ النتيجة الأصلية مجهولة | نعم | [37256339176](https://github.com/gmh5225/test_mac_intel/actions/runs/37256339176) · [JSON](37256339176/audit.json) |
| macos-26-intel | `timer` / `live` | [d61a491](https://github.com/gmh5225/test_mac_intel/commit/d61a4910cf6a05041786c979ef570ac29a054636) | 1000 | نجاح | نعم | [37256341043](https://github.com/gmh5225/test_mac_intel/actions/runs/37256341043) · [JSON](37256341043/audit.json) |
| macos-15-intel | `timer` / `final-only` | [4e4350e](https://github.com/gmh5225/test_mac_intel/commit/4e4350ee23348c4fe9e0902ff8fb1791570086c6) | 501 | فشل | نعم | [37257757852](https://github.com/gmh5225/test_mac_intel/actions/runs/37257757852) · [JSON](37257757852/audit.json) |
| macos-26-intel | `timer` / `final-only` | [4e4350e](https://github.com/gmh5225/test_mac_intel/commit/4e4350ee23348c4fe9e0902ff8fb1791570086c6) | 781 | فشل | نعم | [37257759882](https://github.com/gmh5225/test_mac_intel/actions/runs/37257759882) · [JSON](37257759882/audit.json) |
| macos-15-intel | `timer` / `final-only` | [ac717e4](https://github.com/gmh5225/test_mac_intel/commit/ac717e4288a5ff1e6ce7c93d73568e2739b9c58b) | 1000 | نجاح | نعم | [37259797988](https://github.com/gmh5225/test_mac_intel/actions/runs/37259797988) · [JSON](37259797988/audit.json) |
| macos-26-intel | `timer` / `final-only` | [ac717e4](https://github.com/gmh5225/test_mac_intel/commit/ac717e4288a5ff1e6ce7c93d73568e2739b9c58b) | 571 | فشل | نعم | [37259800022](https://github.com/gmh5225/test_mac_intel/actions/runs/37259800022) · [JSON](37259800022/audit.json) |
| macos-15-intel | `timer` / `final-only` | [fb7a9d2](https://github.com/gmh5225/test_mac_intel/commit/fb7a9d2c9cf0bb5294daf3611c74cdff54f7858b) | 781 | فشل | نعم | [37262095705](https://github.com/gmh5225/test_mac_intel/actions/runs/37262095705) · [JSON](37262095705/audit.json) |
| macos-26-intel | `timer` / `final-only` | [fb7a9d2](https://github.com/gmh5225/test_mac_intel/commit/fb7a9d2c9cf0bb5294daf3611c74cdff54f7858b) | 396 | فشل | نعم | [37262097389](https://github.com/gmh5225/test_mac_intel/actions/runs/37262097389) · [JSON](37262097389/audit.json) |
| macos-15-intel | `halt` / `final-only` | [ca8da7d](https://github.com/gmh5225/test_mac_intel/commit/ca8da7d2045bd7b1186acfe4c3e7b1f63a66ac12) | — | انتهاء مهلة المهمة؛ النتيجة الأصلية مجهولة | غير معروف | [37263893167](https://github.com/gmh5225/test_mac_intel/actions/runs/37263893167) · [JSON](37263893167/audit.json) |
| macos-26-intel | `halt` / `final-only` | [ca8da7d](https://github.com/gmh5225/test_mac_intel/commit/ca8da7d2045bd7b1186acfe4c3e7b1f63a66ac12) | — | انتهاء مهلة المهمة؛ النتيجة الأصلية مجهولة | غير معروف | [37263895410](https://github.com/gmh5225/test_mac_intel/actions/runs/37263895410) · [JSON](37263895410/audit.json) |

نفّذ من جذر المستودع مع توفر سجل الإيداعات المراجعة محلياً:

```sh
python3 scripts/verify_api_evidence.py
python3 -m unittest discover -s scripts -p 'test_verify_api_evidence.py' -q
```
