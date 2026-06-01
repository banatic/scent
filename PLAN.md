# PLAN — scent: Procmon급 관측기 → 판정-우선 멀웨어 트리아지 도구

> 3겹 탐지: **(1) Sigma**(알려진 기법, 커뮤니티 유지보수) · **(2) 불변식 휴리스틱 몇 개**(룰에 없는 신규 조합) · **(3) 전체 텔레메트리 + (선택)LLM**(안전망).
> Findings는 **게이트가 아니라 가속기**다 — 아무것도 안 떠도 raw 이벤트/트리/타임라인은 항상 보인다.
> scent는 자율 차단기가 아니라 **분석 계측기**다. 격리/메모리내부 가시성은 범위 밖.

## 절대 불변식 (모든 단계에서 유지)
- 캡처 순서: **launch suspended → seed root → ETW ready 확인 → resume** (`ipc::start_capture`).
- ETW 콜백 안 = **논블로킹, 가벼운 스키마 체크만**. store 쓰기 / PEB·모듈 스냅샷 같은 무거운 작업은 **단일 ingest 스레드에서만**.
- PID 재사용 안전성: 노드는 모노토닉 `node_id` 키, `pid`는 비영구.
- ETW event id/opcode/필드명은 **버전 의존**. 파싱 변경 전 `explore_providers`(elevated)로 실제 필드명 확인. **추측 금지.**
- UI(Liquid Glass): glass material은 **chrome 전용**, 데이터 표면은 **불투명·고대비**. 색/blur/radius/spacing은 **`src/styles/tokens.css` 토큰만** 참조. 모션은 `lib/motion.ts` 스프링.

## 환경 메모
- 백엔드 게이트: `cd src-tauri && cargo check` · 단위 테스트 `cargo test --lib`.
- 프론트 게이트: `npm install`(최초 1회, 현재 `node_modules` 없음) → `npm run build` + `npx tsc --noEmit`.
- elevated 전용(관리자, 프로세스 스폰): `explore_providers`, `captures_cmd_subtree` — **CI/비관리자 환경에서 못 돌림. 사용자가 관리자 셸에서 실행** 필요.
- 큐레이션 스크립트는 `vendor/sigma`(SigmaHQ submodule) 필요 — 네트워크 접근 시 1회 추가.

---

## 0단계 · 준비 (착수 전, 커밋 없음)
- [x] `npm install`로 프론트 빌드 가능 상태 확인 (베이스라인 `cargo check` 통과 확인).
- [x] **`explore_providers` 확장**: 후보 필드에 `StartAddr`/`StartAddress`/`Win32StartAddr`(ThreadStart), `MandatoryLabel`/`ProcessTokenIsElevated`/`ProcessTokenElevationType`(ProcessStart) 추가 + Thread(0x20)·READ(0x100) keyword 활성화 + 워크로드에 파일 read 추가. **→ 사용자가 elevated로 실행 → 출력 공유 대기.**
  - 확인 대상: ① Kernel-File **READ** event id + keyword 비트, ② Kernel-Process **ThreadStart** event id + keyword 비트 + start-address 필드명, ③ Kernel-Process **ProcessStart(id 1)** 무결성/권한 필드명.

> ⛔ **게이트**: 위 ②③ 필드명이 실측으로 확정되기 전에는 1단계의 해당 ETW 파싱을 머지하지 않는다(추측 금지). cmdline(PEB) 부분은 ETW 스키마와 무관하므로 먼저 진행 가능.

---

## 1단계 · 텔레메트리 보강 (Sigma의 전제조건)
**목표**: Sigma/휴리스틱이 평가할 수 있는 필드를 텔레메트리에 채운다.

- [x] **자식 cmdline (PEB read)** — 신설 `peb.rs`:
  - `read_command_line(pid) -> Option<String>`: `OpenProcess(QUERY_LIMITED_INFORMATION|VM_READ)` → `NtQueryInformationProcess(ProcessBasicInformation)`로 PebBaseAddress → `ReadProcessMemory`로 PEB→`ProcessParameters`(RTL_USER_PROCESS_PARAMETERS)→`CommandLine`(UNICODE_STRING) 읽기.
  - 호출 위치: **ingest 스레드에서 store 락 밖**(`Captured::ProcCreate` 버스트 enrich). ETW 콜백 금지. 종료 프로세스 best-effort `None`.
  - `ProcessNode.cmdline` **및** `EventKind::ProcCreate.cmdline`(`Captured::ProcCreate.cmdline` 경유)을 채운다 → 2단계 sigma_view가 즉시 사용.
- [ ] **integrity/elevation** — `ProcessNode`에 `integrity: Option<String>`, `elevated: Option<bool>` 추가. ProcessStart(id 1) 파싱에서 실측 필드명으로 채움(없으면 무시). ⏳ *(0단계 ③ 실측 후)*
- [ ] **스코프드 READ** — `KF_READ` keyword 활성화(실측 비트). `on_file`의 READ 분기는 **민감 경로 allowlist** 매칭만 통과(`deep.rs::keep_path` 스타일). ⏳ *(0단계 ① 실측 후)*
- [ ] **인젝션 휴리스틱(무료)** — Kernel-Process **Thread** keyword 활성화. 콜백은 경량 `Captured::ThreadStart{pid,tid,start_addr}`만 전송; ingest 스레드가 `modmap::snapshot`(pid 캐시)으로 resolve → unbacked면 `inj_signals` 기록(5단계 Finding 소비). ⏳ *(0단계 ② 실측 후)*
- [x] **건드리는 파일(cmdline)**: `peb.rs`(신규), `Cargo.toml`(Diagnostics_Debug), `lib.rs`(mod), `etw.rs`/`store.rs`/`ipc.rs`(`Captured::ProcCreate.cmdline` plumbing), `capture_smoke.rs`(enrich+assert+explore 확장).
- [x] **검증(cmdline)**: `cargo check` ✓ · `cargo test --lib --no-run` ✓. `captures_cmd_subtree`에 자식 노드 cmdline assert 추가. ⏳ elevated 실행은 사용자.
- [ ] **커밋**: `feat(telemetry): PEB cmdline` (cmdline 선행) → integrity/READ/injection은 실측 후 후속 커밋.

---

## 2단계 · Sigma 필드 어댑터 — 신설 `sigma_fields.rs` ✅
**목표**: 내부 `Event` → Sigma 표준 필드맵. **룰 엔진과 텔레메트리의 유일한 접점.**

- [x] `pub enum SigmaCategory { ProcessCreation, RegistrySet, RegistryEvent, DnsQuery, NetworkConnection, FileEvent, FileAccess, ImageLoad }` (+ `as_str()`/`from_str()` = Sigma logsource.category).
- [x] `fn sigma_view(ev: &Event, cap: &Capture) -> Option<(SigmaCategory, BTreeMap<String,String>)>`
  - **process_creation**: `Image`(자식), `OriginalFileName`(basename), `CommandLine`(자식, 1단계), `ParentImage`/`ParentCommandLine`(`cap` 노드 `ev.node_id`=부모), `IntegrityLevel`(자식 노드: `cap.tracker.live_node(child_pid)` — ingest 직후라 정확, 있으면).
  - **registry_set**(SetValue/DeleteValue) / **registry_event**(CreateKey/DeleteKey): `TargetObject`(정규화 `HKLM\...`, value명 있으면 `\value` 부착), `EventType`(SetValue/CreateKey/…), `Details`(값 데이터 — 미수집이라 보통 생략→해당 룰 "필드 미충족").
  - **dns_query**: `QueryName`, `QueryResults`.
  - **network_connection**: `DestinationIp`, `DestinationPort`, `Initiated`(outbound=`"true"`), `Image`(actor 노드).
  - **file_event**(write/create) / **file_access**(read): `TargetFilename`.
  - **image_load**: `ImageLoaded`.
- [x] `provided_fields(cat) -> &'static [&str]` — 카테고리별 제공 필드 집합. **4단계 큐레이션 스크립트가 이 목록을 하드코딩 복제(동기화)**.
- [x] **건드리는 파일**: `sigma_fields.rs`(신규), `store.rs`(`Capture::node(id)` 헬퍼), `lib.rs`(mod 등록).
- [x] **검증**: 카테고리별 필드맵 단위 테스트 8개 통과(`cargo test --lib sigma_fields`).
- [x] **커밋**: `feat(sigma): Event→Sigma field adapter`

---

## 3단계 · Sigma 미니 평가 엔진 — 신설 `sigma.rs` (`serde_yaml`) ✅
**목표**: 큐레이션된 Sigma YAML을 컴파일 + 필드맵으로 평가. **지원 못 하면 에러 대신 스킵.**

- [x] `Cargo.toml`에 `serde_yaml`/`regex`/`base64` 추가.
- [x] **파싱**: `title,id,status,level`, `tags`(→ `attack.tXXXX` 추출), `logsource.category`, `detection`(임의 selection 맵 + `condition` 문자열). multi-doc/correlation/timeframe → Unsupported.
- [x] **모디파이어**: `contains,startswith,endswith,all,re,cidr,windash,base64,base64offset`(+ re 플래그 i/m/s). 미지원 모디파이어 → 룰 `Unsupported` 스킵(에러X). 기본 대소문자 무시. 리스트=OR, `|all`=AND, `field: null`=부재 매칭.
- [x] **condition 파서**(재귀하강): selection명, `and/or/not`, 괄호, `1 of`/`all of` × (`them`/`name*`/`name`). 미지의 selection 참조 → Unsupported.
- [x] sigma_view 제공 집합에 없는 필드 사용 룰 → `MissingFields` 스킵.
- [x] **API**: `CompiledRule{ id,title,level,status,tags,category,selections,cond }`, `load_rules(dir) -> (Vec<CompiledRule>, LoadReport{loaded,skipped_unsupported,skipped_missing_fields})`(재귀 디렉터리 워크), `CompiledRule::eval(fields) -> bool`.
- [x] **건드리는 파일**: `sigma.rs`(신규), `Cargo.toml`, `lib.rs`, `tests/fixtures/sigma/*.yml`(4개: 3 loadable + 1 skip).
- [x] **검증**: 인라인 룰 매칭/비매칭(encoded powershell·Office 자식 쉘·registry_set·1 of·cidr·base64/windash·미지원·필드미충족) + 픽스처 디렉터리 `load_rules` LoadReport 검증 = **9개 신규 테스트 통과**.
- [x] **커밋**: `feat(sigma): YAML rule compiler + condition evaluator`

---

## 4단계 · 룰셋 큐레이션 — `scripts/curate_sigma.py` (영구 유지보수 경로) ✅
**목표**: SigmaHQ에서 **scent 센서로 실제 평가 가능한** 룰만 골라 동기화. 인수 기준 manifest 산출.

- [x] `vendor/sigma` = SigmaHQ/sigma **git submodule**(shallow) 추가. `README.md`에 갱신법(`git submodule update --remote` → `python scripts/curate_sigma.py`) + DRL 라이선스 명시.
- [x] **필터**: category ∈ {8개+별칭}; product `windows`/미지정; detection 필드 ⊆ provided 집합(스크립트 하드코딩, 어댑터 동기화); status ∈ {stable,test}; level ≥ medium; **미지원 모디파이어/correlation/aggregation/timeframe 제외**.
- [x] **출력**: `src-tauri/rules/stable_medium_plus/`(1392) 와 `.../optin/`(experimental·low, 205) + `manifest.json`(룰 수, ATT&CK 255, 카테고리/스킵 사유 분포). **멱등**(출력 디렉터리 재빌드). 콘솔 사유별 카운트 요약.
- [x] **검증**: 1회 실행 → **3589 스캔 → 1597 evaluable**(manifest). 교차검증 Rust 테스트 `curated_ruleset_loads_cleanly`: 엔진이 **1588/1597 로드**(9개는 Rust regex가 거부하는 lookaround, 런타임에서 안전 스킵), ≥95% 게이트 통과.
- [x] **커밋**: `feat(rules): SigmaHQ curation script + curated ruleset + manifest`

---

## 5단계 · Finding 모델 + 상태형 탐지 + 저장/점수/IPC ✅
**목표**: Sigma 매칭 + 4개 휴리스틱을 Finding으로 통합, 점수화·IPC 노출.

- [x] **model.rs**: `Severity(Info/Low/Med/High/Critical, Ord)`+`weight()`, `FindingSource(Sigma{rule_id}|Stateful{kind}|Deep)`, `Finding{ id, ts_ms, technique, severity, title, description, actor_node, source, evidence }`. `Capture.findings`+`add_finding`(deep_findings 패턴)+`findings_version`. `ProcessNode.suspicion`.
- [x] **탐지 실행**: ingest 스레드에서 `ingest(c)`가 반환한 이벤트 id로 `Capture::detect_event(id, &RuleSet)` → sigma_view 필드맵 → **카테고리 인덱싱된** `RuleSet`만 `eval` → 매칭 결과를 먼저 수집 후 `add_finding(Sigma)`. 룰은 `AppState.ruleset: OnceLock<Arc<RuleSet>>`로 lazy 로드(`load_default_ruleset`, ~1392룰) 후 ingest 스레드 공유.
- [x] **stateful.rs** (4개, 노드별 상태, `Capture` 소유, 주체별 1회 발화):
  - **비커닝**: 같은 `ip:port` ≥5회 + 간격 CV ≤0.25 → **High**(loopback 제외).
  - **DNS 터널**: 부모도메인당 고유 서브도메인 ≥25 → **High**. **DGA**: 라벨 엔트로피 ≥3.2·길이 ≥12 도메인 ≥5개 → **Med**.
  - **랜섬 mass-op**: 5s 윈도 내 같은 새 확장자가 ≥8 디렉터리 / 동일 파일명 ≥5 디렉터리 → **Critical**(benign 확장자/파일명 제외).
  - **자가삭제**: 노드 자기 image delete/rename → **Med**.
  - 각각 **단위 테스트 6개**(합성 시퀀스 주입; 비커닝 비매칭 포함).
- [x] **점수**: `suspicion = Σ severity 가중치`(Crit100/High40/Med10/Low2/Info0). `ProcessNode.suspicion`+`CaptureStatus.suspicion`. `add_finding`에서 노드·캡처 누적.
- [x] **IPC/emit**: `get_findings` 커맨드(`lib.rs` 등록), `CaptureStatus`/`CaptureDelta`에 `findings_count`+`findings_version`+`suspicion`. `EventFilter.event_ids:Option<Vec<u64>>`(증거 점프). 프론트 구독은 6단계.
- [x] **건드리는 파일**: `model.rs`, `store.rs`, `stateful.rs`(신규), `sigma.rs`(RuleSet/load_default_ruleset/severity/description), `sigma_fields.rs`(Hash), `ipc.rs`, `lib.rs`.
- [x] **검증**: `cargo test --lib` **24 통과**(stateful 6 + 기존). `cargo check` 클린.
- [ ] **deferred**: injected-thread 신호 → Finding 승격은 1단계 injection 텔레메트리(실측 대기)와 함께. `FindingSource::Deep` 승격도 후속.
- [x] **커밋**: `feat(detect): Finding model, stateful heuristics, scoring, IPC`

---

## 6단계 · UI 판정-우선 재편 (`src/`) ✅
**목표**: 판정이 먼저 보이되 raw는 항상 접근 가능. 토큰·모션·glass 규칙 준수.

- [x] **types/ipc**: `lib/types.ts`에 `Finding`/`Severity`/`FindingSource`(백엔드 serde 일치) + status/delta 신필드 + `EventFilter.event_ids/ts_from/ts_to` + `ProcessNode.suspicion`. `lib/ipc.ts` `getFindings`. `App.tsx` `findings_version` 구독(변할 때만 refetch).
- [x] **FindingsPanel**(신규, **기본 랜딩 탭**): suspicion 점수 + severity 정렬 카드(배지+기법명+ATT&CK 칩+평문+책임 프로세스). "증거 보기" → `event_ids` 필터로 Events 탭 점프(필터 칩). 빈 상태는 "raw 항상 가용" 강조.
- [x] **ProcessTree/TreeNode**: 직접 max-severity 점수 배지 + 핫 브랜치(조상 전파) 좌측 엣지. **`tokens.css` `--sev-*` 토큰 신설**.
- [x] **TimelineView**: 상단 finding 마커 레인, 비커닝 evidence 연결선(network 트랙), drag **brush 구간선택 → ts 범위 전역 필터**(Events 탭 칩). click=최근접 이벤트 선택.
- [x] **GraphView(@xyflow)**: process 노드 severity 색 오버레이 + 타입드 엣지 라벨(spawned/wrote/persisted/connected/resolved/loaded).
- [x] **IocPanel**(신규): 도메인/외부IP/드롭파일/persistence reg키 자동수집 + 디팽 텍스트·CSV 클립보드 복사.
- [x] **건드리는 파일**: `App.tsx`, `FindingsPanel.tsx`·`IocPanel.tsx`(신규), `lib/findings.ts`(신규), `TreeNode.tsx`·`ProcessTree.tsx`, `TimelineView.tsx`, `GraphView.tsx`, `EventsTable.tsx`, `lib/types.ts`·`ipc.ts`, `styles/tokens.css`·`app.css`, `store.rs`(ts 범위 필터).
- [x] **검증**: `npx tsc --noEmit` 클린 · `npm run build` 성공 · `cargo test --lib` 24 통과.
- [x] **커밋**: `feat(ui): verdict-first FindingsPanel, severity tree, IOC panel, timeline/graph overlays`

---

## 7단계 · LLM 트리아지 output (부가) ✅
**목표**: 텔레메트리 기반 LLM 트리아지 출력 체계. **Findings 불변, 환각이 덮어쓰지 못하게.**

- [x] **컨텍스트 번들러**(신설 `triage.rs`): findings(severity 정렬) + IOC(backend 재수집, verbatim) + 트리/카운트 요약을 결정적 컨텍스트로 직렬화. `TriageBundle{system_prompt, context, ready_prompt}`.
- [x] **가드레일 프롬프트**: "주어진 텔레메트리만으로 판단, 추측 시 'Speculation:' 명시, IOC verbatim 인용, Findings가 authoritative". 출력 스키마(assessment/confidence/summary/key_observations/cited_iocs/recommended_actions/uncertainties) JSON 고정.
- [x] **VerdictPanel**(별도 탭): LLM 출력 전용. Findings/raw 불변. "Copy for LLM"(키 없이 항상)/"Run analysis"(`ANTHROPIC_API_KEY` 있을 때 ureq로 Anthropic 호출, 없으면 명확한 에러). JSON 파싱 실패시 raw 보존.
- [x] **건드리는 파일**: `triage.rs`(신규), `Cargo.toml`(ureq), `ipc.rs`, `lib.rs`, `VerdictPanel.tsx`(신규), `lib/types.ts`·`ipc.ts`, `app.css`.
- [x] **검증**: 키 없이 빌드/실행 정상(`run_triage`는 키 없으면 Err 반환, UI는 수동 번들 안내). `cargo check`·`cargo test --lib`(24)·`npm run build`·`npx tsc --noEmit` 클린.
- [x] **커밋**: `feat(triage): guarded LLM verdict panel (optional)`

---

## 8단계 · UI 재설계 — 복잡도↓·필터↑ (판정-우선/Liquid Glass 유지) (`src/` + 일부 `src-tauri/`)
**진단**: 철학(glass=chrome·data=불투명, 판정-우선, 토큰 규율)은 옳다. 문제는 적용 밀도 — **(1) 7개 평면 탭**(개념은 위계인데 평면), **(2) 상시 3겹 glass 프레임**(topbar+tabs+inspector), **(3) 데이터 풍부함을 못 따라가는 좁은 필터**(`EventFilter`= category·node단일·text·hide_noise·collapse·ts뿐 — op종류/proto/dir/port/severity/서브트리 못 거름).
**목표**: 새 디자인 언어가 아니라 *지금 언어를 덜 쓰고, 필터를 데이터만큼 깊게*. 기존 cross-view 점프(evidence/brush)·불변식 전부 보존.

### 8단계 불변식 (추가)
- glass 규칙·토큰 규칙(`tokens.css`만) 유지. **신규 색 최소**(accent 1개 외 category/severity 팔레트 불변).
- cross-view 동작 **회귀 금지**: evidence 점프(`App.tsx` `showEvidence`)·timeline brush(`onBrush`)·node 필터·collapse·hide_noise·export.
- 백엔드 **캡처 파이프라인 불변**. 8.4는 **읽기 질의(`store::query`)·IPC 시그니처만** 건드린다. ETW 콜백/ingest 무변경.

---

#### 8.1 · IA 통합 (A) — 7탭 → 4, Evidence 세그먼트
- `App.tsx` `Tab` = `"findings" | "evidence" | "ioc" | "verdict"`. Evidence 내부 `evidenceView: "table"|"graph"|"timeline"` 상태 신설(같은 이벤트 스트림의 3 렌즈를 세그먼트로).
- **Deep 탭 제거**: DeepPanel을 탭에서 내림. Deep 데이터는 (a) Evidence>표에서 file-create 행 선택 시 **Inspector**에 caller stack 노출(`Inspector`는 이미 `DeepFinding` 수용), (b) "caller stack 있음" facet은 8.5. `deepMode` 토글/`getDeepFindings` 구독은 **유지**(Inspector·facet용).
- 탭 바: `Findings(badge) · Evidence‹표│그래프│타임라인› · IOCs · Verdict`. ExportMenu 우측 유지.
- `showEvidence`/`onBrush`는 `setTab("evidence")`+`setEvidenceView("table"/"timeline")`로 라우팅.
- **건드리는 파일**: `App.tsx`, `components/Segmented.tsx`(신규, 토큰만), `app.css`(.tabs), DeepPanel import 정리.
- **게이트**: `npx tsc --noEmit` · `npm run build`. 회귀: evidence/brush 점프가 Evidence 적절 서브뷰로.
- **커밋**: `refactor(ui): 7 tabs → Findings/Evidence/IOCs/Verdict, segmented Evidence view`

#### 8.2 · 맥락 Inspector (B) — 상시 300px → 슬라이드-오버
- Inspector를 워크벤치 3번째 상시 컬럼에서 분리. 선택(node/event/deep) 있을 때만 우측 glass 슬라이드-인(`spring.panel`), 빈 상태 미렌더. close(X)/ESC 닫기.
- `.workbench` 2컬럼(rail+center)으로, Inspector는 overlay/motion layout → 데이터 폭 환원. **상시 glass = topbar만**, inspector glass는 맥락화돼 진짜 Liquid Glass 용법.
- **건드리는 파일**: `App.tsx`(조건부+open 상태), `components/Inspector.tsx`(close), `app.css`(.insp overlay/슬라이드), `lib/motion.ts`(필요시 slide variant).
- **게이트**: tsc/build. 회귀: node/event/deep 선택→열림, evidence 점프 후에도 동작.
- **커밋**: `feat(ui): contextual slide-over inspector`

#### 8.3 · glass 1겹화 + 엘리베이션 통일 + TopBar 슬림 (D·E·F)
- **D**: 탭/세그먼트 바의 자체 `backdrop-filter`+specular 제거(`app.css` `.tabs`) → `.view` 상단 통합 헤더(불투명) 또는 무블러 세그먼트. 상시 glass 1겹.
- **E**: TopBar 4카운터 → 상태 캡슐(rec·elapsed·total), procs/live는 title/hover. "behavior analyzer" 태그 제거. 카테고리 카운트는 8.5 facet 범례로 이동.
- **F**: 그림자 레시피 정리 — `--shadow-glass`=floating chrome 전용, 데이터 패널=`--shadow-panel` 단일. "active" 3종(row-selected/primary/chip--on) → `--accent` 1개로 수렴(토큰 신설).
- **건드리는 파일**: `app.css`, `tokens.css`(`--accent`), `TopBar.tsx`, `components/GlassPanel.tsx`(필요시).
- **게이트**: tsc/build. 시각 회귀는 사용자 육안(스크린샷, elevated).
- **커밋**: `style(ui): single glass layer, unified elevation, slim topbar`

#### 8.4 · EventFilter 확장 (C-백엔드) — query 경로만
- `model.rs`/`ipc.rs` `EventFilter`에 추가: `ops: Option<Vec<String>>`(op 키: write/delete/set_value/create_key…), `proto: Option<Proto>`, `direction: Option<NetDir>`, `port_min/port_max: Option<u16>`, `node_ids: Option<Vec<u64>>` + `include_subtree: bool`. findings는 `get_findings`에 `min_severity`.
- `store::query`에 매칭 추가(기존 필터와 AND). op = `EventKind`별 op 문자열. 서브트리 = tracker 자식 전개. **collapse(dedup)보다 필터 먼저** 적용.
- field-scoped text: `host:`/`path:`/`port:` 접두 파싱(서버, 가볍게).
- **건드리는 파일**: `model.rs`, `store.rs`(query), `ipc.rs`(get_findings severity), `lib/types.ts`(미러).
- **게이트**: `cargo check` · `cargo test --lib`(신규 4~6: op/proto/port/subtree/severity/field-scope) · tsc.
- **커밋**: `feat(query): faceted EventFilter (op, proto/dir/port, subtree, severity, field-scope)`

#### 8.5 · facet UI + 트리아지 프리셋 (C-프론트)
- `EventsTable` toolbar → **2단 facet 바**: 1행 카테고리 chip(현행) → 선택 시 2행 op 멀티셀렉트(File: create/open/read/write/delete/rename · Reg: set_value/create_key/… · Net: TCP·UDP·Out·In·포트 · DNS: qtype). 기존 pill 패턴(`EventsTable.tsx` evidence/ts pill) 확장.
- **프리셋 퀵필터**(휴리스틱과 라벨 일치): "지속성"(reg set_value+Run키), "egress"(net outbound), "드롭"(file write/create, temp 제외), "자가삭제". 클릭=facet 조합 세팅.
- FindingsPanel: `min_severity` 필터 칩(정렬+필터). 트리 노드 선택 시 "이 서브트리" 스코프 토글.
- **건드리는 파일**: `components/EventsTable.tsx`, `components/FindingsPanel.tsx`, `components/FacetBar.tsx`(신규), `lib/events.ts`(op 메타/프리셋), `lib/ipc.ts`, `app.css`.
- **게이트**: tsc/build. 회귀: evidence/ts/node pill·collapse·hide_noise 공존.
- **커밋**: `feat(ui): two-level facet filtering + triage presets + severity filter`

---

### 8단계 인수 기준
- [x] `npx tsc --noEmit` · `npm run build` 클린; `cargo test --lib` **29 통과**(기존 24 + 신규 query 5: ops/proto·dir·port/subtree/host·path/port-scope).
- [x] 회귀(코드/타입 레벨) 보존: evidence 점프·timeline brush→ts·node/서브트리 필터·collapse·hide_noise·deep(Evidence>Deep 세그먼트→Inspector 스택)·export 드롭다운(center overflow 비클립). 시각 회귀는 사용자 elevated 스크린샷 대기.
- [x] 상시 glass 1겹(topbar) + 맥락 Inspector 슬라이드-오버; 최상위 탭 4개(Evidence 세그먼트 표/그래프/타임라인/Deep); facet 2단 + 프리셋 4종 + severity 임계 필터 구현.

### 8단계 구현 메모 (계획 대비 편차)
1. **Deep**: "Inspector로만 흡수" 대신 **Evidence 세그먼트의 조건부 4번째 렌즈**(deep_count>0일 때 노출)로 배치 — 최상위 탭은 7→4로 줄이면서 DeepPanel/스택체인 기능 **무손실**. Inspector 스택체인은 그대로(row 클릭).
2. **min_severity**: `get_findings`에 백엔드 파라미터를 추가하지 않고 **FindingsPanel 클라이언트 필터**로 처리 — findings는 이미 프론트 메모리에 전부 있어 즉답·무refetch가 낫고 IPC 시그니처 불변. (`ipc.rs` 무변경.)
3. **glass 통합**: 탭 바를 `.center` 카드의 불투명 헤더로 흡수(별도 glass 슬라브 제거). Export 드롭다운 클립 회피를 위해 overflow는 `.view`에만.

### 8단계 리스크/주의
1. **collapse × 필터 순서**: collapse 재집계가 필터 적용 후 dedup이 되도록(`store::query` 순서). 단위테스트로 고정.
2. **Deep 접근성**: 탭 제거가 deep 데이터 가시성을 낮추지 않게 8.2 Inspector 노출과 묶어 검증.
3. **토큰 규율**: accent 1개 외 색 추가 자제 — category/severity 팔레트 불변.

---

## 최종 인수 기준 결과
- [x] `cargo check` + 기존 smoke 테스트(compile, 5 elevated ignored) + **신규 단위 테스트 24개** 통과.
- [x] `npm run build` + `npx tsc --noEmit` 클린.
- [x] **LLM 키 없이** 캡처/탐지/UI 전부 동작(7단계 부가, run_triage만 키 필요).
- [x] 4단계 큐레이션 1회 실행 → **3589 스캔 → 1597 evaluable**(manifest), 엔진 교차검증 **1588 로드**.

## 사용자 후속(elevated 필요 — 내가 못 돌림)
1. `cargo test --lib -- --ignored --nocapture explore_providers`(관리자) → 출력 공유 → 1단계 deferred(ThreadStart/READ/integrity) 실측 필드명으로 마무리.
2. `cargo test --lib -- --ignored --nocapture captures_cmd_subtree`(관리자) → cmdline 채움 + 파이프라인 회귀 확인.

---

## 최종 인수 기준
- [ ] `cargo check` + 기존 smoke 테스트 + 신규 단위 테스트 통과.
- [ ] `npm run build`, `npx tsc --noEmit` 클린.
- [ ] **LLM 키 없이도** 캡처/탐지/UI 전부 동작(7단계는 부가).
- [ ] 4단계 큐레이션 1회 실행 → "실제로 몇 개 Sigma 룰이 scent 센서로 평가 가능한지" manifest 보고.

## 리스크/의존성
1. **elevated ETW 검증**: 1단계 ②③(ThreadStart/integrity)·①(READ)의 event id/keyword/필드명은 `explore_providers`(관리자) 실측 필요. → 0단계에서 확장본 준비, **사용자 실행 출력 대기**.
2. **vendor/sigma submodule**: 4단계 네트워크 접근 필요. 불가 시 수동 clone 폴백 문서화.
3. **Sigma 엔진 범위**: 미지원 문법은 의도적 스킵(스킵 카운트로 가시화). 목표는 커버리지 100%가 아니라 "정확히 평가 가능한 부분집합".
