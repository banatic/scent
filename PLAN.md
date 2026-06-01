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

## 3단계 · Sigma 미니 평가 엔진 — 신설 `sigma.rs` (`serde_yaml`)
**목표**: 큐레이션된 Sigma YAML을 컴파일 + 필드맵으로 평가. **지원 못 하면 에러 대신 스킵.**

- [ ] `Cargo.toml`에 `serde_yaml` 추가.
- [ ] **파싱**: `title,id,status,level,description`, `tags`(→ `attack.tXXXX` 추출), `logsource.category`, `detection`(임의 selection 맵 + `condition` 문자열).
- [ ] **모디파이어**: `contains,startswith,endswith,all,re,cidr,windash,base64,base64offset`. 미지원 모디파이어 발견 → 룰 전체 `Unsupported`로 **로드시 스킵**(에러X). 기본 대소문자 무시. 리스트=OR, `|all`=AND.
- [ ] **condition 파서**(작은 재귀하강): selection명, `and/or/not`, 괄호, `1 of selection*`, `all of them`, `all of selection*`.
- [ ] sigma_view 제공 집합에 없는 필드를 쓰는 룰 → `MissingFields`로 스킵.
- [ ] **API**: `CompiledRule{ id,title,level,status,tags,category,matcher }`, `load_rules(dir) -> (Vec<CompiledRule>, LoadReport{loaded,skipped_unsupported,skipped_missing_fields})`, `eval(rule, fields) -> bool`.
- [ ] **건드리는 파일**: `sigma.rs`(신규), `Cargo.toml`, `lib.rs`, `tests/fixtures/*.yml`.
- [ ] **검증**: SigmaHQ 실제 룰 3개(encoded powershell·Office 자식 쉘·registry_set 1개)를 `tests/fixtures`에 두고 **매칭/비매칭** 검증. `cargo test --lib`.
- [ ] **커밋**: `feat(sigma): YAML rule compiler + condition evaluator`

---

## 4단계 · 룰셋 큐레이션 — `scripts/curate_sigma.py` (영구 유지보수 경로)
**목표**: SigmaHQ에서 **scent 센서로 실제 평가 가능한** 룰만 골라 동기화. 인수 기준 manifest 산출.

- [ ] `vendor/sigma` = SigmaHQ/sigma **git submodule** 추가. `README.md`에 갱신법(`git submodule update --remote`) 명시.
- [ ] **필터**: category ∈ {8개}; product `windows`/미지정; detection이 쓰는 **모든 필드 ∈ provided 집합**(스크립트 하드코딩, 어댑터와 동기화); status ∈ {stable,test}; level ≥ medium; **미지원 모디파이어/correlation 제외**.
- [ ] **출력**: `src-tauri/rules/stable_medium_plus/` 와 `.../optin/`(experimental·low) 분류 복사 + `manifest.json`(룰 수, ATT&CK 커버리지). **멱등**. 콘솔에 로드/스킵 **사유별 카운트** 요약.
- [ ] **검증**: 1회 실행 → "실제로 몇 개 Sigma 룰이 scent 센서로 평가 가능한지" manifest 보고(인수 기준).
- [ ] **커밋**: `feat(rules): SigmaHQ curation script + curated ruleset + manifest`

---

## 5단계 · Finding 모델 + 상태형 탐지 + 저장/점수/IPC
**목표**: Sigma 매칭 + 4개 휴리스틱을 Finding으로 통합, 점수화·IPC 노출.

- [ ] **model.rs**: `Finding{ id, ts_ms, technique:Vec<String>, severity(Info/Low/Med/High/Critical), title, description, actor_node:Option<u64>, source(Sigma{rule_id}|Stateful{kind}|Deep), evidence:Vec<u64> }`. `Capture`에 `findings` + `add_finding`(deep_findings 패턴 그대로), `findings_version` 범프.
- [ ] **탐지 실행**: ingest 스레드에서 `ingest(ev)`가 만든 이벤트 id를 받아 `Capture::detect(event_id, &rules)` → sigma_view 필드맵 → 카테고리 일치 룰만 `eval` → 매칭시 `add_finding(Sigma)`. 1단계 injected-thread 신호도 여기서 `add_finding(Stateful{"injected_thread"})`로 승격. (borrow: 필드맵·매칭 결과를 먼저 수집 후 `&mut self`로 add.) 룰은 `AppState`에 `Arc<Vec<CompiledRule>>`로 로드해 ingest 스레드에 공유.
- [ ] **stateful.rs** (Sigma로 못 잡는 4개, 노드별 상태, `Capture`가 소유):
  - **비커닝**: 같은 `ip:port` N회 + jitter 임계 이하 → **High**.
  - **DNS DGA/터널**: 부모도메인당 고유 서브도메인 폭증 또는 라벨 Shannon 엔트로피 임계 → **Med/High**.
  - **랜섬 mass-op**: 윈도 내 ≥M개 디렉터리에 일관된 새 확장자/동일 노트명 create·rename → **Critical**.
  - **자가삭제**: 자기 image delete → **Med**.
  - 각각 **단위 테스트**(합성 이벤트 시퀀스 주입).
- [ ] **점수**: 노드별/캡처별 `suspicion = Σ severity 가중치`(Crit100/High40/Med10/Low2). `ProcessNode.suspicion`, `CaptureStatus.suspicion` 노출. `add_finding`에서 누적.
- [ ] **IPC/emit**: `get_findings` 커맨드(`lib.rs generate_handler!` 등록), `CaptureDelta`/`CaptureStatus`에 `findings_version` 추가(프론트는 변할 때만 refetch). `EventFilter`에 `event_ids:Option<Vec<u64>>` 추가(6단계 "증거 보기"용).
- [ ] **건드리는 파일**: `model.rs`, `store.rs`, `stateful.rs`(신규), `sigma_fields.rs`(detect 연계), `ipc.rs`, `lib.rs`, `emit.rs`.
- [ ] **검증**: `cargo test --lib`(stateful 단위 테스트 + 기존 통과). `captures_cmd_subtree` 회귀 없음(사용자 elevated).
- [ ] **커밋**: `feat(detect): Finding model, stateful heuristics, scoring, IPC`

---

## 6단계 · UI 판정-우선 재편 (`src/`)
**목표**: 판정이 먼저 보이되 raw는 항상 접근 가능. 토큰·모션·glass 규칙 준수.

- [ ] **types/ipc**: `lib/types.ts`에 `Finding`/`Severity`(백엔드 serde와 정확 일치), `lib/ipc.ts`에 `getFindings` + `findings_version` 구독.
- [ ] **FindingsPanel**(신규, **기본 랜딩 탭**): severity 정렬 카드(배지+기법명+ATT&CK 칩+평문 한 줄+책임 프로세스). "증거 보기" → `event_ids` 필터로 EventsTable 점프. raw 이벤트 탭은 뒤로 이동.
- [ ] **ProcessTree/TreeNode**: max-severity 색/배지 + 기법 칩 + 핫 브랜치 강조. **`tokens.css`에 `--sev-*` 토큰 신설**(data 색이므로 허용).
- [ ] **TimelineView**: finding 마커 레인 추가, 비커닝은 규칙적 연결 점 시각화, brush 구간선택 → 전역 필터.
- [ ] **GraphView(@xyflow)**: "인과 행위 사슬"(process→dropped file→persistence reg→network) 타입드 엣지(spawned/wrote/persisted/connected) 옵션 + Finding 오버레이.
- [ ] **IocPanel**(신규): 도메인/IP/드롭경로(+해시 있으면)/reg키 자동수집 + 디팽 텍스트·CSV 복사(exporter와 일관).
- [ ] **건드리는 파일**: `App.tsx`, `components/FindingsPanel.tsx`·`IocPanel.tsx`(신규), `TreeNode.tsx`, `TimelineView.tsx`, `GraphView.tsx`, `EventsTable.tsx`, `lib/types.ts`·`ipc.ts`·`events.ts`, `styles/tokens.css`·`app.css`.
- [ ] **검증**: `npm run build` + `npx tsc --noEmit` 클린.
- [ ] **커밋**: `feat(ui): verdict-first FindingsPanel, severity tree, IOC panel, timeline/graph overlays`

---

## 7단계 · LLM 트리아지 output (부가)
**목표**: 텔레메트리 기반 LLM 트리아지 출력 체계. **Findings 불변, 환각이 덮어쓰지 못하게.**

- [ ] **컨텍스트 번들러**(신설 `triage.rs`): findings + IOC + 트리/카운트 요약을 구조화 입력으로 직렬화.
- [ ] **가드레일 프롬프트**: "주어진 텔레메트리만으로 판단, 추측 시 명시, IOC 그대로 인용". 출력 스키마(요약/우선순위/근거 IOC 인용/불확실성 플래그) 고정.
- [ ] **VerdictPanel**(별도 패널): LLM 출력은 여기에만. Findings/raw는 불변. **LLM 키 없으면 비활성(나머지 전부 동작).**
- [ ] **건드리는 파일**: `triage.rs`(신규), `ipc.rs`, `lib.rs`, `components/VerdictPanel.tsx`(신규), `lib/types.ts`·`ipc.ts`.
- [ ] **검증**: 키 없이 빌드/실행 정상. `cargo check` + `npm run build` + `npx tsc --noEmit`.
- [ ] **커밋**: `feat(triage): guarded LLM verdict panel (optional)`

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
