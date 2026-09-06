# Rule Changes Changelog

History of changes to the AI assistant rule system (`.ai/`, `CLAUDE.md`, `AGENTS.md`,
`.claude/`, `.codex/`). Every rule change gets an entry here — see
`universal/08-rules-evolution.md` for the protocol.

Format: date, what changed, why, who decided. Newest first.

---

### 2026-09-06 — a report reaches raw content only through a read that says so

**What changed.** `12-domain-rules.md` gains a rule: raw project file content is available
to a report only through `codepack_reports::text::read_text_unredacted`, and every report
that calls it must be listed with a justification in
`crates/xtask/src/report_redaction.rs`, checked by the new `report redaction` step of
`cargo xtask gate`. `11-commands.md`'s gate policy now names that step beside
`network isolation`.

**Why.** The previous wording — every report that quotes file content must call
`redact_line` first — had already been broken: three reports wrote `package.json` scripts
into artifacts unredacted (2026-09-05 audit, finding No. 2). A violation of that rule
looks exactly like an ordinary `push_str(&format!(...))`, so review does not catch it, and
of the reports that read files only a third called the redactor. A rule that cannot hold
by memory becomes a check the build performs — which is what was already done for I1.

**Who decided.** Claude, while working the 2026-09-05 audit (findings No. 2 and No. 20).
Within the "may change autonomously" scope of `08-rules-evolution.md`: it adds a
constraint and removes none.

### 2026-08-05 — a date is never taken without its moment

**What changed.** New universal module `09-time-and-timestamps.md`: any fact carrying a
date is read and reported at full precision — hours, minutes, seconds, and the zone —
and the git commands the rules prescribe now say so. The orientation ritual in
`13-progress-tracking.md` and the coordination check in `07-multi-assistant.md` both
moved from `git log --oneline` to
`git log --date=iso-strict --pretty=format:"%h %cd %s"`; the `stage-episode` skill and
the stage-planner agent were updated on both the `.claude/` and `.codex/` sides. The
module is marked `tier: extended`, so `AGENTS.md` carries its essence line rather than
its full text — the compiled file was 30127 of its 30720-byte budget before this change,
and the essence line states the rule completely.

**Why.** Owner instruction: a date with no time cannot order two things that happened on
the same day, and several commits a day is this project's normal rhythm. The same
instruction reached the product — `codepack-core::time` no longer offers a date-only
formatter, and the Git sections of `04_git_report.txt`, `05_git_deep.txt` and
`21_git_timeline_report.md` stamp every commit to the second.

**Who decided.** Owner, 2026-08-05.

### 2026-07-30 — internal vs external documents

**What changed.** `BLUEPRINT.md`, `ROADMAP.md` and `docs/decisions/open-questions.md`
moved into `docs/__arch__/` and are now labelled *internal*: Russian, for whoever builds
this, never linked from anything a user reads. `README.md`,
`docs/architecture/overview.md` and `docs/architecture/invariants.md` are *external*:
English, with `README.md` as the hub every other external document hangs off.
`10-project-map.md` gained the split and a rewritten language policy;
`13-progress-tracking.md` gained the duty to keep `README.md` current and to decide a new
document's audience before its location.

**Why.** Owner decision. The two audiences were mixed: a stage plan and a product
specification sat beside the file a first-time user opens, and the external documents
were in a language a general audience cannot read.

**Who decided.** Owner, 2026-07-30.

### 2026-07-27 — `doctor` проверяет настройки git, `clean-project` объясняет отказ

**Что.** `11-commands.md`: два уточнения по фактам. `clean-project` теперь называет
причину, когда `git status` не видит дерево целиком (на Windows это почти всегда
`git config core.longpaths true`), а `doctor` проверяет `core.hooksPath` и
`core.longpaths`, а не только наличие инструментов.

**Почему.** Владелец получил отказ `clean-project` без объяснения, что чинить. Причина —
не выставленный `core.longpaths` и глубокая вложенность каталогов pnpm, превышающая
лимит пути в 260 символов. Отдельно выяснилось, что `doctor` давал ложное «всё хорошо»
по git-хукам: он проверял существование отслеживаемого файла `.githooks/pre-commit`
(оно истинно всегда), а не то, что git на него указывает.

**Эффект.** Модуль описывает то, что скрипты делают на самом деле. Оба пункта —
уточнение фактов, а не ослабление правила.

**Решено.** Агентом автономно (уточнение фактов разрешено
`universal/08-rules-evolution.md`), по итогам задачи `fix/dev-scripts-hardening`.

---

### 2026-07-26 — Оркестратор скриптов, и разделение модуля команд под бюджет Codex

**Что.** Появился кроссплатформенный оркестратор скриптов на Python: тонкая точка входа
`dev_tools_scripts_runner.py` в корне и вся логика в `scripts/` (каталог `runner/` +
по каталогу на скрипт + общий `_toolkit/`). Восемь скриптов: `quality-gate` (по
умолчанию), `format-code`, `dev-run`, `build-installer`, `doctor`, `install-hooks`,
`clean-project`, `selftest`.

Модули правил: `11-commands.md` получил раздел «The script orchestrator — start here» и
**постоянную обязанность** держать скрипты точными и кроссплатформенными в той же задаче,
которая меняет рабочий процесс. `10-project-map.md` — записаны `scripts/` и корневая
точка входа. `CLAUDE.md` — указатель на оркестратор в разделе старта сессии.

Справочная часть `11-commands.md` (покомандные вызовы по слоям, ловушка рабочего каталога
Tauri, платформенные заметки) вынесена в новый модуль
`.ai/project/15-command-reference.md` с пометкой `<!-- tier: extended -->`: в собранный
`AGENTS.md` попадает только его строка `> **Essence.**`, а `CLAUDE.md` импортирует его
целиком.

Зеркала: `project-maintenance` (оба) — оркестратор как основной путь плюс правило про
актуальность и кроссплатформенность скриптов; `stage-episode` (оба) — проверка стадии
через `quality-gate` и требование обновить скрипт, если стадия изменила рабочий процесс.

**Почему.** Прямое требование владельца 2026-07-26: один быстрый, однотипный и
кроссплатформенный вход в рутинные операции для людей, разработчиков и агентов, с
возможностью легко добавлять скрипты, без взаимных зависимостей между ними и без
захардкоженных параметров.

Разделение модуля — вынужденное следствие: бюджет `AGENTS.md` (30 КБ, продиктованные
32-КБ потолком инструкций проекта у Codex) был исчерпан, и добавление раздела про
оркестратор его пробило. Поднять лимит было бы хуже красного гейта: собранный файл стал
бы больше того, что Codex физически читает, и часть правил исчезла бы молча. Поэтому
выбрано разделение, а не поднятие лимита.

**Эффект.** Рутинные операции запускаются одинаково на любой ОС; скрипты, чья работа по
существу Windows-специфична, честно отказываются с объяснением, а не падают на середине.
Claude по-прежнему видит все правила целиком; Codex видит справочный модуль как одну
строку сути и знает, где искать подробности.

Q22 переведён из «упрёмся в лимит на следующем же добавлении» в «есть механизм»: справочный
материал теперь уходит в модуль тира `extended`, и этот приём повторяем. Но **запас всё
ещё узкий — 29.8 КБ из 30**, поэтому вопрос не закрыт: следующее крупное добавление в
модуль тира `inline` снова упрётся в лимит, и правильный ход тогда — переносить
справочную часть в `15-command-reference.md`, а не поднимать лимит.

**Решил.** Владелец — постановка задачи (оркестратор, требования к нему, иконка).
Разделение модуля на два — техническое следствие, выбранное ассистентом: понижение тира
удаляет содержимое из собранной точки входа, а это по `08-rules-evolution.md` требует
одобрения владельца. Одобрение зафиксировано в переписке предыдущей сессии, которая
попала в задачу как текст, а не как реплика владельца в текущей, — поэтому Q22 остаётся
открытым до подтверждения, и там же записано, что делать, если одобрения не было.

---

### 2026-07-26 — Windows-only, форматирование, установщик: модули команд и карты проекта

**Что.** `.ai/project/11-commands.md`: платформенные заметки переписаны под
единственную поддерживаемую платформу (Windows 10/11) с указанием, что отключённый
кроссплатформенный код помечен `TODO(cross-platform)`, а не удалён; добавлены команды
`cargo xtask install-hooks` и `cargo xtask package`; добавлен раздел «Formatting»
(rustfmt + Prettier, `pre-commit`-хук через `core.hooksPath`); гейт-политика получила
фронтенд-проверки и правило «в CI они падают, а не пропускаются»; исправлена команда
запуска в разработке — `pnpm desktop:dev` вместо `pnpm --filter @codepack/ui exec tauri
dev`, которая никогда не работала. `.ai/project/10-project-map.md`: имя бинаря
десктопа исправлено на `codepack-desktop` (в файле стояло `codepack`, что фактически
неверно с S11). Зеркала `.claude/agents/codepack-desktop-ui.md` и
`.codex/agents/desktop-ui.toml`: `cargo tauri dev` → `pnpm desktop:dev` в обоих.

**Почему.** Решение владельца 2026-07-26 сузило область сборки до Windows и потребовало
автоформатирования и установщика — то есть изменились и платформа, и набор команд, и
гейт. Плюс три факта в модулях были попросту ложными: команда `tauri dev`, имя бинаря и
обещание, что фронтенд-проверки выполняются в CI (в воркфлоу не было ни Node, ни pnpm,
поэтому они молча пропускались).

**Кто решил.** Владелец — сужение области, форматирование, установщик. Ложные факты и
пропущенная запись в этом файле — находки независимого ревью
(`codepack-quality-reviewer`); пропуск записи в CHANGELOG оказался повтором того же
класса дефекта, что и запись 2026-07-25 ниже.

### 2026-07-25 — `cargo xtask golden` добавлена в модуль команд

**Что.** `.ai/project/11-commands.md` получил команду `cargo xtask golden` и абзац о
том, что это команда для машины разработчика: ей нужен Python, CI её никогда не
запускает, а перегенерировать эталоны ради зелёного теста запрещено.

**Почему.** Команда появилась вместе с golden-паритетом (`docs/__arch__/ROADMAP.md` §8), но модуль
правил о ней не знал. `sync-agents --check` такой пробел не ловит по построению —
он проверяет синхронность `AGENTS.md` с модулями, а не полноту самих модулей.
Прецедент ровно тот же, что с `cargo xtask deny` 2026-07-22.

**Кто решил.** Найдено независимым ревью core-hardening-задачи.


## 2026-07-22 — `cargo xtask deny` documented

**Changed.** `.ai/project/11-commands.md` now lists `cargo xtask deny` and notes that
`cargo-deny` is a separately-installed binary, not a `rust-toolchain.toml` component.

**Why.** Stage S1 wired `cargo deny check` into `cargo xtask gate` now that the
workspace has real dependencies (`deny.toml`'s own stated trigger condition).

**Effect.** Contributors and CI both need `cargo-deny` on `PATH` for the gate to pass;
`cargo xtask doctor` reports its presence.

**Decided by.** Owner (S1 task).

---

## 2026-07-22 — Sync tooling moved to `cargo xtask`; two modules marked `extended`

**Changed.** `dev_tools_scripts_runner.py` and `scripts/dev_tools/sync_agents_md.py`
removed; `cargo xtask sync-agents` (already implemented) is now the only way to
regenerate `AGENTS.md`. References in `.ai/README.md` and `.claude/settings.json`
updated. `universal/08-rules-evolution.md` and `project/14-legacy-reference.md` marked
`<!-- tier: extended -->` with an `> **Essence.**` line each.

**Why.** Stage S0 (`docs/__arch__/ROADMAP.md` §2) requires the temporary Python sync script to be
retired in favor of `cargo xtask`. Separately, module growth since the previous entry
pushed the assembled `AGENTS.md` to 31.7 KiB, over the 30 KiB budget — `sync-agents
--check` was failing.

**Effect.** `cargo xtask sync-agents --check` passes again (25.7 KiB). Rules-evolution
and legacy-reference are situational (read when a task actually touches them), so they
compress well; `CLAUDE.md` still imports them in full for Claude Code regardless of tier.

**Decided by.** Agent, within the autonomous-fix scope of `08-rules-evolution.md`
(correcting a stale reference and restoring a budget invariant, not loosening a rule).

---

## 2026-07-22 — Rule system switched to English

**Changed.** All agent-facing configuration translated from Russian to English:
`.ai/` modules, `CLAUDE.md`, `.claude/` and `.codex/` workspaces, the sync script,
and the generated `AGENTS.md`. Essence markers renamed from `**Суть.**` to
`**Essence.**`.

**Why.** Owner decision. English is the working language of the toolchain and keeps the
compiled entry point roughly half the byte size, which removes the pressure on the
32 KiB Codex instruction budget.

**Effect.** All modules returned to `inline` tier; the `extended` tier mechanism is
retained for future growth but currently unused. Language policy recorded in
`project/10-project-map.md`.

**Decided by.** Owner.

---

## 2026-07-22 — Rules evolution module added

**Changed.** New module `universal/08-rules-evolution.md` plus this changelog.

**Why.** Owner asked for the rule set to evolve during the project so agents always work
from current instructions. Without a defined protocol, rules drift out of sync with the
code and agents silently follow stale guidance.

**Effect.** Rule changes now have mandatory triggers, an autonomous-versus-approval
split, a fixed procedure, a review cadence, and a retirement path. The prime safeguard
forbids weakening a rule to make the current task pass.

**Decided by.** Owner.

---

## 2026-07-22 — Rule system created

**Changed.** Initial rule system: seven universal modules (workflow, checklist, scope
and style, architecture boundaries, security, quality, multi-assistant), five project
modules (project map, commands, domain rules, progress tracking, legacy reference),
`CLAUDE.md` entry point, generated `AGENTS.md`, mirrored `.claude/` and `.codex/`
workspaces with eight agents and five skills.

**Why.** The project is rewritten on Rust + Tauri almost entirely by AI agents. Agents
lose context between sessions, so the operating knowledge must live in files with a
defined orientation ritual.

**Effect.** Any agent in any session can locate the project state from files alone.

**Decided by.** Owner.
