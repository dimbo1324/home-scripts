<script lang="ts">
  // What the export produced, and the two things a user wants next: find the bundle, or
  // read its reports.
  //
  // A run that did not finish cleanly still lands here with a bundle — the pipeline
  // always writes a manifest and always archives what it collected. Saying so plainly
  // matters more than hiding it: an incomplete bundle that looks complete is the one
  // outcome a tool about safe handoff must never produce.
  import {
    listLocalAgents,
    openDashboard,
    openOnboardingGuide,
    openProjectOverview,
    openResultLocation,
    openReviewChecklist,
    prepareHandoff,
  } from "$lib/api/client";
  import type { HandoffResult, LocalAgentInfo } from "$lib/api/types";
  import Callout from "$lib/components/Callout.svelte";
  import EmptyState from "$lib/components/EmptyState.svelte";
  import Icon, { type IconName } from "$lib/components/Icon.svelte";
  import Stat from "$lib/components/Stat.svelte";
  import type { TranslationKey } from "$lib/i18n/en";
  import { language, t } from "$lib/i18n/index.svelte";
  import { pushToast, reportError } from "$lib/stores/toasts.svelte";
  import { goTo, wizard } from "$lib/stores/wizard.svelte";
  import { copyText } from "$lib/util/clipboard";
  import { baseName, formatCount } from "$lib/util/format";

  interface ReportLink {
    key: TranslationKey;
    hint: TranslationKey;
    icon: IconName;
    open: (path: string) => Promise<void>;
  }

  const reports: ReportLink[] = [
    {
      key: "result.openDashboard",
      hint: "result.openDashboard.hint",
      icon: "chart",
      open: openDashboard,
    },
    {
      key: "result.openOverview",
      hint: "result.openOverview.hint",
      icon: "eye",
      open: openProjectOverview,
    },
    {
      key: "result.openOnboarding",
      hint: "result.openOnboarding.hint",
      icon: "tree",
      open: openOnboardingGuide,
    },
    {
      key: "result.openReviewChecklist",
      hint: "result.openReviewChecklist.hint",
      icon: "check-circle",
      open: openReviewChecklist,
    },
  ];

  /** One handler shared by all four "open a report" buttons: each just names which
   * extraction-and-open call to make, matching how the backend collapses the same
   * four commands onto one shared helper (`open_bundle_report`). */
  async function open(action: (path: string) => Promise<void>, path: string): Promise<void> {
    try {
      await action(path);
    } catch (error) {
      reportError("result.openFailed", error);
    }
  }

  async function copyPath(path: string): Promise<void> {
    const copied = await copyText(path);
    pushToast(copied ? "success" : "danger", copied ? "common.copied" : "common.copyFailed");
  }

  // --- Hand the bundle to a local agent (stage S13, offline path) -------------------
  //
  // Nothing is sent anywhere and nothing is launched: the agent runs on this machine and
  // reads the folder. The page's whole job is to write the file and show the command.
  let agents = $state<LocalAgentInfo[]>([]);
  let selectedAgent = $state("");
  let question = $state("");
  let handoff = $state<HandoffResult | null>(null);
  let preparing = $state(false);

  $effect(() => {
    void (async () => {
      try {
        agents = await listLocalAgents();
        if (!selectedAgent && agents.length > 0) selectedAgent = agents[0].id;
      } catch (error) {
        reportError("result.handoff.failed", error);
      }
    })();
  });

  async function prepare(path: string): Promise<void> {
    preparing = true;
    try {
      handoff = await prepareHandoff(path, selectedAgent, question);
    } catch (error) {
      reportError("result.handoff.failed", error);
    } finally {
      preparing = false;
    }
  }

  async function copyCommand(): Promise<void> {
    if (!handoff) return;
    // Both halves, because the command only works from inside the bundle: copying just
    // `claude` hands over something that runs in the wrong directory.
    const copied = await copyText(`cd "${handoff.working_dir}"\n${handoff.command}`);
    pushToast(copied ? "success" : "danger", copied ? "common.copied" : "common.copyFailed");
  }
</script>

{#if !wizard.exportResult}
  <div class="card">
    <EmptyState icon="package" title={t("result.none")} text={t("result.noneText")}>
      {#snippet action()}
        <button class="btn btn--primary" onclick={() => goTo("export")}>{t("export.title")}</button>
      {/snippet}
    </EmptyState>
  </div>
{:else}
  {@const result = wizard.exportResult}
  {@const tone = result.cancelled ? "warning" : result.successful ? "success" : "danger"}
  <div class="stack">
    <div class="page-header">
      <div class="outcome">
        <span class="outcome__icon outcome__icon--{tone}">
          <Icon name={tone === "success" ? "check-circle" : "alert"} size={22} weight={1.6} />
        </span>
        <div>
          <h1 class="page-title">
            {result.cancelled
              ? t("result.titleCancelled")
              : result.successful
                ? t("result.title")
                : t("result.titleIncomplete")}
          </h1>
          <p class="page-lede">{t("result.lede")}</p>
        </div>
      </div>
      <div class="row row--tight">
        <button class="btn" onclick={() => goTo("export")}>{t("result.newExport")}</button>
        <button class="btn" onclick={() => goTo("history")}>{t("result.viewHistory")}</button>
      </div>
    </div>

    {#if result.cancelled}
      <Callout tone="warning">{t("result.cancelledText")}</Callout>
    {:else if !result.successful}
      <Callout tone="danger">{t("result.incomplete")}</Callout>
    {/if}

    <div class="stats">
      <Stat
        label={t("result.stat.copied")}
        value={formatCount(result.files_copied, language.current)}
        icon="file"
        tone="success"
      />
      <Stat
        label={t("result.stat.skipped")}
        value={formatCount(result.files_skipped, language.current)}
        icon="eye-off"
      />
      <Stat
        label={t("result.stat.errors")}
        value={result.errors}
        icon="alert"
        tone={result.errors > 0 ? "danger" : "neutral"}
      />
      <Stat
        label={t("result.stat.critical")}
        value={result.critical_findings}
        icon="shield"
        tone={result.critical_findings > 0 ? "danger" : "neutral"}
      />
    </div>

    {#if result.result_path}
      {@const path = result.result_path}
      <section class="card">
        <div class="card__body bundle">
          <span class="bundle__icon"><Icon name="package" size={20} /></span>
          <div class="bundle__text">
            <p class="bundle__name">{baseName(path)}</p>
            <p class="path selectable">{path}</p>
          </div>
          <div class="row row--tight">
            <button class="btn btn--sm" onclick={() => copyPath(path)}>
              <Icon name="copy" size={13} />
              {t("result.copyPath")}
            </button>
            <button class="btn btn--primary" onclick={() => open(openResultLocation, path)}>
              <Icon name="folder-open" size={14} />
              {t("result.openFolder")}
            </button>
          </div>
        </div>

        {#if result.archives.length > 0}
          <div class="card__header archives">
            <span class="text-muted text-sm">{t("result.archives")}</span>
          </div>
          <ul class="archive-list">
            {#each result.archives as archive (archive)}
              <li><code class="selectable">{archive}</code></li>
            {/each}
          </ul>
        {/if}
      </section>

      <section class="card">
        <div class="card__header">
          <div>
            <h2 class="card__title">{t("result.handoff")}</h2>
            <p class="card__subtitle">{t("result.handoff.lede")}</p>
          </div>
        </div>
        <div class="card__body handoff">
          <div class="handoff__controls">
            <label class="field">
              <span class="field__label">{t("result.handoff.agent")}</span>
              <select class="input" bind:value={selectedAgent}>
                {#each agents as agent (agent.id)}
                  <option value={agent.id}>{agent.display_name}</option>
                {/each}
              </select>
            </label>
            <label class="field field--grow">
              <span class="field__label">{t("result.handoff.question")}</span>
              <input
                class="input"
                type="text"
                bind:value={question}
                placeholder={t("result.handoff.questionPlaceholder")}
              />
            </label>
            <button
              class="btn btn--primary"
              disabled={preparing || agents.length === 0}
              onclick={() => prepare(path)}
            >
              <Icon name="package" size={14} />
              {t("result.handoff.prepare")}
            </button>
          </div>

          {#if handoff}
            <div class="handoff__result">
              <p class="text-sm">{t("result.handoff.ready")}</p>
              <pre class="handoff__command selectable">cd "{handoff.working_dir}"
{handoff.command}</pre>
              <div class="row row--tight">
                <button class="btn btn--sm" onclick={copyCommand}>
                  <Icon name="copy" size={13} />
                  {t("result.handoff.copyCommand")}
                </button>
              </div>
              <p class="text-muted text-xs">{t("result.handoff.local")}</p>
            </div>
          {/if}
        </div>
      </section>

      <section class="card">
        <div class="card__header">
          <div>
            <h2 class="card__title">{t("result.reports")}</h2>
            <p class="card__subtitle">{t("result.reports.lede")}</p>
          </div>
        </div>
        <div class="card__body reports">
          {#each reports as report (report.key)}
            <button class="report" onclick={() => open(report.open, path)}>
              <span class="report__icon"><Icon name={report.icon} size={16} /></span>
              <span class="report__text">
                <span class="report__title">{t(report.key)}</span>
                <span class="report__hint">{t(report.hint)}</span>
              </span>
              <span class="report__go"><Icon name="external" size={14} /></span>
            </button>
          {/each}
        </div>
      </section>
    {/if}
  </div>
{/if}

<style>
  .outcome {
    display: flex;
    align-items: flex-start;
    gap: var(--space-5);
  }

  .outcome__icon {
    display: grid;
    place-items: center;
    width: 42px;
    height: 42px;
    flex: none;
    border-radius: var(--radius-md);
  }

  .outcome__icon--success {
    background: var(--success-soft);
    color: var(--success);
  }

  .outcome__icon--warning {
    background: var(--warning-soft);
    color: var(--warning);
  }

  .outcome__icon--danger {
    background: var(--danger-soft);
    color: var(--danger);
  }

  .bundle {
    display: flex;
    align-items: center;
    gap: var(--space-5);
    flex-wrap: wrap;
  }

  .bundle__icon {
    display: grid;
    place-items: center;
    width: 40px;
    height: 40px;
    flex: none;
    border-radius: var(--radius-md);
    background: var(--accent-soft);
    color: var(--accent-fg);
  }

  .bundle__text {
    flex: 1;
    min-width: 200px;
  }

  .bundle__name {
    font-size: var(--text-md);
    font-weight: var(--weight-semibold);
    word-break: break-all;
  }

  .archives {
    border-top: 1px solid var(--border);
    border-bottom: 0;
    padding-bottom: 0;
  }

  .archive-list {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
    padding: var(--space-4) var(--space-6) var(--space-6);
    font-size: var(--text-sm);
    word-break: break-all;
  }

  .handoff {
    display: flex;
    flex-direction: column;
    gap: var(--space-5);
  }

  .handoff__controls {
    display: flex;
    align-items: flex-end;
    gap: var(--space-4);
    flex-wrap: wrap;
  }

  .field {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
    min-width: 180px;
  }

  .field--grow {
    flex: 1;
    min-width: 240px;
  }

  .field__label {
    color: var(--fg-muted);
    font-size: var(--text-xs);
  }

  .handoff__result {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
    padding-top: var(--space-4);
    border-top: 1px solid var(--border);
  }

  .handoff__command {
    padding: var(--space-4);
    border-radius: var(--radius-md);
    background: var(--surface-sunken, var(--surface-hover));
    font-family: var(--font-mono);
    font-size: var(--text-sm);
    white-space: pre-wrap;
    word-break: break-all;
  }

  .reports {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    gap: var(--space-4);
  }

  .report {
    display: flex;
    align-items: center;
    gap: var(--space-4);
    padding: var(--space-5);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--surface);
    text-align: left;
    transition:
      border-color var(--duration-fast) var(--ease-out),
      background var(--duration-fast) var(--ease-out);
  }

  .report:hover {
    border-color: var(--accent);
    background: var(--surface-hover);
  }

  .report__icon {
    flex: none;
    color: var(--accent);
  }

  .report__text {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
    flex: 1;
    min-width: 0;
  }

  .report__title {
    font-size: var(--text-base);
    font-weight: var(--weight-medium);
  }

  .report__hint {
    color: var(--fg-muted);
    font-size: var(--text-xs);
    line-height: var(--leading-normal);
  }

  .report__go {
    flex: none;
    color: var(--fg-faint);
  }
</style>
