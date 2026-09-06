<script lang="ts">
  // The last stop before anything is written: the exact file list, with the numbers that
  // decide whether it is the right one.
  import { explainFile, previewProject } from "$lib/api/client";
  import type { FileExplanation, FileStatus } from "$lib/api/types";
  import Callout from "$lib/components/Callout.svelte";
  import EmptyState from "$lib/components/EmptyState.svelte";
  import Icon from "$lib/components/Icon.svelte";
  import PreviewTree, { type ExpandCommand } from "$lib/components/PreviewTree.svelte";
  import SearchField from "$lib/components/SearchField.svelte";
  import Segmented, { type SegmentOption } from "$lib/components/Segmented.svelte";
  import Stat from "$lib/components/Stat.svelte";
  import { language, t } from "$lib/i18n/index.svelte";
  import { reportError } from "$lib/stores/toasts.svelte";
  import { goTo, previewStamp, wizard } from "$lib/stores/wizard.svelte";
  import { formatCompact, formatCount } from "$lib/util/format";
  import { countFiles, filterTree, isFilterActive } from "$lib/util/tree";

  // "Why is this file missing?" is asked while looking at the tree, so it is answered
  // here. The verdict comes from the engine, which is the same code `codepack explain`
  // runs — the two surfaces cannot disagree about a file.
  let explainPath = $state("");
  let explaining = $state(false);
  let explanation = $state<FileExplanation | null>(null);

  async function runExplain() {
    const file = explainPath.trim();
    if (!file || !wizard.project || !wizard.sessionConfig) return;
    explaining = true;
    try {
      explanation = await explainFile(
        wizard.project.root,
        $state.snapshot(wizard.sessionConfig),
        file,
      );
    } catch (error) {
      explanation = null;
      reportError("preview.explain.failed", error);
    } finally {
      explaining = false;
    }
  }

  let query = $state("");
  let status = $state<FileStatus | "all">("all");
  let expand = $state<ExpandCommand>({ token: 0, expanded: false });

  const filters: SegmentOption<FileStatus | "all">[] = $derived([
    { value: "all", label: t("preview.filter.all") },
    { value: "included", label: t("preview.filter.included") },
    { value: "excluded", label: t("preview.filter.excluded") },
    { value: "warning", label: t("preview.filter.warning") },
  ]);

  const filter = $derived({ query, status });

  const visibleTree = $derived(wizard.preview ? filterTree(wizard.preview.tree, filter) : null);

  const matchCount = $derived(visibleTree ? countFiles(visibleTree) : 0);

  const overrideCount = $derived(Object.keys(wizard.fileOverrides).length);

  /** True when the settings that shape a plan have moved since this preview was built.
   * Numbers that quietly describe a previous configuration are worse than no numbers. */
  const stale = $derived(
    wizard.preview !== null &&
      wizard.sessionConfig !== null &&
      wizard.previewConfigStamp !==
        previewStamp($state.snapshot(wizard.sessionConfig), wizard.fileOverrides),
  );

  async function runPreview(): Promise<void> {
    if (!wizard.project || !wizard.sessionConfig) return;
    wizard.previewLoading = true;
    const config = $state.snapshot(wizard.sessionConfig);
    const overrides = { ...wizard.fileOverrides };
    try {
      wizard.preview = await previewProject(wizard.project.root, config, overrides);
      wizard.previewConfigStamp = previewStamp(config, overrides);
    } catch (error) {
      reportError("preview.failed", error);
    } finally {
      wizard.previewLoading = false;
    }
  }

  function onOverride(path: string, include: boolean | null): void {
    const next = { ...wizard.fileOverrides };
    if (include === null) delete next[path];
    else next[path] = include;
    wizard.fileOverrides = next;
  }

  function setExpanded(expanded: boolean): void {
    expand = { token: expand.token + 1, expanded };
  }
</script>

<div class="stack page">
  <div class="page-header">
    <div>
      <h1 class="page-title">{t("preview.title")}</h1>
      <p class="page-lede">{t("preview.lede")}</p>
    </div>
    <div class="row row--tight">
      <button class="btn" onclick={runPreview} disabled={wizard.previewLoading}>
        {#if wizard.previewLoading}
          <span class="spinner"></span>
          {t("preview.loading")}
        {:else}
          <Icon name="refresh" size={14} />
          {wizard.preview ? t("preview.refresh") : t("preview.run")}
        {/if}
      </button>
      <button class="btn btn--primary" onclick={() => goTo("export")}>
        {t("preview.continue")}
        <Icon name="chevron" size={14} />
      </button>
    </div>
  </div>

  {#if !wizard.preview}
    <div class="card">
      <EmptyState icon="tree" title={t("preview.none")} text={t("preview.noneText")}>
        {#snippet action()}
          <button class="btn btn--primary" onclick={runPreview} disabled={wizard.previewLoading}>
            {t("preview.run")}
          </button>
        {/snippet}
      </EmptyState>
    </div>
  {:else}
    {@const preview = wizard.preview}
    {#if stale}
      <Callout tone="warning">{t("preview.stale")}</Callout>
    {/if}

    <div class="stats" style:--stats-min="150px">
      <Stat
        label={t("preview.stat.included")}
        value={formatCount(preview.included_files, language.current)}
        icon="check-circle"
        tone="success"
      />
      <Stat
        label={t("preview.stat.excluded")}
        value={formatCount(preview.excluded_files, language.current)}
        icon="eye-off"
      />
      <Stat label={t("preview.stat.size")} value={preview.estimated_bytes_human} icon="package" />
      <Stat
        label={t("preview.stat.tokens")}
        value={formatCompact(preview.estimated_tokens, language.current)}
        icon="activity"
        hint={formatCount(preview.estimated_tokens, language.current)}
      />
      <Stat
        label={t("preview.stat.skippedDirs")}
        value={formatCount(preview.skipped_dirs, language.current)}
        icon="folder"
      />
    </div>

    {#if preview.dropped_by_budget > 0}
      <Callout tone="info"
        >{t("preview.budgetDropped", { count: preview.dropped_by_budget })}</Callout
      >
    {/if}
    {#if preview.sensitive_count > 0}
      <Callout tone="warning">{t("preview.sensitive", { count: preview.sensitive_count })}</Callout>
    {/if}

    <section class="card card--flush tree-card">
      <div class="card__header toolbar">
        <SearchField bind:value={query} label={t("preview.search")} />

        <Segmented options={filters} value={status} onselect={(value) => (status = value)} />

        <div class="row row--tight">
          <button class="btn btn--sm" onclick={() => setExpanded(true)}>
            {t("preview.expandAll")}
          </button>
          <button class="btn btn--sm" onclick={() => setExpanded(false)}>
            {t("preview.collapseAll")}
          </button>
        </div>
      </div>

      {#if overrideCount > 0}
        <div class="overrides">
          <Icon name="sliders" size={13} />
          <span class="overrides__title">{t("preview.overrides")}</span>
          <span>{t("preview.overrides.count", { count: overrideCount })}</span>
          <button class="btn btn--sm btn--ghost" onclick={() => (wizard.fileOverrides = {})}>
            {t("preview.overrides.clear")}
          </button>
        </div>
      {/if}

      <div class="tree">
        {#if !visibleTree}
          <EmptyState icon="search" title={t("preview.noMatches")} />
        {:else}
          <PreviewTree
            node={visibleTree}
            overrides={wizard.fileOverrides}
            {onOverride}
            {expand}
            forceExpanded={isFilterActive(filter)}
          />
        {/if}
      </div>

      {#if isFilterActive(filter) && visibleTree}
        <p class="tree-footer">
          {t("preview.matches", { count: formatCount(matchCount, language.current) })}
        </p>
      {/if}
    </section>

    <section class="card explain">
      <h2 class="card__title">{t("preview.explain.title")}</h2>
      <p class="explain__hint">{t("preview.explain.hint")}</p>
      <div class="explain__ask">
        <input
          class="input"
          type="text"
          bind:value={explainPath}
          placeholder={t("preview.explain.placeholder")}
          onkeydown={(event) => {
            if (event.key === "Enter") runExplain();
          }}
        />
        <button class="btn" onclick={runExplain} disabled={explaining || !explainPath.trim()}>
          {explaining ? t("preview.explain.asking") : t("preview.explain.ask")}
        </button>
      </div>
      {#if explanation}
        <dl class="explain__answer">
          <dt>{t("preview.explain.verdict")}</dt>
          <dd>{explanation.verdict}</dd>
          <dt>{t("preview.explain.reason")}</dt>
          <dd>{explanation.reason}</dd>
          {#if explanation.skipped_directory}
            <dt>{t("preview.explain.skipped")}</dt>
            <dd>{explanation.skipped_directory}</dd>
          {/if}
          {#if !explanation.exists_on_disk}
            <dt>{t("preview.explain.missing")}</dt>
            <dd>{explanation.file}</dd>
          {/if}
        </dl>
      {/if}
    </section>
  {/if}
</div>

<style>
  .page {
    height: 100%;
  }

  .tree-card {
    display: flex;
    flex-direction: column;
    min-height: 320px;
    flex: 1;
  }

  .toolbar {
    flex-wrap: wrap;
    justify-content: flex-start;
  }

  .overrides {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: var(--space-3) var(--space-6);
    border-bottom: 1px solid var(--border);
    background: var(--accent-soft);
    color: var(--accent-fg);
    font-size: var(--text-sm);
  }

  .overrides__title {
    font-weight: var(--weight-semibold);
  }

  .tree {
    flex: 1;
    overflow: auto;
    padding: var(--space-3) var(--space-2);
  }

  .explain__hint {
    color: var(--text-muted);
    margin: 0 0 var(--space-3);
  }

  .explain__ask {
    display: flex;
    gap: var(--space-2);
  }

  .explain__ask .input {
    flex: 1;
  }

  .explain__answer {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: var(--space-1) var(--space-3);
    margin: var(--space-3) 0 0;
  }

  .explain__answer dt {
    color: var(--text-muted);
  }

  .explain__answer dd {
    margin: 0;
  }

  .tree-footer {
    padding: var(--space-3) var(--space-6);
    border-top: 1px solid var(--border);
    color: var(--fg-muted);
    font-size: var(--text-xs);
  }
</style>
