<script lang="ts">
  // The project passport an export wrote, read back from the bundle rather than
  // recomputed. Recomputing would answer a subtly different question — "what does the
  // project look like now" instead of "what did you actually hand over" — and the second
  // is the one this page exists for.
  import { readProjectProfile } from "$lib/api/client";
  import type { ProjectProfileSummary } from "$lib/api/types";
  import EmptyState from "$lib/components/EmptyState.svelte";
  import Icon from "$lib/components/Icon.svelte";
  import Stat from "$lib/components/Stat.svelte";
  import { riskLabel } from "$lib/i18n/enums";
  import { language, t } from "$lib/i18n/index.svelte";
  import { reportError } from "$lib/stores/toasts.svelte";
  import { goTo, wizard } from "$lib/stores/wizard.svelte";
  import { formatBytes, formatCount } from "$lib/util/format";

  let summary = $state<ProjectProfileSummary | null>(null);
  let loading = $state(false);

  // Reading a profile extracts the bundle, so the call is slow enough for two of them to
  // overlap when a second export finishes while the first read is still running. The
  // generation counter is what stops the older answer from winning the race and
  // describing a bundle the user has already replaced.
  let generation = 0;

  $effect(() => {
    const path = wizard.exportResult?.result_path;
    generation += 1;
    const mine = generation;
    if (!path) {
      summary = null;
      loading = false;
      return;
    }
    loading = true;
    readProjectProfile(path)
      .then((loaded) => {
        if (mine === generation) summary = loaded;
      })
      .catch((error: unknown) => {
        if (mine === generation) reportError("analytics.loadFailed", error);
      })
      .finally(() => {
        if (mine === generation) loading = false;
      });
  });

  /** The scale the reports themselves use. `unknown` maps to neutral rather than to
   * "low": claiming safety the bundle never asserted is the one wrong answer here. */
  function riskTone(level: string): "success" | "warning" | "danger" | "neutral" {
    if (level === "high" || level === "critical") return "danger";
    if (level === "medium") return "warning";
    if (level === "low") return "success";
    return "neutral";
  }

  const riskWidth = $derived.by(() => {
    switch (summary?.risk_level) {
      case "low":
        return 25;
      case "medium":
        return 55;
      case "high":
        return 80;
      case "critical":
        return 100;
      default:
        return 0;
    }
  });
</script>

<div class="stack">
  <div class="page-header">
    <div>
      <h1 class="page-title">{t("analytics.title")}</h1>
      <p class="page-lede">{t("analytics.lede")}</p>
    </div>
  </div>

  {#if loading}
    <div class="card"><div class="loading"><span class="spinner"></span></div></div>
  {:else if !summary}
    <div class="card">
      <EmptyState icon="chart" title={t("analytics.none")} text={t("analytics.noneText")}>
        {#snippet action()}
          <button class="btn btn--primary" onclick={() => goTo("export")}>
            {t("export.title")}
          </button>
        {/snippet}
      </EmptyState>
    </div>
  {:else}
    {@const profile = summary}
    <div class="stats" style:--stats-min="180px">
      <Stat
        label={t("analytics.stat.files")}
        value={formatCount(profile.files, language.current)}
        icon="file"
      />
      <Stat
        label={t("analytics.stat.folders")}
        value={formatCount(profile.folders, language.current)}
        icon="folder"
      />
      <Stat
        label={t("analytics.stat.size")}
        value={formatBytes(profile.total_size_bytes)}
        icon="package"
      />
    </div>

    <div class="split">
      <section class="card">
        <div class="card__header">
          <h2 class="card__title">{t("analytics.riskLevel")}</h2>
          <span class="badge badge--{riskTone(profile.risk_level)}">
            {profile.risk_level ? riskLabel(profile.risk_level) : t("common.none")}
          </span>
        </div>
        <div class="card__body stack--tight stack">
          <div class="meter">
            <div
              class="meter__fill meter__fill--{riskTone(profile.risk_level)}"
              style:width="{riskWidth}%"
            ></div>
          </div>
          {#if profile.risk_reasons.length > 0}
            <p class="reasons__heading">{t("analytics.riskReasons")}</p>
            <ul class="reasons">
              {#each profile.risk_reasons as reason (reason)}
                <li>
                  <Icon name="alert" size={13} />
                  <span class="selectable">{reason}</span>
                </li>
              {/each}
            </ul>
          {/if}
        </div>
      </section>

      <section class="card">
        <div class="card__header">
          <h2 class="card__title">{t("analytics.stack")}</h2>
        </div>
        <div class="card__body stack--tight stack">
          <dl class="kv">
            <dt>{t("analytics.projectType")}</dt>
            <dd>{profile.project_type || t("common.none")}</dd>
          </dl>
          {#if profile.detected_stack.length > 0}
            <div class="chips">
              {#each profile.detected_stack as item (item)}
                <span class="chip">{item}</span>
              {/each}
            </div>
          {:else}
            <p class="text-muted text-sm">{t("common.none")}</p>
          {/if}
        </div>
      </section>
    </div>
  {/if}
</div>

<style>
  .split {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: var(--space-6);
    align-items: start;
  }

  .meter {
    height: 8px;
    border-radius: var(--radius-pill);
    background: var(--surface-sunken);
    overflow: hidden;
  }

  .meter__fill {
    height: 100%;
    border-radius: inherit;
    transition: width var(--duration-slow) var(--ease-out);
    background: var(--fg-faint);
  }

  .meter__fill--success {
    background: var(--success);
  }

  .meter__fill--warning {
    background: var(--warning);
  }

  .meter__fill--danger {
    background: var(--danger);
  }

  .reasons__heading {
    color: var(--fg-muted);
    font-size: var(--text-sm);
    font-weight: var(--weight-medium);
  }

  .reasons {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
    font-size: var(--text-base);
  }

  .reasons li {
    display: flex;
    align-items: flex-start;
    gap: var(--space-3);
    color: var(--fg-secondary);
    line-height: var(--leading-normal);
  }

  .reasons :global(svg) {
    margin-top: 3px;
    color: var(--warning);
  }

  .chips {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-3);
  }

  .loading {
    display: grid;
    place-items: center;
    padding: var(--space-10);
  }
</style>
