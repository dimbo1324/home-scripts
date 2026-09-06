<script lang="ts">
  // Two separate questions on one page: what the safety mode will exclude before copying,
  // and what the scanner still finds in the source.
  //
  // The findings list is grouped by file rather than left flat. A flat list of forty rows
  // is thirty files repeated; grouped, the same data answers "which files are the
  // problem" without counting.
  import { scanProject } from "$lib/api/client";
  import type { Finding } from "$lib/api/types";
  import EmptyState from "$lib/components/EmptyState.svelte";
  import Icon from "$lib/components/Icon.svelte";
  import SearchField from "$lib/components/SearchField.svelte";
  import Segmented, { type SegmentOption } from "$lib/components/Segmented.svelte";
  import Stat from "$lib/components/Stat.svelte";
  import { confidenceLabel, severityLabel } from "$lib/i18n/enums";
  import { t } from "$lib/i18n/index.svelte";
  import { reportError } from "$lib/stores/toasts.svelte";
  import { goTo, wizard } from "$lib/stores/wizard.svelte";

  type Severity = "all" | "critical" | "warning";

  let severity = $state<Severity>("all");
  let query = $state("");

  const safeModes: SegmentOption<string>[] = $derived([
    {
      value: "safe",
      label: t("security.safeMode.safe"),
      hint: t("security.safeMode.hint.safe"),
    },
    {
      value: "balanced",
      label: t("security.safeMode.balanced"),
      hint: t("security.safeMode.hint.balanced"),
    },
    {
      value: "full",
      label: t("security.safeMode.full"),
      hint: t("security.safeMode.hint.full"),
    },
  ]);

  const severityFilters: SegmentOption<Severity>[] = $derived([
    { value: "all", label: t("security.filter.all") },
    { value: "critical", label: t("security.filter.critical") },
    { value: "warning", label: t("security.filter.warning") },
  ]);

  const filtered = $derived.by(() => {
    const findings = wizard.scan?.findings ?? [];
    const needle = query.trim().toLowerCase();
    return findings.filter((finding) => {
      if (severity === "critical" && finding.severity !== "critical") return false;
      if (severity === "warning" && finding.severity === "critical") return false;
      if (!needle) return true;
      return (
        finding.file.toLowerCase().includes(needle) ||
        finding.rule.toLowerCase().includes(needle) ||
        finding.message.toLowerCase().includes(needle)
      );
    });
  });

  /** Grouped in first-seen order, which is the scanner's own order — sorting by count
   * would reorder the list on every rescan and make it impossible to keep your place. */
  const grouped = $derived.by(() => {
    const order: string[] = [];
    const byFile: Record<string, Finding[]> = {};
    for (const finding of filtered) {
      const bucket = byFile[finding.file];
      if (bucket) {
        bucket.push(finding);
      } else {
        byFile[finding.file] = [finding];
        order.push(finding.file);
      }
    }
    return order.map((file) => [file, byFile[file]] as const);
  });

  async function runScan(): Promise<void> {
    if (!wizard.project || !wizard.sessionConfig) return;
    wizard.scanLoading = true;
    try {
      wizard.scan = await scanProject(wizard.project.root, $state.snapshot(wizard.sessionConfig));
    } catch (error) {
      reportError("security.scanFailed", error);
    } finally {
      wizard.scanLoading = false;
    }
  }
</script>

{#if wizard.sessionConfig}
  {@const config = wizard.sessionConfig}
  <div class="stack">
    <div class="page-header">
      <div>
        <h1 class="page-title">{t("security.title")}</h1>
        <p class="page-lede">{t("security.lede")}</p>
      </div>
      <button class="btn btn--primary" onclick={() => goTo("preview")}>
        {t("preview.title")}
        <Icon name="chevron" size={14} />
      </button>
    </div>

    <section class="card">
      <div class="card__body">
        <Segmented
          label={t("security.safeMode")}
          options={safeModes}
          value={config.safe_export_mode}
          onselect={(value) => (config.safe_export_mode = value)}
        />
      </div>
    </section>

    <section class="card card--flush">
      <div class="card__header">
        <div>
          <h2 class="card__title">{t("security.scan")}</h2>
          {#if wizard.scan}
            <p class="card__subtitle">
              {t("security.stat.scanned")}: {wizard.scan.scanned_files}
            </p>
          {/if}
        </div>
        <button
          class="btn"
          class:btn--primary={!wizard.scan}
          onclick={runScan}
          disabled={wizard.scanLoading}
        >
          {#if wizard.scanLoading}
            <span class="spinner"></span>
            {t("security.scanning")}
          {:else}
            <Icon name="shield" size={14} />
            {wizard.scan ? t("security.rescan") : t("security.scan")}
          {/if}
        </button>
      </div>

      {#if !wizard.scan}
        <EmptyState
          icon="shield"
          title={t("security.notScanned")}
          text={t("security.notScannedText")}
        />
      {:else if wizard.scan.findings.length === 0}
        <EmptyState
          icon="check-circle"
          title={t("security.noFindings")}
          text={t("security.noFindingsText")}
        />
      {:else}
        {@const summary = wizard.scan.summary}
        <div class="card__body stack--tight stack">
          <div class="stats" style:--stats-min="150px">
            <Stat label={t("security.stat.total")} value={summary.total_findings} icon="alert" />
            <Stat
              label={t("security.stat.critical")}
              value={summary.critical}
              icon="alert"
              tone={summary.critical > 0 ? "danger" : "neutral"}
            />
            <Stat label={t("security.stat.sensitiveFiles")} value={summary.sensitive_files} />
            <Stat label={t("security.stat.potentialSecrets")} value={summary.potential_secrets} />
            <Stat label={t("security.stat.riskyCode")} value={summary.risky_code} />
          </div>

          <div class="toolbar">
            <SearchField bind:value={query} label={t("security.search")} minWidth="220px" />
            <Segmented
              options={severityFilters}
              value={severity}
              onselect={(value) => (severity = value)}
            />
          </div>
        </div>

        {#if grouped.length === 0}
          <EmptyState icon="search" title={t("security.noMatches")} />
        {:else}
          <ul class="groups">
            {#each grouped as [file, findings] (file)}
              <li class="group">
                <div class="group__head">
                  <Icon name="file" size={14} />
                  <span class="group__file selectable">{file}</span>
                  <span class="badge badge--muted">{findings.length}</span>
                </div>
                <ul>
                  {#each findings as finding (JSON.stringify( [finding.rule, finding.line, finding.message] ))}
                    <li class="finding">
                      <span
                        class="badge badge--{finding.severity === 'critical'
                          ? 'critical'
                          : 'warning'}"
                      >
                        {severityLabel(finding.severity)}
                      </span>
                      <span class="finding__body">
                        <span class="finding__message selectable">{finding.message}</span>
                        <span class="finding__meta">
                          {t(`security.kind.${finding.kind}`)}
                          · <code>{finding.rule}</code>
                          {#if finding.line}· <span class="num">:{finding.line}</span>{/if}
                          · {t("security.confidence", {
                            value: confidenceLabel(finding.confidence),
                          })}
                        </span>
                      </span>
                    </li>
                  {/each}
                </ul>
              </li>
            {/each}
          </ul>
        {/if}
      {/if}
    </section>
  </div>
{/if}

<style>
  .toolbar {
    display: flex;
    align-items: center;
    gap: var(--space-5);
    flex-wrap: wrap;
  }

  .groups {
    border-top: 1px solid var(--border);
    max-height: 58vh;
    overflow: auto;
  }

  .group + .group {
    border-top: 1px solid var(--border);
  }

  .group__head {
    position: sticky;
    top: 0;
    z-index: var(--z-sticky);
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: var(--space-4) var(--space-6);
    background: var(--surface-sunken);
    color: var(--fg-secondary);
  }

  .group__file {
    flex: 1;
    min-width: 0;
    font-family: var(--font-mono);
    font-size: var(--text-sm);
    word-break: break-all;
  }

  .finding {
    display: flex;
    align-items: flex-start;
    gap: var(--space-4);
    padding: var(--space-4) var(--space-6);
  }

  .finding + .finding {
    border-top: 1px solid var(--border);
  }

  .finding__body {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
    min-width: 0;
  }

  .finding__message {
    line-height: var(--leading-normal);
  }

  .finding__meta {
    color: var(--fg-muted);
    font-size: var(--text-xs);
  }
</style>
