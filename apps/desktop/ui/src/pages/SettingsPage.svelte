<script lang="ts">
  // Everything that shapes an export, grouped by the question it answers.
  //
  // The previous version was one flat column of twelve controls, so "which of these
  // decides what leaves my machine" had no answer on screen. Grouping plus a sentence per
  // control is the whole change in substance; the rest is presentation.
  import {
    applyPreset,
    applyProfile,
    saveGlobalSettings,
    setUiZoom,
    startWatch,
    stopWatch,
  } from "$lib/api/client";
  import type { AppInfo } from "$lib/api/types";
  import Field from "$lib/components/Field.svelte";
  import Icon from "$lib/components/Icon.svelte";
  import Segmented, { type SegmentOption } from "$lib/components/Segmented.svelte";
  import { archiveFormatOptions } from "$lib/util/archiveFormats";
  import Switch from "$lib/components/Switch.svelte";
  import { setLanguage, t } from "$lib/i18n/index.svelte";
  import { pushToast, reportError } from "$lib/stores/toasts.svelte";
  import { setThemePreference, type ThemePreference } from "$lib/theme/index.svelte";
  import { goTo, wizard } from "$lib/stores/wizard.svelte";

  interface Props {
    appInfo: AppInfo;
  }
  const { appInfo }: Props = $props();

  let selectedPreset = $state("");
  let saving = $state(false);

  const diffModes: SegmentOption<string>[] = $derived([
    { value: "all", label: t("settings.diffMode.all"), hint: t("settings.diffMode.hint.all") },
    {
      value: "last_export",
      label: t("settings.diffMode.lastExport"),
      hint: t("settings.diffMode.hint.lastExport"),
    },
    {
      value: "git_ref",
      label: t("settings.diffMode.gitRef"),
      hint: t("settings.diffMode.hint.gitRef"),
    },
    {
      value: "uncommitted",
      label: t("settings.diffMode.uncommitted"),
      hint: t("settings.diffMode.hint.uncommitted"),
    },
  ]);

  const archiveFormats = $derived(archiveFormatOptions());

  const themeModes: SegmentOption<ThemePreference>[] = $derived([
    { value: "light", label: t("settings.theme.light") },
    { value: "dark", label: t("settings.theme.dark") },
    { value: "system", label: t("settings.theme.system") },
  ]);

  const languages: SegmentOption<"en" | "ru">[] = [
    { value: "en", label: "English" },
    { value: "ru", label: "Русский" },
  ];

  // Both handlers take the element so they can put it back on failure. A `<select>` whose
  // bound value did not change gives Svelte no reason to re-render, so a rejected apply
  // would otherwise leave the list showing an option the session config does not hold —
  // the screen claiming a profile the export will not use.
  async function onPresetChange(select: HTMLSelectElement): Promise<void> {
    const previous = selectedPreset;
    const name = select.value;
    selectedPreset = name;
    if (!wizard.sessionConfig || !name) return;
    try {
      wizard.sessionConfig = await applyPreset($state.snapshot(wizard.sessionConfig), name);
    } catch (error) {
      selectedPreset = previous;
      select.value = previous;
      reportError("settings.applyFailed", error);
    }
  }

  async function onProfileChange(select: HTMLSelectElement): Promise<void> {
    if (!wizard.sessionConfig || !select.value) return;
    const previous = wizard.sessionConfig.export_profile;
    try {
      wizard.sessionConfig = await applyProfile(
        $state.snapshot(wizard.sessionConfig),
        select.value,
      );
    } catch (error) {
      select.value = previous;
      reportError("settings.applyFailed", error);
    }
  }

  async function saveAsDefaults(): Promise<void> {
    if (!wizard.sessionConfig) return;
    saving = true;
    try {
      await saveGlobalSettings($state.snapshot(wizard.sessionConfig));
      pushToast("success", "settings.saved");
    } catch (error) {
      reportError("settings.saveFailed", error);
    } finally {
      saving = false;
    }
  }

  function onZoom(factor: number): void {
    if (!wizard.sessionConfig) return;
    wizard.sessionConfig.ui_zoom = factor;
    // Applied live rather than on save: a scale you cannot see until you restart is a
    // setting you cannot choose. The slider used to change nothing at all.
    void setUiZoom(factor).catch((error: unknown) => reportError("settings.applyFailed", error));
  }

  /** Watch mode is a running background task, not a stored flag — the previous UI wrote
   * the flag and never started anything, so the switch was decorative. */
  async function onWatch(enabled: boolean): Promise<void> {
    if (!wizard.sessionConfig || !wizard.project) return;
    wizard.sessionConfig.watch_enabled = enabled;
    try {
      if (enabled) {
        await startWatch(wizard.project.root, $state.snapshot(wizard.sessionConfig));
        wizard.watchActive = true;
      } else {
        await stopWatch();
        wizard.watchActive = false;
        wizard.watchChangedPaths = [];
      }
    } catch (error) {
      wizard.sessionConfig.watch_enabled = false;
      wizard.watchActive = false;
      reportError("watch.failed", error);
    }
  }
</script>

{#if wizard.sessionConfig}
  {@const config = wizard.sessionConfig}
  <div class="stack">
    <div class="page-header">
      <div>
        <h1 class="page-title">{t("settings.title")}</h1>
        <p class="page-lede">{t("settings.lede")}</p>
      </div>
      <button class="btn btn--primary" onclick={() => goTo("security")}>
        {t("settings.continue")}
        <Icon name="chevron" size={14} />
      </button>
    </div>

    <section class="card">
      <div class="card__header">
        <h2 class="card__title">{t("settings.group.export")}</h2>
      </div>
      <div class="card__body stack">
        <div class="pair">
          <Field label={t("settings.profile")} hint={t("settings.profile.hint")}>
            <select
              class="select"
              value={config.export_profile}
              onchange={(event) => onProfileChange(event.currentTarget)}
            >
              {#each appInfo.profiles as profile (profile.key)}
                <option value={profile.key}>{profile.label}</option>
              {/each}
            </select>
          </Field>

          <Field label={t("settings.preset")} hint={t("settings.preset.hint")}>
            <select
              class="select"
              value={selectedPreset}
              onchange={(event) => onPresetChange(event.currentTarget)}
            >
              <option value="">{t("settings.preset.none")}</option>
              {#each appInfo.presets as preset (preset.name)}
                <option value={preset.name}>{preset.name} — {preset.description}</option>
              {/each}
            </select>
          </Field>
        </div>

        <Segmented
          label={t("settings.diffMode")}
          options={diffModes}
          value={config.diff_export_mode}
          onselect={(value) => (config.diff_export_mode = value)}
        />

        <Segmented
          label={t("archive.format")}
          options={archiveFormats}
          value={config.archive_format}
          onselect={(value) => (config.archive_format = value)}
        />

        {#if config.diff_export_mode === "git_ref"}
          <div class="pair">
            <Field label={t("settings.diffBaseRef")} hint={t("settings.diffRef.hint")}>
              <input class="input input--mono" bind:value={config.diff_base_ref} />
            </Field>
            <Field label={t("settings.diffTargetRef")} hint={t("settings.diffRef.hint")}>
              <input class="input input--mono" bind:value={config.diff_target_ref} />
            </Field>
          </div>
        {/if}
      </div>
    </section>

    <section class="card">
      <div class="card__header">
        <h2 class="card__title">{t("settings.group.content")}</h2>
      </div>
      <div class="card__body stack">
        <Switch
          label={t("settings.redactSecrets")}
          hint={t("settings.redactSecrets.hint")}
          checked={config.redact_secrets}
          onchange={(checked) => (config.redact_secrets = checked)}
        />
        <Switch
          label={t("settings.redactionLabels")}
          hint={t("settings.redactionLabels.hint")}
          checked={config.redaction_labels}
          onchange={(checked) => (config.redaction_labels = checked)}
        />
        <Switch
          label={t("settings.strictChecksums")}
          hint={t("settings.strictChecksums.hint")}
          checked={config.strict_token_checksums}
          onchange={(checked) => (config.strict_token_checksums = checked)}
        />
        <Switch
          label={t("settings.includeGitPatch")}
          hint={t("settings.includeGitPatch.hint")}
          checked={config.include_git_patch}
          onchange={(checked) => (config.include_git_patch = checked)}
        />
        <Switch
          label={t("settings.keepStaging")}
          hint={t("settings.keepStaging.hint")}
          checked={config.keep_staging_folder}
          onchange={(checked) => (config.keep_staging_folder = checked)}
        />

        <div class="pair">
          <Field label={t("settings.tokenBudget")} hint={t("settings.tokenBudget.hint")}>
            <div class="budget">
              <input
                class="input"
                type="number"
                min="0"
                step="1000"
                bind:value={config.token_budget}
              />
              {#if config.token_budget === 0}
                <span class="badge badge--muted">{t("settings.tokenBudget.unlimited")}</span>
              {/if}
            </div>
          </Field>
        </div>

        <Field label={t("settings.developerContext")} hint={t("settings.developerContext.hint")}>
          <textarea class="textarea" rows="3" bind:value={config.developer_context}></textarea>
        </Field>
      </div>
    </section>

    <section class="card">
      <div class="card__header">
        <h2 class="card__title">{t("settings.group.workflow")}</h2>
      </div>
      <div class="card__body stack">
        <Switch
          label={t("settings.watch")}
          hint={t("settings.watch.hint")}
          checked={config.watch_enabled}
          disabled={!wizard.project}
          onchange={(checked) => void onWatch(checked)}
        />
        <Switch
          label={t("settings.watchClipboard")}
          hint={t("settings.watchClipboard.hint")}
          checked={config.watch_clipboard_auto_update}
          disabled={!config.watch_enabled}
          onchange={(checked) => (config.watch_clipboard_auto_update = checked)}
        />
      </div>
    </section>

    <section class="card">
      <div class="card__header">
        <h2 class="card__title">{t("settings.group.application")}</h2>
      </div>
      <div class="card__body stack">
        <div class="pair">
          <Segmented
            label={t("settings.theme")}
            options={themeModes}
            value={config.theme}
            onselect={(value) => {
              config.theme = value;
              setThemePreference(value);
            }}
          />
          <Segmented
            label={t("settings.language")}
            options={languages}
            value={config.language}
            onselect={(value) => {
              config.language = value;
              setLanguage(value);
            }}
          />
        </div>

        <Field label={t("settings.uiZoom")} hint={t("settings.uiZoom.hint")}>
          <div class="zoom">
            <input
              type="range"
              min="0.75"
              max="2"
              step="0.05"
              value={config.ui_zoom}
              oninput={(event) => onZoom(Number(event.currentTarget.value))}
            />
            <span class="zoom__value num">{Math.round(config.ui_zoom * 100)}%</span>
            <button class="btn btn--sm" onclick={() => onZoom(1)} disabled={config.ui_zoom === 1}>
              {t("settings.uiZoom.reset")}
            </button>
          </div>
        </Field>
      </div>
      <div class="card__header footer">
        <span class="text-muted text-sm">{t("settings.save.hint")}</span>
        <button class="btn" onclick={saveAsDefaults} disabled={saving}>
          {#if saving}<span class="spinner"></span>{/if}
          {t("settings.save")}
        </button>
      </div>
    </section>
  </div>
{/if}

<style>
  .pair {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: var(--space-6);
    align-items: start;
  }

  .budget {
    display: flex;
    align-items: center;
    gap: var(--space-4);
  }

  .budget input {
    max-width: 180px;
  }

  .zoom {
    display: flex;
    align-items: center;
    gap: var(--space-5);
    flex-wrap: wrap;
  }

  .zoom input[type="range"] {
    flex: 1;
    min-width: 180px;
    max-width: 320px;
    accent-color: var(--accent);
  }

  .zoom__value {
    min-width: 4ch;
    color: var(--fg-secondary);
    font-size: var(--text-sm);
  }

  .footer {
    border-top: 1px solid var(--border);
    border-bottom: 0;
  }
</style>
