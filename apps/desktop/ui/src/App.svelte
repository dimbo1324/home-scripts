<script lang="ts">
  import { onMount } from "svelte";

  import {
    getAppInfo,
    loadGlobalSettings,
    onExportFinished,
    onExportProgress,
    onWatchChanged,
    onWindowDragDrop,
    setUiZoom,
  } from "$lib/api/client";
  import type { AppInfo } from "$lib/api/types";
  import { openProjectAt } from "$lib/actions/project.svelte";
  import Icon from "$lib/components/Icon.svelte";
  import Sidebar from "$lib/components/Sidebar.svelte";
  import StatusBar from "$lib/components/StatusBar.svelte";
  import Toasts from "$lib/components/Toasts.svelte";
  import TopBar from "$lib/components/TopBar.svelte";
  import { setLanguage, t } from "$lib/i18n/index.svelte";
  import { errorMessage, pushToast } from "$lib/stores/toasts.svelte";
  import { initTheme } from "$lib/theme/index.svelte";
  import { receiveExportEvent, wizard } from "$lib/stores/wizard.svelte";
  import { copyText } from "$lib/util/clipboard";
  import { formatWatchSummary } from "$lib/util/watchSummary";

  import AnalyticsPage from "./pages/AnalyticsPage.svelte";
  import ExportPage from "./pages/ExportPage.svelte";
  import HistoryPage from "./pages/HistoryPage.svelte";
  import PreviewPage from "./pages/PreviewPage.svelte";
  import ProjectPage from "./pages/ProjectPage.svelte";
  import ResultPage from "./pages/ResultPage.svelte";
  import SecurityPage from "./pages/SecurityPage.svelte";
  import SettingsPage from "./pages/SettingsPage.svelte";
  import SterileCopyPage from "./pages/SterileCopyPage.svelte";

  let appInfo = $state<AppInfo | null>(null);
  let startupError = $state<string | null>(null);
  let dragging = $state(false);

  onMount(() => {
    const unlisteners: (() => void)[] = [];

    (async () => {
      try {
        const [info, settings] = await Promise.all([getAppInfo(), loadGlobalSettings()]);
        appInfo = info;
        setLanguage(settings.language);
        initTheme(settings.theme);
        // The stored zoom was never applied at startup, so a user who set 150% got 100%
        // back on every launch. Failing here must not stop the app from opening.
        void setUiZoom(settings.ui_zoom).catch(() => undefined);
      } catch (error) {
        // `errorMessage`, not `String(error)`: every command rejects with
        // `CommandError { message }`, which stringifies to "[object Object]".
        startupError = errorMessage(error);
      }

      // Registered once, at the root, so progress keeps accumulating in the Export
      // page's buffer even if the user is looking at a different step while an
      // export they started runs in the background.
      unlisteners.push(await onExportProgress(receiveExportEvent));
      unlisteners.push(
        await onExportFinished((event) => {
          if (event.run_id !== wizard.exportRunId) return;
          wizard.exportRunning = false;
          wizard.exportCancelling = false;
          wizard.exportFinishedAt = Date.now();
          wizard.exportResult = event.report;
          wizard.exportError = event.error;
          if (event.error) {
            pushToast("danger", "export.failed", { detail: event.error });
          } else if (event.report) {
            wizard.exportStepCurrent = null;
            pushToast(
              event.report.successful ? "success" : "warning",
              event.report.cancelled ? "export.cancelled" : "export.finished",
            );
            wizard.step = "result";
          }
        }),
      );
      unlisteners.push(
        await onWatchChanged((event) => {
          wizard.watchChangedPaths = event.changed_paths;
          if (event.changed_paths.length === 0) {
            return;
          }
          pushToast("info", "watch.changed", { params: { count: event.changed_paths.length } });

          // Finding 4, 2026-07-27 audit: this setting was shown to the user and read by
          // nothing. The backend deliberately leaves the decision here (see
          // `commands/watch.rs`), so this is where it belongs.
          if (wizard.sessionConfig?.watch_clipboard_auto_update === true) {
            const summary = formatWatchSummary(event.changed_paths, wizard.project?.root ?? null);
            // Failure is reported rather than swallowed: the user asked for the
            // clipboard to be updated, so silently not updating it would be the same
            // class of defect this change exists to fix.
            void copyText(summary).then((copied) => {
              pushToast(
                copied ? "success" : "warning",
                copied ? "watch.copied" : "watch.copyFailed",
              );
            });
          }
        }),
      );
      unlisteners.push(
        await onWindowDragDrop((phase, paths) => {
          // The Sterile-copy page owns drag-and-drop for its own source field while
          // it is the active view (see `SterileCopyPage.svelte`); this handler stays
          // silent there so a drop is not acted on twice.
          if (wizard.step === "sterile") return;
          if (phase === "enter") {
            dragging = true;
          } else if (phase === "leave") {
            dragging = false;
          } else {
            dragging = false;
            const dropped = paths[0];
            // Only the first path is used: `open_project` takes one root, and silently
            // picking one of several would be a guess the user never made.
            if (dropped) void openProjectAt(dropped);
          }
        }),
      );
    })();

    return () => {
      for (const unlisten of unlisteners) unlisten();
    };
  });
</script>

{#if startupError}
  <div class="fatal">
    <div class="callout callout--danger" role="alert">
      <span class="callout__icon"><Icon name="alert" size={16} /></span>
      <div class="callout__body">
        <p class="callout__title">{t("shell.startupFailed")}</p>
        <p class="selectable">{startupError}</p>
      </div>
    </div>
  </div>
{:else if !appInfo}
  <div class="booting"><span class="spinner"></span></div>
{:else}
  <div class="shell">
    <Sidebar />
    <div class="shell__main">
      <TopBar />
      <main class="shell__content">
        <div class="shell__page">
          {#if wizard.step === "project"}
            <ProjectPage {appInfo} />
          {:else if wizard.step === "settings"}
            <SettingsPage {appInfo} />
          {:else if wizard.step === "security"}
            <SecurityPage />
          {:else if wizard.step === "preview"}
            <PreviewPage />
          {:else if wizard.step === "export"}
            <ExportPage />
          {:else if wizard.step === "result"}
            <ResultPage />
          {:else if wizard.step === "history"}
            <HistoryPage {appInfo} />
          {:else if wizard.step === "analytics"}
            <AnalyticsPage />
          {:else if wizard.step === "sterile"}
            <SterileCopyPage />
          {/if}
        </div>
      </main>
      <StatusBar {appInfo} />
    </div>
  </div>

  {#if dragging}
    <div class="dropzone">
      <div class="dropzone__card">
        <Icon name="folder-open" size={32} weight={1.4} />
        <p>{t("project.dropActive")}</p>
      </div>
    </div>
  {/if}
{/if}

<Toasts />

<style>
  .shell {
    display: flex;
    height: 100%;
    overflow: hidden;
  }

  .shell__main {
    display: flex;
    flex-direction: column;
    flex: 1;
    min-width: 0;
  }

  .shell__content {
    flex: 1;
    overflow: auto;
    /* The scrollbar's width is reserved whether or not it is showing, so filtering a
       long list does not shift the page sideways under the pointer. */
    scrollbar-gutter: stable;
    /* A pane that has hit its end stops there rather than passing the scroll to the
       shell behind it. */
    overscroll-behavior: contain;
    padding: var(--space-8) var(--space-8) var(--space-10);
  }

  /* One measure for every page. Long prose and wide tables both become unreadable when
     a maximised window stretches them across 2000 pixels. */
  .shell__page {
    max-width: var(--layout-content-max);
    margin: 0 auto;
    height: 100%;
  }

  .booting,
  .fatal {
    display: grid;
    place-items: center;
    height: 100%;
    padding: var(--space-8);
  }

  .fatal .callout {
    max-width: 620px;
  }

  .dropzone {
    position: fixed;
    inset: 0;
    z-index: var(--z-overlay);
    display: grid;
    place-items: center;
    padding: var(--space-8);
    background: color-mix(in srgb, var(--canvas) 78%, transparent);
    backdrop-filter: blur(2px);
  }

  .dropzone__card {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--space-5);
    padding: var(--space-10) var(--space-11);
    border: 2px dashed var(--accent);
    border-radius: var(--radius-xl);
    background: var(--surface);
    box-shadow: var(--shadow-lg);
    color: var(--accent-fg);
    font-size: var(--text-md);
    font-weight: var(--weight-medium);
  }

  @media (max-width: 720px) {
    .shell {
      flex-direction: column;
    }

    .shell__content {
      padding: var(--space-6) var(--space-5) var(--space-8);
    }
  }
</style>
