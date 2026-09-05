<script lang="ts">
  // The pipeline steps, driven entirely by what the engine reported.
  //
  // The data was already arriving — `ExportProgressEvent.step` and `step_finished` — and
  // the old UI discarded both, so a multi-minute export showed only a scrolling log. A
  // step is never marked done because time passed; only because the engine said so.
  //
  // `total` comes from the events too. The names below are the eight steps this build
  // knows; a step beyond them still gets a slot and a number, because the honest failure
  // mode for an unrecognised pipeline is "unnamed step", not "step that does not exist".
  import { t } from "$lib/i18n/index.svelte";
  import { PIPELINE_STEP_KEYS, stepState } from "$lib/util/pipeline";

  interface Props {
    done: number;
    current: number | null;
    total: number;
    /** A finished run keeps its final state visible instead of animating a step that is
     * no longer running. */
    running: boolean;
  }

  const { done, current, total, running }: Props = $props();

  const ordinals = $derived(Array.from({ length: Math.max(total, 1) }, (_, index) => index + 1));

  const percent = $derived(Math.round((done / Math.max(total, 1)) * 100));

  function label(ordinal: number): string {
    const key = PIPELINE_STEP_KEYS[ordinal - 1];
    return key ? t(key) : t("pipeline.step.generic", { n: ordinal });
  }
</script>

<div class="steps" aria-label={t("export.progress", { current: done, total })}>
  <div
    class="track"
    role="progressbar"
    aria-valuemin={0}
    aria-valuemax={100}
    aria-valuenow={percent}
  >
    <div class="track__fill" style:width="{percent}%"></div>
  </div>

  <ol class="list">
    {#each ordinals as ordinal (ordinal)}
      {@const state = stepState(ordinal, done, running ? current : null)}
      <li class="step step--{state}">
        <span class="step__marker">
          {#if state === "done"}
            <svg viewBox="0 0 24 24" width="11" height="11" aria-hidden="true">
              <path
                d="M5 12.5l4.5 4.5L19 7"
                fill="none"
                stroke="currentColor"
                stroke-width="3"
                stroke-linecap="round"
                stroke-linejoin="round"
              />
            </svg>
          {:else if state === "running"}
            <span class="pulse"></span>
          {:else}
            {ordinal}
          {/if}
        </span>
        <span class="step__label" title={label(ordinal)}>{label(ordinal)}</span>
      </li>
    {/each}
  </ol>
</div>

<style>
  .steps {
    display: flex;
    flex-direction: column;
    gap: var(--space-5);
  }

  .track {
    height: 4px;
    border-radius: var(--radius-pill);
    background: var(--surface-sunken);
    overflow: hidden;
  }

  .track__fill {
    height: 100%;
    border-radius: inherit;
    background: var(--accent);
    transition: width var(--duration-slow) var(--ease-out);
  }

  .list {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(96px, 1fr));
    gap: var(--space-3);
  }

  .step {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    min-width: 0;
    color: var(--fg-faint);
    font-size: var(--text-xs);
  }

  .step__marker {
    display: grid;
    place-items: center;
    width: 20px;
    height: 20px;
    flex: none;
    border: 1px solid var(--border-strong);
    border-radius: var(--radius-pill);
    font-size: var(--text-2xs);
    font-variant-numeric: tabular-nums;
  }

  .step__label {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .step--done {
    color: var(--fg-secondary);
  }

  .step--done .step__marker {
    border-color: transparent;
    background: var(--success);
    color: #fff;
  }

  .step--running {
    color: var(--accent-fg);
    font-weight: var(--weight-semibold);
  }

  .step--running .step__marker {
    border-color: var(--accent);
    color: var(--accent);
  }

  .pulse {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--accent);
    animation: pulse 1.1s var(--ease-in-out) infinite;
  }

  @keyframes pulse {
    50% {
      opacity: 0.25;
      transform: scale(0.7);
    }
  }
</style>
