<script lang="ts">
  // One number with its name. Used in rows of three to five: the counts a user checks at
  // a glance before deciding whether to hand a bundle over.
  import Icon, { type IconName } from "./Icon.svelte";

  type Tone = "neutral" | "accent" | "success" | "warning" | "danger";

  interface Props {
    label: string;
    value: string | number;
    hint?: string;
    icon?: IconName;
    tone?: Tone;
  }

  const { label, value, hint, icon, tone = "neutral" }: Props = $props();
</script>

<div class="stat stat--{tone}">
  <div class="stat__head">
    {#if icon}<span class="stat__icon"><Icon name={icon} size={14} /></span>{/if}
    <!-- The label ellipsises when the column is narrow, and a Russian label is often
         the one that does; the tooltip is the only way to read it then. -->
    <span class="stat__label" title={label}>{label}</span>
  </div>
  <div class="stat__value num">{value}</div>
  {#if hint}<div class="stat__hint">{hint}</div>{/if}
</div>

<style>
  .stat {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
    padding: var(--space-5) var(--space-6);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--surface);
    min-width: 0;
  }

  .stat__head {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    color: var(--fg-muted);
  }

  .stat__label {
    font-size: var(--text-sm);
    font-weight: var(--weight-medium);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .stat__value {
    font-family: var(--font-display);
    font-size: var(--text-2xl);
    font-weight: var(--weight-semibold);
    line-height: var(--leading-tight);
  }

  .stat__hint {
    color: var(--fg-muted);
    font-size: var(--text-xs);
  }

  .stat--accent {
    border-color: var(--accent-soft-border);
    background: var(--accent-soft);
  }

  .stat--accent .stat__value,
  .stat--accent .stat__head {
    color: var(--accent-fg);
  }

  .stat--success {
    border-color: var(--success-soft-border);
    background: var(--success-soft);
  }

  .stat--success .stat__value,
  .stat--success .stat__head {
    color: var(--success);
  }

  .stat--warning {
    border-color: var(--warning-soft-border);
    background: var(--warning-soft);
  }

  .stat--warning .stat__value,
  .stat--warning .stat__head {
    color: var(--warning);
  }

  .stat--danger {
    border-color: var(--danger-soft-border);
    background: var(--danger-soft);
  }

  .stat--danger .stat__value,
  .stat--danger .stat__head {
    color: var(--danger);
  }
</style>
