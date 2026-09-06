<script lang="ts">
  // A search box with its icon and its clear button. Two pages had this markup and its
  // styles character for character, differing only in a min-width and the placeholder
  // (audit No. 36) — so the icon, the padding that makes room for it, and the clear
  // button's placement were three chances to drift apart.
  import { t } from "../i18n/index.svelte";
  import Icon from "./Icon.svelte";

  interface Props {
    /** Bound to the caller's query. */
    value: string;
    /** Placeholder and accessible name — the two are the same text here, because the
     *  field has no visible label of its own. */
    label: string;
    /** How narrow the field may get before the toolbar wraps. */
    minWidth?: string;
  }

  let { value = $bindable(), label, minWidth = "200px" }: Props = $props();
</script>

<div class="search" style:min-width={minWidth}>
  <span class="search__icon"><Icon name="search" size={14} /></span>
  <input class="input" aria-label={label} placeholder={label} bind:value />
  {#if value}
    <button
      class="btn btn--ghost btn--icon btn--sm"
      aria-label={t("common.clear")}
      onclick={() => (value = "")}
    >
      <Icon name="x" size={13} />
    </button>
  {/if}
</div>

<style>
  .search {
    position: relative;
    display: flex;
    align-items: center;
    flex: 1;
  }

  .search__icon {
    position: absolute;
    left: var(--space-4);
    color: var(--fg-faint);
    pointer-events: none;
  }

  /* Room for the icon on the left and the clear button on the right, so neither sits on
     top of the text the user is typing. */
  .search .input {
    padding-left: calc(var(--space-4) * 2 + 14px);
    padding-right: 32px;
  }

  .search button {
    position: absolute;
    right: 3px;
  }
</style>
