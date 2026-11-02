<script lang="ts">
  import type { SortState } from "../sort";

  let {
    label,
    column,
    sort,
    onToggle,
  }: {
    label: string;
    column: string;
    sort: SortState | null;
    onToggle: (column: string) => void;
  } = $props();
</script>

<th
  class="sortable"
  aria-sort={sort?.key === column
    ? sort.direction === "asc"
      ? "ascending"
      : "descending"
    : "none"}
>
  <button type="button" onclick={() => onToggle(column)}>
    <span>{label}</span>
    {#if sort?.key === column}
      <span class="sort-indicator" aria-hidden="true">
        {sort.direction === "asc" ? "▲" : "▼"}
      </span>
    {/if}
  </button>
</th>
