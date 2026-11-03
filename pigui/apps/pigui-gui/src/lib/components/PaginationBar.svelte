<script lang="ts">
  let {
    total,
    dbTotal,
    offset,
    loaded,
    filtering,
    loading,
    onPrev,
    onNext,
  }: {
    total: number;
    dbTotal: number;
    offset: number;
    loaded: number;
    filtering: boolean;
    loading: boolean;
    onPrev: () => void;
    onNext: () => void;
  } = $props();

  const displayTotal = $derived(filtering ? total : dbTotal);
  const start = $derived(displayTotal === 0 ? 0 : offset + 1);
  const end = $derived(Math.min(offset + loaded, displayTotal));
  const canPrev = $derived(offset > 0 && !loading);
  const canNext = $derived(offset + loaded < displayTotal && !loading);
  const summary = $derived.by(() => {
    if (dbTotal === 0) {
      return "No rows in database";
    }
    if (total === 0) {
      return `No matching rows · ${dbTotal} total in database`;
    }
    if (filtering) {
      return `Showing ${start}–${end} of ${total} matching · ${dbTotal} total in database`;
    }
    return `Showing ${start}–${end} of ${dbTotal} in database`;
  });
</script>

<div class="pagination">
  <span class="pagination-summary">{summary}</span>
  <div class="pagination-actions">
    <button type="button" onclick={onPrev} disabled={!canPrev}>Prev</button>
    <button type="button" onclick={onNext} disabled={!canNext}>Next</button>
  </div>
</div>
