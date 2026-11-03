<script lang="ts">
  let {
    total,
    offset,
    loaded,
    pageSize,
    loading,
    onPrev,
    onNext,
    onLoadMore,
  }: {
    total: number;
    offset: number;
    loaded: number;
    pageSize: number;
    loading: boolean;
    onPrev: () => void;
    onNext: () => void;
    onLoadMore: () => void;
  } = $props();

  const start = $derived(total === 0 ? 0 : offset + 1);
  const end = $derived(Math.min(offset + loaded, total));
  const canPrev = $derived(offset > 0 && !loading);
  const canNext = $derived(offset + loaded < total && !loading);
  const canLoadMore = $derived(offset + loaded < total && !loading);
</script>

<div class="pagination">
  <span class="pagination-summary">
    Showing {start}-{end} of {total} · page size {pageSize}
  </span>
  <div class="pagination-actions">
    <button type="button" onclick={onPrev} disabled={!canPrev}>Prev</button>
    <button type="button" onclick={onNext} disabled={!canNext}>Next</button>
    <button type="button" onclick={onLoadMore} disabled={!canLoadMore}>Load more</button>
  </div>
</div>
