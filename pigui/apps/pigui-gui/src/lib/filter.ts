export function filterItems<T>(
  items: T[],
  needle: string,
  values: (item: T) => unknown[],
): T[] {
  const text = needle.trim().toLowerCase();
  if (!text) return items;
  return items.filter((item) =>
    values(item)
      .filter(Boolean)
      .some((value) => String(value).toLowerCase().includes(text)),
  );
}
