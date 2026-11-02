export type SortDirection = "asc" | "desc";

export interface SortState {
  key: string;
  direction: SortDirection;
}

export type SortValue = string | number | boolean | null | undefined;

export type SortColumns<T> = Record<string, (item: T) => SortValue>;

const collator = new Intl.Collator(undefined, {
  numeric: true,
  sensitivity: "base",
});

function isEmpty(value: SortValue): boolean {
  return value === null || value === undefined || value === "";
}

export function compareValues(left: SortValue, right: SortValue): number {
  if (typeof left === "number" && typeof right === "number") {
    return left - right;
  }
  if (typeof left === "boolean" && typeof right === "boolean") {
    return Number(left) - Number(right);
  }
  return collator.compare(String(left), String(right));
}

export function toggleSort(
  current: SortState | null,
  key: string,
): SortState | null {
  if (!current || current.key !== key) {
    return { key, direction: "asc" };
  }
  if (current.direction === "asc") {
    return { key, direction: "desc" };
  }
  return null;
}

export function sortBy<T>(
  items: T[],
  sort: SortState | null,
  columns: SortColumns<T>,
): T[] {
  if (!sort) return items;
  const valueFor = columns[sort.key];
  if (!valueFor) return items;

  const direction = sort.direction === "asc" ? 1 : -1;
  return [...items].sort((left, right) => {
    const leftValue = valueFor(left);
    const rightValue = valueFor(right);
    const leftEmpty = isEmpty(leftValue);
    const rightEmpty = isEmpty(rightValue);
    if (leftEmpty && rightEmpty) return 0;
    if (leftEmpty) return 1;
    if (rightEmpty) return -1;
    return direction * compareValues(leftValue, rightValue);
  });
}
