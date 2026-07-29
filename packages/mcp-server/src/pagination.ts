export const DEFAULT_PAGE_SIZE = 50;
export const MAX_PAGE_SIZE = 200;

export interface PaginationParams {
  cursor?: string | null;
  pageSize?: number;
}

export interface PageResult<T> {
  data: T[];
  next_cursor: string | null;
}

export function clampPageSize(pageSize: number | undefined | null): number {
  return Math.min(Math.max(pageSize ?? DEFAULT_PAGE_SIZE, 1), MAX_PAGE_SIZE);
}

export function decodeCursor(cursor: string): { after: string; tiebreaker: string } | null {
  try {
    const decoded = Buffer.from(cursor, "base64").toString("utf8");
    const match = decoded.match(/^after:([^|]+)\|(.+)$/);
    if (!match) return null;
    return { after: match[1], tiebreaker: match[2] };
  } catch {
    return null;
  }
}

export function decodeBeforeCursor(cursor: string): { before: string; tiebreaker: string } | null {
  try {
    const decoded = Buffer.from(cursor, "base64").toString("utf8");
    const match = decoded.match(/^before:([^|]+)\|(.+)$/);
    if (!match) return null;
    return { before: match[1], tiebreaker: match[2] };
  } catch {
    return null;
  }
}

export function encodeCursor(after: string, tiebreaker: string): string {
  return Buffer.from(`after:${after}|${tiebreaker}`, "utf8").toString("base64");
}

export function encodeBeforeCursor(before: string, tiebreaker: string): string {
  return Buffer.from(`before:${before}|${tiebreaker}`, "utf8").toString("base64");
}

export function buildAfterCursorPredicate(
  cursor: string,
  orderColumn: string,
  tiebreakerColumn: string,
): string | null {
  const decoded = decodeCursor(cursor);
  if (!decoded) return null;
  return `and(${orderColumn}.gt.${decoded.after},${orderColumn}.eq.${decoded.after},${tiebreakerColumn}.gt.${decoded.tiebreaker})`;
}

export function buildBeforeCursorPredicate(
  cursor: string,
  orderColumn: string,
  tiebreakerColumn: string,
): string | null {
  const decoded = decodeBeforeCursor(cursor);
  if (!decoded) return null;
  return `or(${orderColumn}.lt.${decoded.before},and(${orderColumn}.eq.${decoded.before},${tiebreakerColumn}.lt.${decoded.tiebreaker}))`;
}

export async function paginateQuery<T extends Record<string, any>>(
  rows: T[],
  pageSize: number,
  encodeFn: (row: T) => string,
): Promise<PageResult<T>> {
  const hasMore = rows.length > pageSize;
  const page = hasMore ? rows.slice(0, pageSize) : rows;
  const next_cursor = hasMore && page.length > 0 ? encodeFn(page[page.length - 1]) : null;
  return { data: page, next_cursor };
}
