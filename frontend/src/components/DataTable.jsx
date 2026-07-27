import { useMemo, useState } from 'react';
import { formatDateTime, formatNumber } from '../lib/format';
import { simplifyDomain } from '../lib/domain-parser';

function compareValues(a, b) {
  if (a === b) return 0;
  if (a == null) return 1;
  if (b == null) return -1;
  if (typeof a === 'number' && typeof b === 'number') return a - b;
  return String(a).localeCompare(String(b));
}

export default function DataTable({ columns, rows, emptyState, initialSortKey, className = '', maxTableHeight }) {
  const [sortKey, setSortKey] = useState(initialSortKey || columns.find((column) => column.sortable)?.key);
  const [direction, setDirection] = useState('desc');

  const sortedRows = useMemo(() => {
    const sortableRows = [...rows];
    if (!sortKey) return sortableRows;

    sortableRows.sort((left, right) => {
      const result = compareValues(left[sortKey], right[sortKey]);
      return direction === 'desc' ? -result : result;
    });

    return sortableRows;
  }, [rows, sortKey, direction]);

  function handleSort(column) {
    if (!column.sortable) return;
    if (sortKey === column.key) {
      setDirection((current) => (current === 'asc' ? 'desc' : 'asc'));
      return;
    }
    setSortKey(column.key);
    setDirection(column.defaultDirection || 'desc');
  }

  if (!rows.length) {
    return emptyState || null;
  }

  return (
    <div className={`overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-soft ${className}`}>
      <div className={maxTableHeight ? "overflow-auto" : ""} style={maxTableHeight ? { maxHeight: maxTableHeight } : {}}>
        <table className="w-full border-collapse text-left text-sm">
          <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500 sticky top-0 z-10">
            <tr>
              {columns.map((column) => (
                <th key={column.key} className={`px-4 py-3 ${column.align === 'right' ? 'text-right' : 'text-left'}`}>
                  <button
                    type="button"
                    onClick={() => handleSort(column)}
                    className={`inline-flex items-center gap-1 ${column.sortable ? 'hover:text-slate-900' : 'cursor-default'}`}
                  >
                    <span>{column.label}</span>
                    {column.sortable && sortKey === column.key ? (
                      <span className="text-[10px] text-slate-400">{direction === 'asc' ? '↑' : '↓'}</span>
                    ) : null}
                  </button>
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 bg-white">
            {sortedRows.map((row) => (
              <tr key={row.id || row.domain} className="transition-colors hover:bg-slate-50/80">
                {columns.map((column) => {
                  const value = column.render ? column.render(row) : row[column.key];
                  return (
                    <td key={column.key} className={`px-4 py-3 align-top text-slate-700 ${column.align === 'right' ? 'text-right' : 'text-left'}`}>
                      {value}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function MonospacedValue({ value }) {
  return <span className="font-mono text-xs text-slate-600">{value}</span>;
}

export function TimestampValue({ value }) {
  return <span className="text-slate-500">{formatDateTime(value)}</span>;
}

export function NumericValue({ value }) {
  return <span className="font-medium text-slate-900">{formatNumber(value)}</span>;
}

export function DomainValue({ value }) {
  if (!value) return null;
  const simplified = simplifyDomain(value);
  
  if (simplified.isSimplified) {
    return (
      <div className="flex flex-col gap-0.5" title={value}>
        <span className="font-medium text-slate-900">{simplified.name}</span>
        <span className="text-[10px] text-slate-400 font-mono truncate max-w-[200px]">{value}</span>
      </div>
    );
  }
  return <span className="text-slate-900">{value}</span>;
}
