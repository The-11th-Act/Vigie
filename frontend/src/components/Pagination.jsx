import React from 'react';
import { ChevronLeft, ChevronRight } from 'lucide-react';

// Previous / next pager shared by the paginated lists. `page` is zero-based,
// like the `skip = page * PAGE_SIZE` the lists send; a single page needs no
// pager, so nothing renders.
export default function Pagination({ page, totalPages, onPageChange }) {
  if (totalPages <= 1) return null;

  const isFirst = page <= 0;
  const isLast = page >= totalPages - 1;

  return (
    <nav className="pagination" aria-label="Pagination">
      <button
        type="button"
        className="icon-button"
        onClick={() => onPageChange(Math.max(0, page - 1))}
        disabled={isFirst}
        aria-label="Previous page"
      >
        <ChevronLeft size={18} />
      </button>
      <span className="pagination-status">
        Page {page + 1} of {totalPages}
      </span>
      <button
        type="button"
        className="icon-button"
        onClick={() => onPageChange(Math.min(totalPages - 1, page + 1))}
        disabled={isLast}
        aria-label="Next page"
      >
        <ChevronRight size={18} />
      </button>
    </nav>
  );
}
