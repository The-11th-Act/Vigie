import { Search } from 'lucide-react';

// Text search with its magnifier, as the lists draw it. The width belongs to
// the caller (`style` on the wrapper): a toolbar search grows, an inline one
// does not.
export default function SearchInput({ value, onChange, placeholder, label, style }) {
  return (
    <div className="search-field" style={style}>
      <Search size={16} className="search-field-icon" aria-hidden="true" />
      <input
        type="search"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        aria-label={label || placeholder}
      />
    </div>
  );
}
