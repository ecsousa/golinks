import React, { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';

export default function LinkList({ links }) {
  const navigate = useNavigate();
  const [query, setQuery] = useState('');

  const entries = useMemo(() => {
    const sorted = Object.entries(links).sort(([a], [b]) => a.localeCompare(b));
    const q = query.trim().toLowerCase();
    if (!q) return sorted;
    return sorted.filter(
      ([key, target]) =>
        key.toLowerCase().includes(q) || target.toLowerCase().includes(q)
    );
  }, [links, query]);

  return (
    <div className="page-shell">
      <header className="page-header">
        <div>
          <h1>Golinks</h1>
          <p className="muted">{Object.keys(links).length} links configured</p>
        </div>
        <button
          type="button"
          className="btn btn-primary"
          onClick={() => navigate('/edit')}
        >
          New
        </button>
      </header>

      <div className="search-bar">
        <input
          type="search"
          placeholder="Filter links by keyword or target…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          aria-label="Filter links"
        />
      </div>

      {entries.length === 0 ? (
        <div className="empty-state card">
          {Object.keys(links).length === 0 ? (
            <p className="muted">No links yet. Click &ldquo;New&rdquo; to create your first link.</p>
          ) : (
            <p className="muted">No links match &ldquo;{query}&rdquo;.</p>
          )}
        </div>
      ) : (
        <ul className="link-list">
          {entries.map(([key, target]) => (
            <li
              key={key}
              className="link-item"
              onClick={() => navigate(`/edit/${encodeURIComponent(key)}`)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  navigate(`/edit/${encodeURIComponent(key)}`);
                }
              }}
              role="button"
              tabIndex={0}
            >
              <div className="link-main">
                <span className="link-key">{key}</span>
                <span className="link-target">{target}</span>
              </div>
              <a
                className="link-open"
                href={`/${encodeURIComponent(key)}`}
                target="_blank"
                rel="noopener noreferrer"
                onClick={(e) => e.stopPropagation()}
                title={`Open /${key}`}
              >
                Open ↗
              </a>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
