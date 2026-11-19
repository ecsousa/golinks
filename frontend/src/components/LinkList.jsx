import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';

export default function LinkList({ links }) {
  const navigate = useNavigate();
  const [query, setQuery] = useState('');
  const [promptLink, setPromptLink] = useState(null); // { key, target } | null
  const [paramValue, setParamValue] = useState('');

  const entries = useMemo(() => {
    const sorted = Object.entries(links).sort(([a], [b]) => a.localeCompare(b));
    const q = query.trim().toLowerCase();
    if (!q) return sorted;
    return sorted.filter(
      ([key, target]) =>
        key.toLowerCase().includes(q) || target.toLowerCase().includes(q)
    );
  }, [links, query]);

  useEffect(() => {
    if (!promptLink) return;
    function onKeyDown(e) {
      if (e.key === 'Escape') {
        setPromptLink(null);
      }
    }
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [promptLink]);

  function handleOpenClick(e, key, target) {
    e.stopPropagation();
    if (target.includes('%s')) {
      e.preventDefault();
      setParamValue('');
      setPromptLink({ key, target });
    }
  }

  function handlePromptSubmit(e) {
    e.preventDefault();
    if (!promptLink) return;
    const base = `/${encodeURIComponent(promptLink.key)}`;
    const url = paramValue
      ? `${base}/${encodeURIComponent(paramValue)}`
      : base;
    window.open(url, '_blank', 'noopener,noreferrer');
    setPromptLink(null);
  }

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
                onClick={(e) => handleOpenClick(e, key, target)}
                title={`Open /${key}`}
              >
                Open ↗
              </a>
            </li>
          ))}
        </ul>
      )}

      {promptLink && (
        <div
          className="modal-backdrop"
          onClick={() => setPromptLink(null)}
          role="dialog"
          aria-modal="true"
          aria-labelledby="param-dialog-title"
        >
          <div className="card modal-card" onClick={(e) => e.stopPropagation()}>
            <h2 id="param-dialog-title">Open &ldquo;{promptLink.key}&rdquo;</h2>
            <p className="muted modal-target">{promptLink.target}</p>
            <form onSubmit={handlePromptSubmit}>
              <div className="field">
                <label htmlFor="param-input">Parameter</label>
                <input
                  id="param-input"
                  type="text"
                  placeholder="Enter value for %s"
                  autoFocus
                  value={paramValue}
                  onChange={(e) => setParamValue(e.target.value)}
                />
              </div>
              <div className="modal-actions">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setPromptLink(null)}
                >
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary">
                  Go
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
