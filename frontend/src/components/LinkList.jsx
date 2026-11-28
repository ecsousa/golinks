import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';

function encodeLinkPath(key) {
  return key.split('/').map(encodeURIComponent).join('/');
}

export default function LinkList({ links, tags = [] }) {
  const navigate = useNavigate();
  const [query, setQuery] = useState('');
  const [selectedTags, setSelectedTags] = useState([]);
  const [uncategorizedSelected, setUncategorizedSelected] = useState(false);
  const [promptLink, setPromptLink] = useState(null); // { key, target } | null
  const [paramValue, setParamValue] = useState('');

  const showUncategorized = useMemo(() => {
    let hasTagged = false;
    let hasUntagged = false;
    for (const entry of Object.values(links)) {
      if (Array.isArray(entry?.tags) && entry.tags.length > 0) {
        hasTagged = true;
      } else {
        hasUntagged = true;
      }
      if (hasTagged && hasUntagged) {
        return true;
      }
    }
    return false;
  }, [links]);

  useEffect(() => {
    setSelectedTags((prev) => {
      const next = prev.filter((tag) => tags.includes(tag));
      return next.length === prev.length ? prev : next;
    });
  }, [tags]);

  useEffect(() => {
    if (!showUncategorized && uncategorizedSelected) {
      setUncategorizedSelected(false);
    }
  }, [showUncategorized, uncategorizedSelected]);

  function toggleTag(tag) {
    setSelectedTags((prev) =>
      prev.includes(tag) ? prev.filter((t) => t !== tag) : [...prev, tag]
    );
  }

  const entries = useMemo(() => {
    const sorted = Object.entries(links).sort(([a], [b]) => a.localeCompare(b));
    const q = query.trim().toLowerCase();
    const hasTagFilter = selectedTags.length > 0 || uncategorizedSelected;
    return sorted.filter(([key, entry]) => {
      const target = entry?.target || '';
      const linkTags = Array.isArray(entry?.tags) ? entry.tags : [];
      if (q && !key.toLowerCase().includes(q) && !target.toLowerCase().includes(q)) {
        return false;
      }
      if (hasTagFilter) {
        const matchesTag = linkTags.some((t) => selectedTags.includes(t));
        const matchesUncategorized = uncategorizedSelected && linkTags.length === 0;
        if (!matchesTag && !matchesUncategorized) {
          return false;
        }
      }
      return true;
    });
  }, [links, query, selectedTags, uncategorizedSelected]);

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
    const base = `/${encodeLinkPath(promptLink.key)}`;
    const url = paramValue
      ? `${base}%20${encodeURIComponent(paramValue)}`
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

      {(tags.length > 0 || showUncategorized) && (
        <div className="tag-filter-bar" role="group" aria-label="Filter by tags">
          {tags.map((tag) => {
            const active = selectedTags.includes(tag);
            return (
              <button
                key={tag}
                type="button"
                className={active ? 'tag-pill active' : 'tag-pill'}
                aria-pressed={active}
                onClick={() => toggleTag(tag)}
              >
                {tag}
              </button>
            );
          })}
          {showUncategorized && (
            <button
              type="button"
              className={
                uncategorizedSelected
                  ? 'tag-pill tag-pill-pseudo active'
                  : 'tag-pill tag-pill-pseudo'
              }
              aria-pressed={uncategorizedSelected}
              onClick={() => setUncategorizedSelected((prev) => !prev)}
            >
              uncategorized
            </button>
          )}
        </div>
      )}

      {entries.length === 0 ? (
        <div className="empty-state card">
          {Object.keys(links).length === 0 ? (
            <p className="muted">No links yet. Click &ldquo;New&rdquo; to create your first link.</p>
          ) : (
            <p className="muted">
              No links match the current filter
              {query.trim() ? ` (“${query.trim()}”)` : ''}.
            </p>
          )}
        </div>
      ) : (
        <ul className="link-list">
          {entries.map(([key, entry]) => {
            const target = entry?.target || '';
            const linkTags = Array.isArray(entry?.tags) ? entry.tags : [];
            return (
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
                  <div className="link-key-row">
                    <span className="link-key">{key}</span>
                    {linkTags.length > 0 && (
                      <span className="link-tags">
                        {linkTags.map((tag) => (
                          <span key={tag} className="tag-badge">
                            {tag}
                          </span>
                        ))}
                      </span>
                    )}
                  </div>
                  <span className="link-target">{target}</span>
                </div>
                <a
                  className="link-open"
                  href={`/${encodeLinkPath(key)}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  onClick={(e) => handleOpenClick(e, key, target)}
                  title={`Open /${key}`}
                >
                  Open ↗
                </a>
              </li>
            );
          })}
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
