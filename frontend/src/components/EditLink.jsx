import React, { useEffect, useRef, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { deleteLink, saveLink, UnauthorizedError } from '../api.js';

function commitTagText(rawText, currentTags) {
  const words = rawText
    .split(/\s+/)
    .map((w) => w.trim().toLowerCase())
    .filter(Boolean);
  if (words.length === 0) return currentTags;

  const next = [...currentTags];
  for (const word of words) {
    if (!next.includes(word)) {
      next.push(word);
    }
  }
  return next;
}

export default function EditLink({ links, onDataUpdated, onUnauthorized }) {
  const { keyword: rawParam } = useParams();
  const navigate = useNavigate();
  const tagInputRef = useRef(null);

  const routeKeyword = rawParam ? decodeURIComponent(rawParam) : '';
  const isExisting = Boolean(
    routeKeyword && Object.prototype.hasOwnProperty.call(links, routeKeyword)
  );
  const existingEntry = isExisting ? links[routeKeyword] : null;

  const [keyInput, setKeyInput] = useState(routeKeyword);
  const [targetInput, setTargetInput] = useState(existingEntry?.target || '');
  const [tags, setTags] = useState(() =>
    Array.isArray(existingEntry?.tags) ? [...existingEntry.tags] : []
  );
  const [tagInput, setTagInput] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setKeyInput(routeKeyword);
    setTargetInput(existingEntry?.target || '');
    setTags(Array.isArray(existingEntry?.tags) ? [...existingEntry.tags] : []);
    setTagInput('');
    setError('');
  }, [routeKeyword, existingEntry]);

  function handleTagInputChange(e) {
    const val = e.target.value;
    if (/\s/.test(val)) {
      const endsWithSpace = /\s$/.test(val);
      const parts = val.split(/\s+/);
      const toCommit = endsWithSpace ? parts : parts.slice(0, -1);
      const remainder = endsWithSpace ? '' : parts[parts.length - 1];
      setTags((prev) => commitTagText(toCommit.join(' '), prev));
      setTagInput(remainder);
      return;
    }
    setTagInput(val);
  }

  function handleTagKeyDown(e) {
    if (e.key === 'Tab' && tagInput.trim()) {
      e.preventDefault();
      setTags((prev) => commitTagText(tagInput, prev));
      setTagInput('');
    } else if (e.key === 'Backspace' && tagInput === '' && tags.length > 0) {
      setTags((prev) => prev.slice(0, -1));
    }
  }

  function handleTagBlur() {
    if (tagInput.trim()) {
      setTags((prev) => commitTagText(tagInput, prev));
      setTagInput('');
    }
  }

  function handleAddTagClick() {
    if (tagInput.trim()) {
      setTags((prev) => commitTagText(tagInput, prev));
      setTagInput('');
    }
    tagInputRef.current?.focus();
  }

  function handleRemoveTag(tagToRemove) {
    setTags((prev) => prev.filter((t) => t !== tagToRemove));
  }

  async function handleSave(e) {
    e.preventDefault();
    const finalTags = commitTagText(tagInput, tags);
    setTags(finalTags);
    setTagInput('');
    setError('');
    setBusy(true);
    try {
      const updated = await saveLink({
        originalKey: isExisting ? routeKeyword : undefined,
        key: keyInput.trim(),
        target: targetInput.trim(),
        tags: finalTags,
      });
      onDataUpdated(updated);
      navigate('/', { replace: true });
    } catch (err) {
      if (err instanceof UnauthorizedError) {
        onUnauthorized(err.oidcEnabled);
        return;
      }
      setError(err.message || 'Failed to save link.');
      setBusy(false);
    }
  }

  async function handleDelete() {
    if (!isExisting) return;
    setError('');
    setBusy(true);
    try {
      const updated = await deleteLink(routeKeyword);
      onDataUpdated(updated);
      navigate('/', { replace: true });
    } catch (err) {
      if (err instanceof UnauthorizedError) {
        onUnauthorized(err.oidcEnabled);
        return;
      }
      setError(err.message || 'Failed to delete link.');
      setBusy(false);
    }
  }

  return (
    <div className="page-shell">
      <div className="card edit-card">
        <h1>{isExisting ? `Edit "${routeKeyword}"` : 'New Link'}</h1>
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        <form onSubmit={handleSave}>
          <div className="field">
            <label htmlFor="link-keyword">Link Keyword</label>
            <input
              id="link-keyword"
              type="text"
              placeholder="e.g. google"
              required
              autoFocus={!routeKeyword}
              value={keyInput}
              onChange={(e) => setKeyInput(e.target.value)}
              disabled={busy}
            />
          </div>

          <div className="field">
            <label htmlFor="link-target">Link Target</label>
            <input
              id="link-target"
              type="url"
              placeholder="https://www.google.com/search?q=%s"
              required
              autoFocus={Boolean(routeKeyword)}
              value={targetInput}
              onChange={(e) => setTargetInput(e.target.value)}
              disabled={busy}
            />
            <span className="hint">
              Include <code>%s</code> to substitute URL-encoded query parameters.
            </span>
          </div>

          <div className="field">
            <label htmlFor="link-tags">Tags</label>
            <div className="tag-input-row">
              <div
                className="tag-input-box"
                onClick={() => tagInputRef.current?.focus()}
              >
                {tags.map((tag) => (
                  <span key={tag} className="tag-chip">
                    {tag}
                    <button
                      type="button"
                      className="tag-chip-remove"
                      onClick={(e) => {
                        e.stopPropagation();
                        handleRemoveTag(tag);
                      }}
                      disabled={busy}
                      aria-label={`Remove tag ${tag}`}
                    >
                      &times;
                    </button>
                  </span>
                ))}
                <input
                  id="link-tags"
                  ref={tagInputRef}
                  type="text"
                  className="tag-input-field"
                  placeholder={tags.length === 0 ? 'e.g. work docs' : ''}
                  value={tagInput}
                  onChange={handleTagInputChange}
                  onKeyDown={handleTagKeyDown}
                  onBlur={handleTagBlur}
                  disabled={busy}
                />
              </div>
              <button
                type="button"
                className="btn btn-secondary"
                onMouseDown={(e) => e.preventDefault()}
                onClick={handleAddTagClick}
                disabled={busy || !tagInput.trim()}
              >
                Add
              </button>
            </div>
            <span className="hint">
              Separate tags with spaces, press Tab, leave the box, or click Add.
            </span>
          </div>

          <div className="actions">
            <div className="actions-left">
              <button
                type="submit"
                className="btn btn-primary"
                onMouseDown={(e) => e.preventDefault()}
                disabled={busy}
              >
                {busy ? 'Saving…' : 'Save'}
              </button>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => navigate('/')}
                disabled={busy}
              >
                Cancel
              </button>
            </div>
            {isExisting && (
              <button
                type="button"
                className="btn btn-danger"
                onClick={handleDelete}
                disabled={busy}
              >
                Delete
              </button>
            )}
          </div>
        </form>
      </div>
    </div>
  );
}
