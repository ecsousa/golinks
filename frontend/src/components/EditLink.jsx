import React, { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { deleteLink, saveLink, UnauthorizedError } from '../api.js';

export default function EditLink({ links, onLinksUpdated, onUnauthorized }) {
  const { keyword: rawParam } = useParams();
  const navigate = useNavigate();

  const routeKeyword = rawParam ? decodeURIComponent(rawParam) : '';
  const isExisting = Boolean(
    routeKeyword && Object.prototype.hasOwnProperty.call(links, routeKeyword)
  );

  const [keyInput, setKeyInput] = useState(routeKeyword);
  const [targetInput, setTargetInput] = useState(isExisting ? links[routeKeyword] : '');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setKeyInput(routeKeyword);
    setTargetInput(isExisting ? links[routeKeyword] : '');
    setError('');
  }, [routeKeyword, isExisting, links]);

  async function handleSave(e) {
    e.preventDefault();
    setError('');
    setBusy(true);
    try {
      const updated = await saveLink({
        originalKey: isExisting ? routeKeyword : undefined,
        key: keyInput.trim(),
        target: targetInput.trim(),
      });
      onLinksUpdated(updated);
      navigate('/', { replace: true });
    } catch (err) {
      if (err instanceof UnauthorizedError) {
        onUnauthorized();
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
      onLinksUpdated(updated);
      navigate('/', { replace: true });
    } catch (err) {
      if (err instanceof UnauthorizedError) {
        onUnauthorized();
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

          <div className="actions">
            <div className="actions-left">
              <button type="submit" className="btn btn-primary" disabled={busy}>
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
