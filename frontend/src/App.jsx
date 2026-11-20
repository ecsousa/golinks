import React, { useCallback, useEffect, useState } from 'react';
import { HashRouter, Navigate, Route, Routes } from 'react-router-dom';
import { getLinks, UnauthorizedError } from './api.js';
import LoginPage from './components/LoginPage.jsx';
import LinkList from './components/LinkList.jsx';
import EditLink from './components/EditLink.jsx';

function getSafeNextPath() {
  const params = new URLSearchParams(window.location.search);
  const next = params.get('next');
  if (
    next &&
    next.startsWith('/') &&
    !next.startsWith('//') &&
    !next.includes('\\') &&
    !next.includes('\r') &&
    !next.includes('\n') &&
    next !== '/'
  ) {
    return next;
  }
  return null;
}

export default function App() {
  const [status, setStatus] = useState('loading'); // 'loading' | 'unauthenticated' | 'authenticated' | 'error'
  const [links, setLinks] = useState({});
  const [loadError, setLoadError] = useState('');

  const refreshLinks = useCallback(async () => {
    try {
      const data = await getLinks();
      setLinks(data);
      setLoadError('');
      setStatus('authenticated');
    } catch (err) {
      if (err instanceof UnauthorizedError) {
        if (err.oidcEnabled) {
          window.location.replace('/');
          return;
        }
        setStatus('unauthenticated');
      } else {
        setLoadError(err.message || 'Failed to load links.');
        setStatus('error');
      }
    }
  }, []);

  useEffect(() => {
    refreshLinks();
  }, [refreshLinks]);

  const handleLoginSuccess = useCallback(async () => {
    const nextPath = getSafeNextPath();
    if (nextPath) {
      window.location.replace(nextPath);
      return;
    }
    setStatus('loading');
    await refreshLinks();
  }, [refreshLinks]);

  const handleUnauthorized = useCallback((oidcEnabled = false) => {
    if (oidcEnabled) {
      window.location.replace('/');
      return;
    }
    setStatus('unauthenticated');
  }, []);

  if (status === 'loading') {
    return (
      <div className="centered-shell">
        <p className="muted">Loading…</p>
      </div>
    );
  }

  if (status === 'unauthenticated') {
    return <LoginPage onSuccess={handleLoginSuccess} />;
  }

  if (status === 'error') {
    return (
      <div className="centered-shell">
        <div className="card">
          <h1>Golinks</h1>
          <p className="error" role="alert">{loadError}</p>
          <button type="button" className="btn btn-primary" onClick={refreshLinks}>
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <HashRouter>
      <Routes>
        <Route path="/" element={<LinkList links={links} />} />
        <Route
          path="/edit"
          element={
            <EditLink
              links={links}
              onLinksUpdated={setLinks}
              onUnauthorized={handleUnauthorized}
            />
          }
        />
        <Route
          path="/edit/:keyword"
          element={
            <EditLink
              links={links}
              onLinksUpdated={setLinks}
              onUnauthorized={handleUnauthorized}
            />
          }
        />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </HashRouter>
  );
}
