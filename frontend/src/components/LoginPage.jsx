import React, { useState } from 'react';
import { login } from '../api.js';

export default function LoginPage({ onSuccess }) {
  const [secret, setSecret] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    setSubmitting(true);
    try {
      await login(secret);
      await onSuccess();
    } catch (err) {
      setError(err.message || 'Invalid secret.');
      setSubmitting(false);
    }
  }

  return (
    <div className="centered-shell">
      <main className="card login-card">
        <h1>Golinks Authentication</h1>
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        <form onSubmit={handleSubmit}>
          <div className="field">
            <label htmlFor="secret">Secret</label>
            <input
              id="secret"
              type="password"
              autoComplete="current-password"
              autoFocus
              required
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              disabled={submitting}
            />
          </div>
          <button type="submit" className="btn btn-primary btn-full" disabled={submitting}>
            {submitting ? 'Signing in…' : 'Continue'}
          </button>
        </form>
      </main>
    </div>
  );
}
