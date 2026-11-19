export class UnauthorizedError extends Error {
  constructor() {
    super('Unauthorized');
    this.name = 'UnauthorizedError';
  }
}

async function parseJsonSafe(resp) {
  try {
    return await resp.json();
  } catch {
    return {};
  }
}

export async function getLinks() {
  const resp = await fetch('/?action=getLinks', {
    method: 'GET',
    credentials: 'same-origin',
    headers: { Accept: 'application/json' },
  });
  if (resp.status === 401) {
    throw new UnauthorizedError();
  }
  const data = await parseJsonSafe(resp);
  if (!resp.ok) {
    throw new Error(data.error || `Failed to load links (${resp.status})`);
  }
  return data.links || {};
}

export async function login(secret) {
  const resp = await fetch('/?action=login', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ secret }),
  });
  const data = await parseJsonSafe(resp);
  if (!resp.ok) {
    throw new Error(data.error || 'Invalid secret.');
  }
  return data;
}

export async function saveLink({ originalKey, key, target }) {
  const resp = await fetch('/?action=saveLink', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ originalKey, key, target }),
  });
  if (resp.status === 401) {
    throw new UnauthorizedError();
  }
  const data = await parseJsonSafe(resp);
  if (!resp.ok) {
    throw new Error(data.error || `Failed to save link (${resp.status})`);
  }
  return data.links || {};
}

export async function deleteLink(key) {
  const resp = await fetch('/?action=deleteLink', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ key }),
  });
  if (resp.status === 401) {
    throw new UnauthorizedError();
  }
  const data = await parseJsonSafe(resp);
  if (!resp.ok) {
    throw new Error(data.error || `Failed to delete link (${resp.status})`);
  }
  return data.links || {};
}
