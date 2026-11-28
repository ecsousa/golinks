export class UnauthorizedError extends Error {
  constructor(oidcEnabled = false) {
    super('Unauthorized');
    this.name = 'UnauthorizedError';
    this.oidcEnabled = Boolean(oidcEnabled);
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
  const data = await parseJsonSafe(resp);
  if (resp.status === 401) {
    throw new UnauthorizedError(data.oidcEnabled);
  }
  if (!resp.ok) {
    throw new Error(data.error || `Failed to load links (${resp.status})`);
  }
  return {
    links: data.links || {},
    tags: Array.isArray(data.tags) ? data.tags : [],
  };
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

export async function saveLink({ originalKey, key, target, tags = [] }) {
  const resp = await fetch('/?action=saveLink', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ originalKey, key, target, tags }),
  });
  const data = await parseJsonSafe(resp);
  if (resp.status === 401) {
    throw new UnauthorizedError(data.oidcEnabled);
  }
  if (!resp.ok) {
    throw new Error(data.error || `Failed to save link (${resp.status})`);
  }
  return {
    links: data.links || {},
    tags: Array.isArray(data.tags) ? data.tags : [],
  };
}

export async function deleteLink(key) {
  const resp = await fetch('/?action=deleteLink', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ key }),
  });
  const data = await parseJsonSafe(resp);
  if (resp.status === 401) {
    throw new UnauthorizedError(data.oidcEnabled);
  }
  if (!resp.ok) {
    throw new Error(data.error || `Failed to delete link (${resp.status})`);
  }
  return {
    links: data.links || {},
    tags: Array.isArray(data.tags) ? data.tags : [],
  };
}
