# Link Tagging Design

## Intent & Why

Add per-user tagging to `golinks` so users can categorize and filter their links in the management UI without affecting go-link redirect behavior.

## Goals, Non-Goals & Anti-Goals

- **Goals:**
  - Let users attach zero or more tags to a link when creating or editing it.
  - Persist tags in a dedicated per-user unique `tags` table and a many-to-many `link_tags` join table across both SQLite and PostgreSQL.
  - Automatically delete unused tags when no links reference them anymore.
  - Display all of the current user's existing tags below the search box on the main page, supporting multi-select **OR** filtering combined with the text filter.
  - Display a link's assigned tags as small badges on each link row.
- **Non-Goals:**
  - Changing go-link redirect resolution (`GET /<keyword>`), URL encoding, or `%s` substitution.
  - Adding a separate tag-management page or tag rename/merge UI.
  - Adding new top-level HTTP paths (all API actions remain on `/` via `?action=...`).
- **Anti-Goals:**
  - Leaking tags across users in multi-user OIDC mode.
  - Leaving orphaned/unused tags behind after edits or link deletions.
  - Breaking SQLite / PostgreSQL schema version parity enforced by `build.rs`.

## Constraints & Architectural Invariants

- All API endpoints remain on `/` (`?action=getLinks`, `saveLink`, `deleteLink`); no new non-root paths.
- All database queries and mutations remain scoped by `user_id`.
- Schema changes must update `full_schema.sql` and add matching `migration_v0000003.sql` files under both `db/sqlite/` and `db/postgres/` (PostgreSQL objects live in the `golinks` schema).
- Redirect lookups (`Database::get_link_target`) remain untouched.
- Frontend continues to build into a single self-contained `frontend/dist/index.html` using `HashRouter`.

## Approaches Considered

1. **Approach A — Additive API fields (`links` + `linkTags` + `tags`):**
   - Keep `links: { [keyword]: target }` unchanged and add sibling `linkTags: { [keyword]: string[] }` and `tags: string[]` fields to API responses.
   - *Trade-off:* Preserves backwards compatibility with existing API consumers/tests, at the cost of splitting each link's properties across two maps.
2. **Approach B — Nested link objects (`links: { [keyword]: { target, tags } }` + `tags: string[]`) *(Selected)*:**
   - Represent each link as `{ target: string, tags: string[] }` inside `links`, alongside a top-level sorted `tags: string[]` list of all tags belonging to the user.
   - *Trade-off:* Requires updating existing API tests and frontend callers to the new response shape, in exchange for a cleaner, cohesive per-link data model.
3. **Approach C — Separate `?action=getTags` endpoint *(Dropped)*:**
   - Adds an extra HTTP round-trip and client-side synchronization complexity even though links and tags are always loaded and mutated together.

**Choice:** Approach B was selected by the user for the cleaner per-link object model.

## Design Decisions

### Database Schema (`v0000003`)

Both `db/sqlite/` and `db/postgres/` (`full_schema.sql` and `migration_v0000003.sql`) add:

- `tags`:
  - `tag_id` (`INTEGER PRIMARY KEY AUTOINCREMENT` in SQLite; `SERIAL PRIMARY KEY` in PostgreSQL)
  - `user_id` (`INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE`)
  - `tag_name` (`VARCHAR(32) NOT NULL`)
  - `created_on` (`TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP`)
  - `CONSTRAINT uq_tags_user_name UNIQUE (user_id, tag_name)`
- `link_tags`:
  - `link_id` (`INTEGER NOT NULL REFERENCES links(link_id) ON DELETE CASCADE`)
  - `tag_id` (`INTEGER NOT NULL REFERENCES tags(tag_id) ON DELETE CASCADE`)
  - `PRIMARY KEY (link_id, tag_id)`
- Index on `link_tags(tag_id)` to keep orphan-tag cleanup fast.

### Backend API & Tag Lifecycle

- **Tag normalization & validation:**
  - Each submitted tag is trimmed and lowercased (`Work` → `work`), deduplicated, and sorted.
  - Empty strings are ignored; valid tags are 1–32 characters and contain no whitespace. Invalid tags return `400 Bad Request`.
- **Response shape (`getLinks`, `saveLink`, `deleteLink`):**
  ```json
  {
    "links": {
      "gh": { "target": "https://github.com/%s", "tags": ["tools", "work"] }
    },
    "tags": ["docs", "tools", "work"]
  }
  ```
- **`POST /?action=saveLink`:**
  - Accepts `{ "originalKey"?: string, "key": string, "target": string, "tags"?: string[] }` (`tags` defaults to `[]` if omitted).
  - Runs in a single transaction: handles optional rename/delete, upserts the link and obtains its `link_id`, replaces its `link_tags` rows (creating missing `tags` rows for `user_id` via `ON CONFLICT DO NOTHING`), and deletes any `tags` rows for `user_id` that have no remaining `link_tags` rows.
- **`POST /?action=deleteLink`:**
  - Runs in a transaction: deletes the link (cascading its `link_tags` rows) and deletes any `tags` rows for `user_id` that have no remaining `link_tags` rows.

### Frontend UI

- **Create/Edit Link (`EditLink.jsx`):**
  - Adds a **Tags** field with a chip/pill container and text input plus an **Add** button.
  - Whitespace splits input into tags. Typing space (or pasting whitespace-separated words), pressing `Tab` (when input has text), blurring the input, or clicking **Add** converts the word(s) into boxed tag chips (lowercased, deduplicated).
  - Clicking `×` on a chip removes it; pressing `Backspace` on an empty input removes the last chip.
  - Submitting **Save** commits any pending uncommitted text in the tag input before calling `saveLink`.
- **Main Page (`LinkList.jsx`):**
  - Displays all existing tags (from `tags`) as clickable pills directly below the search box (hidden when no tags exist).
  - Clicking a tag toggles its selection state. Multiple tags may be selected; filtering uses **OR** semantics across selected tags (a link matches if it has at least one selected tag), combined via **AND** with the search text filter.
  - Deselecting all tags removes the tag filter.
  - Each link row renders its assigned tags as small badges.

## Left to the Builder

- Exact CSS styling/spacing for tag pills, active filter chips, and the chip-input wrapper (matching existing light/dark CSS variables in `frontend/src/styles.css`).
- Exact Rust struct/method naming in `src/db/mod.rs` and `src/main.rs`.
- Updating `AGENTS.md`, `MEMORY.md`, and `README.md` alongside the implementation, and adding unit/integration tests for tag CRUD, orphan cleanup, multi-user isolation, and migrations.
