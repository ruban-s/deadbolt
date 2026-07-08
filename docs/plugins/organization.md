# Organizations

Multi-tenant organizations with configurable role-based access control, members, invitations, and teams. Roles are defined by an `AccessControl` that maps each role to a set of `resource -> actions` permissions plus a low-to-high hierarchy; the default mirrors owner > admin > member.

## Install

Included in the core install.

## Setup

```python
import deadbolt as db
from deadbolt.plugins.organization import organization

auth = db.Auth(
    adapter=db.MemoryAdapter(),
    secret="a-32-byte-or-longer-secret......",
    email_and_password=db.EmailPassword(enabled=True),
    plugins=[organization()],
)
```

Pass a custom `AccessControl` to define your own roles and permissions:

```python
from deadbolt.plugins.organization import access_control, organization

ac = access_control(
    roles={
        "owner": {
            "organization": ["update", "delete"],
            "invitation": ["create", "cancel"],
            "billing": ["manage"],
        },
        "billing": {"billing": ["manage"]},
        "viewer": {},
    },
    hierarchy=("viewer", "billing", "owner"),
    creator_role="owner",
    invite_default="viewer",
)

auth = db.Auth(..., plugins=[organization(access=ac)])
```

## Configuration

The `organization()` factory takes a single keyword argument.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `access` | `AccessControl \| None` | `None` (uses `DEFAULT_ACCESS_CONTROL`) | Role definitions, hierarchy, creator role, and invite default. |

### `access_control(...)`

Build an `AccessControl` from a role → resource → actions map.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `roles` | `Mapping[str, Mapping[str, Iterable[str]]]` | required | Maps each role name to its `resource -> actions` permissions. |
| `hierarchy` | `Sequence[str]` | required | Role names ordered low to high. Used to block granting/removing at or above the caller's own rank. Roles absent from the hierarchy rank as `-1`. |
| `creator_role` | `str` | `"owner"` | Role assigned to the user who creates an organization. |
| `invite_default` | `str` | `"member"` | Role used for an invitation when none is supplied. |

### Default roles and permissions

`DEFAULT_ACCESS_CONTROL` with hierarchy `("member", "admin", "owner")`:

| Role | Resource | Actions |
| --- | --- | --- |
| `owner` | `organization` | `update`, `delete` |
| `owner` | `member` | `create`, `update`, `delete` |
| `owner` | `invitation` | `create`, `cancel` |
| `owner` | `team` | `create`, `update`, `delete` |
| `admin` | `member` | `create`, `update`, `delete` |
| `admin` | `invitation` | `create`, `cancel` |
| `admin` | `team` | `create`, `update`, `delete` |
| `member` | — | (no permissions) |

## API

All endpoints require a valid session cookie. Endpoints that mutate data additionally require a specific permission; read endpoints require organization membership. Error responses use the envelope `{"error": {"code": "...", "message": "..."}}` with the listed HTTP status.

Two errors are common to every endpoint and omitted from the per-endpoint tables below:

| Status | Code | When |
| --- | --- | --- |
| `401` | `unauthorized` | No valid session. |
| `400` | `invalid_request` | A required body/query field is missing or invalid. |

### Organization endpoints

#### `POST /organization/create`

Creates an organization and makes the caller its `creator_role` (owner by default). **Auth:** session required.

**Request**:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `name` | string | yes | Display name. |
| `slug` | string | yes | Unique slug; lowercased before storage. |

**Response `200`**:

```json
{
  "organization": {
    "id": "org_abc",
    "name": "Acme",
    "slug": "acme",
    "created_at": "2026-07-08T00:00:00Z"
  }
}
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `409` | `slug_taken` | The slug is already in use. |

#### `POST /organization/update`

Updates an organization's name and/or slug. **Auth:** requires permission `organization:update`.

**Request**:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `organization_id` | string | yes | Organization to update. |
| `name` | string | no | New display name (applied only if a string). |
| `slug` | string | no | New slug; lowercased. Applied only if a string. |

**Response `200`**:

```json
{ "organization": { "id": "org_abc", "name": "Renamed", "slug": "acme", "created_at": "..." } }
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `403` | `forbidden` | Caller lacks `organization:update`. |
| `409` | `slug_taken` | The new slug belongs to another organization. |

#### `POST /organization/delete`

Deletes the organization and cascades its team members, teams, members, invitations, and active-organization rows. **Auth:** requires permission `organization:delete`.

**Request**:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `organization_id` | string | yes | Organization to delete. |

**Response `200`**:

```json
{ "success": true }
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `403` | `forbidden` | Caller lacks `organization:delete`. |

#### `GET /organization/list`

Lists the caller's organizations, each annotated with the caller's role. **Auth:** session required.

**Response `200`**:

```json
{
  "organizations": [
    { "id": "org_abc", "name": "Acme", "slug": "acme", "created_at": "...", "role": "owner" }
  ]
}
```

#### `GET /organization/get-full`

Returns an organization with its members, pending invitations, and teams. Falls back to the caller's active organization when `organization_id` is omitted. **Auth:** session required and membership.

**Request** (query string):

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `organization_id` | string | no | Organization to fetch; defaults to the active organization. |

**Response `200`**:

```json
{
  "organization": { "id": "org_abc", "name": "Acme", "slug": "acme", "created_at": "..." },
  "members": [ { "user_id": "usr_1", "role": "owner", "email": "owner@b.com" } ],
  "invitations": [],
  "teams": []
}
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `400` | `invalid_request` | No organization specified and none active. |
| `403` | `forbidden` | Caller is not a member. |

#### `POST /organization/set-active`

Sets (or updates) the caller's active organization. **Auth:** session required and membership.

**Request**:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `organization_id` | string | yes | Organization to make active. |

**Response `200`**:

```json
{ "active_organization_id": "org_abc" }
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `403` | `forbidden` | Caller is not a member. |

#### `GET /organization/get-active`

Returns the caller's active organization, or `null` if none is set. **Auth:** session required.

**Response `200`**:

```json
{ "active_organization_id": "org_abc", "organization": { "id": "org_abc", "name": "Acme", "slug": "acme", "created_at": "..." } }
```

### Members

#### `GET /organization/list-members`

Lists an organization's members. **Auth:** session required and membership.

**Request** (query string):

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `organization_id` | string | yes | Organization to list. |

**Response `200`**:

```json
{ "members": [ { "user_id": "usr_1", "role": "owner", "email": "owner@b.com" } ] }
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `403` | `forbidden` | Caller is not a member. |

#### `POST /organization/remove-member`

Removes a member. A caller cannot remove a member whose role ranks equal to or higher than their own. **Auth:** requires permission `member:delete`.

**Request**:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `organization_id` | string | yes | Organization. |
| `user_id` | string | yes | Member to remove. |

**Response `200`**:

```json
{ "success": true }
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `403` | `forbidden` | Caller lacks `member:delete`, or target ranks equal/higher. |
| `404` | `not_a_member` | Target is not a member. |

#### `POST /organization/update-role`

Changes a member's role. The new role cannot rank above the caller's own. **Auth:** requires permission `member:update`.

**Request**:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `organization_id` | string | yes | Organization. |
| `user_id` | string | yes | Member to update. |
| `role` | string | yes | New role; must be a known role. |

**Response `200`**:

```json
{ "success": true }
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `400` | `invalid_role` | The role is not defined. |
| `403` | `forbidden` | Caller lacks `member:update`, or the role ranks above the caller. |
| `404` | `not_a_member` | Target is not a member. |

#### `POST /organization/leave`

Removes the caller from an organization. The sole remaining `creator_role` holder cannot leave. **Auth:** session required.

**Request**:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `organization_id` | string | yes | Organization to leave. |

**Response `200`**:

```json
{ "success": true }
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `400` | `sole_owner` | Caller is the last owner; transfer ownership or delete first. |
| `404` | `not_a_member` | Caller is not a member. |

### Invitations

#### `POST /organization/invite`

Creates a pending invitation (7-day TTL) and sends an email if an email sender is configured. The invited role cannot rank above the caller's own. **Auth:** requires permission `invitation:create`.

**Request**:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `organization_id` | string | yes | Organization. |
| `email` | string | yes | Invitee email; lowercased. |
| `role` | string | no | Role to grant; defaults to `invite_default`. Must be a known role. |

**Response `200`**:

```json
{
  "invitation": {
    "id": "inv_1",
    "organization_id": "org_abc",
    "email": "invitee@b.com",
    "role": "member",
    "status": "pending",
    "inviter_id": "usr_1",
    "expires_at": "...",
    "created_at": "..."
  }
}
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `400` | `invalid_role` | The role is not defined. |
| `403` | `forbidden` | Caller lacks `invitation:create`, or the role ranks above the caller. |

#### `POST /organization/accept-invitation`

Accepts a pending invitation addressed to the caller's email and adds them as a member. **Auth:** session required.

**Request**:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `invitation_id` | string | yes | Invitation to accept. |

**Response `200`**:

```json
{ "member": { "id": "mem_1", "organization_id": "org_abc", "user_id": "usr_2", "role": "admin", "created_at": "..." } }
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `400` | `invalid_invitation` | Invitation missing, not pending, or expired. |
| `403` | `forbidden` | Invitation is for another email. |

#### `POST /organization/reject-invitation`

Marks a pending invitation addressed to the caller as rejected. **Auth:** session required.

**Request**:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `invitation_id` | string | yes | Invitation to reject. |

**Response `200`**:

```json
{ "success": true }
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `400` | `invalid_invitation` | Invitation missing, not pending, or expired. |
| `403` | `forbidden` | Invitation is for another email. |

#### `POST /organization/cancel-invitation`

Cancels a pending invitation. **Auth:** requires permission `invitation:cancel`.

**Request**:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `invitation_id` | string | yes | Invitation to cancel. |

**Response `200`**:

```json
{ "success": true }
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `400` | `invalid_invitation` | Invitation missing, not pending, or expired. |
| `403` | `forbidden` | Caller lacks `invitation:cancel`. |

#### `GET /organization/list-invitations`

Lists pending invitations for an organization. **Auth:** session required and membership.

**Request** (query string):

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `organization_id` | string | yes | Organization. |

**Response `200`**:

```json
{ "invitations": [ { "id": "inv_1", "organization_id": "org_abc", "email": "invitee@b.com", "role": "member", "status": "pending", "inviter_id": "usr_1", "expires_at": "...", "created_at": "..." } ] }
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `403` | `forbidden` | Caller is not a member. |

### Teams

#### `POST /organization/create-team`

Creates a team within an organization. **Auth:** requires permission `team:create`.

**Request**:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `organization_id` | string | yes | Organization. |
| `name` | string | yes | Team name. |

**Response `200`**:

```json
{ "team": { "id": "team_1", "organization_id": "org_abc", "name": "Eng", "created_at": "..." } }
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `403` | `forbidden` | Caller lacks `team:create`. |

#### `GET /organization/list-teams`

Lists an organization's teams. **Auth:** session required and membership.

**Request** (query string):

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `organization_id` | string | yes | Organization. |

**Response `200`**:

```json
{ "teams": [ { "id": "team_1", "organization_id": "org_abc", "name": "Eng", "created_at": "..." } ] }
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `403` | `forbidden` | Caller is not a member. |

#### `POST /organization/update-team`

Renames a team. **Auth:** requires permission `team:update`.

**Request**:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `team_id` | string | yes | Team to rename. |
| `name` | string | yes | New name. |

**Response `200`**:

```json
{ "team": { "id": "team_1", "organization_id": "org_abc", "name": "Platform", "created_at": "..." } }
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `404` | `team_not_found` | No such team. |
| `403` | `forbidden` | Caller lacks `team:update`. |

#### `POST /organization/remove-team`

Deletes a team and its members. **Auth:** requires permission `team:delete`.

**Request**:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `team_id` | string | yes | Team to delete. |

**Response `200`**:

```json
{ "success": true }
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `404` | `team_not_found` | No such team. |
| `403` | `forbidden` | Caller lacks `team:delete`. |

#### `POST /organization/add-team-member`

Adds an organization member to a team. Idempotent: returns success if the user is already on the team. **Auth:** requires permission `team:update`.

**Request**:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `team_id` | string | yes | Team. |
| `user_id` | string | yes | User to add; must already be an organization member. |

**Response `200`**:

```json
{ "success": true }
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `404` | `team_not_found` | No such team. |
| `403` | `forbidden` | Caller lacks `team:update`. |
| `400` | `not_a_member` | The user is not an organization member. |

#### `POST /organization/remove-team-member`

Removes a user from a team. **Auth:** requires permission `team:update`.

**Request**:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `team_id` | string | yes | Team. |
| `user_id` | string | yes | User to remove. |

**Response `200`**:

```json
{ "success": true }
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `404` | `team_not_found` | No such team. |
| `403` | `forbidden` | Caller lacks `team:update`. |

#### `GET /organization/list-team-members`

Lists a team's members. **Auth:** session required and membership of the team's organization.

**Request** (query string):

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `team_id` | string | yes | Team. |

**Response `200`**:

```json
{ "members": [ { "user_id": "usr_2" } ] }
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `404` | `team_not_found` | No such team. |
| `403` | `forbidden` | Caller is not a member of the organization. |

### Permissions

#### `POST /organization/has-permission`

Checks whether the caller's role grants a set of `resource -> actions` permissions in an organization. Returns `false` (not an error) when the caller is not a member. **Auth:** session required.

**Request**:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `organization_id` | string | yes | Organization. |
| `permissions` | object | yes | Map of `resource -> [actions]` to check. |

**Response `200`**:

```json
{ "allowed": true }
```

**Errors**:

| Status | Code | When |
| --- | --- | --- |
| `400` | `invalid_request` | `permissions` is not an object. |

## Notes

- **Role hierarchy guard.** Rank is the index of a role in `hierarchy` (unknown roles rank `-1`). A caller can never grant a role above their own (`invite`, `update-role`) nor remove a member ranking at or above themselves (`remove-member`).
- **Permission model.** A role's permissions are checked with `resource -> actions` subset matching; a role grants an action only if the requested actions are a subset of what its map lists for that resource. The default `member` role has no permissions.
- **Sole-owner guard.** The last holder of `creator_role` cannot `leave`; ownership must be transferred (via `update-role`) or the organization deleted first.
- **Creator role.** Creating an organization makes the caller `creator_role` (owner by default). This is the only member added automatically.
- **Invitation lifecycle.** Invitations are created `pending` with a 7-day TTL. They can be accepted or rejected only by the addressed email, and cancelled by anyone with `invitation:cancel`. Accept/reject/cancel all require the invitation to still be pending and unexpired, else `invalid_invitation`.
- **Slug uniqueness.** Slugs are lowercased and must be unique across all organizations.
- **Active organization** is stored per user; `get-full` uses it as a fallback when no `organization_id` is supplied.
- **Cascade deletes.** Deleting an organization removes its members, invitations, active-organization rows, teams, and team members. Deleting a team removes its team members.
