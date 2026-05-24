# TODOS

## Deferred from multi-org OAuth2 grant plan (2026-05-24)

- [ ] **Client-initiated org access requests (phase 2)** — Allow a third-party app to request access to an org; org owner approves/rejects. This is the "product" that makes the grant table useful for external SaaS devs. Requires: request table, email notification, approval UI in org settings.
- [ ] **Superadmin grant management UI** — Admin panel view of all `client_org_grants` rows with search/filter.
- [ ] **Notification emails on grant/revoke** — Email org owner when a client is added/removed.
- [ ] **Per-org scopes** — Allow different allowed scopes per `(client_id, org_id)` pair. Currently all granted orgs share the same scopes.
- [ ] **Client registration self-service** — Allow developers to register OAuth2 clients without admin involvement. Currently requires admin panel.
