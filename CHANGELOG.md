# Changelog

## 0.1.0-rc.2 (2026-10-31)

- `:resolver`, `WardrikOAuth.Resolver`: your app says which provider each principal signs in
  with by name. Each provider has a `key` naming its OAuth app, which keeps its registered client
  apart from every other app's.
- Each grant records the key of the provider that issued it, and an expired one is refreshed only
  by that provider. A principal who now resolves to another signs in again with it. Grants kept
  by rc.1 came from the deployment's provider, and are refreshed only by it.
- Without `:resolver`, providers belong to an owner: the deployment, an org or a person. A
  principal signs in with the nearest of a name along `Wardrik.Owners.chain/1`. See
  `WardrikOAuth.Owners`.
- A runtime provider's `client_secret` is only `{:secret, name}`, read from its owner's vault each
  time it's needed.
- Provider and start options are validated with NimbleOptions, documented from the schema.

### Breaking

- `finish/3` finishes a sign-in only `as:` the principal who started it, and answers
  `{:ok, %{provider: name, principal: principal}}`. Anyone else gets `{:error, :wrong_principal}`,
  and the sign-in stays open. `WardrikOAuth.Plug` takes a required `:principal`, which says who is
  at the browser.
- An app's client secret is read only if it's sealed as a `:client_secret`.
- `add_provider/4`, `remove_provider/3` and `providers/2` take the owner, and `providers/2`
  returns `WardrikOAuth.Provider` structs.

## 0.1.0-rc.1 (2026-10-30)

- Sign-ins that give WardrikCore agents a person's accounts, each grant sealed in WardrikVault.
- Providers from an `issuer`'s metadata, a `resource`, or their endpoints, with scopes, extra
  authorization parameters and `client_auth: :basic`.
- Browser and device sign-ins. A call that needs a credential not yet granted parks on its sign-in
  URL, and `on_granted` says when to resume it.
- `WardrikOAuth.Plug`, the sign-in pages to mount in your app.
- Wardrik's own client ID where a provider has none, from a Client ID Metadata Document or
  dynamic registration.
- Tokens refreshed before the person is asked again, under a cluster-wide lock.
- Providers added at runtime, kept in the store for every node. Client secrets read from the vault
  as `{:secret, name}`.
