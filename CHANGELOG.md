# Changelog

## 0.1.0-rc.2 (2026-10-31)

- Each grant records the key of the provider that issued it, and an expired one is refreshed only
  by that provider. A principal who now resolves to another signs in again with it.
- `forget_client/2` forgets the client Wardrik registered for a provider's key.
- Provider and start options are validated with NimbleOptions, documented from the schema.

### Breaking

- `:resolver` is required: your app says which provider each principal signs in with, by name.
  See `WardrikOAuth.Resolver`. Each provider has a `key` naming its OAuth app, which keeps its
  registered client apart from every other app's.
- `:providers`, `add_provider/2`, `remove_provider/2`, `providers/2` and `WardrikOAuth.Owners`
  are gone, and so are a provider's `owner` and `source`. A provider's `client_secret` is the
  secret itself: your resolver reads it.
- A grant kept by rc.1 records no provider, so its principal signs in again once.
- `c:WardrikOAuth.Resolver.provider/2` takes a `WardrikOAuth.Resolver.Request`, then its
  options, and `WardrikOAuth` implements `WardrikVault.Grants` rc.2's request callbacks.
- `finish/3` finishes a sign-in only `as:` the principal who started it, and answers
  `{:ok, %{provider: name, principal: principal}}`. Anyone else gets `{:error, :wrong_principal}`,
  and the sign-in stays open. `WardrikOAuth.Plug` takes a required `:principal`, which says who is
  at the browser.
- An app's client secret is read only if it's sealed as a `:client_secret`.
- `Browser.exchange/3` takes `:code` and `:verifier` with its options, `Device.poll/3` the
  `:device` and `:req_options`, `Renewal.renew/2` the `:provider`, `:principal` and `:token`,
  `Request.post_as/3` the provider `as:` in its options, and `ClientSecrets.seal/2` the `:name`
  and `:secret`.

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
