# Changelog

## 0.1.0-rc.2 (2026-11-02)

- `signing_in?/3` says whether a sign-in is still under way.
- `forget_client/2` forgets the client Wardrik registered for a provider's key.
- Each token records the key of the provider that issued it. Only that provider refreshes it.
- Provider and start options are validated with NimbleOptions, and documented from the schema.

### Breaking

- `:resolver` is required. It gives the provider each user signs in with, by name, with a `key`
  naming its OAuth app. See `WardrikOAuth.Resolver`.
- `:providers`, `add_provider/3`, `remove_provider/2` and `providers/1` are gone.
- A provider's `client_secret` is the secret itself, not `{:secret, name}`.
- A token kept by rc.1 records no provider, so its user signs in again once.
- `finish/3` takes `as:`, who is at the browser, and finishes only their own sign-in. Anyone else
  gets `{:error, :wrong_principal}`. It returns `{:ok, %{provider: name, principal: principal}}`.
- `WardrikOAuth.Plug` requires `:principal`, which says who is at the browser.
- `WardrikOAuth` implements the rc.2 `WardrikVault.Grants` callbacks, which take a request struct.
- A registered client's secret is read only if sealed as a `:client_secret`.
- `Browser.exchange/3`, `Device.poll/3`, `Renewal.renew/2`, `Request.post_as/3` and
  `ClientSecrets.seal/2` take their arguments as a keyword list.

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
