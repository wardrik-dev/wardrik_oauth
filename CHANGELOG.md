# Changelog

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
