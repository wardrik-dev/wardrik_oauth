# Changelog

## Unreleased

- Providers belong to an owner: the deployment, an org or a person. A principal signs in with the
  nearest along `Wardrik.Owners.chain/1`. `add_provider/4`, `remove_provider/3` and
  `providers/2` take the owner, and `providers/2` returns `WardrikOAuth.Provider` structs.
- A runtime provider's `client_secret` is only `{:secret, name}`, read from its owner's vault
  secrets each time it's needed.
- Each grant records the owner of the provider that issued it, and is renewed with that provider.
  Grants kept before resolve along the chain.

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
