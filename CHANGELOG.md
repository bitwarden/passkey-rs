# Changelog

## Paskey v0.3.1
### passkey-client v0.3.1

The client now supports additional user-defined properties in the client data, while also clarifying how the client
handles client data and its hash.

- Change `register` and `authenticate` to take a `ClientData<E>` instead of `Option<Vec<u8>>`.
- Custom client data hashes are now specified using `DefaultClientDataWithCustomHash(Vec<u8>)` instead of 
  `Some(Vec<u8>)`.
- Additional fields can be added to the client data using `DefaultClientDataWithExtra(ExtraData)`.

### passkey-client v0.2.1

`CollectedClientData` is now generic and supports additional strongly typed fields.

- `CollectedClientData` has changed to `CollectedClientData<E = ()>`

## Passkey v0.3.0
### passkey-authenticator v0.3.0

The changes in this version are centered around giving the users of this library more control over the validation process.
The `UserValidationMethod` trait has been updated to give the implementation more information about the request, which can be
used to decide whether additional validations are needed. To reflect this, the `UserValidationMethod` trait now also
returns which validations were performed.

- ⚠ BREAKING: Consolidated `UserValidationMethod::check_user_presence` and `UserValidationMethod::check_user_verification`
  into a single `UserValidationMethod::check_user` method ([#5](https://github.com/bitwarden/passkey-rs/pull/5)).

### passkey-client v0.3.0

Updated to support the changes in `passkey-authenticator` v0.3.0.

## Passkey v0.2.1
### passkey-authenticator v0.2.1

These changes add functionality without breaking previously working stores. However, it does change
the semantics of `save_credential` whose doc said that it should be used for both saving and updating.
`update_credential` only needs to be implemented if the authenticator supports signature counters.

- Add support for signature counters
	- ⚠ BREAKING: Add `update_credential` function to store ([#3](https://github.com/bitwarden/passkey-rs/pull/3)).
	- Add `make_credentials_with_signature_counter` to `authenticator`.

### passkey-client v0.2.1

- The client no longer hardcodes the UV value sent to the authenticator. ([#2](https://github.com/bitwarden/passkey-rs/pull/2))

## Passkey v0.2.0
### passkey-types v0.2.0

Most of these changes are adding fields to structs which are breaking changes due to the current lack of builder methods for these types. Due to this, additions of fields to structs or variants to enums won't be marked as breaking in this release's notes. Other types of breaking changes will be explicitly called out.

- ⚠ BREAKING: Update `bitflags` from v1 to v2. This means `ctap2::Flags` no longer implement `PartialOrd`, `Ord` and `Hash` as those traits aren't applicable.
- Added a `transports` field to `ctap2::get_info::Response`
- Changes in `webauthn::PublicKeyCredential`:
	- ⚠ BREAKING: `authenticator_attachment` is now optional
	- ⚠ BREAKING: `client_extension_results`'s type has been renamed from `AuthenticationExtensionsClientOutputs` to `AuthenticatorExtensionsClientOutputs`
- Changes for `webauthn::PublicKeyCredentialRequestOptions`:
	- `timeout` now supports deserializing from a stringified number
	- `user_verification` will now ignore unknown values instead of returning an error on deserialization
	- Add `hints` field (#9)
	- Add `attestation` and `attestation_formats` fields
- Changes for `webauthn::AuthenticatorAssertionResponse`
	- Add `attestation_object` field
- Changes for `webauthn::PublicKeyCredentialCreationOptions`:
	- `timeout` now supports deserializing from a stringified number
	- Add `hints` field (#9)
	- Add `attestation_formats` field
- Fix `webauthn::CollectedClientData` JSON serialization to correctly follow the spec. (#6)
	- Add `unknown_keys` field
	- Always serializes `cross_origin` with a boolean even if it is set to `None`
	- ⚠ BREAKING: Remove from `#[typeshare]` generation as `#[serde(flatten)]` on `unknown_keys` is not supported.
- Add `webauthn::ClientDataType::PaymentGet` variant.
- Make all enums with unit variants `Clone`, `Copy`, `PartialEq` and `Eq`
- Add support for the `CredProps` extension with `authenticatorDisplayName`

### passkey-authenticator v0.2.0

- Add `Authenticator::transports(Vec<AuthenticatorTransport>)` builder method for customizing the transports during credential creation. The default is `internal` and `hybrid`.
- Add `Authenticator:{set_display_name, display_name}` methods for setting a display name for the `CredProps` extension's `authenticatorDisplayName`.
- Update `p256` to version `0.13`
- Update `signature` to version `2`

### passkey-client v0.2.0

- Add `WebauthnError::is_vendor_error()` for verifying if the internal CTAP error was in the range of `passkey_types::ctap2::VendorError`
- Break out Rp Id verification from the `Client` into its own `RpIdVerifier` which it now uses internally. This allows the use of `RpIdVerifier::assert_domain` publicly now instead of it being a private method to client without the need for everything else the client needs.
- `Client::register` now handles `CredProps` extension requests.
- Update `idna` to version `0.5`

### public-suffix v0.1.1

- Update the public suffix list