/**
 * Passkey ceremonies with the WebAuthn PRF extension, same as the CLI's
 * localhost helper page: the PRF output (never sent anywhere but our server)
 * unwraps the vault key, so an authenticator without PRF can't be used.
 */

const NO_PRF =
  "This browser or authenticator doesn't support the PRF extension needed to encrypt the vault. Try a recent Chrome, Edge or Safari, or a FIDO2 security key.";

export function b64url(buffer: ArrayBuffer | ArrayBufferView): string {
  const bytes = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromB64url(text: string): Uint8Array<ArrayBuffer> {
  const padded = text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (text.length % 4)) % 4);
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

const challenge = () => crypto.getRandomValues(new Uint8Array(32));

type PrfResults = { enabled?: boolean; results?: { first?: ArrayBuffer } };

function prfOf(credential: PublicKeyCredential): PrfResults | undefined {
  return (credential.getClientExtensionResults() as { prf?: PrfResults }).prf;
}

export function passkeysSupported(): boolean {
  return typeof window.PublicKeyCredential === "function" && window.isSecureContext;
}

/** Why passkeys won't work on this page, or null when they should. */
export function passkeyProblem(rpId: string): string | null {
  if (!passkeysSupported()) return "This browser doesn't support passkeys here.";
  if (location.hostname !== rpId) return `Passkeys are tied to "${rpId}". Open http://${rpId}:${location.port} instead.`;
  return null;
}

export async function authenticatePasskey(
  rpId: string,
  credentials: { credentialId: string; prfSalt: string; transports?: string[] }[],
): Promise<{ credentialId: string; prfOutput: string }> {
  const evalByCredential: Record<string, { first: Uint8Array<ArrayBuffer> }> = {};
  for (const c of credentials) evalByCredential[c.credentialId] = { first: fromB64url(c.prfSalt) };
  const assertion = (await navigator.credentials.get({
    publicKey: {
      rpId,
      challenge: challenge(),
      userVerification: "required",
      timeout: 120_000,
      allowCredentials: credentials.map((c) => ({ type: "public-key", id: fromB64url(c.credentialId), transports: c.transports as AuthenticatorTransport[] | undefined })),
      extensions: { prf: { evalByCredential } } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null;
  if (!assertion) throw new Error("No passkey was used");
  const out = prfOf(assertion)?.results?.first;
  if (!out) throw new Error(NO_PRF);
  return { credentialId: b64url(assertion.rawId), prfOutput: b64url(out) };
}

export async function registerPasskey(
  options: { rpId: string; userId: string; userName: string; exclude: string[]; prfSalt: string },
  onSecondTouch?: () => void,
): Promise<{ credentialId: string; prfOutput: string; transports: string[] }> {
  const salt = fromB64url(options.prfSalt);
  const credential = (await navigator.credentials.create({
    publicKey: {
      rp: { id: options.rpId, name: "autho" },
      user: { id: fromB64url(options.userId), name: options.userName, displayName: options.userName },
      challenge: challenge(),
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -8 },
        { type: "public-key", alg: -257 },
      ],
      authenticatorSelection: { userVerification: "required", residentKey: "preferred" },
      attestation: "none",
      timeout: 120_000,
      excludeCredentials: options.exclude.map((id) => ({ type: "public-key", id: fromB64url(id) })),
      extensions: { prf: { eval: { first: salt } } } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null;
  if (!credential) throw new Error("No passkey was created");
  const prf = prfOf(credential);
  if (!prf || prf.enabled === false) throw new Error(NO_PRF);
  let out = prf.results?.first;
  if (!out) {
    // Many authenticators only evaluate the PRF during an assertion.
    onSecondTouch?.();
    const assertion = (await navigator.credentials.get({
      publicKey: {
        rpId: options.rpId,
        challenge: challenge(),
        userVerification: "required",
        timeout: 120_000,
        allowCredentials: [{ type: "public-key", id: credential.rawId }],
        extensions: { prf: { eval: { first: salt } } } as AuthenticationExtensionsClientInputs,
      },
    })) as PublicKeyCredential | null;
    out = assertion ? prfOf(assertion)?.results?.first : undefined;
  }
  if (!out) throw new Error(NO_PRF);
  const response = credential.response as AuthenticatorAttestationResponse;
  return { credentialId: b64url(credential.rawId), prfOutput: b64url(out), transports: response.getTransports?.() ?? [] };
}
