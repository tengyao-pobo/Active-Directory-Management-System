type DescriptorJson = Omit<PublicKeyCredentialDescriptor, 'id'> & { id: string };
export type RequestOptionsJson = Omit<PublicKeyCredentialRequestOptions, 'challenge' | 'allowCredentials'> & {
  challenge: string; allowCredentials?: DescriptorJson[];
};
export type CreationOptionsJson = Omit<PublicKeyCredentialCreationOptions, 'challenge' | 'user' | 'excludeCredentials'> & {
  challenge: string; user: Omit<PublicKeyCredentialUserEntity, 'id'> & { id: string }; excludeCredentials?: DescriptorJson[];
};
export function decodeBase64Url(value: string): ArrayBuffer {
  if (!/^[A-Za-z0-9_-]*={0,2}$/.test(value) || value.length > 65536) throw new Error('Invalid base64url');
  const binary = atob(value.replace(/-/g, '+').replace(/_/g, '/'));
  const result = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) result[i] = binary.charCodeAt(i);
  return result.buffer;
}
export function encodeBase64Url(value: ArrayBuffer): string {
  let binary = '';
  for (const byte of new Uint8Array(value)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function requestOptions(json: RequestOptionsJson): PublicKeyCredentialRequestOptions {
  return { ...json, challenge: decodeBase64Url(json.challenge), allowCredentials: json.allowCredentials?.map(c => ({ ...c, id: decodeBase64Url(c.id) })) };
}
export function creationOptions(json: CreationOptionsJson): PublicKeyCredentialCreationOptions {
  return { ...json, challenge: decodeBase64Url(json.challenge), user: { ...json.user, id: decodeBase64Url(json.user.id) },
    excludeCredentials: json.excludeCredentials?.map(c => ({ ...c, id: decodeBase64Url(c.id) })) };
}
function requireSupport() {
  if (!window.isSecureContext || typeof PublicKeyCredential === 'undefined' || !navigator.credentials) throw new Error('WebAuthn unavailable');
}
export async function performAssertion(json: RequestOptionsJson) {
  requireSupport();
  const credential = await navigator.credentials.get({ publicKey: requestOptions(json) });
  if (!(credential instanceof PublicKeyCredential) || !(credential.response instanceof AuthenticatorAssertionResponse)) throw new Error('Unexpected assertion');
  const response = credential.response;
  return { id: credential.id, rawId: encodeBase64Url(credential.rawId), type: credential.type,
    clientExtensionResults: credential.getClientExtensionResults(), response: {
      authenticatorData: encodeBase64Url(response.authenticatorData), clientDataJSON: encodeBase64Url(response.clientDataJSON),
      signature: encodeBase64Url(response.signature), userHandle: response.userHandle ? encodeBase64Url(response.userHandle) : null,
    } };
}
export async function performRegistration(json: CreationOptionsJson) {
  requireSupport();
  const credential = await navigator.credentials.create({ publicKey: creationOptions(json) });
  if (!(credential instanceof PublicKeyCredential) || !(credential.response instanceof AuthenticatorAttestationResponse)) throw new Error('Unexpected attestation');
  return { id: credential.id, rawId: encodeBase64Url(credential.rawId), type: credential.type,
    clientExtensionResults: credential.getClientExtensionResults(), response: {
      attestationObject: encodeBase64Url(credential.response.attestationObject), clientDataJSON: encodeBase64Url(credential.response.clientDataJSON),
      transports: credential.response.getTransports?.() ?? [],
    } };
}
