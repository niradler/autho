import type { EnvMapping, UnlockCredentials } from "./index.ts";

export class LeaseInputError extends Error {}

export function leaseObject(value: unknown, allowed: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new LeaseInputError("Expected a JSON object");
  const object = value as Record<string, unknown>;
  if (Object.keys(object).some((key) => !allowed.includes(key))) throw new LeaseInputError("Unexpected request field");
  return object;
}

function text(value: unknown, label: string, max = 4096): string {
  if (typeof value !== "string" || value.length === 0 || value.length > max || value.includes("\0")) {
    throw new LeaseInputError(`Invalid ${label}`);
  }
  return value;
}

export type LeaseIssueInput = {
  credentials: UnlockCredentials;
  leaseId?: string;
  name?: string;
  remember: boolean;
  secretRefs?: string[];
  ttlSeconds?: number;
};

export function parseLeaseIssue(value: unknown): LeaseIssueInput {
  const body = leaseObject(value, ["credentials", "leaseId", "name", "remember", "secretRefs", "ttlSeconds"]);
  const raw = leaseObject(body.credentials, ["password", "totp", "recovery", "passkey"]);
  if (typeof raw.password !== "string" || raw.password.length > 65536) throw new LeaseInputError("Invalid credentials");
  const credentials: UnlockCredentials = { password: raw.password };
  if (raw.totp !== undefined) credentials.totp = text(raw.totp, "TOTP", 16);
  if (raw.recovery !== undefined) credentials.recovery = text(raw.recovery, "recovery credential");
  if (raw.passkey !== undefined) {
    const passkey = leaseObject(raw.passkey, ["credentialId", "prfOutput"]);
    credentials.passkey = {
      credentialId: text(passkey.credentialId, "passkey ID"),
      prfOutput: text(passkey.prfOutput, "passkey output"),
    };
  }
  if (body.remember !== undefined && typeof body.remember !== "boolean") throw new LeaseInputError("Invalid remember setting");
  const input: LeaseIssueInput = { credentials, remember: body.remember === true };
  if (body.leaseId !== undefined) {
    input.leaseId = text(body.leaseId, "lease ID", 32);
    if (!/^[a-f0-9]{32}$/.test(input.leaseId)) throw new LeaseInputError("Invalid lease ID");
    if (body.name !== undefined || body.secretRefs !== undefined || body.ttlSeconds !== undefined) {
      throw new LeaseInputError("Existing leases cannot be extended or widened when issuing a key");
    }
    return input;
  }
  if (!Number.isSafeInteger(body.ttlSeconds) || (body.ttlSeconds as number) < 1 || (body.ttlSeconds as number) > 2_592_000) {
    throw new LeaseInputError("Lease TTL must be a whole number from 1 to 2592000 seconds");
  }
  if (!Array.isArray(body.secretRefs) || body.secretRefs.length === 0 || body.secretRefs.length > 128) {
    throw new LeaseInputError("Select from 1 to 128 secrets");
  }
  input.name = body.name === undefined ? "agent" : text(body.name, "lease name", 256);
  input.secretRefs = body.secretRefs.map((ref: unknown) => text(ref, "secret reference", 256));
  input.ttlSeconds = body.ttlSeconds as number;
  return input;
}

export function parseLeaseMappings(value: unknown): EnvMapping[] {
  const body = leaseObject(value, ["mappings"]);
  if (!Array.isArray(body.mappings) || body.mappings.length === 0 || body.mappings.length > 128) {
    throw new LeaseInputError("Provide from 1 to 128 mappings");
  }
  const names = new Set<string>();
  return body.mappings.map((value: unknown) => {
    const mapping = leaseObject(value, ["envName", "secretRef"]);
    const envName = text(mapping.envName, "environment name", 256);
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(envName) || names.has(envName.toUpperCase())) throw new LeaseInputError("Invalid or duplicate environment name");
    names.add(envName.toUpperCase());
    return { envName, secretRef: text(mapping.secretRef, "secret reference", 256) };
  });
}
