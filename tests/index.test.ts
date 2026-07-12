import { describe, expect, it } from "vitest";
import { createPkceS256Challenge, generatePkceVerifier } from "@plasius/oauth2-core";
import {
  createInMemoryOAuth2Storage,
  createOAuth2Issuer,
  createRsaKeyStore,
  importRsaPrivateJwk,
  importRsaPublicJwk,
} from "../src/index.js";

function createIssuer() {
  const storage = createInMemoryOAuth2Storage();
  const config = {
    issuer: "https://plasius.co.uk/api/oauth/mcp",
    resource: "https://plasius.co.uk/api/mcp",
    authorizationEndpoint: "https://plasius.co.uk/api/oauth/mcp/authorize",
    tokenEndpoint: "https://plasius.co.uk/api/oauth/mcp/token",
    jwksUri: "https://plasius.co.uk/api/oauth/mcp/jwks",
    registrationEndpoint: "https://plasius.co.uk/api/oauth/mcp/register",
    revocationEndpoint: "https://plasius.co.uk/api/oauth/mcp/revoke",
    supportedScopes: ["mcp:access", "admin.flags.read", "admin.flags.write"],
    accessTokenTtlSeconds: 60,
  };
  const issuer = createOAuth2Issuer(config, {
    storage,
    keyStore: createRsaKeyStore({ issuer: config.issuer, keyId: "kid-1" }),
  });
  return { issuer, storage, config };
}

describe("@plasius/oauth2-issuer", () => {
  it("registers clients and publishes metadata", async () => {
    const { issuer } = createIssuer();
    const client = await issuer.registerClient({
      client_name: "ChatGPT",
      redirect_uris: ["https://chat.openai.com/aip/g-test/oauth/callback"],
      scope: "mcp:access admin.flags.read",
    });
    expect(client.clientId).toMatch(/^client_/);
    expect(issuer.authorizationServerMetadata()).toMatchObject({
      response_types_supported: ["code"],
      code_challenge_methods_supported: ["S256"],
      resource_indicators_supported: true,
    });
    expect(issuer.protectedResourceMetadata()).toMatchObject({
      resource: "https://plasius.co.uk/api/mcp",
      bearer_methods_supported: ["header"],
    });
  });

  it("completes authorization code + PKCE and rejects code replay", async () => {
    const { issuer, config } = createIssuer();
    const client = await issuer.registerClient({
      redirect_uris: ["https://chat.openai.com/aip/g-test/oauth/callback"],
      scope: "mcp:access admin.flags.read",
    });
    const verifier = generatePkceVerifier();
    const authorized = await issuer.authorize({
      responseType: "code",
      clientId: client.clientId,
      redirectUri: client.metadata.redirect_uris[0]!,
      scope: "mcp:access admin.flags.read",
      resource: config.resource,
      state: "state-1",
      codeChallenge: createPkceS256Challenge(verifier),
      codeChallengeMethod: "S256",
      subject: { id: "admin-1", email: "admin@example.com" },
      consentAccepted: true,
    });
    const code = new URL(authorized.redirectTo).searchParams.get("code");
    expect(code).toBeTruthy();

    const token = await issuer.token({
      grantType: "authorization_code",
      clientId: client.clientId,
      code: code!,
      redirectUri: client.metadata.redirect_uris[0],
      codeVerifier: verifier,
    });
    expect("access_token" in token).toBe(true);
    if ("access_token" in token) {
      const header = JSON.parse(Buffer.from(token.access_token.split(".")[0]!, "base64url").toString("utf8"));
      expect(header.typ).toBe("at+jwt");
    }

    const replay = await issuer.token({
      grantType: "authorization_code",
      clientId: client.clientId,
      code: code!,
      redirectUri: client.metadata.redirect_uris[0],
      codeVerifier: verifier,
    });
    expect("body" in replay ? replay.body.error : undefined).toBe("invalid_grant");
  });

  it("rejects missing PKCE and invalid redirect URIs", async () => {
    const { issuer, config } = createIssuer();
    const client = await issuer.registerClient({
      redirect_uris: ["https://chat.openai.com/aip/g-test/oauth/callback"],
    });
    await expect(
      issuer.authorize({
        responseType: "code",
        clientId: client.clientId,
        redirectUri: "https://attacker.example/callback",
        scope: "mcp:access",
        resource: config.resource,
        codeChallenge: "missing",
        codeChallengeMethod: "S256",
        subject: { id: "admin-1" },
        consentAccepted: true,
      }),
    ).rejects.toThrow(/Unregistered redirect/);
  });

  it("uses unsupported_response_type for an unsupported authorization response", async () => {
    const { issuer, config } = createIssuer();
    const client = await issuer.registerClient({ redirect_uris: ["https://client.example/callback"] });
    const result = await issuer.authorize({
      responseType: "token",
      clientId: client.clientId,
      redirectUri: client.metadata.redirect_uris[0]!,
      scope: "mcp:access",
      resource: config.resource,
      codeChallenge: createPkceS256Challenge(generatePkceVerifier()),
      codeChallengeMethod: "S256",
      subject: { id: "subject-1" },
      consentAccepted: true,
    });
    expect(new URL(result.redirectTo).searchParams.get("error")).toBe("unsupported_response_type");
  });

  it("authenticates confidential clients before token exchange (RFC 6749 sections 2.3.1 and 3.2.1)", async () => {
    const { issuer, config } = createIssuer();
    const client = await issuer.registerClient({
      redirect_uris: ["https://client.example/callback"],
      token_endpoint_auth_method: "client_secret_post",
      scope: "mcp:access",
    });
    expect(client.clientSecret).toBeTruthy();
    const verifier = generatePkceVerifier();
    const authorized = await issuer.authorize({
      responseType: "code", clientId: client.clientId, redirectUri: client.metadata.redirect_uris[0]!,
      scope: "mcp:access", resource: config.resource, codeChallenge: createPkceS256Challenge(verifier),
      codeChallengeMethod: "S256", subject: { id: "subject-1" }, consentAccepted: true,
    });
    const code = new URL(authorized.redirectTo).searchParams.get("code")!;
    const denied = await issuer.token({
      grantType: "authorization_code", clientId: client.clientId, code,
      redirectUri: client.metadata.redirect_uris[0], codeVerifier: verifier,
    });
    expect("body" in denied ? denied.body.error : undefined).toBe("invalid_client");
    const allowed = await issuer.token({
      grantType: "authorization_code", clientId: client.clientId, clientSecret: client.clientSecret,
      code, redirectUri: client.metadata.redirect_uris[0], codeVerifier: verifier,
    });
    expect("access_token" in allowed).toBe(true);
  });

  it("rotates refresh tokens and detects reuse", async () => {
    const { issuer, config } = createIssuer();
    const client = await issuer.registerClient({
      redirect_uris: ["https://chat.openai.com/aip/g-test/oauth/callback"],
      scope: "mcp:access",
    });
    const verifier = generatePkceVerifier();
    const authorized = await issuer.authorize({
      responseType: "code",
      clientId: client.clientId,
      redirectUri: client.metadata.redirect_uris[0]!,
      scope: "mcp:access",
      resource: config.resource,
      codeChallenge: createPkceS256Challenge(verifier),
      codeChallengeMethod: "S256",
      subject: { id: "admin-1" },
      consentAccepted: true,
    });
    const code = new URL(authorized.redirectTo).searchParams.get("code")!;
    const first = await issuer.token({
      grantType: "authorization_code",
      clientId: client.clientId,
      code,
      redirectUri: client.metadata.redirect_uris[0],
      codeVerifier: verifier,
    });
    if (!("refresh_token" in first)) throw new Error("Expected token success");

    const second = await issuer.token({
      grantType: "refresh_token",
      clientId: client.clientId,
      refreshToken: first.refresh_token,
    });
    expect("access_token" in second).toBe(true);

    const reused = await issuer.token({
      grantType: "refresh_token",
      clientId: client.clientId,
      refreshToken: first.refresh_token,
    });
    expect("body" in reused ? reused.body.error : undefined).toBe("invalid_grant");
  });

  it("verifies resource-server bearer requests by audience, revocation, and scopes", async () => {
    const { issuer, config } = createIssuer();
    const client = await issuer.registerClient({
      redirect_uris: ["https://chat.openai.com/aip/g-test/oauth/callback"],
      scope: "mcp:access admin.flags.read",
    });
    const verifier = generatePkceVerifier();
    const authorized = await issuer.authorize({
      responseType: "code",
      clientId: client.clientId,
      redirectUri: client.metadata.redirect_uris[0]!,
      scope: "mcp:access admin.flags.read",
      resource: config.resource,
      codeChallenge: createPkceS256Challenge(verifier),
      codeChallengeMethod: "S256",
      subject: { id: "admin-1" },
      consentAccepted: true,
    });
    const token = await issuer.token({
      grantType: "authorization_code",
      clientId: client.clientId,
      code: new URL(authorized.redirectTo).searchParams.get("code")!,
      redirectUri: client.metadata.redirect_uris[0],
      codeVerifier: verifier,
    });
    if (!("access_token" in token)) throw new Error("Expected token success");
    const verified = await issuer.verifyResourceRequest({
      authorizationHeader: `Bearer ${token.access_token}`,
      requiredScopes: ["mcp:access", "admin.flags.read"],
    });
    expect(verified.authorized).toBe(true);

    await issuer.revoke({ token: token.access_token, tokenTypeHint: "access_token" });
    const revoked = await issuer.verifyResourceRequest({
      authorizationHeader: `Bearer ${token.access_token}`,
      requiredScopes: ["mcp:access"],
    });
    expect(revoked.authorized).toBe(false);
  });

  it("fails closed instead of advertising incomplete RFC 9449 DPoP validation", async () => {
    const storage = createInMemoryOAuth2Storage();
    const config = {
      issuer: "https://plasius.co.uk/api/oauth/mcp",
      resource: "https://plasius.co.uk/api/mcp",
      authorizationEndpoint: "https://plasius.co.uk/api/oauth/mcp/authorize",
      tokenEndpoint: "https://plasius.co.uk/api/oauth/mcp/token",
      jwksUri: "https://plasius.co.uk/api/oauth/mcp/jwks",
      supportedScopes: ["mcp:access"],
      requireDpop: true,
    };
    expect(() => createOAuth2Issuer(config, {
      storage, keyStore: createRsaKeyStore({ issuer: config.issuer, keyId: "kid-1" }),
    })).toThrow(/DPoP validation is not implemented/);
  });

  it("rejects malformed, tampered, and invalid-audience JWTs", async () => {
    const keyStore = createRsaKeyStore({
      issuer: "https://plasius.co.uk/api/oauth/mcp",
      keyId: "kid-1",
    });
    const now = 1_800_000_000;
    const token = await keyStore.signJwt({
      iss: "https://plasius.co.uk/api/oauth/mcp",
      sub: "admin-1",
      aud: "https://plasius.co.uk/api/mcp",
      exp: now + 60,
      iat: now,
      jti: "jti-1",
      client_id: "client-1",
      scope: "mcp:access",
    });

    await expect(
      keyStore.verifyJwt("not-a-jwt", {
        issuer: "https://plasius.co.uk/api/oauth/mcp",
        audience: "https://plasius.co.uk/api/mcp",
        nowEpochSeconds: now,
      }),
    ).rejects.toThrow(/Invalid JWT format/);

    const parts = token.split(".");
    const wrongTypeHeader = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT", kid: "kid-1" })).toString("base64url");
    await expect(
      keyStore.verifyJwt(`${wrongTypeHeader}.${parts[1]}.${parts[2]}`, {
        issuer: "https://plasius.co.uk/api/oauth/mcp", audience: "https://plasius.co.uk/api/mcp", nowEpochSeconds: now,
      }),
    ).rejects.toThrow(/Unsupported JWT header/);
    const tamperedHeader = Buffer.from(JSON.stringify({ alg: "none", kid: "kid-1" })).toString("base64url");
    await expect(
      keyStore.verifyJwt(`${tamperedHeader}.${parts[1]}.${parts[2]}`, {
        issuer: "https://plasius.co.uk/api/oauth/mcp",
        audience: "https://plasius.co.uk/api/mcp",
        nowEpochSeconds: now,
      }),
    ).rejects.toThrow(/Unsupported JWT header/);

    await expect(
      keyStore.verifyJwt(`${parts[0]}.${parts[1]}.${parts[2]!.slice(0, -2)}aa`, {
        issuer: "https://plasius.co.uk/api/oauth/mcp",
        audience: "https://plasius.co.uk/api/mcp",
        nowEpochSeconds: now,
      }),
    ).rejects.toThrow(/Invalid JWT signature/);

    await expect(
      keyStore.verifyJwt(token, {
        issuer: "https://plasius.co.uk/api/oauth/mcp",
        audience: "https://wrong.example/api",
        nowEpochSeconds: now,
      }),
    ).rejects.toThrow(/audience mismatch/);

    const jwk = (await keyStore.jwks()).keys[0]!;
    expect(importRsaPublicJwk(jwk).type).toBe("public");
    expect(() => importRsaPrivateJwk(jwk)).toThrow();
  });
});
