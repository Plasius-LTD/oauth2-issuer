import {
  createPrivateKey,
  createPublicKey,
  createHash,
  createSign,
  createVerify,
  generateKeyPairSync,
  randomBytes,
  randomUUID,
  type KeyObject,
} from "node:crypto";
import {
  base64UrlEncode,
  buildAuthorizationServerMetadata,
  buildBearerChallenge,
  buildProtectedResourceMetadata,
  buildTokenErrorResponse,
  createPkceS256Challenge,
  parseScopeString,
  scopesContainAll,
  validateClientMetadata,
  validateJwtAccessTokenClaims,
  validateRedirectUri,
  verifyPkceS256Challenge,
  type OAuth2AuthorizationServerMetadata,
  type OAuth2ClientMetadata,
  type OAuth2ErrorCode,
  type OAuth2JwtAccessTokenClaims,
  type OAuth2ProtectedResourceMetadata,
  type OAuth2TokenErrorResponse,
} from "@plasius/oauth2-core";

export const OAUTH2_ISSUER_PACKAGE = "@plasius/oauth2-issuer";

export interface OAuth2Subject {
  id: string;
  displayName?: string;
  email?: string;
  groups?: readonly string[];
}

export interface OAuth2RegisteredClient {
  clientId: string;
  clientSecretHash?: string;
  metadata: OAuth2ClientMetadata;
  createdAtEpochSeconds: number;
}

export interface OAuth2AuthorizationCodeGrant {
  code: string;
  clientId: string;
  redirectUri: string;
  resource: string;
  scope: string;
  subject: OAuth2Subject;
  codeChallenge: string;
  codeChallengeMethod: "S256";
  expiresAtEpochSeconds: number;
  consumedAtEpochSeconds?: number;
}

export interface OAuth2RefreshGrant {
  refreshToken: string;
  clientId: string;
  resource: string;
  scope: string;
  subject: OAuth2Subject;
  expiresAtEpochSeconds: number;
  revokedAtEpochSeconds?: number;
  rotatedFrom?: string;
}

export interface OAuth2StoragePort {
  saveClient(client: OAuth2RegisteredClient): Promise<void>;
  getClient(clientId: string): Promise<OAuth2RegisteredClient | null>;
  saveAuthorizationCode(grant: OAuth2AuthorizationCodeGrant): Promise<void>;
  getAuthorizationCode(code: string): Promise<OAuth2AuthorizationCodeGrant | null>;
  consumeAuthorizationCode(code: string, consumedAtEpochSeconds: number): Promise<boolean>;
  saveRefreshGrant(grant: OAuth2RefreshGrant): Promise<void>;
  getRefreshGrant(refreshToken: string): Promise<OAuth2RefreshGrant | null>;
  revokeRefreshGrant(refreshToken: string, revokedAtEpochSeconds: number): Promise<void>;
  revokeAccessTokenJti(jti: string, revokedAtEpochSeconds: number): Promise<void>;
  isAccessTokenJtiRevoked(jti: string): Promise<boolean>;
}

export interface OAuth2AuditPort {
  record(event: {
    type: string;
    status: "succeeded" | "denied" | "failed";
    subjectId?: string;
    clientId?: string;
    resource?: string;
    reasonCode?: string;
    metadata?: Record<string, unknown>;
  }): Promise<void>;
}

export interface OAuth2KeyStorePort {
  currentKid(): string;
  jwks(): Promise<{ keys: JsonWebKey[] }>;
  signJwt(claims: OAuth2JwtAccessTokenClaims): Promise<string>;
  verifyJwt(token: string, options: {
    issuer: string;
    audience: string;
    nowEpochSeconds: number;
  }): Promise<OAuth2JwtAccessTokenClaims>;
}

export interface OAuth2IssuerConfig {
  issuer: string;
  resource: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
  registrationEndpoint?: string;
  revocationEndpoint?: string;
  supportedScopes: readonly string[];
  accessTokenTtlSeconds?: number;
  refreshTokenTtlSeconds?: number;
  authorizationCodeTtlSeconds?: number;
  requireDpop?: boolean;
}

export interface OAuth2IssuerPorts {
  storage: OAuth2StoragePort;
  keyStore: OAuth2KeyStorePort;
  audit?: OAuth2AuditPort;
  clock?: () => Date;
  randomId?: (prefix: string) => string;
}

export interface OAuth2AuthorizeInput {
  responseType: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  resource: string;
  state?: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  subject: OAuth2Subject;
  consentAccepted: boolean;
}

export interface OAuth2TokenInput {
  grantType: string;
  clientId: string;
  code?: string;
  redirectUri?: string;
  codeVerifier?: string;
  refreshToken?: string;
  resource?: string;
}

export interface OAuth2TokenSuccess {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  refresh_token?: string;
  scope: string;
}

export interface OAuth2VerificationSuccess {
  authorized: true;
  claims: OAuth2JwtAccessTokenClaims;
  scopes: string[];
  subject: OAuth2Subject;
}

export interface OAuth2VerificationFailure {
  authorized: false;
  status: 401 | 403;
  challenge: string;
  reasonCode: string;
}

export type OAuth2VerificationResult = OAuth2VerificationSuccess | OAuth2VerificationFailure;

const DEFAULT_ACCESS_TTL_SECONDS = 5 * 60;
const DEFAULT_REFRESH_TTL_SECONDS = 60 * 60 * 24 * 30;
const DEFAULT_CODE_TTL_SECONDS = 5 * 60;

function nowSeconds(clock: () => Date): number {
  return Math.floor(clock().getTime() / 1000);
}

function secureId(prefix: string): string {
  return `${prefix}_${randomBytes(32).toString("base64url")}`;
}

function supportedScopeSet(scopes: readonly string[]): Set<string> {
  return new Set(scopes);
}

function assertSupportedScopes(scope: string, supportedScopes: readonly string[]): string {
  const requested = parseScopeString(scope);
  const supported = supportedScopeSet(supportedScopes);
  const unsupported = requested.filter((item) => !supported.has(item));
  if (unsupported.length > 0) {
    throw oauthError("invalid_scope", `Unsupported scope: ${unsupported.join(", ")}`);
  }
  return requested.join(" ");
}

function oauthError(error: OAuth2ErrorCode, message: string): Error & { oauthError: OAuth2ErrorCode } {
  const err = new Error(message) as Error & { oauthError: OAuth2ErrorCode };
  err.oauthError = error;
  return err;
}

function toTokenError(error: unknown): OAuth2TokenErrorResponse {
  if (error && typeof error === "object" && "oauthError" in error) {
    const oauth = error as Error & { oauthError: OAuth2ErrorCode };
    return buildTokenErrorResponse({
      error: oauth.oauthError,
      errorDescription: oauth.message,
    });
  }
  return buildTokenErrorResponse({
    error: "server_error",
    status: 500,
    errorDescription: "OAuth issuer failed to process the request.",
  });
}

function buildClientSecretHash(secret: string): string {
  return base64UrlEncode(createHash("sha256").update(secret).digest());
}

function isRegisteredRedirect(client: OAuth2RegisteredClient, redirectUri: string): boolean {
  return client.metadata.redirect_uris.includes(redirectUri);
}

function appendRedirectError(redirectUri: string, error: OAuth2ErrorCode, state?: string): string {
  const url = new URL(redirectUri);
  url.searchParams.set("error", error);
  if (state) url.searchParams.set("state", state);
  return url.toString();
}

function appendAuthorizationCode(redirectUri: string, code: string, state?: string): string {
  const url = new URL(redirectUri);
  url.searchParams.set("code", code);
  if (state) url.searchParams.set("state", state);
  return url.toString();
}

export function createOAuth2Issuer(config: OAuth2IssuerConfig, ports: OAuth2IssuerPorts) {
  const clock = ports.clock ?? (() => new Date());
  const randomId = ports.randomId ?? secureId;
  const accessTokenTtlSeconds = config.accessTokenTtlSeconds ?? DEFAULT_ACCESS_TTL_SECONDS;
  const refreshTokenTtlSeconds = config.refreshTokenTtlSeconds ?? DEFAULT_REFRESH_TTL_SECONDS;
  const authorizationCodeTtlSeconds =
    config.authorizationCodeTtlSeconds ?? DEFAULT_CODE_TTL_SECONDS;

  async function audit(input: Parameters<OAuth2AuditPort["record"]>[0]): Promise<void> {
    await ports.audit?.record(input);
  }

  async function registerClient(metadata: OAuth2ClientMetadata): Promise<OAuth2RegisteredClient & {
    clientSecret?: string;
  }> {
    const validation = validateClientMetadata(metadata);
    if (!validation.valid) {
      throw oauthError("invalid_request", validation.errors.join("; "));
    }
    const grantTypes = metadata.grant_types ?? ["authorization_code", "refresh_token"];
    if (grantTypes.includes("client_credentials")) {
      throw oauthError("unauthorized_client", "Client credentials grant is disabled by default.");
    }
    const clientId = metadata.client_id ?? randomId("client");
    const authMethod = metadata.token_endpoint_auth_method ?? "none";
    const clientSecret = authMethod === "none" ? undefined : randomId("secret");
    const client: OAuth2RegisteredClient = {
      clientId,
      ...(clientSecret ? { clientSecretHash: buildClientSecretHash(clientSecret) } : {}),
      metadata: {
        ...metadata,
        client_id: clientId,
        grant_types: grantTypes,
        response_types: metadata.response_types ?? ["code"],
        token_endpoint_auth_method: authMethod,
      },
      createdAtEpochSeconds: nowSeconds(clock),
    };
    await ports.storage.saveClient(client);
    await audit({ type: "oauth.client.register", status: "succeeded", clientId });
    return { ...client, ...(clientSecret ? { clientSecret } : {}) };
  }

  async function authorize(input: OAuth2AuthorizeInput): Promise<{ redirectTo: string }> {
    const client = await ports.storage.getClient(input.clientId);
    if (!client) {
      throw oauthError("unauthorized_client", "Unknown OAuth client.");
    }
    if (!isRegisteredRedirect(client, input.redirectUri)) {
      throw oauthError("invalid_request", "Unregistered redirect_uri.");
    }
    if (!validateRedirectUri(input.redirectUri).valid) {
      throw oauthError("invalid_request", "Invalid redirect_uri.");
    }
    if (input.responseType !== "code") {
      return { redirectTo: appendRedirectError(input.redirectUri, "unsupported_grant_type", input.state) };
    }
    if (input.codeChallengeMethod !== "S256" || !input.codeChallenge) {
      return { redirectTo: appendRedirectError(input.redirectUri, "invalid_request", input.state) };
    }
    if (input.resource !== config.resource) {
      return { redirectTo: appendRedirectError(input.redirectUri, "invalid_request", input.state) };
    }
    if (!input.consentAccepted) {
      return { redirectTo: appendRedirectError(input.redirectUri, "access_denied", input.state) };
    }
    const scope = assertSupportedScopes(input.scope, config.supportedScopes);
    const code = randomId("code");
    await ports.storage.saveAuthorizationCode({
      code,
      clientId: client.clientId,
      redirectUri: input.redirectUri,
      resource: input.resource,
      scope,
      subject: input.subject,
      codeChallenge: input.codeChallenge,
      codeChallengeMethod: "S256",
      expiresAtEpochSeconds: nowSeconds(clock) + authorizationCodeTtlSeconds,
    });
    await audit({
      type: "oauth.authorize",
      status: "succeeded",
      subjectId: input.subject.id,
      clientId: client.clientId,
      resource: input.resource,
      metadata: { scope },
    });
    return { redirectTo: appendAuthorizationCode(input.redirectUri, code, input.state) };
  }

  async function issueTokens(input: {
    clientId: string;
    resource: string;
    scope: string;
    subject: OAuth2Subject;
    rotatedFrom?: string;
  }): Promise<OAuth2TokenSuccess> {
    const issuedAt = nowSeconds(clock);
    const expiresAt = issuedAt + accessTokenTtlSeconds;
    const jti = randomId("jti");
    const refreshToken = randomId("refresh");
    const claims: OAuth2JwtAccessTokenClaims = {
      iss: config.issuer,
      sub: input.subject.id,
      aud: input.resource,
      exp: expiresAt,
      iat: issuedAt,
      nbf: issuedAt,
      jti,
      client_id: input.clientId,
      scope: input.scope,
    };
    const accessToken = await ports.keyStore.signJwt(claims);
    await ports.storage.saveRefreshGrant({
      refreshToken,
      clientId: input.clientId,
      resource: input.resource,
      scope: input.scope,
      subject: input.subject,
      expiresAtEpochSeconds: issuedAt + refreshTokenTtlSeconds,
      ...(input.rotatedFrom ? { rotatedFrom: input.rotatedFrom } : {}),
    });
    return {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: accessTokenTtlSeconds,
      refresh_token: refreshToken,
      scope: input.scope,
    };
  }

  async function token(input: OAuth2TokenInput): Promise<OAuth2TokenSuccess | OAuth2TokenErrorResponse> {
    try {
      const client = await ports.storage.getClient(input.clientId);
      if (!client) {
        throw oauthError("invalid_client", "Unknown OAuth client.");
      }
      if (input.grantType === "authorization_code") {
        if (!input.code || !input.redirectUri || !input.codeVerifier) {
          throw oauthError("invalid_request", "Authorization code, redirect_uri, and code_verifier are required.");
        }
        const grant = await ports.storage.getAuthorizationCode(input.code);
        const current = nowSeconds(clock);
        if (!grant || grant.clientId !== input.clientId || grant.redirectUri !== input.redirectUri) {
          throw oauthError("invalid_grant", "Invalid authorization code grant.");
        }
        if (grant.consumedAtEpochSeconds || grant.expiresAtEpochSeconds <= current) {
          throw oauthError("invalid_grant", "Authorization code has expired or was already used.");
        }
        if (!verifyPkceS256Challenge({ verifier: input.codeVerifier, challenge: grant.codeChallenge })) {
          throw oauthError("invalid_grant", "PKCE verification failed.");
        }
        const consumed = await ports.storage.consumeAuthorizationCode(input.code, current);
        if (!consumed) {
          throw oauthError("invalid_grant", "Authorization code was already consumed.");
        }
        await audit({
          type: "oauth.token.authorization-code",
          status: "succeeded",
          subjectId: grant.subject.id,
          clientId: input.clientId,
          resource: grant.resource,
        });
        return issueTokens({
          clientId: input.clientId,
          resource: grant.resource,
          scope: grant.scope,
          subject: grant.subject,
        });
      }
      if (input.grantType === "refresh_token") {
        if (!input.refreshToken) {
          throw oauthError("invalid_request", "refresh_token is required.");
        }
        const grant = await ports.storage.getRefreshGrant(input.refreshToken);
        const current = nowSeconds(clock);
        if (!grant || grant.clientId !== input.clientId || grant.expiresAtEpochSeconds <= current) {
          throw oauthError("invalid_grant", "Invalid refresh token grant.");
        }
        if (grant.revokedAtEpochSeconds) {
          await audit({
            type: "oauth.refresh.reuse",
            status: "denied",
            subjectId: grant.subject.id,
            clientId: grant.clientId,
            resource: grant.resource,
            reasonCode: "refresh-token-reuse",
          });
          throw oauthError("invalid_grant", "Refresh token was already used or revoked.");
        }
        await ports.storage.revokeRefreshGrant(input.refreshToken, current);
        await audit({
          type: "oauth.token.refresh",
          status: "succeeded",
          subjectId: grant.subject.id,
          clientId: grant.clientId,
          resource: grant.resource,
        });
        return issueTokens({
          clientId: grant.clientId,
          resource: grant.resource,
          scope: grant.scope,
          subject: grant.subject,
          rotatedFrom: input.refreshToken,
        });
      }
      throw oauthError("unsupported_grant_type", "Only authorization_code and refresh_token grants are enabled.");
    } catch (error) {
      await audit({
        type: "oauth.token",
        status: "denied",
        clientId: input.clientId,
        reasonCode: error instanceof Error ? error.message : "token-denied",
      });
      return toTokenError(error);
    }
  }

  async function revoke(input: { token: string; tokenTypeHint?: "access_token" | "refresh_token" }): Promise<void> {
    const current = nowSeconds(clock);
    if (input.tokenTypeHint === "refresh_token" || input.token.startsWith("refresh_")) {
      await ports.storage.revokeRefreshGrant(input.token, current);
      return;
    }
    try {
      const claims = await ports.keyStore.verifyJwt(input.token, {
        issuer: config.issuer,
        audience: config.resource,
        nowEpochSeconds: current,
      });
      await ports.storage.revokeAccessTokenJti(claims.jti, current);
    } catch {
      return;
    }
  }

  async function verifyResourceRequest(input: {
    authorizationHeader?: string | null;
    requiredScopes?: readonly string[];
    dpopProof?: string;
  }): Promise<OAuth2VerificationResult> {
    const challenge = (error: OAuth2ErrorCode, reasonCode: string, status: 401 | 403 = 401): OAuth2VerificationFailure => ({
      authorized: false,
      status,
      reasonCode,
      challenge: buildBearerChallenge({
        resourceMetadataUrl: `${config.resource.replace(/\/+$/u, "")}/.well-known/oauth-protected-resource`,
        error,
        scope: input.requiredScopes,
      }),
    });
    const raw = input.authorizationHeader;
    if (!raw?.startsWith("Bearer ")) {
      return challenge("invalid_token", "missing-bearer-token");
    }
    try {
      const claims = await ports.keyStore.verifyJwt(raw.slice("Bearer ".length).trim(), {
        issuer: config.issuer,
        audience: config.resource,
        nowEpochSeconds: nowSeconds(clock),
      });
      const validation = validateJwtAccessTokenClaims(claims, {
        issuer: config.issuer,
        audience: config.resource,
        nowEpochSeconds: nowSeconds(clock),
      });
      if (!validation.valid) {
        return challenge("invalid_token", validation.errors.join("; "));
      }
      if (await ports.storage.isAccessTokenJtiRevoked(claims.jti)) {
        return challenge("invalid_token", "revoked-access-token");
      }
      if (config.requireDpop && (!claims.cnf?.jkt || !input.dpopProof)) {
        return challenge("invalid_token", "missing-dpop-proof");
      }
      if (input.requiredScopes?.length && !scopesContainAll(claims.scope ?? "", input.requiredScopes)) {
        return challenge("insufficient_scope", "insufficient-scope", 403);
      }
      return {
        authorized: true,
        claims,
        scopes: parseScopeString(claims.scope),
        subject: { id: claims.sub },
      };
    } catch {
      return challenge("invalid_token", "invalid-token");
    }
  }

  function authorizationServerMetadata(): OAuth2AuthorizationServerMetadata {
    return buildAuthorizationServerMetadata({
      issuer: config.issuer,
      authorizationEndpoint: config.authorizationEndpoint,
      tokenEndpoint: config.tokenEndpoint,
      jwksUri: config.jwksUri,
      registrationEndpoint: config.registrationEndpoint,
      revocationEndpoint: config.revocationEndpoint,
      scopesSupported: config.supportedScopes,
      dpopSigningAlgValuesSupported: config.requireDpop ? ["ES256", "RS256"] : undefined,
    });
  }

  function protectedResourceMetadata(): OAuth2ProtectedResourceMetadata {
    return buildProtectedResourceMetadata({
      resource: config.resource,
      authorizationServers: [config.issuer],
      jwksUri: config.jwksUri,
      scopesSupported: config.supportedScopes,
      resourceName: "Plasius MCP",
      dpopSigningAlgValuesSupported: config.requireDpop ? ["ES256", "RS256"] : undefined,
      dpopBoundAccessTokensRequired: config.requireDpop,
    });
  }

  return {
    authorizationServerMetadata,
    protectedResourceMetadata,
    registerClient,
    authorize,
    token,
    revoke,
    verifyResourceRequest,
    jwks: () => ports.keyStore.jwks(),
  };
}

export function createInMemoryOAuth2Storage(): OAuth2StoragePort {
  const clients = new Map<string, OAuth2RegisteredClient>();
  const codes = new Map<string, OAuth2AuthorizationCodeGrant>();
  const refreshGrants = new Map<string, OAuth2RefreshGrant>();
  const revokedJtis = new Set<string>();
  return {
    async saveClient(client) {
      clients.set(client.clientId, client);
    },
    async getClient(clientId) {
      return clients.get(clientId) ?? null;
    },
    async saveAuthorizationCode(grant) {
      codes.set(grant.code, grant);
    },
    async getAuthorizationCode(code) {
      return codes.get(code) ?? null;
    },
    async consumeAuthorizationCode(code, consumedAtEpochSeconds) {
      const grant = codes.get(code);
      if (!grant || grant.consumedAtEpochSeconds) return false;
      codes.set(code, { ...grant, consumedAtEpochSeconds });
      return true;
    },
    async saveRefreshGrant(grant) {
      refreshGrants.set(grant.refreshToken, grant);
    },
    async getRefreshGrant(refreshToken) {
      return refreshGrants.get(refreshToken) ?? null;
    },
    async revokeRefreshGrant(refreshToken, revokedAtEpochSeconds) {
      const grant = refreshGrants.get(refreshToken);
      if (grant) refreshGrants.set(refreshToken, { ...grant, revokedAtEpochSeconds });
    },
    async revokeAccessTokenJti(jti) {
      revokedJtis.add(jti);
    },
    async isAccessTokenJtiRevoked(jti) {
      return revokedJtis.has(jti);
    },
  };
}

function encodeJson(value: unknown): string {
  return base64UrlEncode(JSON.stringify(value));
}

function decodeJsonSegment(segment: string): Record<string, unknown> {
  const padded = segment.padEnd(segment.length + ((4 - (segment.length % 4)) % 4), "=");
  return JSON.parse(Buffer.from(padded.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8")) as Record<string, unknown>;
}

export function createRsaKeyStore(options: {
  issuer: string;
  keyId?: string;
  now?: () => Date;
}): OAuth2KeyStorePort {
  const kid = options.keyId ?? randomUUID();
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  const publicJwk = publicKey.export({ format: "jwk" }) as JsonWebKey;
  return {
    currentKid() {
      return kid;
    },
    async jwks() {
      return {
        keys: [
          {
            ...publicJwk,
            kid,
            use: "sig",
            alg: "RS256",
          },
        ],
      };
    },
    async signJwt(claims) {
      const header = { alg: "RS256", typ: "JWT", kid };
      const signingInput = `${encodeJson(header)}.${encodeJson(claims)}`;
      const signature = createSign("RSA-SHA256").update(signingInput).sign(privateKey);
      return `${signingInput}.${base64UrlEncode(signature)}`;
    },
    async verifyJwt(token, verifyOptions) {
      const [encodedHeader, encodedPayload, encodedSignature] = token.split(".");
      if (!encodedHeader || !encodedPayload || !encodedSignature) {
        throw new Error("Invalid JWT format.");
      }
      const header = decodeJsonSegment(encodedHeader);
      if (header.alg !== "RS256" || header.kid !== kid) {
        throw new Error("Unsupported JWT header.");
      }
      const signature = Buffer.from(
        encodedSignature.padEnd(encodedSignature.length + ((4 - (encodedSignature.length % 4)) % 4), "=")
          .replace(/-/g, "+")
          .replace(/_/g, "/"),
        "base64",
      );
      const ok = createVerify("RSA-SHA256")
        .update(`${encodedHeader}.${encodedPayload}`)
        .verify(publicKey, signature);
      if (!ok) {
        throw new Error("Invalid JWT signature.");
      }
      const claims = decodeJsonSegment(encodedPayload) as unknown as OAuth2JwtAccessTokenClaims;
      const validation = validateJwtAccessTokenClaims(claims, verifyOptions);
      if (!validation.valid) {
        throw new Error(validation.errors.join("; "));
      }
      return claims;
    },
  };
}

export function importRsaPublicJwk(jwk: JsonWebKey): KeyObject {
  return createPublicKey({ key: jwk, format: "jwk" });
}

export function importRsaPrivateJwk(jwk: JsonWebKey): KeyObject {
  return createPrivateKey({ key: jwk, format: "jwk" });
}

export const packageDescriptor = Object.freeze({
  name: OAUTH2_ISSUER_PACKAGE,
  version: "0.1.0",
  summary:
    "Zero-trust OAuth 2.1 authorization-server and resource-server engine with injected persistence and key-management ports.",
});
