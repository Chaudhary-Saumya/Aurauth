import type { RequestHandler, Router, Request } from 'express';

export interface PublicUser {
  id: string; email: string; roles: string[]; emailVerified: boolean; createdAt?: Date; providers?: string[]; [customField: string]: unknown;
}
export interface Hasher {
  name?: string; maxBytes?: number;
  hash(plain: string): Promise<string>;
  verify(plain: string, hash: string): Promise<boolean>;
  needsRehash?(hash: string): boolean | Promise<boolean>;
}
export interface Signer {
  sign(claims: Record<string, unknown>, opts: { expiresInSeconds: number }): Promise<string>;
  verify(token: string): Promise<Record<string, any>>;
}
export interface MailMessage { to: string; type: 'verify' | 'reset'; subject: string; text: string; html: string; url: string; token: string }
export interface Mailer { send(message: MailMessage): Promise<unknown> | unknown }
export interface RateLimiter { hit(key: string, rule: { max: number; windowMs: number }): Promise<{ allowed: boolean; retryAfterSec: number }>; close?(): void }
export interface HookContext { req?: Request }

export interface Identity {
  id: string;
  userId: string;
  provider: string;
  providerId: string;
  email?: string;
  createdAt?: Date;
}

/** Field shorthand types: "string", "number", "boolean", "date", "url", "phone" */
export type FieldType = 'string' | 'number' | 'boolean' | 'date' | 'url' | 'phone';
/** Shorthand field definitions: "string required unique" or { type: "string", required: true, unique: true } */
export type FieldShorthand = `${FieldType}${'' | ` ${string}`}` | { type: FieldType; required?: boolean; unique?: boolean; lowercase?: boolean; register?: boolean; [mongooseOpt: string]: unknown };
/** Field definition: native Mongoose schema OR shorthand */
export type FieldDefinition = FieldShorthand | { type: unknown; [key: string]: unknown };

export interface GoogleProviderConfig {
  clientId: string;
  clientSecret?: string;
  redirectUri?: string;
  successRedirect?: string;
  errorRedirect?: string;
  linkExistingAccounts?: boolean;
  allowedDomains?: string[];
  /** Injectable fetch function for testing (defaults to global fetch) */
  fetch?: typeof globalThis.fetch;
  /** Injectable JWKS for testing (defaults to Google's remote JWKS) */
  jwks?: any;
}

export interface ProvidersConfig {
  google?: GoogleProviderConfig;
}

export interface AuthConfig {
  secret?: string | string[];
  database: string | 'memory' | { url?: string; connection?: unknown; store?: unknown; connectOptions?: object; mongoose?: unknown };
  appName?: string; appUrl?: string; frontendUrl?: string; basePath?: string;
  roles?: string[] | { list: string[]; default: string };
  user?: { fields?: Record<string, FieldDefinition>; registerFields?: string[] };
  fields?: Record<string, FieldDefinition>;
  password?: 'bcrypt' | 'argon2' | 'scrypt' | `bcrypt:${number}` | { hasher?: Hasher | 'bcrypt' | 'argon2' | 'scrypt' | `bcrypt:${number}`; minLength?: number; maxLength?: number; validate?(pw: string, ctx: { email: string | null }): boolean | string | void | Promise<boolean | string | void> };
  tokens?: 'jsonwebtoken' | { accessTtl?: string | number; refreshTtl?: string | number; absoluteTtl?: string | number; issuer?: string; audience?: string; adapter?: Signer | 'jsonwebtoken' };
  session?: { transport?: 'cookie' | 'bearer' | 'both'; checkOnRequest?: boolean; loadUser?: boolean; refreshReuseGrace?: string | number;
    cookies?: { prefix?: string; sameSite?: 'lax' | 'strict' | 'none'; secure?: boolean; domain?: string } };
  emailVerification?: { enabled?: boolean; required?: boolean; ttl?: string | number; url?(token: string): string };
  passwordReset?: { enabled?: boolean; ttl?: string | number; url?(token: string): string };
  email?: Mailer | ((m: MailMessage) => Promise<unknown> | unknown);
  registration?: { enabled?: boolean; autoLogin?: boolean };
  lockout?: { maxAttempts?: number; duration?: string | number };
  rateLimit?: false | { limiter?: RateLimiter; rules?: Record<string, { max: number; windowMs: number }> };
  security?: { trustedOrigins?: string[] };
  use?: RequestHandler[];
  routeMiddleware?: Partial<Record<string, RequestHandler[]>>;
  routes?: Partial<Record<string, boolean>>;
  hooks?: {
    beforeRegister?(ctx: HookContext & { email: string; fields: Record<string, unknown> }): unknown;
    afterRegister?(ctx: HookContext & { user: PublicUser; provider?: string }): unknown;
    afterLogin?(ctx: HookContext & { user: PublicUser; provider?: string }): unknown;
    onLoginFailed?(ctx: HookContext & { email: string }): unknown;
    onRefreshReuse?(ctx: HookContext & { userId: string }): unknown;
    afterPasswordReset?(ctx: HookContext & { user: PublicUser }): unknown;
    afterEmailVerified?(ctx: HookContext & { user: PublicUser }): unknown;
    beforeProfileUpdate?(ctx: HookContext & { user: PublicUser; fields: Record<string, unknown> }): unknown;
    beforeAccountDelete?(ctx: HookContext & { user: PublicUser }): unknown;
  };
  seedUsers?: Array<{ email: string; password: string; roles?: string[]; emailVerified?: boolean; [field: string]: unknown }>;
  logger?: { info(...a: unknown[]): void; warn(...a: unknown[]): void; error(...a: unknown[]): void };
  providers?: ProvidersConfig;
}

export interface AuthInstance extends Router {
  protect: RequestHandler;
  optional: RequestHandler;
  requireRole(...roles: string[]): RequestHandler;
  requireVerified: RequestHandler;
  api: {
    createUser(u: { email: string; password: string; roles?: string[]; emailVerified?: boolean; [f: string]: unknown }): Promise<PublicUser>;
    findUserByEmail(email: string): Promise<PublicUser | null>;
    findUserById(id: string): Promise<PublicUser | null>;
    setRoles(userId: string, roles: string[]): Promise<PublicUser | null>;
    setDisabled(userId: string, disabled: boolean): Promise<PublicUser | null>;
    revokeSessions(userId: string): Promise<void>;
    deleteUser(userId: string): Promise<void>;
    listIdentities(userId: string): Promise<Identity[]>;
    unlinkIdentity(userId: string, provider: string): Promise<void>;
  };
  ready: Promise<void>;
  close(): Promise<void>;
}

export function defineAuth(config: AuthConfig): AuthInstance;
export function createAuth(config: AuthConfig): AuthInstance;
export const hashers: { scrypt(o?: { N?: number; r?: number; p?: number }): Hasher; bcrypt(lib: unknown, o?: { rounds?: number }): Hasher; argon2(lib: unknown, o?: object): Hasher };
export const jwt: { jose(o: { secret: string | string[]; issuer?: string; audience?: string }): Signer; jsonwebtoken(lib: unknown, o: { secret: string; algorithm?: string; issuer?: string; audience?: string }): Signer };
export const mailers: { console(log?: unknown): Mailer; nodemailer(transporter: unknown, o: { from: string }): Mailer };
export const rateLimiters: { memory(o?: { maxKeys?: number }): RateLimiter };
export const stores: { memory(): unknown; mongo(o: object): unknown };
export class AuthError extends Error { constructor(status: number, code: string, message: string, headers?: Record<string, string>); status: number; code: string }
export class ConfigError extends Error {}

declare const aurauth: {
  defineAuth: typeof defineAuth;
  createAuth: typeof createAuth;
  hashers: typeof hashers;
  jwt: typeof jwt;
  mailers: typeof mailers;
  rateLimiters: typeof rateLimiters;
  stores: typeof stores;
  AuthError: typeof AuthError;
  ConfigError: typeof ConfigError;
};

export default aurauth;

declare global { namespace Express { interface Request { user?: PublicUser; auth?: { userId: string; sessionId: string; roles: string[]; claims: Record<string, any> } } } }
