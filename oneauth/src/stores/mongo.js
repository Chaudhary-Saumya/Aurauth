'use strict';
const { ConfigError } = require('../errors');

const RESERVED = ['id', '_id', 'email', 'passwordHash', 'roles', 'emailVerified', 'failedLogins', 'lockUntil', 'disabled', 'passwordChangedAt', 'createdAt', 'updatedAt'];

/**
 * MongoDB store built on mongoose. Creates its own models (oneauth_users, oneauth_sessions,
 * oneauth_tokens) so the developer never defines a User model. Expired sessions/tokens are
 * removed automatically by TTL indexes.
 */
function createMongoStore({ mongoose: mongooseLib, connection, url, connectOptions, userFields = {} }) {
  let mongoose;
  try { mongoose = mongooseLib || require('mongoose'); } catch {
    throw new ConfigError('mongoose is not installed. Run `npm i mongoose`, or pass your own store via `database: { store }`.');
  }
  for (const k of Object.keys(userFields))
    if (RESERVED.includes(k)) throw new ConfigError(`\`user.fields.${k}\` is reserved by oneauth. Pick another field name.`);

  let conn = connection || null;
  let ownsConnection = false;
  let User, Session, Token, Identity;

  const isId = (id) => typeof id === 'string' && mongoose.isValidObjectId(id);
  const strip = (d) => { if (!d) return null; const { _id, __v, ...rest } = d; return { id: String(_id), ...rest }; };

  return {
    kind: 'mongo',

    async connect() {
      if (!conn) {
        conn = await mongoose.createConnection(url, connectOptions).asPromise();
        ownsConnection = true;
      }
      const { Schema } = mongoose;
      const model = (name, schema) => conn.models[name] || conn.model(name, schema);

      const userSchema = new Schema({
        ...userFields,
        email: { type: String, required: true, unique: true, lowercase: true, trim: true, maxlength: 254 },
        passwordHash: { type: String, required: false, default: null },
        roles: { type: [String], default: [] },
        emailVerified: { type: Boolean, default: false },
        failedLogins: { type: Number, default: 0 },
        lockUntil: { type: Date, default: null },
        disabled: { type: Boolean, default: false },
        passwordChangedAt: { type: Date, default: null },
      }, { timestamps: true, collection: 'oneauth_users' });

      const sessionSchema = new Schema({
        userId: { type: String, required: true, index: true },
        familyId: { type: String, required: true, index: true },
        tokenHash: { type: String, required: true, unique: true },
        startedAt: Date,
        expiresAt: { type: Date, required: true },
        usedAt: { type: Date, default: null },
        revokedAt: { type: Date, default: null },
        ip: String,
        userAgent: String,
      }, { timestamps: { createdAt: true, updatedAt: false }, collection: 'oneauth_sessions' });
      sessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

      const tokenSchema = new Schema({
        userId: { type: String, required: true, index: true },
        type: { type: String, required: true },
        hash: { type: String, required: true, unique: true },
        expiresAt: { type: Date, required: true },
        usedAt: { type: Date, default: null },
      }, { collection: 'oneauth_tokens' });
      tokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

      User = model('OneAuthUser', userSchema);
      Session = model('OneAuthSession', sessionSchema);
      Token = model('OneAuthToken', tokenSchema);

      const identitySchema = new Schema({
        userId: { type: String, required: true, index: true },
        provider: { type: String, required: true },
        providerId: { type: String, required: true },
        email: { type: String, lowercase: true },
      }, { timestamps: { createdAt: true, updatedAt: false }, collection: 'oneauth_identities' });
      identitySchema.index({ provider: 1, providerId: 1 }, { unique: true });
      Identity = model('OneAuthIdentity', identitySchema);

      // Build indexes before serving traffic: the unique email index is what prevents duplicate accounts.
      await Promise.all([User.init(), Session.init(), Token.init(), Identity.init()]);
    },

    async close() { if (ownsConnection && conn) await conn.close(); },

    users: {
      async create(data) {
        try {
          const doc = await User.create(data);
          return strip(doc.toObject());
        } catch (e) {
          if (e && e.code === 11000) throw Object.assign(new Error('Duplicate email'), { code: 'DUPLICATE_EMAIL' });
          throw e;
        }
      },
      async findById(id) { return isId(String(id)) ? strip(await User.findById(String(id)).lean()) : null; },
      async findByEmail(email) { return strip(await User.findOne({ email: String(email) }).lean()); },
      async update(id, patch) {
        if (!isId(String(id))) return null;
        return strip(await User.findByIdAndUpdate(String(id), { $set: patch }, { new: true, runValidators: true }).lean());
      },
      async incrementFailedLogins(id) {
        const d = await User.findByIdAndUpdate(String(id), { $inc: { failedLogins: 1 } }, { new: true }).lean();
        return d ? d.failedLogins : 0;
      },
      async delete(id) {
        if (!isId(String(id))) return;
        await User.findByIdAndDelete(String(id));
      },
    },

    sessions: {
      async create(s) { await Session.create(s); },
      async findByTokenHash(hash) { return strip(await Session.findOne({ tokenHash: String(hash) }).lean()); },
      async consume(id) {
        if (!isId(String(id))) return false;
        const r = await Session.findOneAndUpdate({ _id: String(id), usedAt: null, revokedAt: null }, { $set: { usedAt: new Date() } }).lean();
        return !!r;
      },
      async revokeFamily(familyId) {
        await Session.updateMany({ familyId: String(familyId), revokedAt: null }, { $set: { revokedAt: new Date() } });
      },
      async revokeAllForUser(userId, { exceptFamilyId } = {}) {
        const filter = { userId: String(userId), revokedAt: null };
        if (exceptFamilyId) filter.familyId = { $ne: String(exceptFamilyId) };
        await Session.updateMany(filter, { $set: { revokedAt: new Date() } });
      },
      async isFamilyActive(familyId) {
        return !!(await Session.exists({ familyId: String(familyId), usedAt: null, revokedAt: null, expiresAt: { $gt: new Date() } }));
      },
      async listActiveForUser(userId) {
        const rows = await Session.find({ userId: String(userId), usedAt: null, revokedAt: null, expiresAt: { $gt: new Date() } }).lean();
        return rows.map(strip);
      },
    },

    tokens: {
      async create({ userId, type, hash, expiresAt }) { await Token.create({ userId: String(userId), type, hash, expiresAt }); },
      async consume(type, hash) {
        const r = await Token.findOneAndUpdate(
          { type: String(type), hash: String(hash), usedAt: null, expiresAt: { $gt: new Date() } },
          { $set: { usedAt: new Date() } },
        ).lean();
        return strip(r);
      },
      async deleteForUser(userId, type) { await Token.deleteMany({ userId: String(userId), type: String(type) }); },
    },

    identities: {
      async create({ userId, provider, providerId, email }) {
        try {
          const doc = await Identity.create({ userId: String(userId), provider, providerId, email });
          return strip(doc.toObject());
        } catch (e) {
          if (e && e.code === 11000) throw Object.assign(new Error('Duplicate identity'), { code: 'DUPLICATE_IDENTITY' });
          throw e;
        }
      },
      async find(provider, providerId) {
        return strip(await Identity.findOne({ provider: String(provider), providerId: String(providerId) }).lean());
      },
      async listForUser(userId) {
        const rows = await Identity.find({ userId: String(userId) }).lean();
        return rows.map(strip);
      },
      async delete(provider, providerId) {
        await Identity.deleteOne({ provider: String(provider), providerId: String(providerId) });
      },
    },
  };
}

module.exports = { createMongoStore };
