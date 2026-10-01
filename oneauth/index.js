'use strict';
const { defineAuth } = require('./src/defineAuth');
const hashers = require('./src/hashers');
const tokens = require('./src/tokens');
const { consoleMailer, nodemailer } = require('./src/mailers');
const { memoryLimiter } = require('./src/ratelimit');
const { createMemoryStore } = require('./src/stores/memory');
const { createMongoStore } = require('./src/stores/mongo');
const { AuthError, ConfigError } = require('./src/errors');

const aurauth = {
  defineAuth,
  createAuth: defineAuth,
  hashers: { scrypt: hashers.scrypt, bcrypt: hashers.bcrypt, argon2: hashers.argon2 },
  jwt: { jose: tokens.jose, jsonwebtoken: tokens.jsonwebtoken },
  mailers: { console: consoleMailer, nodemailer },
  rateLimiters: { memory: memoryLimiter },
  stores: { memory: createMemoryStore, mongo: createMongoStore },
  AuthError,
  ConfigError,
};

aurauth.default = aurauth;

module.exports = aurauth;
