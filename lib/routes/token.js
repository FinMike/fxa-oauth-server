/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*jshint camelcase: false*/
const AppError = require('../error');
const buf = require('buf').hex;
const hex = require('buf').to.hex;
const Joi = require('joi');

const config = require('../config');
const db = require('../db');
const encrypt = require('../encrypt');
const logger = require('../logging')('routes.token');
const P = require('../promise');
const validators = require('../validators');

const AUTHORIZATION_CODE = 'authorization_code';
const REFRESH_TOKEN = 'refresh_token';

function confirmClient(id, secret) {
  return db.getClient(buf(id)).then(function(client) {
    if (!client) {
      logger.debug('client.notFound', { id: id });
      throw AppError.unknownClient(id);
    }

    var submitted = hex(encrypt.hash(buf(secret)));
    var stored = hex(client.secret);
    if (submitted !== stored) {
      logger.info('client.mismatchSecret', { client: id });
      logger.verbose('client.mismatchSecret.details', {
        submitted: submitted,
        db: stored
      });
      throw AppError.incorrectSecret(id);
    }

    return client;
  });
}

function confirmCode(id, code) {
  return db.getCode(buf(code)).then(function(codeObj) {
    if (!codeObj) {
      logger.debug('code.notFound', { code: code });
      throw AppError.unknownCode(code);
    } else if (hex(codeObj.clientId) !== hex(id)) {
      logger.debug('code.mismatch', {
        client: hex(id),
        code: hex(codeObj.clientId)
      });
      throw AppError.mismatchCode(code, id);
    } else {
      // + because loldatemath. without it, it does string concat
      var expiresAt = +codeObj.createdAt + config.get('expiration.code');
      if (Date.now() > expiresAt) {
        logger.debug('code.expired', { code: code });
        throw AppError.expiredCode(code, expiresAt);
      }
    }
    return codeObj;
  });
}

function confirmScopes(/*allowed, requested*/) {
  return true;
}

function confirmToken(params) {
  return db.getRefreshToken(params.refresh_token)
  .then(function(tokObj) {
    if (!tokObj) {
      logger.debug('refresh_token.notFound', params.refresh_token);
      throw AppError.invalidToken();
    } else if (hex(tokObj.clientId) !== hex(params.client_id)) {
      logger.debug('refresh_token.mismatch', {
        client: params.client_id,
        code: tokObj.clientId
      });
      throw AppError.invalidToken();
    } else if (!confirmScopes(tokObj.scope, params.scope)) {
      logger.debug('refresh_token.invalidScopes', {
        allowed: tokObj.scope,
        requested: params.scope
      });
      throw AppError.invalidScopes();
    }
    return tokObj;
  });
}

function generateToken(options) {
  // we always are generating an access token here
  // but depending on options, we may also be generating a refresh_token
  var promises = [db.generateAccessToken(options)];
  if (options.generateRefreshToken) {
    promises.push(db.generateRefreshToken(options));
  }
  return P.all(promises).spread(function(access, refresh) {
    var json = {
      access_token: access.token.toString('hex'),
      token_type: access.type,
      scope: access.scope.join(' '),
      auth_at: options.authAt
    };
    if (access.expiresAt) {
      json.expires_at = access.expiresAt.getTime();
    }
    if (refresh) {
      json.refresh_token = refresh.token.toString('hex');
    }
    return json;
  });
  //return [code.authAt, db.removeCode(code.code), db.generateToken(code)];
}


var payloadSchema = Joi.object({
  /*jshint camelcase: false*/
  client_id: validators.clientId,
  client_secret: validators.clientSecret,

  grant_type: Joi.string()
    .valid(AUTHORIZATION_CODE, REFRESH_TOKEN)
    .default(AUTHORIZATION_CODE)
    .optional(),

  ttl: Joi.number()
    .max(60 * 60 * 24 * 2) // 2weeks
    .optional(),

  scope: Joi.alternatives().when('grant_type', {
    is: REFRESH_TOKEN,
    then: Joi.string(),
    otherwise: Joi.forbidden()
  }),

  code: Joi.string()
    .length(config.get('unique.code') * 2)
    .regex(validators.HEX_STRING)
    .required()
    .when('grant_type', {
      is: AUTHORIZATION_CODE,
      otherwise: Joi.forbidden()
    }),

  refresh_token: Joi.alternatives().when('grant_type', {
    is: REFRESH_TOKEN,
    then: validators.token.required(),
    otherwise: Joi.forbidden()
  })
});

module.exports = {
  validate: {
    // stripUnknown is used to allow various oauth2 libraries to be used
    // with FxA OAuth. Sometimes, they will send other parameters that
    // we don't use, such as `response_type`, or something else. Instead
    // of giving an error here, we can just ignore them.
    payload: function validatePayload(value, options, next) {
      return Joi.validate(value, payloadSchema, { stripUnknown: true }, next);
    }
  },
  response: {
    schema: {
      access_token: Joi.string().required(),
      scope: Joi.string().required().allow(''),
      token_type: Joi.string().valid('bearer').required(),
      auth_at: Joi.number().required()
    }
  },
  handler: function tokenEndpoint(req, reply) {
    var params = req.payload;
    confirmClient(params.client_id, params.client_secret)
    .then(function() {
      if (params.grant_type === AUTHORIZATION_CODE) {
        return confirmCode(params.client_id, params.code);
      } else if (params.grant_type === REFRESH_TOKEN) {
        return confirmToken(params);
      }
    })
    .then(generateToken)
    .done(reply, reply);
  }
};
