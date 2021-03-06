/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const buf = require('buf').hex;
const hex = require('buf').to.hex;
const Joi = require('joi');
const URI = require('URIjs');

const AppError = require('../error');
const config = require('../config');
const db = require('../db');
const logger = require('../logging')('routes.authorization');
const P = require('../promise');
const validators = require('../validators');
const verify = require('../browserid');

const CODE = 'code';
const TOKEN = 'token';

const UNTRUSTED_CLIENT_ALLOWED_SCOPES = [
  'profile:uid',
  'profile:email',
  'profile:display_name'
];

/*jshint camelcase: false*/

function set(arr) {
  var obj = {};
  for (var i = 0; i < arr.length; i++) {
    obj[arr[i]] = true;
  }
  return Object.keys(obj);
}

function scopeStringToSet(scopes) {
  return typeof scopes === 'string' ?
    set(scopes.split(/\s+/g)) :
    scopes;
}

function isLocalHost(url) {
  var host = new URI(url).hostname();
  return host === 'localhost' || host === '127.0.0.1';
}

function detectInvalidScopes(requestedScopes, validScopes) {
  var invalidScopes = [];

  requestedScopes.forEach(function(scope) {
    if (validScopes.indexOf(scope) === -1) {
      invalidScopes.push(scope);
    }
  });

  return invalidScopes;
}

function generateCode(claims, client, scope, req) {
  return db.generateCode(
    client.id,
    buf(claims.uid),
    claims['fxa-verifiedEmail'],
    scope,
    claims['fxa-lastAuthAt']
  ).then(function(code) {
    logger.debug('redirecting', { uri: req.payload.redirect_uri });

    var redirect = URI(req.payload.redirect_uri)
      .addQuery({ state: req.payload.state, code: hex(code) });


    var out = { redirect: String(redirect) };
    logger.info('generateCode', {
      request: {
        client_id: req.payload.client_id,
        redirect_uri: req.payload.redirect_uri,
        scope: req.payload.scope,
        state: req.payload.state,
        response_type: req.payload.response_type
      },
      response: out
    });
    return out;
  });
}

function generateGrant(claims, client, scope) {
  return db.generateToken({
    clientId: client.id,
    userId: buf(claims.uid),
    email: claims['fxa-verifiedEmail'],
    scope: scope
  }).then(function(token) {
    return {
      access_token: hex(token.token),
      token_type: 'bearer',
      scope: scope.join(' '),
      auth_at: claims['fxa-lastAuthAt']
    };
  });
}

module.exports = {
  validate: {
    payload: {
      client_id: validators.clientId,
      assertion: Joi.string()
        // taken from mozilla/persona/lib/validate.js
        .min(50)
        .max(10240)
        .regex(/^[a-zA-Z0-9_\-\.~=]+$/)
        .required(),
      redirect_uri: Joi.string()
        .max(256),
      scope: Joi.string()
        .max(256),
      response_type: Joi.string()
        .valid(CODE, TOKEN)
        .default(CODE),
      state: Joi.string()
        .max(256)
        .when('response_type', {
          is: TOKEN,
          then: Joi.optional(),
          otherwise: Joi.required()
        })
    }
  },
  response: {
    schema: Joi.object().keys({
      redirect: Joi.string(),
      access_token: Joi.string().regex(validators.HEX_STRING),
      token_type: Joi.string().valid('bearer'),
      scope: Joi.string(),
      auth_at: Joi.number()
    }).without('redirect', [
      'access_token',
      'token_type',
      'scope',
      'auth_at'
    ]).with('access_token', 'token_type', 'scope', 'auth_at')
  },
  handler: function authorizationEndpoint(req, reply) {
    logger.debug('response_type', req.payload.response_type);
    var start = Date.now();
    var wantsGrant = req.payload.response_type === TOKEN;
    var exitEarly = false;
    var scope = req.payload.scope ? scopeStringToSet(req.payload.scope) : [];
    P.all([
      verify(req.payload.assertion).then(function(claims) {
        logger.info('time.browserid_verify', { ms: Date.now() - start });
        if (!claims) {
          exitEarly = true;
          throw AppError.invalidAssertion();
        }
        return claims;
      }),
      db.getClient(Buffer(req.payload.client_id, 'hex')).then(function(client) {
        logger.info('time.db_get_client', { ms: Date.now() - start });
        if (exitEarly) {
          // assertion was invalid, we can just stop here
          return;
        }
        if (!client) {
          logger.debug('notFound', { id: req.payload.client_id });
          throw AppError.unknownClient(req.payload.client_id);
        } else if (!client.trusted) {
          var invalidScopes = detectInvalidScopes(scope,
                                UNTRUSTED_CLIENT_ALLOWED_SCOPES);

          if (invalidScopes.length) {
            throw AppError.invalidScopes(invalidScopes);
          }
        }

        var uri = req.payload.redirect_uri || client.redirectUri;

        if (uri !== client.redirectUri) {
          logger.debug('redirect.mismatch', {
            param: uri,
            registered: client.redirectUri
          });

          if (config.get('localRedirects') && isLocalHost(uri)) {
            logger.debug('redirect.local', { uri: uri });
          } else {
            throw AppError.incorrectRedirect(uri);
          }

        }

        if (wantsGrant && !client.canGrant) {
          logger.warn('implicitGrant.notAllowed', {
            id: req.payload.client_id
          });
          throw AppError.invalidResponseType();
        }

        req.payload.redirect_uri = uri;

        return client;
      }),
      scope,
      req
    ])
    .spread(wantsGrant ? generateGrant : generateCode)
    .done(reply, reply);
  }
};
