/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const auth = require('../../auth');
const db = require('../../db');
const hex = require('buf').to.hex;

function developerResponse(developer) {
  return {
    developerId: hex(developer.developerId),
    email: developer.email,
    createdAt: developer.createdAt
  };
}

/*jshint camelcase: false*/
module.exports = {
  auth: {
    strategy: auth.AUTH_STRATEGY,
    scope: [auth.SCOPE_CLIENT_MANAGEMENT]
  },
  handler: function activateRegistration(req, reply) {
    var email = req.auth.credentials.email;

    return db.getDeveloper(email)
        .then(function(developer) {
          if (developer) {
            return developer;
          } else {
            return db.activateDeveloper(email);
          }
        })
        .then(developerResponse)
        .done(reply, reply);
  }
};
