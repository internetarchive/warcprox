/* 
 * Copyrights Loic J. Duros 2012
 * lduros@member.fsf.org
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

var self = require("self");
var notification = require("notification-box").NotificationBox({
  'value': 'important-message',
  'label': 'You have been warned...',
  'priority': 'WARNING_HIGH',
  'image': self.data.url("gnu-icon.png"),
  'buttons': [{'label': "Gotcha",
              'onClick': function () { console.log("You clicked the important button!"); }}]
});
