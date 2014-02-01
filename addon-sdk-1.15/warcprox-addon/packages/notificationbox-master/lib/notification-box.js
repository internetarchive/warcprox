/* 
 * Copyrights Loic J. Duros 2012
 * lduros@member.fsf.org
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

const { Cc, Ci } = require("chrome");
const { getMostRecentBrowserWindow } = require('sdk/window/utils');
/* I haven't found this sort of validation functions in the SDK,
except for the deprecated api-utils module. */
let isString = function (str) {
  return typeof(str) == 'string' || str instanceof String;
};

let isArray = function (obj) {
  return Object.prototype.toString.call(obj) === '[object Array]';
};

exports.NotificationBox = function (options) {
  options = options || {};
  let mainWindow = getWindow();

  if (options.allTabs == true){
      var browsers = mainWindow.gBrowser.browsers;
      for (var i= 0; i<browsers.length; i++) {
          let nb = mainWindow.gBrowser.getNotificationBox(browsers[i]);
          BuildNotifications(options, nb);
      }
  } else {
      let nb = mainWindow.gBrowser.getNotificationBox();
      BuildNotifications(options, nb);
  }

//  can't return when using 'allTabs' would have to return a large array instead
//  return {'notificationbox': built.nb, 'notification': built.notification};
};

function BuildNotifications(options, nb){
  let notification, priority, label, image, value, buttons = [];

    // if another notification is up, will close it first, then append new
  if (options.closeprev) nb.removeTransientNotifications();

  if (options.value && isString(options.value)) {
    notification = nb.getNotificationWithValue(options.value);
    value = options.value;
  }
  else {
    notification = nb.getNotificationWithValue('');
    value = '';
  }

  // Add label or create empty notification.
  if (options.label && isString(options.label))
    label = options.label;
  else
    label = "";

  // Set priority of the notification (from info low, to critical
  // block.
  if (options.priority && options.priority in PRIORITY)
    priority = nb[PRIORITY[options.priority]];
  else
    priority = nb[PRIORITY.INFO_LOW];

  // Set a custom icon for the notification or use the regular info
  // icon.
  if (options.image && isString(options.image))
    image = options.image;
  else
    image = 'chrome://browser/skin/Info.png';

  // Add buttons.
  if (isArray(options.buttons)) {
    for (let i = 0, length = options.buttons.length; i < length; i++) {
      buttons.push(NotificationButton(options.buttons[i]));
    }
  }
  else if (typeof(options.buttons) === 'object') {
    // If it's not an array of buttons, then it should be a single button.
    buttons.push(NotificationButton(options.buttons));
  }
  else {
    buttons = null;
  }

  // add new notification to notificationbox.
  nb.appendNotification(label, value,
                        image,
                        priority, buttons);

  return {'nb': nb, 'notification': notification};
}

exports.clearNotification = function (value){
    let mainWindow = getWindow();
    var browsers = mainWindow.gBrowser.browsers;
    for (var i= 0; i<browsers.length; i++) {
        let nb = mainWindow.gBrowser.getNotificationBox(browsers[i]);
        var notification = nb.getNotificationWithValue(value);
        if (notification) nb.removeNotification(notification);
    }
}


var NotificationButton = function (options) {

  options = options || {};
  let accessKey, onClick, label, popup;

  if (options.accessKey)
    accessKey = options.accessKey;
  else
    accessKey = '';

  if (options.onClick)
    onClick = options.onClick;
  else
    onClick = function () {};

  if (options.label)
    label = options.label;
  else
    label = "";
  
  // no popup for now... maybe we can use a panel later.
  popup = null;
  
  return {label: label, 
          accessKey: accessKey,
          callback: onClick,
          popup: popup};

};

const PRIORITY = {
    'INFO_LOW': 'PRIORITY_INFO_LOW',
    'INFO_MEDIUM': 'PRIORITY_INFO_MEDIUM',
    'INFO_HIGH': 'PRIORITY_INFO_HIGH',
    'WARNING_LOW': 'PRIORITY_WARNING_LOW',
    'WARNING_MEDIUM': 'PRIORITY_WARNING_MEDIUM',
    'WARNING_HIGH': 'PRIORITY_WARNING_HIGH',
    'CRITICAL_LOW': 'PRIORITY_CRITICAL_LOW',
    'CRITICAL_MEDIUM': 'PRIORITY_CRITICAL_MEDIUM',
    'CRITICAL_HIGH': 'PRIORITY_CRITICAL_HIGH',
    'CRITICAL_BLOCK': 'PRIORITY_CRITICAL_BLOCK'
};

let getWindow = function () {
  return getMostRecentBrowserWindow();
};

exports.PRIORITY = PRIORITY;

