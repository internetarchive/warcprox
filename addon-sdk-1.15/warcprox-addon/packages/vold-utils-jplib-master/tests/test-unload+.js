/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
"use strict";

var timer = require("timer");
var {Cc,Ci} = require("chrome");
const windowUtils = require("window-utils");
const { Loader } = require('test-harness/loader');

function makeEmptyWindow() {
  var xulNs = "http://www.mozilla.org/keymaster/gatekeeper/there.is.only.xul";
  var blankXul = ('<?xml version="1.0"?>' +
                  '<?xml-stylesheet href="chrome://global/skin/" ' +
                  '                 type="text/css"?>' +
                  '<window xmlns="' + xulNs + '">' +
                  '</window>');
  var url = "data:application/vnd.mozilla.xul+xml," + escape(blankXul);
  var features = ["chrome", "width=10", "height=10"];

  var ww = Cc["@mozilla.org/embedcomp/window-watcher;1"]
           .getService(Ci.nsIWindowWatcher);
  return ww.openWindow(null, url, null, features.join(","), null);
}

exports.testUnloading = function(test) {
  var loader = Loader(module);
  var {unload} = loader.require("unload+");
  var unloadCalled = 0;

  function unloader() {
    unloadCalled++;
    throw "error";
  }
  unload(unloader);

  function unloader2() unloadCalled++;
  var removeUnloader2 = unload(unloader2);

  function unloader3() unloadCalled++;
  unload(unloader3);

  // remove unloader2
  removeUnloader2();

  loader.unload();
  test.assertEqual(
      unloadCalled, 2, "Unloader functions are called on unload.");
};

exports.testUnloadingWindow = function(test) {
  test.waitUntilDone();

  var loader = Loader(module);
  var {unload} = loader.require("unload+");
  var unloadCalled = 0;
  var finished = false;
  var myWindow;

  var delegate = {
    onTrack: function(window) {
      if (window == myWindow) {
        test.pass("onTrack() called with our test window");

        let unloader = function unloader() {
          unloadCalled++;
        }
        unload(unloader, window);
        unload(unloader);

        timer.setTimeout(function() {
          window.close();

          test.assertEqual(
                unloadCalled, 0, "no unloaders called.");

          if (window.closed) {
            test.pass("window closed");
          } else {
            test.fail("window is not closed!");
          }

          timer.setTimeout(function() {
            test.assertEqual(
                unloadCalled, 0, "zero unloaders called.");

            loader.unload();

            test.assertEqual(
                  unloadCalled, 1, "one unloaders called.");

            if (finished) {
              test.pass("finished");
              test.done();
            } else {
              test.fail("not finished!");
            }
          }, 1);
        }, 1);
      }
    },
    onUntrack: function(window) {
      if (window == myWindow) {
        test.pass("onUntrack() called with our test window");

          if (!finished) {
            finished = true;
            myWindow = null;
            wt.unload();
          } else {
            test.fail("finishTest() called multiple times.");
          }
      }
    }
  };

  var wt = new windowUtils.WindowTracker(delegate);
  myWindow = makeEmptyWindow();
};
