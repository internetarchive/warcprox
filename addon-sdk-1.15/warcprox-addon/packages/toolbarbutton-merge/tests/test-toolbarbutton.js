/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
'use strict';

const windows = require("windows").browserWindows;
const toolbarbutton = require("toolbarbutton");
//const { Loader } = require('sdk/test/loader');
const winUtils = require('sdk/window/utils');

const NS_XUL = "http://www.mozilla.org/keymaster/gatekeeper/there.is.only.xul";

const TEST_ICON_URL = module.uri.replace(/[^\.\\\/]*\.js$/, "test.png");
const TEST_ICON_BLACK_URL = module.uri.replace(/[^\.\\\/]*\.js$/, "black.png");

function $(id) winUtils.getMostRecentBrowserWindow().document.getElementById(id);

function createToolbarButton(options, test) {
  test.assertEqual(!$(options.id), true);

  var tbb = toolbarbutton.ToolbarButton(options);
  test.assertEqual(!$(options.id), true);

  tbb.moveTo(options);
  test.assertEqual(!$(options.id), false);

  return tbb;
}

function buttonExists(button, options, test) {
  test.assertEqual(!button, false, 'test button');
  test.assertEqual(button.parentNode, $(options.toolbarID), 'test parent');
  test.assertEqual(button.id, options.id, 'test id');
  if (options.label)
    test.assertEqual(button.label, options.label, 'test label');
  if (options.image)
    test.assertEqual(button.image, options.image);
  else
    test.assertEqual(button.image, "");
}

exports.testTBBExists = function(test) {
  var options = {
    id: "test-tbb",
    label: "test",
    toolbarID: "nav-bar",
    forceMove: true
  };

  var tbb = createToolbarButton(options, test);
  buttonExists($(options.id), options, test);
  tbb.destroy();
  test.assertEqual(!$(options.id), true);
  var tbb = createToolbarButton(options, test);
  tbb.destroy();
};

exports.testTBBDoesNotExist = function(test) {
  var options = {
    id: "test-tbb2",
    label: "test"
  };
  var tbb = createToolbarButton(options, test);
  var tbbEle = $(options.id);
  test.assertEqual(!tbbEle, true, 'toolbar button dne');
  tbb.destroy();
};

exports.testTBBLabelChange = function(test) {
  test.waitUntilDone();

  var options = {
    id: "test-tbb3",
    label: "test",
    toolbarID: "nav-bar",
    forceMove: true
  };

  let tbb = createToolbarButton(options, test);
  buttonExists($(options.id), options, test);
  tbb.label = 'test change';
  test.assertEqual($(options.id).label, 'test change', 'the label is changed');
  test.assertEqual(tbb.label, 'test change', 'the label is changed');

  tbb.destroy();
  test.done();
};

exports.testTBBPropertyChange = function(test) {
  test.waitUntilDone();

  var options = {
    id: "test-tbb4",
    label: "test",
    toolbarID: "nav-bar",
    forceMove: true,
    image: TEST_ICON_URL,
    tooltiptext: 'a'
  };

  let tbb = createToolbarButton(options, test);
  buttonExists($(options.id), options, test);
  test.assertEqual($(options.id).image, TEST_ICON_URL, 'the image is correct');
  test.assertEqual(tbb.image, TEST_ICON_URL, 'the image is correct');
  test.assertEqual(tbb.tooltiptext, 'a', 'the tooltiptext is correct');
  tbb.setIcon({url: TEST_ICON_BLACK_URL});
  test.assertEqual($(options.id).image, TEST_ICON_BLACK_URL, 'the image is changed');
  test.assertEqual(tbb.image, TEST_ICON_BLACK_URL, 'the image is changed');
  tbb.tooltiptext = 'b';
  test.assertEqual($(options.id).getAttribute('tooltiptext'), 'b', 'the tooltiptext is changed');
  test.assertEqual(tbb.tooltiptext, 'b', 'the tooltiptext is changed');

  tbb.destroy();
  test.done();
};

exports.testTBBIteratorWithNonBrowserWindow = function(test) {
  test.waitUntilDone();

  let scratchpad = winUtils.getMostRecentBrowserWindow().Scratchpad.openScratchpad();
  let options = {
    id: "test-tbb5",
    label: "TEST",
    toolbarID: "nav-bar",
    image: TEST_ICON_URL
  };
  windows.open({
    onOpen: function(window) {
      let tbb = createToolbarButton(options, test);
      test.assertEqual(windows.length, 2);

      scratchpad.close();
      tbb.destroy();
      window.close(function() test.done());
    }
  })
};

exports.testTBBIterator2 = function(test) {
  test.waitUntilDone();

  let window1 = winUtils.getMostRecentBrowserWindow();
  let options = {
    id: "test-tbb6",
    label: "TEST",
    toolbarID: "nav-bar",
    image: TEST_ICON_URL
  };
  let button = window1.document.createElementNS(NS_XUL, "toolbarbutton");
  button.setAttribute('id', options.id);
  window1.document.getElementById(options.toolbarID).appendChild(button);
  test.assert(!!$(options.id));

  windows.open({
    onOpen: function(window) {
      let tbb = createToolbarButton(options, test);
      test.assertEqual(windows.length, 2);

      tbb.destroy();
      button.parentNode.removeChild(button);
      window.close(function() test.done());
    }
  })
};
