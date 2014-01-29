var data = require('sdk/self').data;
const {Cc, Ci, Cu} = require("chrome");
var {XPCOMUtils} = Cu.import("resource://gre/modules/XPCOMUtils.jsm");

var mediator = Cc['@mozilla.org/appshell/window-mediator;1'].getService(Ci.nsIWindowMediator);
var prefs = require("sdk/preferences/service");
var pageMod = require("sdk/page-mod");
var panel = require("sdk/panel")
var xhr = require("sdk/net/xhr");

var pageModObject;

prefs.set("extensions.sdk.console.logLevel", "all");

function ButtonClick(){
    if (prefs.get("network.proxy.type") == 5 ) {
        turnOnProxy();
    } else {
        turnOffProxy();
    }
}

function testProxyConnection() {
    var oReq = new xhr.XMLHttpRequest();
    var success;
    try{
        oReq.onload = function () {
            console.debug("**** page req succeeded!!!");
            success = true;
        }
        oReq.onerror = function () {
            console.debug("*** error on page req!");
            success = false;
        }
        oReq.open("get", "http://warcprox./ca.pem", false);
        oReq.send();
    }
    catch (e)
    {
        console.debug("*** connection error caught");
        success = false;
    }
    return success;
}

function turnOnProxy(){
    var ip = "127.0.0.1";
    var port = 8000;
    prefs.set("network.proxy.type", 1);
    prefs.set("network.proxy.http", ip);
    prefs.set("network.proxy.http_port", port);

    if ( testProxyConnection() ) {
        console.debug("*** success! proxy connected!");

        //    SaveCert("http://warcprox./ca.pem");
        ShowVisuals(true);
    } else {
        console.debug("*** bad proxy connection");
        turnOffProxy();
        // send out error msg to user
    }
}

function turnOffProxy(){
    prefs.set("network.proxy.type", 5);
    ShowVisuals(false);
}

function ShowVisuals(bool){
    if (bool) {
        // show warnings with css
        pageModObject = pageMod.PageMod({
            include: "*",
            contentScriptFile: data.url("page.js"),
            contentStyleFile: data.url("page.css")
        });

        // turn button icon green
        btn.image = data.url('img/ait-logo-green16.png');

    } else if (pageModObject) {
        pageModObject.destroy();
        // return button to default
        btn.image = data.url('img/ait-logo-black16.png');
    }
}

function SaveCert(url){
    var gIOService = Cc["@mozilla.org/network/io-service;1"].getService(Ci.nsIIOService);
    var certDB = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB2);
    var scriptableStream = Cc["@mozilla.org/scriptableinputstream;1"].getService(Ci.nsIScriptableInputStream);

    var URI = gIOService.newURI(url, null, null);
    var uriChannel = gIOService.newChannelFromURI(URI, null, null);

    var input = uriChannel.open();
    scriptableStream.init(input);

    var certfile = scriptableStream.read(input.available());
    scriptableStream.close();
    input.close();

    var beginCert = "-----BEGIN CERTIFICATE-----";
    var endCert = "-----END CERTIFICATE-----";

    certfile = certfile.replace(/[\r\n]/g, "");
    var begin = certfile.indexOf(beginCert);
    var end = certfile.indexOf(endCert);
    var cert = certfile.substring(begin + beginCert.length, end);

    console.debug(certfile);
    certDB.addCertFromBase64(cert, "C,c,c", "");

    // var certDB2 = Components.classes["@mozilla.org/security/x509certdb;1"].getService(Components.interfaces.nsIX509CertDB2);
    // var certDB = Components.classes["@mozilla.org/security/x509certdb;1"].getService(Components.interfaces.nsIX509CertDB);
    // var gIOService = Components.classes['@mozilla.org/network/io-service;1'].getService(Components.interfaces.nsIIOService);
    // var scriptableStream = Components.classes["@mozilla.org/scriptableinputstream;1"].getService(Components.interfaces.nsIScriptableInputStream);
    // var uriChannel = gIOService.newChannelFromURI(uri, null, null);

    // var input = uriChannel.open();
    // scriptableStream.init(input);

    // var certfile = scriptableStream.read(input.available());
    // scriptableStream.close();
    // input.close();

    // var beginCert = "-----BEGIN CERTIFICATE-----";
    // var endCert = "-----END CERTIFICATE-----";

    // certfile = certfile.replace(/[\r\n]/g, "");
    // var begin = certfile.indexOf(beginCert);
    // var end = certfile.indexOf(endCert);
    // var cert = certfile.substring(begin + beginCert.length, end);

    // // certDB2.addCertFromBase64(cert, "C,c,c", "");

    // this_cert = certDB.constructX509FromBase64(cert);

    // // list = certDB2.getCerts();
    // // list.addCert(this_cert);
}
/*function RemoveCert(){
//     var certDB2 = Components.classes["@mozilla.org/security/x509certdb;1"].getService(Components.interfaces.nsIX509CertDB2);
//     var certDB = Components.classes["@mozilla.org/security/x509certdb;1"].getService(Components.interfaces.nsIX509CertDB);
//
//     var list = certDB2.getCerts();
//     list.deleteCert(this_cert);
}*/

var optionsPanel = panel.Panel({
      width: 400,
      height: 400,
      contentURL: data.url("options.html"),
      contentScriptFile: data.url("options.js")
    });

var btn = require("toolbarbutton").ToolbarButton({
        id: "warcprox-button",
        label: "Warcprox toggle",
        onCommand: function () {
            ButtonClick(); // kills the toolbar button
        },
        image: data.url('img/ait-logo-black16.png')//,
//        panel: optionsPanel

      });


// exports.main is called when extension is installed or re-enabled
exports.main = function(options, callbacks) {

    if (options.loadReason == "install") {
        btn.moveTo({
            toolbarID: "nav-bar",
            forceMove: false // only move from palette
        });
    }
    // Send the content script a message called "show" when
    // the panel is shown.
    optionsPanel.on("show", function() {
      optionsPanel.port.emit("show");
    });

    // Listen for messages called "text-entered" coming from
    // the content script. The message payload is the text the user
    // entered.
    // In this implementation we'll just log the text to the console.
    optionsPanel.port.on("text-entered", function (text) {
      console.log(text);
      optionsPanel.hide();
    });

};

// exports.onUnload is called when Firefox starts and when the extension is disabled or uninstalled
exports.onUnload = function(reason) {
    btn.destroy();
    turnOffProxy();
//    RemoveCert();
};