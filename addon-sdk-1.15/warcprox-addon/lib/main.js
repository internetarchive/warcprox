var data = require('sdk/self').data;
const {Cc, Ci, Cu} = require("chrome");
var {XPCOMUtils} = Cu.import("resource://gre/modules/XPCOMUtils.jsm");

var mediator = Cc['@mozilla.org/appshell/window-mediator;1'].getService(Ci.nsIWindowMediator);
var prefs = require("sdk/preferences/service");
var pageMod = require("sdk/page-mod");
var xhr = require("sdk/net/xhr");

var pageModObject;

prefs.set("extensions.sdk.console.logLevel", "all");

// add our button
function addToolbarButton() {
    // this document is an XUL document
    var document = mediator.getMostRecentWindow('navigator:browser').document;
    var navBar = document.getElementById('nav-bar');
    if (!navBar) {
        return;
    }
    var btn = document.createElement('toolbarbutton');
    btn.setAttribute('id', 'mybutton-id');
    btn.setAttribute('type', 'button');
    // the toolbarbutton-1 class makes it look like a traditional button
    btn.setAttribute('class', 'toolbarbutton-1');
    // the data.url is relative to the data folder
    btn.setAttribute('image', data.url('img/ait-logo-black16.png'));
    btn.setAttribute('orient', 'horizontal');
    // this text will be shown when the toolbar is set to text or text and iconss
    btn.setAttribute('label', 'My Button');
    btn.addEventListener('click', ButtonClick, false)
    navBar.appendChild(btn);
}

function removeToolbarButton() {
    // this document is an XUL document
    var document = mediator.getMostRecentWindow('navigator:browser').document;
    var navBar = document.getElementById('nav-bar');
    var btn = document.getElementById('mybutton-id');
    if (navBar && btn) {
        navBar.removeChild(btn);
    }
}

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
        changeButtonColor("on");
        ShowWarnings(true);
    } else {
        console.debug("*** bad proxy connection");
        turnOffProxy();
        // send out error msg to user
    }
}

function turnOffProxy(){
    prefs.set("network.proxy.type", 5);
    changeButtonColor("off");
    ShowWarnings(false);
}

function changeButtonColor(setting){
    var document = mediator.getMostRecentWindow('navigator:browser').document;
    var btn = document.getElementById('mybutton-id');

    if ( setting == "on" ) {
        btn.setAttribute('image', data.url('img/ait-logo-green16.png'));
    } else {
        btn.setAttribute('image', data.url('img/ait-logo-black16.png'));
    }
}

function ShowWarnings(bool) {
    if (bool) {
        pageModObject = pageMod.PageMod({
            include: "*",
            contentScriptFile: data.url("page.js"),
            contentStyleFile: data.url("page.css")
        });
    } else if (pageModObject) {
        pageModObject.destroy();
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





// exports.main is called when extension is installed or re-enabled
exports.main = function(options, callbacks) {
    addToolbarButton();
    // do other stuff
    var panel = require("sdk/panel").Panel({
      width: 400,
      height: 400,
      contentURL: "https://en.wikipedia.org/w/index.php?title=Jetpack&useformat=mobile"
    });

    panel.show();
};

// exports.onUnload is called when Firefox starts and when the extension is disabled or uninstalled
exports.onUnload = function(reason) {
    turnOffProxy();
    RemoveCert();
    removeToolbarButton();
    // do other stuff
};