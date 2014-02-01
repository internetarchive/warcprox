var data = require('sdk/self').data;
const {Cc, Ci, Cu} = require("chrome");
var {XPCOMUtils} = Cu.import("resource://gre/modules/XPCOMUtils.jsm");

var mediator = Cc['@mozilla.org/appshell/window-mediator;1'].getService(Ci.nsIWindowMediator);
var prefs = require("sdk/preferences/service");
var pageMod = require("sdk/page-mod");
var panel = require("sdk/panel")
var xhr = require("sdk/net/xhr");
var notification = require("notification-box");
var tabs = require("sdk/tabs");


var pageModObject, optionsPanel, btn, cert_issuer, cert_serialno;
var whitelogo = data.url('img/ait-logo-white16.png');
var blacklogo = data.url('img/ait-logo-black16.png');
var greenlogo = data.url('img/ait-logo-green16.png');
var ProxyOn = false;

// default msgs
var warning_id = "warning-being-archived";
var warning_msg = "Warcprox Connected - Careful!!  Your activity is being archived!";
var disconnect_id = "success-disconnect";
var disconnect_msg = "Warcprox Disconnected - Disconnected from proxy.";

// for debugging
//prefs.set("extensions.sdk.console.logLevel", "all");

function turnOnProxy(addr, port) {
    prefs.set("network.proxy.type", 1);
    prefs.set("network.proxy.http", addr);
    prefs.set("network.proxy.ssl", addr);
    prefs.set("network.proxy.ssl_port", port);
    prefs.set("network.proxy.http_port", port);

    if ( testProxyConnection() ) {
        console.debug("*** success! proxy connected!");

        SaveCert("http://warcprox./ca.pem");
        ShowVisuals(true);
        return true;
    } else {
        console.debug("*** bad proxy connection");
        turnOffProxy();
        // send out error msg to user
        return false;
    }
}

function turnOffProxy(){
    prefs.set("network.proxy.type", 5);
    ShowVisuals(false);
    RemoveCert();
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

function ShowVisuals(bool){
    ProxyOn = bool;
    if (bool) {
        /*// show warnings with css
        pageModObject = pageMod.PageMod({
            include: "*",
            contentScriptFile: data.url("page.js"),
            contentStyleFile: data.url("page.css")
        });*/

        // turn button icon green
        btn.image = greenlogo;

    } /*else if (pageModObject) {
        pageModObject.destroy();
    }*/
    // return button to default
    if (!bool){
        btn.image = blacklogo;
        notification.clearNotification(warning_id);
    }
}

function SaveCert(url){
    var certDB2 = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB2);
    var certDB = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB);
    var gIOService = Cc["@mozilla.org/network/io-service;1"].getService(Ci.nsIIOService);
    var scriptableStream = Cc["@mozilla.org/scriptableinputstream;1"].getService(Ci.nsIScriptableInputStream);

    var URI = gIOService.newURI(url, null, null);
    var channel = gIOService.newChannelFromURI(URI, null, null);

    var input = channel.open();
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
    certDB2.addCertFromBase64(cert, "C,c,c", "");
    var this_cert = certDB.constructX509FromBase64(cert);
    cert_issuer = this_cert.issuerCommonName;
    cert_serialno = this_cert.serialNumber;

}

function RemoveCert(){
    var certDB = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB);
    var certDB2 = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB2);

    var foundcert = false;
    var listenum = certDB2.getCerts().getEnumerator();
    var cert = listenum.getNext().QueryInterface(Ci.nsIX509Cert);
    while( listenum.hasMoreElements() ){
        if (cert.issuerCommonName == cert_issuer
            && cert.serialNumber == cert_serialno){

            console.debug("** found cert and will remove: "+ cert.issuerCommonName);
            certDB.deleteCertificate(cert);
            foundcert = true;
            break;
        }
        else cert = listenum.getNext().QueryInterface(Ci.nsIX509Cert);
    }
    if (!foundcert) console.debug("** never found cert to remove");
}

function notify(id, txt, priority, allTabs){
    if(allTabs == null ) allTabs = true;
    if (!priority ) priority = 'WARNING_HIGH';
    if (priority.startsWith("INFO"))
        var logo = whitelogo;
    else
        var logo = blacklogo;
    notification.NotificationBox({
        'value': id,
        'label': txt,
        'image': logo,
        'closeprev': true,
        'allTabs' : allTabs,
        'priority': priority
    });
}


// exports.main is called when extension is installed or re-enabled
exports.main = function(options, callbacks) {

    /**** create panel ***/
    optionsPanel = panel.Panel({
        width: 300,
        height: 150,
        contentURL: data.url("options.html"),
        contentScriptFile: data.url("options.js"),
        position: {
            top: 0,
            right: 0
        }
    });

    /**** Panel functions/methods ***/
    optionsPanel.on("show", function() {
        optionsPanel.port.emit("show");
    });

    optionsPanel.port.on("startproxy", function(addr, port){
        var txt;
        if( addr != null && port != null ){
            if(turnOnProxy(addr, port)){
                optionsPanel.port.emit("connected");
                optionsPanel.hide();
                notify(warning_id, warning_msg);
            } else {
                txt = "Error: Unable to connect with these settings.";
                optionsPanel.port.emit("errors", txt);
            }
        } else {
            txt = "Error: Please provide both an address ("+addr+") and port ("+port+") for connection.";
            optionsPanel.port.emit("errors", txt);
        }
    });

    optionsPanel.port.on("stopproxy", function(){
        turnOffProxy();
        optionsPanel.port.emit("disconnected");
        optionsPanel.hide();
        notify(disconnect_id, disconnect_msg, "INFO_LOW", false);
    });

    /***** create toolbar button ****/
    btn  = require("toolbarbutton").ToolbarButton({
        id: "warcprox-button",
        label: "Warcprox toggle",
        image: data.url('img/ait-logo-black16.png'),
        panel: optionsPanel
      });

    /**** move toolbarbutton to nav-bar on install ***/
    if (options.loadReason == "install") {
        btn.moveTo({
            toolbarID: "nav-bar",
            forceMove: false // only move from palette
        });
    }
    tabs.on('ready', function(tab) {
        if(ProxyOn) notify(warning_id, warning_msg);
    });
    tabs.on('open', function(tab) {
        if(ProxyOn) notify(warning_id, warning_msg);
    });
};

// exports.onUnload is called when Firefox starts and when the extension is disabled or uninstalled
exports.onUnload = function(reason) {
    btn.destroy();
    turnOffProxy();
};

// string checking helper
if (typeof String.prototype.startsWith != 'function') {
  String.prototype.startsWith = function (str){
    return this.slice(0, str.length) == str;
  };
}