CustomButton = { 

    1: function () { 

        const url = "http://google.com";
        document.getElementById("content").webNavigation.loadURI(url, 0, null, null, null);

    }, 

    2: function(){
        var prefs = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranch);
        // prefs.setIntPref("network.proxy.type", 0); 
        // prefs.setCharPref("network.proxy.socks",'');
        // prefs.setIntPref("network.proxy.socks_port",0);
        // prefs.setCharPref("network.proxy.ssl",'');
        // prefs.setIntPref("network.proxy.ssl_port",0);
        // prefs.setCharPref("network.proxy.ftp",'');
        // prefs.setIntPref("network.proxy.ftp_port",0);


        if (prefs.getIntPref("network.proxy.type") != 5) {
            prefs.setIntPref("network.proxy.type", 5);
        } else {
            ip="127.0.0.1";
            port=8000;
            prefs.setIntPref("network.proxy.type", 1); 
            prefs.setCharPref("network.proxy.http", ip);
            prefs.setIntPref("network.proxy.http_port", port); 
            // prefs.setCharPref("javascript.enabled", "true");
            prefs.setCharPref("network.proxy.no_proxies_on", "local host")
            // SaveCert("");
        }

        if (prefs.getIntPref("network.proxy.type") == 5) {
            msg = "System";
        } else {
            msg = "Proxy";
        }
        alert("network setting: "+ msg);
    }

}


function SaveCert(uri){

// function installCert(CertName, CertTrust) {
    var gIOService = Components.classes["@mozilla.org/network/io-service;1"]
                        .getService(Ci.nsIIOService);
    var certDB = Components.classes["@mozilla.org/security/x509certdb;1"]
                        .getService(Ci.nsIX509CertDB2);

    var ios = Components.classes['@mozilla.org/network/io-service;1']
          .getService(Components.interfaces.nsIIOService);
    var uriChannel = ios.newChannelFromURI(uri, null, null);

    var scriptableStream = Components.classes["@mozilla.org/scriptableinputstream;1"]
                                .getService(Ci.nsIScriptableInputStream);
    // var channel = gIOService.newChannel(self.data.url(CertName), null, null);

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

    certDB.addCertFromBase64(cert, "C,c,c", "");
}

// exports.main = function() {
//     installCert("cacert-root.crt", "C,c,c");
// }



/**
 * Installs the toolbar button with the given ID into the given
 * toolbar, if it is not already present in the document.
 *
 * @param {string} toolbarId The ID of the toolbar to install to.
 * @param {string} id The ID of the button to install.
 * @param {string} afterId The ID of the element to insert after. @optional
 */
function installButton(toolbarId, id, afterId) {
    if (!document.getElementById(id)) {
        var toolbar = document.getElementById(toolbarId);

        // If no afterId is given, then append the item to the toolbar
        var before = null;
        if (afterId) {
            let elem = document.getElementById(afterId);
            if (elem && elem.parentNode == toolbar)
                before = elem.nextElementSibling;
        }

        toolbar.insertItem(id, before);
        toolbar.setAttribute("currentset", toolbar.currentSet);
        document.persist(toolbar.id, "currentset");

        if (toolbarId == "addon-bar")
            toolbar.collapsed = false;
    }
}

if (firstRun) {
    installButton("nav-bar", "AIT-button");
    // The "addon-bar" is available since Firefox 4
    installButton("addon-bar", "AIT-button");
}