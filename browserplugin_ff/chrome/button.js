var prefs = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranch);

function ButtonClick() { 
    if (prefs.getIntPref("network.proxy.type") == 5) {
        turnProxyOn();
        msg = "Proxy";
    } else {
        turnProxyOff();
        msg = "System";
    }
    alert("network setting: "+ msg);
}

function turnProxyOff(){
    prefs.setIntPref("network.proxy.type", 5);
    swapClass("AIT-button", "custombutton_on", "custombutton_off");

}

function turnProxyOn(){
    ip="127.0.0.1";
    port=8000;
    prefs.setIntPref("network.proxy.type", 1); 
    prefs.setCharPref("network.proxy.http", ip);
    prefs.setIntPref("network.proxy.http_port", port); 
    // prefs.setCharPref("javascript.enabled", "true");
    
    // give preset warcprox url to cert pem
    // SaveCert("http://warcprox./ca.pem");
    swapClass("AIT-button", "custombutton_off", "custombutton_on");
}

function SaveCert(uri){

    // var certDB = Components.classes["@mozilla.org/security/x509certdb;1"].getService(Components.interfaces.nsIX509CertDB2);
    var certDB = Components.classes["@mozilla.org/security/x509certdb;1"].getService(Components.interfaces.nsIX509CertDB);
    var gIOService = Components.classes['@mozilla.org/network/io-service;1'].getService(Components.interfaces.nsIIOService);
    var scriptableStream = Components.classes["@mozilla.org/scriptableinputstream;1"].getService(Components.iinterfaces.nsIScriptableInputStream);
    var uriChannel = gIOService.newChannelFromURI(uri, null, null);

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

    // certDB.addCertFromBase64(cert, "C,c,c", "");
    created_cert = certDB.constructX509FromBase64(cert);

}

function swapClass(id, removeClass, addClass){
    el = document.getElementById(id);
    if (el.classList.contains(removeClass)) {
        el.classList.remove(removeClass);
    }
    if (!el.classList.contains(addClass)) {
        el.classList.add(addClass);
    }
}



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
turnProxyOff();