//var widgets = require("sdk/widget");
//var tabs = require("sdk/tabs");
//var widget = widgets.Widget({
//   id: "mozilla-link",
//   label: "Mozilla website",
//   contentURL: "http://www.mozilla.org/favicon.ico",
//   onClick: function() {
//     tabs.open("http://www.mozilla.org/");
//   }
//});

// import the modules we need
var data = require('sdk/self').data;
var {Cc, Ci} = require('chrome');
var mediator = Cc['@mozilla.org/appshell/window-mediator;1'].getService(Ci.nsIWindowMediator);
var prefs = require("sdk/preferences/service");

// exports.main is called when extension is installed or re-enabled
exports.main = function(options, callbacks) {
    addToolbarButton();
    // do other stuff
};

// exports.onUnload is called when Firefox starts and when the extension is disabled or uninstalled
exports.onUnload = function(reason) {
    removeToolbarButton();
    // do other stuff
};

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

function changeButtonColor(setting){
    var document = mediator.getMostRecentWindow('navigator:browser').document;
    var btn = document.getElementById('mybutton-id');

    if ( setting == "on" ) {
        console.debug("button color changed to 'on'/green");
        btn.setAttribute('image', data.url('img/ait-logo-green16.png'));
    }
    if (setting == "off") {
        console.debug("button color changed to 'off'/black");
        btn.setAttribute('image', data.url('img/ait-logo-black16.png'));
    }
}

function turnOnProxy(){
    ip="127.0.0.1";
    port=8000;
    prefs.set("network.proxy.type", 1);
    prefs.set("network.proxy.http", ip);
    prefs.set("network.proxy.http_port", port);

    changeButtonColor("on");
}

function turnOffProxy(){
    prefs.set("network.proxy.type", 5);

    changeButtonColor("off");
}

