/*
 * Google Chrome Extension built for Archive-It
 * Extension toggles between turning on & using proxy at specified url and toggling back to normal web browsing.
 *
 */

var proxy_used = "fixed_servers";

chrome.webNavigation.onCommitted.addListener(
    function(details){
        chrome.proxy.settings.get( {}, 
            function(config) {
                console.log(JSON.stringify(config));
                if(config.value.mode == proxy_used){
                    chrome.tabs.executeScript( {file: "page.js"}, function (result) {
                        console.log("-loaded page.js");
                    });
                    chrome.tabs.insertCSS( {file: "page.css"}, function (result) {
                        console.log("-loaded page.css");
                    });
                }
            });
    });


chrome.proxy.onProxyError.addListener(
    function(details) {
        console.log("***ProxyError: "+JSON.stringify(details));
        stopWarcprox("error");
        chrome.proxy.settings.get( {}, 
            function(config) {
                console.log("Reverting back to system settings: "+JSON.stringify(config));
            });

    });
