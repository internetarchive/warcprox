/*
 * Google Chrome Extension built for Archive-It
 * Extension toggles between turning on & using proxy at specified url and toggling back to normal web browsing.
 *
 */


var proxy_used = "system";

chrome.tabs.onUpdated.addListener(
    function(id, changeInfo, updatedTab) {
        console.log("tab "+id+" status "+ JSON.stringify(changeInfo.status));  
        chrome.proxy.settings.get( {}, 
            function(config) {
                console.log(JSON.stringify(config.value.mode));
                if(config.value.mode == proxy_used && changeInfo.status == "loading") {
                    chrome.tabs.executeScript( id, {file: "page.js"}, function (result) {
                        console.log("-loaded page.js");
                    });
                    chrome.tabs.insertCSS( id, {file: "page.css"}, function (result) {
                        console.log("-loaded page.css");
                    });
                }
            });
  
    });