/*
 * Google Chrome Extension built for Archive-It
 * Extension toggles between turning on & using proxy at specified url and toggling back to normal web browsing.
 *
 */

var pac_url = "http://wayback.archive-it.org/proxy.pac";
var proxy_config = {
  mode: "pac_script",
  pacScript: {
    url: pac_url
  }
};

function check_state_and_toggle() {
    chrome.proxy.settings.get( {}, 
        function(config) {

            if ( config.value.mode == "pac_script"){
                // toggle proxy off
                chrome.proxy.settings.clear({'scope': 'regular'});
                chrome.browserAction.setBadgeText({ "text" : "OFF"});
                chrome.browserAction.setBadgeBackgroundColor({ "color" : "#7D0001" });
                chrome.browserAction.setTitle({"title": "Archive-it Wayback Proxy \nClick to turn proxy ON."});
            } else {
                // toggle proxy on
                chrome.proxy.settings.set(
                    {value: proxy_config, scope: 'regular'},
                    function() {});
                chrome.browserAction.setBadgeText({ "text" : "ON"});  
                chrome.browserAction.setBadgeBackgroundColor({ "color" : "#14552C" });
                chrome.browserAction.setTitle({"title": "Archive-it Wayback Proxy\nClick to turn proxy OFF.\nCurrently using proxy: \n" + pac_url});
            }
        });
}


chrome.browserAction.onClicked.addListener( check_state_and_toggle );
