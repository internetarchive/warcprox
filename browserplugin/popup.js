
function startWarcprox() {
    var given_host = "127.0.0.1";//document.getElementById("host");
    var given_port = 8000;//document.getElementById("port");

    var proxy_config = {
        mode: "fixed_servers",
        rules: {
            proxyForHttp: {
                scheme: "http",
                host: given_host,
                port: given_port
            },
            // bypassList: ["foobar.com"]
        }
    };
    // chrome.proxy.settings.set(
    //         {value: proxy_config, scope: 'regular'},
    //         function() {});
    chrome.browserAction.setBadgeText({ "text" : "ON"});

}

function stopWarcprox() {
    chrome.proxy.settings.clear({'scope': 'regular'});
    chrome.browserAction.setBadgeText({ "text" : ""});
}


document.addEventListener('DOMContentLoaded', 
    function() { 
        // check_state_and_update_page();
        chrome.proxy.settings.clear({'scope': 'regular'});
        document.getElementById("submit_settings").addEventListener("click", startWarprox); 

    });
