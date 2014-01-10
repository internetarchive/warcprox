
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
    chrome.proxy.settings.set(
            {value: proxy_config, scope: 'regular'},
            function() {});

    // add ajax test call to proxy.  if successful, continue, else alert user & stop

    chrome.browserAction.setBadgeText({ "text" : "ON"});
    console.log("started proxy server at " + given_host + ":" + given_port);
    chrome.proxy.onProxyError.addListener(
        function(details) {
            console.log("ProxyError: "+JSON.stringify(details)+"\nReverting back to system settings");
            // document.getElementById("proxyErrors").innerHTML = "Proxy Settings produced and error. ";
            stopWarcprox();

        });

}




document.addEventListener('DOMContentLoaded', 
    function() { 
        chrome.proxy.settings.clear({'scope': 'regular'});
        document.getElementById("submit_settings").addEventListener("click", startWarcprox); 
        document.getElementById("stop_proxy").addEventListener("click", stopWarcprox);

    });
