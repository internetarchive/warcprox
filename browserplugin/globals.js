
function stopWarcprox(type) {
    console.log("inside stopWarcprox");
    chrome.proxy.settings.clear({'scope': 'regular'});
    chrome.browserAction.setBadgeText({ "text" : ""});
    console.log("cleared proxy");
    if (type == "error"){
    	alert("Proxy Error!\nProxy settings disconnected.");
    }
}

