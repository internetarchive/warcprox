
var button_text_on = "On";
var button_text_off = "Off";
var on_text = "Proxy is currently ON";    
var off_text = "Proxy is currently OFF";
var text_id = "toggletext";
var button_id = "toggle_button";

var proxy_config = {
  mode: "pac_script",
  pacScript: {
    url: "http://wayback.archive-it.org/proxy.pac"
  }
};

function toggle_proxy(mode) {
    if ( mode == "pac_script"){
        // toggle proxy off
        chrome.proxy.settings.clear({'scope': 'regular'});
        update_page("");

    } else {
        // toggle proxy on
        chrome.proxy.settings.set(
            {value: proxy_config, scope: 'regular'},
            function() {});
        update_page("pac_script");
    }

    // debugging only
    // chrome.proxy.settings.get( {}, 
    //     function(config) {console.log(JSON.stringify(config.value.mode));});
}

function check_state(func) {
    if (func) {
    chrome.proxy.settings.get( {}, 
        function(config) {
            console.log(JSON.stringify(config.value.mode));
            func(config.value.mode);
        });
    } else {
        chrome.proxy.settings.get( {}, 
        function(config) {
            console.log(JSON.stringify(config.value.mode));
            func(config.value.mode);
        });
    }
}

function check_state_and_toggle() {
    check_state(toggle_proxy);
}
function check_state_and_update_page() {
    check_state(update_page);
}
function update_page(mode) {
    if (mode == "pac_script"){
        // change button to say "Off" and say that proxy is currently ON
        document.getElementById(button_id).firstChild.data = button_text_off;
        print_to_screen(on_text);
        chrome.browserAction.setBadgeText({ "text" : "ON"});
    } else {
        // change button to say "On" and say that proxy is currently OFF
        document.getElementById(button_id).firstChild.data = button_text_on;
        print_to_screen(off_text);
        chrome.browserAction.setBadgeText({ "text" : "OFF"});
    }
}

function print_to_screen(text) {
    var p=document.createElement("P");
    var t=document.createTextNode(text);
    p.setAttribute("id", text_id);
    p.appendChild(t); 

    toggle_el = document.getElementById(text_id);

    if (toggle_el) { // if exists, rewrite text inside
        document.body.replaceChild(p, toggle_el);
    } else { // else create element
        document.body.appendChild(p);
    }
}

document.addEventListener('DOMContentLoaded', 
    function() { 
        check_state_and_update_page();
        document.getElementById(button_id).addEventListener("click", check_state_and_toggle); 
    });
