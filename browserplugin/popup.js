var proxy_config = {
  mode: "pac_script",
  pacScript: {
    url: "http://wayback.archive-it.org/proxy.pac"
  }
};
// chrome.proxy.settings.set(
//     {value: proxy_config, scope: 'regular'},
//     function() {});

// chrome.proxy.settings.clear({'scope': 'regular'});

// chrome.proxy.settings.get("value.mode") ??


on_text = "Proxy is ON";    
off_text = "Proxy is OFF";

function toggle_proxy(){
    var button = document.getElementById("toggle_button").firstChild;
    if( button.data == "On" ){
        print_to_screen(on_text);
        chrome.proxy.settings.set(
            {value: proxy_config, scope: 'regular'},
            function() {});
    } else {
        chrome.proxy.settings.clear({'scope': 'regular'});
        print_to_screen(off_text);
    }
    button.data = button.data == "On" ? "Off" : "On";

}

function print_to_screen(text){
    toggle_el = document.getElementById("toggletext");
    // get current state
    
    if (toggle_el){ // rewrite text inside
        var p=document.createElement("P");
        var t=document.createTextNode(text);
        p.setAttribute("id", "toggletext");
        p.appendChild(t); 
        document.body.replaceChild(p, toggle_el);

    } else { // create element
        var p=document.createElement("P");
        var t=document.createTextNode(text);
        p.setAttribute("id", "toggletext");
        p.appendChild(t); 
        document.body.appendChild(p);
    }
}

document.addEventListener('DOMContentLoaded', 
    function() { 
        document.getElementById("toggle_button").addEventListener("click", toggle_proxy); 
    });
