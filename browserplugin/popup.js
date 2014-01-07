
var def_config = {
  mode: "system"
}


var proxy_config = {
  mode: "pac_script",
  pacScript: {
    url: "http://wayback.archive-it.org/proxy.pac"
  }
};
// chrome.proxy.settings.set(
//     {value: proxy_config, scope: 'regular'},
//     function() {});


// chrome.proxy.settings.get("value.mode") ??


on_text = "Proxy is ON";    
off_text = "Proxy is OFF";

function onload(){
    var on_button = document.getElementById("proxy_on");
    var off_button = document.getElementById("proxy_off");
    on_button.addEventListener("click", toggle_on);
    off_button.addEventListener("click", toggle_off)

}

function toggle_on(){
    toggle(on_text);
}
function toggle_off(){
    toggle(off_text);
}

function toggle(text){

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
    
    hide_show_proxy_button();
}

function hide_show_proxy_button(){
    on = document.getElementById("proxy_on");
    off = document.getElementById("proxy_off");
    
    if (off.style.display == "none"){
        off.style.display = "inline";
        on.style.display = "none";
    } else {
        on.style.display = "inline";
        off.style.display = "none";
    }
}


onload();