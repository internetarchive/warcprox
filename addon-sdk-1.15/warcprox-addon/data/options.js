self.port.on("show", function (arg) {
//    var startbtn = document.getElementById("start");
//    var stopbtn = document.getElementById("stop");
   ;


    document.getElementById("start").onclick = function(event) {
        var port = document.getElementById("port").value;
        var addr = document.getElementById("addr").value;
        self.port.emit("startproxy", addr, parseInt(port));
    };

    document.getElementById("stop").onclick = function(event) {
        self.port.emit("stopproxy");
    };

//    var defaultbtn = document.getElementById("defaults");
//    defaultbtn.onclick = function() {
//        self.port.emit("startproxy", "127.0.0.1", 8000)
//    };

//  var textArea = document.getElementById('edit-box');
//  textArea.focus();
//  // When the user hits return, send a message to main.js.
//  // The message payload is the contents of the edit box.
//  textArea.onkeyup = function(event) {
//    if (event.keyCode == 13) {
//      // Remove the newline.
//      text = textArea.value.replace(/(\r\n|\n|\r)/gm,"");
//      self.port.emit("text-entered", text);
//      textArea.value = '';
//    }
//  };
});

self.port.on("errors", function(txt){
    document.getElementById("errors").innerHTML = txt;
});

self.port.on("connected", function(){
    // hide the settings & show the STOP button
    var startsettings = document.getElementById("startsettings");
    var stopsettings = document.getElementById("stopsettings");

    startsettings.style.display = "none";
    stopsettings.style.display = "inline";

});

self.port.on("disconnected", function(){
    // show the settings & hide the STOP button
    var startsettings = document.getElementById("startsettings");
    var stopsettings = document.getElementById("stopsettings");

    startsettings.style.display = "inline";
    stopsettings.style.display = "none";

});