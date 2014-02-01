self.port.on("show", function (arg) {

    document.getElementById("start").onclick = function(event) {
        var port = document.getElementById("port").value;
        var addr = document.getElementById("addr").value;
        self.port.emit("startproxy", addr, parseInt(port));
    };

    document.getElementById("stop").onclick = function(event) {
        self.port.emit("stopproxy");
    };

    /****** default button used for testing only!!!!! *****/
/*    document.getElementById("defaults").onclick = function() {
        self.port.emit("startproxy", "127.0.0.1", 8000)
    };*/

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

    // clear out any previous errors
    document.getElementById("errors").innerHTML = "";

});

self.port.on("disconnected", function(){
    // show the settings & hide the STOP button
    var startsettings = document.getElementById("startsettings");
    var stopsettings = document.getElementById("stopsettings");

    startsettings.style.display = "inline";
    stopsettings.style.display = "none";

});