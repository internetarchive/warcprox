/* 
 * Places a red border around the body of the page & a warning div at the top.
 */

div = document.getElementById("ArchivingWarningTopDiv");

if (!div){ // to prevent multiple writes to same page
	var div = document.createElement("DIV");
	var t = document.createTextNode("Careful! Your activity is being archived!");

	div.setAttribute("id", "ArchivingWarningTopDiv");
	div.style.display = "none";
	div.appendChild(t);

	document.body.insertBefore(div, document.body.firstChild);
}

document.body.setAttribute("class", "ArchivingWarningBodyBorder");
