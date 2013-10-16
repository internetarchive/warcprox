##warcprox - WARC writing MITM HTTP/S proxy

Based on the excellent and simple pymiproxy by Nadeem Douba.
https://github.com/allfro/pymiproxy

License: because pymiproxy is GPL and warcprox is a derivative work of
pymiproxy, warcprox is also GPL.

###Trusting the CA cert

For best results while browsing through warcprox, you need to add the CA cert
as a trusted cert in your browser. If you don't do that, you will get the
warning when you visit each new site. But worse, any embedded https content on
a different server will simply fail to load, because the browser will reject
the certificate without telling you. 
