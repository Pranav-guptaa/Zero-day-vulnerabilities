// Sample JavaScript code for testing the analysis

// Rule: eval (JS1001)
eval("console.log('This is an eval call.');");

// Rule: innerHTML (JS1002)
document.getElementById("element").innerHTML = '<script>alert("XSS Attack");</script>';

// Rule: localStorage (JS1003)
localStorage.setItem("password", "12345");

// Rule: XMLHttpRequest (JS1004)
var xhr = new XMLHttpRequest();
xhr.open("GET", "http://example.com/data", true);

// Rule: setTimeout|setInterval (JS1005)
setTimeout("alert('Insecure timer')", 1000);

// Rule: WebSockets (JS1006)
var socket = new WebSocket("ws://example.com");

// Rule: React dangerouslySetInnerHTML (JS1007)
const dangerouslySetHTML = { __html: '<script>alert("XSS Attack");</script>' };

// Rule: Crypto.getRandomValues (JS1008)
var randomValues = new Uint32Array(5);
crypto.getRandomValues(randomValues);

// Rule: localStorage.getItem (JS1009)
var userPassword = localStorage.getItem("password");

// Rule: JSON.parse (JS1010)
var data = JSON.parse('{"key": "value"}');
