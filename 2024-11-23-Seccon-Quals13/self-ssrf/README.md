# self-ssrf

Guess the flag, or abuse the `/ssrf` endpoint.

```js
import express from "express";

const PORT = 3000;
const LOCALHOST = new URL(`http://localhost:${PORT}`);
const FLAG = Bun.env.FLAG!!;

const app = express();

app.use("/", (req, res, next) => {
  if (req.query.flag === undefined) {
    const path = "/flag?flag=guess_the_flag";
    res.send(`Go to <a href="${path}">${path}</a>`);
  } else next();
});

app.get("/flag", (req, res) => {
  res.send(
    req.query.flag === FLAG // Guess the flag
      ? `Congratz! The flag is '${FLAG}'.`
      : `<marquee>🚩🚩🚩</marquee>`
  );
});

app.get("/ssrf", async (req, res) => {
  try {
    const url = new URL(req.url, LOCALHOST);

    if (url.hostname !== LOCALHOST.hostname) {
      res.send("Try harder 1");
      return;
    }
    if (url.protocol !== LOCALHOST.protocol) {
      res.send("Try harder 2");
      return;
    }

    url.pathname = "/flag";
    url.searchParams.append("flag", FLAG);
    res.send(await fetch(url).then((r) => r.text()));
  } catch {
    res.status(500).send(":(");
  }
});

app.listen(PORT);

```

## Description

The target app serves two endpoints and has a middleware. The middleware returns a static response unless you send a request with the `flag` parameter in the query.

```js
app.use("/", (req, res, next) => {
  if (req.query.flag === undefined) {
    const path = "/flag?flag=guess_the_flag";
    res.send(`Go to <a href="${path}">${path}</a>`);
  } else next();
});
```

The `/flag` endpoint returns the flag if the `flag` parameter is equal to the actual flag. It is a strict comparison without type casting.

```js
app.get("/flag", (req, res) => {
  res.send(
    req.query.flag === FLAG // Guess the flag
      ? `Congratz! The flag is '${FLAG}'.`
      : `<marquee>🚩🚩🚩</marquee>`
  );
});
```

The `/ssrf` endpoint takes the `req.url`, changes the path to `/flag`, appends a real flag, makes a fetch to that location and returns the response.

```js
app.get("/ssrf", async (req, res) => {
  try {
    const url = new URL(req.url, LOCALHOST);

    if (url.hostname !== LOCALHOST.hostname) {
      res.send("Try harder 1");
      return;
    }
    if (url.protocol !== LOCALHOST.protocol) {
      res.send("Try harder 2");
      return;
    }

    url.pathname = "/flag";
    url.searchParams.append("flag", FLAG);
    res.send(await fetch(url).then((r) => r.text()));
  } catch {
    res.status(500).send(":(");
  }
});
```

So without the middleware, we would make the request to `/ssrf`, it would append a real flag and make a request to `/flag?flag=SECCON{REALFLAG}` and that would return us the flag. But because the midleware forces us to send a `flag` parameter of our own, no matter if we send:

- `flag=a`
- `flag=`
- `flag[1]=a`
- `flag[key]=value`

  the second request will have two flags - our one and the real one. It will be converted to either an array or an object which will never pass the `===` comparison with the real flag. So we have to somehow send a `flag` parameter that will be the `flag` parameter that will disappear before the internal request.

## The solution

The solution was to send `/ssrf?flag[a=]=b`.

When parsed by the middleware, the `a=` would be treated as the object key and the second equal sign as the value separator. The `req.query` object would be

```json
{
  "flag": {
    "a=": "b"
  }
}
```

While this behaviour of allowing to send objects or arrays in a URL query is pretty common in web frameworks, it isn't part of the standard. Technically, a query contains `key=value` pairs of strings, separated by an equal sign. That's why `new URL('/ssrf?flag%5Ba=%5D=b')` treats the first equal sign as the key=value separator and URL-encodes the second equal sign. Thus, the second request only has one non-URL-encoded equal sign in our parameter.

It is being sent to `/flag?flag%5Ba=%5D%3Db&flag=seccon%7BREALFLAG%7D` so when parsed by the flag router, the `req.query` is

```json
{
  "flag[a": "]=b",
  "flag": "seccon{REALFLAG}"
}
```

so it only has one flag parameter, with the real flag which we receive in the response.

![solve](./solve.png)

The flag's message says it wasn't the intended one. In one [blogpost](https://zenn.dev/ponyopoppo/articles/894c3c2e5a06b6), I saw someone solving with with `?flag\uFEFF`.
