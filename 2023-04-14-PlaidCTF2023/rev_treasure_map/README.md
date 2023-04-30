## Treasure Map

Note that the writeup was written after the task's webpage was taken down so it is written based on my memory of this task and the scripts are untested.

In this task we were linked to a webpage, where we could enter a flag and the website let us check whether the flag is correct or not.

By looking at the web page source, we could quickly see that it checks the flag length and imports a module called 0.js.
By entering a test flag, we could see in the Chrome developer console's Network tab that more js files are downloaded (including the .map files for these .js files) and eventually a script `fail.js` is downloaded and executed.

The `.map` files raised suspicion and also suggested that there are files indexes from 0 to 200, in addition to `success.js` and `fail.js`.

The indexed JavaScript files seemed to be fully identical. The files started with a declaration of a `b64` multiline literal, which seemingly had all the base64 characters one per line.

Each file also exported a function called `go` (the one for `0.js` is invoked by the script on the web page), which does some magic, followed by an import of another script and execution of the `go` function exported to it.

This leaves us with an important question. What differs these flags between each other? We should be able to execute parts of this source code!
It seems that the script first does a `fetch(import.meta.url)`, which basically seems to download the script's own source code, then parses it somehow.
We can define the `b64` array in the developer console, and then execute the following code:
```js
await (async function(){
    const bti = b64.trim().split("\n").reduce((acc, x, i) => (acc.set(x, i), acc), new Map());
    const moi = await fetch("/" + i + ".js").then((x) => x.text())
    console.log(moi.slice(moi.lastIndexOf("=") + 1));
});
```
Thanks to which we can see that the file which the script attempts to load is the `.map` file for the script.
Next I looked at what the parts of the long expression were and luckily the `filter` expression referencing the flag input (the `upc` variable) was at the very end of it. 
Which meant that there was some map generated based on the `.map` file for the given script and then the name of the next file to load is simply taken from this generated map.

Since we have a graph (or a tree if we are lucky) which we need to navigate. We need to find a path in this graph of a known length.
I told the team to make a script to find the path in a graph given a particular JSON format I thought I could generate and proceeded to make a quick script to generate this JSON from the developer console.

### Script to generate the map JSON
```js
await (async function(){
const b64 = `
A
B
C
D
E
F
G
H
I
J
K
L
M
N
O
P
Q
R
S
T
U
V
W
X
Y
Z
a
b
c
d
e
f
g
h
i
j
k
l
m
n
o
p
q
r
s
t
u
v
w
x
y
z
0
1
2
3
4
5
6
7
8
9
+
/
=`;
let ret = {};
for (let i = 0; i < 200; i++) {
    const bti = b64.trim().split("\n").reduce((acc, x, i) => (acc.set(x, i), acc), new Map());
    const moi = await fetch("/" + i + ".js").then((x) => x.text())
    const tg = await fetch(moi.slice(moi.lastIndexOf("=") + 1)).then((x) => x.json())
    const fl = tg.mappings.split(";").flatMap((v, l) =>v.split(",").filter((x) => !!x).map((input) => input.split("").map((x) => bti.get(x)).reduce((acc, i) => (i & 32 ? [...acc.slice(0, -1), [...acc.slice(-1)[0], (i & 31)]] : [...acc.slice(0, -1), [[...acc.slice(-1)[0], i].reverse().reduce((acc, i) => (acc << 5) + i, 0)]].map((x) => typeof x === "number" ? x : x[0] & 0x1 ? (x[0] >>> 1) === 0 ? -0x80000000 : -(x[0] >>> 1) : (x[0] >>> 1)).concat([[]])), [[]]).slice(0, -1)).map(([c, s, ol, oc, n]) => [l,c,s??0,ol??0,oc??0,n??0]).reduce((acc, e, i) => [...acc, [l, e[1] + (acc[i - 1]?.[1]??0), ...e.slice(2)]], [])).reduce((acc, e, i) => [...acc, [...e.slice(0, 2), ...e.slice(2).map((x, c) => x + (acc[i - 1]?.[c + 2] ?? 0))]], []).map(([l, c, s, ol, oc, n], i, ls) => [tg.sources[s],moi.split("\n").slice(l, ls[i+1] ? ls[i+1]?.[0] + 1 : undefined).map((x, ix, nl) => ix === 0 ? l === ls[i+1]?.[0] ? x.slice(c, ls[i+1]?.[1]) : x.slice(c) : ix === nl.length - 1 ? x.slice(0, ls[i+1]?.[1]) : x).join("\n").trim()]);
    //console.log(fl);
    ret["/" + i + ".js"] = fl;
    console.log(i, fl);
}
window.ret = ret;
}());
```

### Script to find the path
```py
import json
import random

G = json.load(open('message.txt'))

G['success.js'] = []

stack = []
maxd = 0
visit = set()
def dfs(x):
    if x in visit: return
    visit.add(x)

    print(u, ''.join(stack))

    g = G[x][:]
    random.shuffle(g)
    for v, e in g:
        stack.append(e)
        dfs(v)
        stack.pop()

for u in G:
    dfs(u)
    visit.clear()
```
