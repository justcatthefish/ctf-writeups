# CSS
Task description:
```
I found this locked chest at the bottom o' the ocean, but the lock seems downright... criminal. Think you can open it? We recommend chrome at 100% zoom. Other browsers may be broken.
```

## Solution
In this challenge the HTML file was provided that required entering a password. When correct password (flag) is entered then `correct!` message appeared.

Each chosen letter resulted in a expansion of hidden div that increased overall height which was used to calculate position of several SVGs via CSS. The password were split into groups of 3 letters that controlled independent 4 SVGs - when the letters were set as expected then these images aligned in a such way that `correct!` message was displayed.

It was possible to brute each group of 3 letters asynchronously, at first we've came with an idea to make this with a macro however it would take us in worst case scenario approx. 6 hours (in a single browser). The second approach used custom JS code that would try each possible 3 letter combinations and we were observing when `correct!` message did appear.

```javascript
function format_selector(selector, idx) {
    return selector.replace('%', ""+idx);
}

const alphabet = 'abcdefghijklmnopqrstuvwxyz_';

function set_character(position, c) {
    let block = Math.floor(position / 3);
    let selector = `body > div > div:nth-child(${9+block}) > div:nth-child(7) > details:nth-child(%)`;
    const cidx = 26-alphabet.indexOf(c);
    for (let i = 0; i < 26; ++i) {
        let b = i >= cidx;
        let elem = document.querySelector(format_selector(selector, 1 + i + 26*(position % 3)));
        if (!elem) {
            console.log(`not found: position=${position} c=${c}, i=${i}, selector=${format_selector(selector, 1 + i + 26*(position % 3))}`);
        }
        elem.open = b;
    }
}

async function iterate_opens2(timeout) {
    timeout = timeout || 1;
    let current_prefix = "";
    let next_block = Math.floor(current_prefix.length / 3);
    let start_div_block_idx = 9;
    for (let i = start_div_block_idx + next_block + 1; i < 23; ++i) {
        document.querySelector(`body > div > div:nth-child(${start_div_block_idx + next_block + 1})`).remove();
    }

    for (let i = 0; i < current_prefix.length; ++i) {
        set_character(i, current_prefix[i]);
    }

    let f = async (idx) => {
        if (idx < next_block*3+3) {
            for (let x = 0; x < 27; ++x) {
                set_character(idx, alphabet[x]);
                await f(idx + 1);
            }
        } else {
            await new Promise(r => setTimeout(r, timeout));
        }
    }
    await f(current_prefix.length);
}

async function brute() {
    for (let x = 0; x < 27; ++x) {
        for (let y = 0; y < 27; ++y) {
            for (let z = 0; z < 27; ++z) {
                for (let i = 0; i < 26; ++i) {
                    let b = i > x;
                    let elem = document.querySelector(format_selector(selector, 1 + i));
                    if (!elem) {
                        console.log(`x: Not found: ${i}, ${format_selector(selector, 1+i)}`);
                    }
                    elem.open = b;
                }
                for (let i = 0; i < 26; ++i) {
                    let b = i > y;
                    let elem = document.querySelector(format_selector(selector, 1 + i + 26));
                    if (!elem) {
                        console.log(`y: Not found: ${i}, ${format_selector(selector, 1+i+26)}`);
                    }
                    elem.open = b;
                }
                for (let i = 0; i < 26; ++i) {
                    let b = i > z;
                    let elem = document.querySelector(format_selector(selector, 1 + i + 26*2));
                    if (!elem) {
                        console.log(`z: Not found: ${i}, ${format_selector(selector, 1+i+26*2)}`);
                    }
                    elem.open = b;
                }
                await new Promise(r => setTimeout(r, 5));
            }
        }
    }
}
```
