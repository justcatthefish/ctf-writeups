# Just The Check Please

## Task description

Ahoy, me matey! There be this program that be wantin’ a brawl, and a fine argument I shall give, standing tall! It claims to check the argument, but I get naught but fail; time and time again, it be driving me up the rail! I’ve tried inputs aplenty, but to no avail---most of the time, it quickly shouts fail! Can ye lend me a hand, me hearty, and give me an argument with flair, so I can show this program what a proper argument can bear?

## Solution

Opening the binary in IDA tells us that we are dealing with Rust binary:

```c
  result = sub_178A0(&memptr, &v25);
  v6 = (const char *)memptr;
  if ( !memptr )
  {
    v6 = "Index out of bounds()/rustc/9eb3afe9ebe9c7d2b84b71002d44f4a0edac95e0/library/core/src/str/pattern.rs";
    v7 = 0LL;
    goto LABEL_9;
  }
```

The core of the program is located in `sub_9210()` function which has ~7000 lines after decompilation, so there is a lot of code to analyze...

After quick analysis it turned out that the binary expects a word passed as first command line argument, and it should be 16 characters long. Found that by tracing the return value of the following instruction:


```c
.text:000000000000930B                 mov     rax, qword ptr [rsp+2B8h+fd]
.text:0000000000009313                 mov     r12, [rax+r13*8]
.text:0000000000009317                 mov     rdi, r12        ; s
.text:000000000000931A                 call    cs:strlen_ptr
```


At this point I was curious if binary is doing early exiting if input does not match. To verify this hypothesis I've created the following script:

```py
import string
from subprocess import check_output
import subprocess

def get_instr_cnt(word):
    try:
        output = check_output(f'LC_ALL=C perf stat -e instructions:u ./check "{word}"', shell=True, stderr=subprocess.STDOUT)
    except Exception as e:
        o = e.output.decode()
        try:
            instr = next(filter(lambda line: 'instructions:u' in line, o.splitlines())).split('instructions')[0].strip().replace(' ', '')
            instr = int(instr)
            # print(instr, word.encode())
            return instr
        except Exception as e2: pass
    
    return 0

stats = {}
for c in string.printable:
    stats[c] = get_instr_cnt(c * 16)

instr_sort = sorted(stats.items(), key=lambda t: t[1], reverse=True)
print(instr_sort)
```

and the output looked like this:

```
[('T', 30668100), ('e', 30170435), ('i', 30170430), ('8', 30170409), ('6', 30170407), ('\n', 30170377), (':', 30170255), ('y', 30170249), ('a', 30170191), ('+', 30170154), ('A', 30170145), ('n', 30170099), ('K', 30170080), ('O', 30170076), ('P', 30170068), ('x', 30170039), ('F', 30170037), (']', 30170027), ('(', 30170025), ('b', 30170015), ('Z', 30170010), ('u', 30169966), ('%', 30169959), ('Q', 30169948), ('V', 30169948), ('v', 30169932), ('g', 30169925), ('}', 30169918), ('W', 30169912), (',', 30169900), ('c', 30169885), ('X', 30169842), ('M', 30169840), ('7', 30169837), ('I', 30169835), ('D', 30169827), ('r', 30169824), ('1', 30169822), ('o', 30169812), ('f', 30169811), ('U', 30169809), ('k', 30169805), ('#', 30169795), ('B', 30169793), ('s', 30169786), ('\x0c', 30169782), ('~', 30169777), ('^', 30169758), ('|', 30169756), ('.', 30169751), ('=', 30169747), ('w', 30169742), ('?', 30169737), ('\r', 30169732), ('/', 30169731), ('S', 30169727), ('L', 30169726), ('\x0b', 30169716), ('m', 30169715), ('-', 30169711), ('&', 30169710), ('z', 30169702), ('<', 30169700), ('*', 30169697), ('q', 30169673), ('E', 30169667), ('N', 30169660), ("'", 30169654), ('9', 30169645), ('h', 30169645), ('d', 30169642), (' ', 30169628), ('Y', 30169614), ('3', 30169606), ('!', 30169606), ('t', 30169602), ('l', 30169573), (')', 30169571), ('@', 30169547), ('[', 30169539), ('0', 30169530), ('5', 30169530), ('H', 30169526), ('4', 30169416), ('J', 30169376), ('\t', 30169368), ('>', 30169367), ('{', 30169349), ('p', 30169330), ('2', 30169320), ('j', 30169312), ('_', 30169302), ('R', 30169281), ('G', 30169277), (';', 30169275), ('C', 30169259), ('`', 276041), ('$', 271283), ('\\', 270905), ('"', 270228)]
```

It is clear that a word consisting only of the letters `T` caused the program to execute the most instructions. A bit of playing with this information was enough to figure out that the password is not checked char by char, but rather chars are tested in random order.


The above information was enough to write a solver script:

```py
import string
from subprocess import check_output
import subprocess

FLAG_LEN = 16
recovered = [None] * FLAG_LEN

def get_instr_cnt(word):
    try:
        output = check_output(f'LC_ALL=C perf stat -e instructions:u ./check "{word}"', shell=True, stderr=subprocess.STDOUT)
    except Exception as e:
        o = e.output.decode()
        try:
            instr = next(filter(lambda line: 'instructions:u' in line, o.splitlines())).split('instructions')[0].strip().replace(' ', '')
            instr = int(instr)
            # print(instr, word.encode())
            return instr
        except Exception as e2: pass
    
    return 0

for i in range(FLAG_LEN):
    stats = {}
    for c in string.printable:
        word = ''.join(map(lambda c: '?' if c is None else c, recovered))
        word = word.replace('?', c)
        stats[c] = get_instr_cnt(word)

    instr_sort = sorted(stats.items(), key=lambda t: t[1], reverse=True)
    best_letter, instr_cnt = instr_sort[0]

    # now find the position
    stats = {}
    for pos in range(FLAG_LEN):
        word = list(map(lambda c: '?' if c is None else c, recovered))
        word[pos] = best_letter
        word = ''.join(word)
        stats[pos] = get_instr_cnt(word)

    instr_sort = sorted(stats.items(), key=lambda t: t[1], reverse=True)
    best_pos, instr_cnt = instr_sort[0]
    recovered[best_pos] = best_letter
    word = ''.join(map(lambda c: '?' if c is None else c, recovered))
    print(word)
```

```
?????T??????????
??t??T??????????
??t??T??????l???
w?t??T??????l???
w?t3?T??????l???
w?t3?T?g????l???
w?t3?T1g????l???
w?t3?T1g??-?l???
w?t3?T1g?T-?l???
w?t3rT1g?T-?l???
w?t3rT1g?T-?l?z?
w?t3rT1g?T-bl?z?
wat3rT1g?T-bl?z?
wat3rT1g?T-bl?z3
wat3rT1g?T-blAz3
wat3rT1ghT-blAz3
```

The secret phrase is: `wat3rT1ghT-blAz3` and once sent to the remote service - it gives flag: `PCTF{my_check_is_s1gned_with_my_arrrrtograph__426300c6ae4524d8ff4c3abeee}`
