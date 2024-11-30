# F is for flag (re)

I used ida, renamed the super long named lambda functions to something shorter that I could manage to look at.

I started by trying to understand how the entire thing works, and the flag length check was a nice introduction to that. It also gave me the idea to rename the overly long lambda function invokers to something more managable, eg. call_cmd, call_if, call_add, etc.

The main logic was in a fix<...> method. I kept renaming methods called from it to create a tree, eg. the first function called from it I renamed to FIX_1, the first method called from it FIX_1_1, etc. This allowed me to almost stay sane reversing this task.

The lambda context that was usually passed in arg2 iirc seemed to match up with what was passed to the constructors, in most cases I just resorted to guessing though what the params meant.

std::variant<unsigned int, std::string, Cons> was used in a lot of places, where Cons was a pair of two of these variants. Cons was used to build lists, like the ones created in `main`. Since the list was created linearly one could just copy paste the constants from IDA to recover these lists.

Then I just boringly reversed the functions assuming they'd be written mostly in a linear way with no overly fancy functional logic; I rewrote them as fors that I just assumed to be partially wrong but still probably good enough to motsly guess what the functions do.

I identified one of the functions to get n-th element from a Cons based list that I will refer to as find(list, index) in the code below. fix1/fix2/fix3 are the functions called from the fix<...> function.

```
void fix1() { // 50D2
  ret = []
  for (int i = 0; ; i += 4) {
    if (i + 4 >= a4.size()) { // A6DE
      uint x = (getcharat(a4, i+3) << 24) | (getcharat(a4, i+2) << 16) | (getcharat(a4, i+1) << 8) | getcharat(a4, i);
      ret.append(x);
      break;
    } else { // B0F8
      uint x = (getcharat(a4, i+3) << 24) | (getcharat(a4, i+2) << 16) | (getcharat(a4, i+1) << 8) | getcharat(a4, i);
      ret.append(x);
    }
  }
  return ret
}

void fix2() {
  for (int i = 0; i < 8; ) { // I1
   int i2 = i + 1;
   ret = [0]
   for (int j = 0; j < 16; j++) { // I11->I111
     uint v = find(?, j);
     subret = 0
     for (int k = 0; k < 8; k++) { // I1111->I11111
       subret |= find(a2[8], (a2[1] >> (4 * k)) & 15) << (4 * k);
     }
     ret.append(subret)
   }

    ret =[0]
    for (int j = 0; j < 16; j++)
      ret.append(0x4E6A44B9 * find(, j));

     ret = [0]
     for (int j = 0; j < 16; j++) {
       if ((j + 16 < a2[5] + 16 && a2[5] + 12 < j + 16) || (j < a2[5] + 16 && a2[5] + 12 < j)) {
         ret.append(find(a2[2], j))
       } else {
         x = rotl(find(, (j + 3) % 16), 29)
         x ^= rotl(find(, (j + 2) % 16), 17)
         x ^= rotl(find(, (j + 1) % 16), 7)
         x ^= find(, j % 16)
         ret.append(x)
       }
     }
  }
}

int fix3(a3, a4) { // 531C
  for (int i = 0; i < 16; i++)
    if (find(a3, i) != find(a4, i))  //if (find(a2[5], i) != find(a2[3], i)) // C888
      return 1;
  return 0;
} 
```

We can see that the code coverts the string bytes to uint32s, then does some transformations, and then compares the resulting values against some table (presumably one of the lists created in main). The transformations were repeated 8 times and included a substitution of every 4 bits in each of the uint32s (presumably using the other table created in main), multiplication by a constant and a xor combined with rotations of 4 neighboring values with the exclusion of 4 values per each iteration. This is reversable and I wrote a python script to reverse it all. Any unclear code above was guessed, and in general I treated the pseudocode above with caution. I rewrote what I thought the code should do in python first and compared whether it does the right thing with a debugger and then wrote the code reversing it.

```py

tab1 = [-1209425244,419743314,-1098187187,-1122470054,-2105271052,-759048785,255368266,1159664922,-714564980,-1837409319,-127106345,884767840,-1750140823,739036381,-1999442789,293154835][::-1]
tab2 = [7, 0, 12, 13, 2, 15, 11, 8, 6, 5, 9, 4, 10, 1, 14, 3][::-1]

obf_indices_s = [13, 14, 15, 0, 1, 2, 3, 4]

import ctypes
tab1 = [ctypes.c_uint32(x).value for x in tab1]

tab2r = [0] * 16
for i, x in enumerate(tab2):
    tab2r[x] = i

def rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


flag = 'abbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'

tab = [0] * 16
for i in range(16):
    tab[i] = int.from_bytes(flag[4*i:4*i+4].encode(), 'little')




# for i in range(8):
#     for j in range(16):
#         rv = 0
#         for k in range(8):
#             rv |= tab2[(tab[j] >> (k * 4)) & 0xf] << (k * 4)
#         tab[j] = rv

#     print([hex(x) for x in tab[::-1]])
#     tab = [(v * 0x4E6A44B9) & 0xffffffff for v in tab]

#     print([hex(x) for x in tab[::-1]])
#     for j in range(0, 16-3):
#         ind = obf_indices_s[i] + j + 3
#         x = rotl(tab[(ind + 3) % 16], 29)
#         x ^= rotl(tab[(ind + 2) % 16], 17)
#         x ^= rotl(tab[(ind + 1) % 16], 7)
#         tab[ind % 16] ^= x

#     print([hex(x) for x in tab[::-1]])
#     exit()



# exit()

tab = tab1
# tab1 = tab1[::-1]




for i in range(8):
    for j in range(16-3-1, -1, -1):
        ind = obf_indices_s[::-1][i] + j + 3
        x = rotl(tab[(ind + 3) % 16], 29)
        x ^= rotl(tab[(ind + 2) % 16], 17)
        x ^= rotl(tab[(ind + 1) % 16], 7)
        tab[ind % 16] ^= x

    tab = [(545292681 * v) & 0xFFFFFFFF for v in tab]

    for j in range(16):
        rv = 0
        for k in range(8):
            rv |= tab2r[(tab[j] >> (k * 4)) & 0xf] << (k * 4)
        tab[j] = rv

print(tab)

ds = []
for j in range(16):
    ds.append(int.to_bytes(tab[j], 4, 'little'))
print(b''.join(ds))
```