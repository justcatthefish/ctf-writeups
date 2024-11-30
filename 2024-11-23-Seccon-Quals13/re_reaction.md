# Reaction (re)

I started by re'ing and rewriting the C++ code roughly:

```cpp
struct Environment {
  size_t width, height;
  int maxValue;
  std::vector<std::vector<Attribute>> data;
  std::mt19937 rng;
};

bool Environment::react(int i, int j, Attribute v) {
  int k = 0;
  std::vector<std::pair<long,long>> q;
  std::unordered_set<long,long> m;
  q.emplace_back(i, j);
  while (!q.empty()) {
    i = q.back().first;
    j = q.back().second;
    q.pop_back();

    if (!m.contains({i, j})) {
      m.insert({i, j});
      k += 1;
      if (i > 0 && data[j][i - 1] == v)
        q.emplace_back(i - 1, j);
      if (j > 0 && data[j - 1][i] == v)
        q.emplace_back(i, j - 1);
      if (i < width - 1 && data[j][i + 1] == v)
        q.emplace_back(i + 1, j);
      if (j < height - 1 && data[j + 1][i] == v)
        q.emplace_back(i, j + 1);
    }
  }
  if (k <= 3)
    return false;
  for (auto const& e : m)
    data[e.first][e.second] = (Attribute)0;
  return true;
}

bool Environment::set() {
  rng();
  int rand[2];
  uint8_t input[2];
  for (int i = 0; i < 2; i++)
    rand[i] = rand_1_2_3_4(rng);
  write(1, {rand[0], rand[1]}, 2);
  read(0, input, 2);
  if (input[1] > 3) return false;
  if (input[1] == 0) {
    if (input[0] >= height) return false;
    for (int i = 0; i < 2; i++) {
      if (data[height - 1 - i][input[1]] != (Attribute)0)
        return false;
      data[height - 1 - i][input[1]] = rand[i];
    }
    return true;
  }
  if (input[1] == 2) {
    if (input[0] >= height) return false;
    for (int i = 0; i < 2; i++) {
      if (data[height - 2 + i][input[1]] != (Attribute)0)
        return false;
      data[height - 2 + i][input[1]] = rand[i];
    }
    return true;
  }
  if (input[1] == 1) {
    if (input[0] >= height - 1) return false;
    for (int i = 0; i < 2; i++) {
      if (data[height - 1][input[0] + i] != (Attribute)0)
        return false;
      data[height - 1][input[0] + i] = rand[i];
    }
    return true;
  }
  if (input[1] == 3) {
    if (input[0] >= height - 1) return false;
    for (int i = 0; i < 2; i++) {
      if (data[height - 1][input[0] + 1 - i] != (Attribute)0)
        return false;
      data[height - 1][input[0] + 1 - i] = rand[i];
    }
    return true;
  }
}

bool Environment::update() {
  if (!set())
    return false;
  int value = 0;
  do {
    bool flag = false;
    for (int i = 0; i < width; i++) {
      int j = 0;
      for (; j < height; j++)
        if (data[j][i] == (Attribute)0)
          break;
      for (int k = j + 1; k < height; k++) {
        if (data[k][i] != (Attribute)0) {
          data[j][i] = data[k][i];
          data[k][i] = (Attribute)0;
          j++;
          flag = true;
        }
      }
    }
    for (int j = height - 1; j >= 0; --j) {
      for (int i = 0; i < width; i++)
        if (data[j][i] != (Environemnt)0)
          if (react(i, j, data[j][i]))
            break;
    }
    value++;
  } while (flag);
  if (this->maxValue < value)
   this->maxValue = value; // goal: maxValue > 13
  return true;
}
```

So we have some game where we are given two attributes to be placed somewhere on the board, and we can select the direction and column to place them in. Something like tetris in this aspect. There are 4 possible attribute types.
After placement all attributes in a given column are moved to the start of it. Then once 4 or more cells with the same element are directly connected they all are deleted. If anything was deleted, this is repeated. Goal is for at least 14 deletions to occur after a single given move.

With this code I could make a strategy: use the first 8 columns as a space to non optimally throw attributes into, in a way that we just do not lose (I wrote my code so that each column from these first 8 can only have attributes of a given type, and we select moves as not to violate this invariant). This allows us to build an arbitrary attribute pattern on the last few columns as follows:
1. fill the 14th column with the pattern 21212121212121
2. fill the 13th column with the pattern 21212121212121
3. fill the 12th column with the pattern 21212121212121
4. place a 3, 3 attribute pair on the 10th and 11th column so both of these columns start with 3
5. fill 11th column with 3212121212121_
6. place a 3, 2 attribute pair so that the 11th column becomes 32121212121212 and 9th becomes 33____________
7. place a 3, 3 attribute pair on the 9th column so it is deleted

I think the above is how it works but I'm not 100% confident. I was intending for the patterns to be 12121212121212 but had to swap what I use in the 7th step from 3,1 to 3,2 for it to work (I dumped the board state via gdb) and not think much about it further, so I went with a random explaination for why this might be happening that I did not verify.

Code I wrote is below:
```py
from pwn import *

orders = [1,2,3,4,2,4,1,3]
# blob = bytearray([])
#blob = open('blob.bin', 'wb')

r = None
r = remote('reaction.seccon.games', 5000)

dbg = open('dbg.bin', 'wb')

# https://github.com/tliston/mt19937/blob/main/mt19937.py
class mt19937():
    u, d = 11, 0xFFFFFFFF
    s, b = 7, 0x9D2C5680
    t, c = 15, 0xEFC60000
    l = 18
    n = 624

    def my_int32(self, x):
        return(x & 0xFFFFFFFF)

    def __init__(self, seed):
        w = 32
        r = 31
        f = 1812433253
        self.m = 397
        self.a = 0x9908B0DF
        self.MT = [0] * self.n
        self.index = self.n + 1
        self.lower_mask = (1 << r) - 1
        self.upper_mask = self.my_int32(~self.lower_mask)
        self.MT[0] = self.my_int32(seed)
        for i in range(1, self.n):
            self.MT[i] = self.my_int32((f * (self.MT[i - 1] ^ (self.MT[i - 1] >> (w - 2))) + i))

    def extract_number(self):
        if self.index >= self.n:
            self.twist()
            self.index = 0
        y = self.MT[self.index]
        y = y ^ ((y >> self.u) & self.d)
        y = y ^ ((y << self.s) & self.b)
        y = y ^ ((y << self.t) & self.c)
        y = y ^ (y >> self.l)
        self.index += 1
        return self.my_int32(y)

    def twist(self):
        for i in range(0, self.n):
            x = (self.MT[i] & self.upper_mask) + (self.MT[(i + 1) % self.n] & self.lower_mask)
            xA = x >> 1
            if(x % 2) != 0:
                xA = xA ^ self.a
            self.MT[i] = self.MT[(i + self.m) % self.n] ^ xA


def mapr(x):
    y = x & 3
    if y == 2:
        return 3
    if y >= 3:
        return 4
    return 1 - ((y == 0) - 1)

mt = mt19937(0xcc540200)
# mt = mt19937(0xf6400000)

stage = 'build1'
stagen = 0

while stage != 'end':
    mt.extract_number()
    values = [mapr(mt.extract_number()) for _ in range(2)]

    #values = r.recv(2)
    #print(values, values_g)

    cmd = [0,0]
    print(stage, stagen)

    if stage == 'build1' and values == [1, 2]:
        cmd = [13, 0]
        stagen += 1
        if stagen == 14//2:
            stage = 'build2'
            stagen = 0
    elif stage == 'build2' and values == [1, 2]:
        cmd = [12, 0]
        stagen += 1
        if stagen == 14//2:
            stage = 'build3'
            stagen = 0
    elif stage == 'build3' and values == [1, 2]:
        cmd = [11, 0]
        stagen += 1
        if stagen == 14//2:
            stage = 'build4_prep'
            stagen = 0
    elif stage == 'build4_prep' and values == [3, 3]:
        cmd = [9, 1]
        stage = 'build4'
        stagen = 0
    elif stage == 'build4' and values == [1, 2]:
        cmd = [10, 0]
        stagen += 1
        if stagen == 14//2-1:
            stage = 'build5'
            stagen = 0
    elif stage == 'build5' and values == [3, 2]:
        cmd = [9, 1]
        stage = 'build5_2'
    elif stage == 'build5_2' and values == [3, 3]:
        cmd = [9, 0]
        stagen += 1
        if stagen == 2:
            stage = 'end'

    elif values[0] == values[1]:
        idx = orders.index(values[0])
        cmd = [idx, 0]
    else:
        for i in range(len(orders) - 1):
            if orders[i] == values[0] and orders[i+1] == values[1]:
                cmd = [i, 1]
            elif orders[i] == values[1] and orders[i+1] == values[0]:
                cmd = [i, 3]
    #print(cmd)
    if r:
        r.send(bytes(cmd))

    dbg.write(bytes(cmd))

r.send(bytes([10, 10]))
r.interactive()
```