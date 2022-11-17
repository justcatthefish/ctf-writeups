## find flag task

Description:

```
Where is the flag?

nc find-flag.seccon.games 10042

findflag.tar.gz 3b1c1ba8cf18a534d9569de94e3765ee53e2c705
```

## Writeup

In this challenge we received source code in python:

```python
#!/usr/bin/env python3.9
import os

FLAG = os.getenv("FLAG", "FAKECON{*** REDUCTED ***}").encode()

def check():
    try:
        filename = input("filename: ")
        if open(filename, "rb").read(len(FLAG)) == FLAG:
            return True
    except FileNotFoundError:
        print("[-] missing")
    except IsADirectoryError:
        print("[-] seems wrong")
    except PermissionError:
        print("[-] not mine")
    except OSError:
        print("[-] hurting my eyes")
    except KeyboardInterrupt:
        print("[-] gone")
    return False

if __name__ == '__main__':
    try:
        check = check()
    except:
        print("[-] something went wrong")
        exit(1)
    finally:
        if check:
            print("[+] congrats!")
            print(FLAG.decode())
```

The idea here was to raise a exception in `check()` function that won't be handled and printed by the function itself. This allows to pass `if check:` in finally statement because variable will be never initialized and this condition will always pass because reference to function is not None.

Last step is to find an exception that can be raised by a user input that isn't expected by the function. This could be done by passing null-byte which would raise a `ValueError` exception.

We created a small script which connects to the socket and send `\x00\x0a` which returns flag.

```
python .\solver.py
b'[-] something went wrong\n[+] congrats!\nSECCON{exit_1n_Pyth0n_d0es_n0t_c4ll_exit_sysc4ll}\n'
```

The full exploit for this challenge can be found in the [solve.py](solve.py) file.
