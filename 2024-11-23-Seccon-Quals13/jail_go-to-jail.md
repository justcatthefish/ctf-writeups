# Go To Jail

## Challenge Overview:

In simple terms the objective of this task was to create a Go program, which would somehow reveal the contents of `/flag-<md5>.txt`. The source code of this program would then be submitted to the CTF's infra over a telnet connection. The infra would validate the constraints, and run the program with `go run <file path>` and if it compiled and exited with a 0 exit code, it's stdout would be returned to the player. Otherwise a sad face would be printed (`:-(`).

In addition to that there were the following constraints:

- The file can have at most 170 characters.
- It can have at most one `{` 
- It can have at most one `(` character

## Approach I (unsuccessful): Use go's embed package

We really quickly realized that the `(` and `{` characters are used up by the `func main() {}` declaration, which in golang is mandatory for the main package (and thus running it with `go run`). That meant that calling any functions or control flow expressions in Go are not possible - both require the use of parentheses or curly braces. 

We remembered that go has the [`embed`](https://pkg.go.dev/embed) package which allows a Go program to include any files in the compiled binary and use them (I believe it's mostly used for embedding HTML content in webapps). 


Here is an example of using this feature from the docs:

```go
import _ "embed"

//go:embed hello.txt
var b []byte
print(string(b))
```

Go allows the use of globs in the filename, so I could do this:


```go
package main

import _ "embed"

//go:embed flag*
var f []byte

func main() {}
```

This code compiled on my computer and the `f` variable had the contents of any file with the name starting in `flag`. The problem now is that there is no way to simply print the contents of this variable without calling any function (which would require an extra set of parentheses).

The only things we could do now is: create variables, assign things to them, do mathematical operations and index arrays. I decided to use those primitives to leak the contents of the file.

```go
package main

import _ "embed"

//go:embed jail_go*
var f []byte

func main() {
	var m [1]byte // Create an array which only has an element at the 0-th index
	x := m[f[0] - 102] // This will not panic only when the first byte of the flag file is an ASCII 'f'
	x=x // So that go does not complain that x is unused
}
```

Thanks to this construct I could leak one bit of information per one invocation - did the program run successfully or did it crash? 

By manipulating the used constants I could check characters at different indexes in the flag file, as well as by changing the length of the `m` array I could do a less than/greater than comparison and thus do a binary search, requiring less operations. The idea was to automate this with some python script. 

But before automating it I decided to run one iteration manually in the provided docker container - as a sanity check. Unfortunately I very quickly realized a fatal flaw in our solution: **For security reasons Go only allows embedding files that are in the same directory (or deeper) as the source file**. Unfortunately the flag was in the root directory of the container, and the program was being run from `/tmp`, which completely prevented this solution from working. On my PC it worked, because I put the flag file in the same directory for simplicity while developing the solution. 

Key takeaway: Test your solutions in the environments provided by the organizers from the very beginning, to prevent wasting time.

## Approach II (successful)

While trying to come up with another solution I remembered about another special Go feature: [Cgo](https://pkg.go.dev/cmd/cgo). As per the docs: "Cgo enables the creation of Go packages that call C code."

One cool feature of Cgo is that C source code can be included in a Go comment just before the import of the "C" package. This code will then be compiled and linked with the resulting Go binary. 

Here is an example:

```go
package main

// int fortytwo()
// {
//	    return 42;
// }
import "C"
import "fmt"

func main() {
	fmt.Println(C.fortytwo(C))
	// Output: 42
}
```

The intended purpose of this mechanism is to allow writing "glue" code between Go and a native library. Later one can call those C functions from Go. Of course for our solution this is not possible since we cannot use parenthesis. Additionally you cannot define the `main` function in the C code. Of course `{` and `(` used in C code also count in the constraints.

For this we knew that we would have to somehow invoke a C function automatically as well as abuse the C macro system to circumvent the forbidden characters.

The first part can be done by using [`__attribute__((constructor))`](https://gcc.gnu.org/onlinedocs/gcc-4.5.3/gcc/Function-Attributes.html) on a function. It is normally used to call C++ constructors for global variables. But it can be manually added to C functions to have them called before `main` is executed.

So this is what our code will look like:

```go
package main

/*
#include <stdlib.h>

__attribute__((constructor))
void f() {
  system("cat /f*")
}
*/
import "C"
import "fmt"

func main() {
}
```

Of course there is one glaring problem with this code: It uses way to many curly braces and parentheses. 

I decided to include some `.h` header in the provided docker container, and modify it using `#define` to change it's behavior to do what I want.

My requirements were:

- It defines a function with a body (which is uncommon for headers, they usually only declare)
- The body of the function only calls another function with exactly one argument.
- The function has some attributes defined using the `__attribute__`
- It does not have any unnecessary garbage, which could be affected by substituting identifier with a `#define`

So with some clever grepping I came up with `pkuintrin.h`. This header looks like this:

<details>
<summary>pkuintrin.h contents</summary>

```c
/* Copyright (C) 2015-2023 Free Software Foundation, Inc.

   This file is part of GCC.

   GCC is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   GCC is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   Under Section 7 of GPL version 3, you are granted additional
   permissions described in the GCC Runtime Library Exception, version
   3.1, as published by the Free Software Foundation.

   You should have received a copy of the GNU General Public License and
   a copy of the GCC Runtime Library Exception along with this program;
   see the files COPYING3 and COPYING.RUNTIME respectively.  If not, see
   <http://www.gnu.org/licenses/>.  */

#ifndef _X86GPRINTRIN_H_INCLUDED
# error "Never use <pkuintrin.h> directly; include <x86gprintrin.h> instead."
#endif

#ifndef _PKUINTRIN_H_INCLUDED
#define _PKUINTRIN_H_INCLUDED

#ifndef __PKU__
#pragma GCC push_options
#pragma GCC target("pku")
#define __DISABLE_PKU__
#endif /* __PKU__ */

extern __inline unsigned int
__attribute__((__gnu_inline__, __always_inline__, __artificial__))
_rdpkru_u32 (void)
{
  return __builtin_ia32_rdpkru ();
}

extern __inline void
__attribute__((__gnu_inline__, __always_inline__, __artificial__))
_wrpkru (unsigned int __key)
{
  __builtin_ia32_wrpkru (__key);
}

#ifdef __DISABLE_PKU__
#undef __DISABLE_PKU__
#pragma GCC pop_options
#endif /* __DISABLE_PKU__ */

#endif /* _PKUINTRIN_H_INCLUDED */
```
</details>

I could hijack the `_wrpkru` function to call `system()` for me and change one of it's attributes to `constructor` using macros. I would also have to redefine the `__inline` and `extern` keywords, because with them the `constructor` attribute does not work.

```go
package main
//#include <stdlib.h>
//#define _X86GPRINTRIN_H_INCLUDED
//#define __gnu_inline__ constructor
//#define extern
//#define return
//#define __builtin_ia32_wrpkru __key="cat flag*";system
//#define int char*
//#define __inline
//#include <pkuintrin.h>
//#undef int
import "C"
func main() {}
```

This is what I came up with. It has the right amount of parentheses and braces, but has two problems: It uses 301 characters, as well as another function from the header (`_rdpkru_u32`) also gets assigned the `constructor` attribute, which unfortunately would cause the program to randomly crash due to it being called too.


I then found the `clwbintrin.h` header, which had only one such function, thus preventing the crash. 

<details>
<summary>clwbintrin.h contents</summary>

```c
/* Copyright (C) 2013-2023 Free Software Foundation, Inc.

   This file is part of GCC.

   GCC is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   GCC is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   Under Section 7 of GPL version 3, you are granted additional
   permissions described in the GCC Runtime Library Exception, version
   3.1, as published by the Free Software Foundation.

   You should have received a copy of the GNU General Public License and
   a copy of the GCC Runtime Library Exception along with this program;
   see the files COPYING3 and COPYING.RUNTIME respectively.  If not, see
   <http://www.gnu.org/licenses/>.  */

#ifndef _X86GPRINTRIN_H_INCLUDED
# error "Never use <clwbintrin.h> directly; include <x86gprintrin.h> instead."
#endif

#ifndef _CLWBINTRIN_H_INCLUDED
#define _CLWBINTRIN_H_INCLUDED

#ifndef __CLWB__
#pragma GCC push_options
#pragma GCC target("clwb")
#define __DISABLE_CLWB__
#endif /* __CLWB__ */

extern __inline void
__attribute__((__gnu_inline__, __always_inline__, __artificial__))
_mm_clwb (void *__A)
{
  __builtin_ia32_clwb (__A);
}

#ifdef __DISABLE_CLWB__
#undef __DISABLE_CLWB__
#pragma GCC pop_options
#endif /* __DISABLE_CLWB__ */

#endif /* _CLWBINTRIN_H_INCLUDED */
```

</details>


This was our program:

```go
package main
/*#cgo CFLAGS:-D_X86GPRINTRIN_H_INCLUDED -D__artificial__=constructor -D__inline=
#define __builtin_ia32_clwb __A="cat /*";system
#include<clwbintrin.h>*/
import "C"
func main(){}
```


I also did some tricks to reduce the character count:

- switched to a multiline comment
- used the CFLAGS feature of cgo to use the compiler arguments instead of `#defines` (less characters)
- removed the stdlib include (wasn't really needed, only produced a warning)
- removed definition of `extern` (worked as well without it)
- trimmed some white space. 
- did not `#define` any types - the void pointer was automatically cast (produced a warning)

The program still had 192 characters.

Since it was going in a good direction I decided to find another header. This time it was `clzerointrin.h`:

<details>
<summary>Contents of `clzerointrin.h`</summary>

```c
/* Copyright (C) 2012-2024 Free Software Foundation, Inc.

   This file is part of GCC.

   GCC is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   GCC is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   Under Section 7 of GPL version 3, you are granted additional
   permissions described in the GCC Runtime Library Exception, version
   3.1, as published by the Free Software Foundation.

   You should have received a copy of the GNU General Public License and
   a copy of the GCC Runtime Library Exception along with this program;
   see the files COPYING3 and COPYING.RUNTIME respectively.  If not, see
   <http://www.gnu.org/licenses/>.  */

#ifndef _CLZEROINTRIN_H_INCLUDED
#define _CLZEROINTRIN_H_INCLUDED

#ifndef __CLZERO__
#pragma GCC push_options
#pragma GCC target("clzero")
#define __DISABLE_CLZERO__
#endif /* __CLZERO__ */

extern __inline void __attribute__((__gnu_inline__, __always_inline__, __artificial__))
_mm_clzero (void * __I)
{
  __builtin_ia32_clzero (__I);
}

#ifdef __DISABLE_CLZERO__
#undef __DISABLE_CLZERO__
#pragma GCC pop_options
#endif /* __DISABLE_CLZERO__ */

#endif /* _CLZEROINTRIN_H_INCLUDED */

```

</details>

Our code:

```go
package main
/*#cgo CFLAGS:-D__artificial__=constructor -D__inline=
#define __builtin_ia32_clzero __I="cat /*";system
#include<clzerointrin.h>*/
import "C"
func main(){}
```

This was our final solution - it worked. It was exactly 170 characters long. The reduction came from clzerointrin.h not needing an include guard. 

After the CTF finished I looked at some of the other solutions and noticed:

- They were using [trigraphs](https://en.wikibooks.org/wiki/C_Programming/C_trigraph) to write `??<` instead of `{`. I vaguely knew about this feature but thought it had to be enabled via a flag in modern GCC. Apparently this is not the case.
- They were using the `[[gnu::constructor]]` syntax. I somehow forgot it exists lol.

Due to those things I think our solution is pretty unique, but coming up with it did pose some challenges. 
