# Kraken
Task description:
```
Set sail for the most exclusive stolen NFTs in the digital seas with Kraken! Enjoy one rare collection per week valued at millions of doubloons, all for free!
```

Server sources available [here](https://github.com/luker983/kraken/)

## Solution
The challenge gives us a link to a webserver serving "NFTs" which upon clicking are retrieved from some hidden location.

The flag image was hidden under a `/private/Flag/` directory on the final webserver which would respond with `Remote access to this file is disabled` upon requesting.

The network requests done during image retrieval are websocket connections with random looking binary traffic and originate from a wasm file. Upon decompilation in ghidra it ends up being a compiled go binary that has a userland network stack set up to estabilish a wireguard connection with the remote server through websocket as the main transport, and then sends a HTTP request to an internal webserver (thank you for leaving the symbols).

We ended up re-implementing the entire wasm file in go to closely resemble the original one and this let us send our own arbitrary parameters and requests through that wireguard tunnel.

To bypass the remote access error message, it was necessary to change the `addr` parameter (our own "public" IP address) when estabilishing the websocket connection. The final address we landed on after testing multiple of them was `::ffff::127.0.0.1`.

After the CTF has ended we discovered that this was actually a [documented bug in gvisor](https://github.com/luker983/kraken/blob/main/README.md#about-spoilers) after the author has answered questions on the CTF discord.

The `main.go` file in this directory contains our final solution that dumps the flag image into the current directory.
