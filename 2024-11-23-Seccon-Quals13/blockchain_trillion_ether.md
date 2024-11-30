# Trillion Ether

```c
function _newWallet(bytes32 name, uint256 balance, address owner) internal returns (Wallet storage wallet) {
        wallet = wallet;
        wallet.name = name;
        wallet.balance = balance;
        wallet.owner = owner;
    }
```

wallet is unitialized so name points to storage slot 0 which also is wallet array length. It allows us to change array length before pushing it, allowing us writing to arbitary storage slot.

by creating wallet with name 0x0 we are writing to storage slots

```py
keccak256(abi.encode(0))     - name
keccak256(abi.encode(0)) + 1 - balance
keccak256(abi.encode(0)) + 2 - owner
```

then by creating wallet with name `0x5555555555555555555555555555555555555555555555555555555555555555` we are writing to storage slots

```py
keccak256(abi.encode(0)) + 0x5555555555555555555555555555555555555555555555555555555555555555 * 3 - name
keccak256(abi.encode(0)) + 0x5555555555555555555555555555555555555555555555555555555555555555 * 3 + 1 - balance
keccak256(abi.encode(0)) + 0x5555555555555555555555555555555555555555555555555555555555555555 * 3 + 2 - owner
```
which `& type(uint256).max` is equal:

```py
keccak256(abi.encode(0)) - 1  - name
keccak256(abi.encode(0))      - balance
keccak256(abi.encode(0)) + 1  - owner
```

so old name will get overridden by new balance and old balance will get overridden by new owner

then we can just withdraw trillion ether from wallet with id 0
