# Blockade

## Reading the code

I have started by opening the project in Codium (fork of Visual Studio Code) and started analysing the server code.

The game seems to have been written rather well, although there are some design choices that I consider really weird. Such as storing the game state in a database. Web challenge, I guess?

Thanks to the use of a rather-up-to-date version of a data validation library, as well as widespread usage of immutable types, it allows us to eliminate a lot of places that could contain bugs (and made keeping track of places that change state much easier).

Some of the state is also stored outside of the database, which is a bit of a red flag. In particular the round number. If we managed to crash the server without clearing the database we'd be able to basically solve this task. Unfortunately, it seems impossible as the database is cleared at the very beginning of the main() function. An alternative would be to have two instances of the server running in parallel but this also seems impossible.

All the code is `async`, which means potential races (and there's a database too so we would have a chance exploiting them). As much as intended this path sounds, it seems that the `advanceRound` function unfortunately runs all the logic behind a mutex. The package used for the mutex seems to have a lot of downloads, and I also looked at it's implementation and it looked sound. Since all the database accesses happen behind this mutex, there's no hope of finding a race triggered directly by the client.

I then spent a while looking at the round code, how points are calculated and how we could even win. We have a point disadvantage and the enemy has better ships (two Frigate ships which have the largest range and overall the best parameters, while we have none) placed in pretty good locations). It seemed that winning would be tough. If we destroyed every single ship that the enemy had immediately at the start of the game and immediately teleport to the best positions, we'd be only able to get 3520 points in the remaining 40 rounds which is just barely enough to win (each round there are 4 turns, and the most points our ships can get while remaining stationary are: 5, 5, 3, 3, 3, 3), but it is obviously impossible to do without some major flaw in the code. The code awards 2 times the amount of points for a given flag if it wasn't in a given ship's reach before, so it could be possible to use this fact to gain more points as well (for example, if we could figure a good route that'd jump between two positions).

For destroying the ships, I made a quick note with the most important ship parameters that cannot be easily read out from the map:
```
Sloop:   HP 10,  HPRegen 6,  RamDmg 5,  CannonDmg 10
Brig:    HP 90,  HPRegen 8,  RamDmg 10, CannonDmg 15
Galleon: HP 120, HPRegen 10, RamDmg 20, CannonDmg 20
Frigate: HP 150, HPRegen 12, RamDmg 20, CannonDmg 20
```
HP is the `hull` value, HPRegen is the `carpentryRate` value and represents the amount of HP that is regenerated at the end of each round, RamDmg is the amount of damage the ship does by ramming (note that the ship takes an equivalent amount of damage by doing this) and CannonDmg is the amount of damage the ship's cannons can do. Note that we can only fire the cannon a totals a total of 4 times (we initially get 2 cannonballs, and then we will get 2 more within maximally 2 rounds).

The "AI"'s logic is just attempting to fire left on every turn.

I also tried to play this game manually and I'd say the game is not very playable.

## Getting closer

The code handling the round logic looks very sane (with the exception of it using a database). The objects are used carefully, the AI never makes moves at the same time as the player. Seems the code is perfect and there are no bugs. But this can't be the case!

Assuming that the objects provided by the client are fully validated against the schemas (which they seem to be), and there is no way to undo rounds (there also seems to be impossible), this means the update logic itself must be flawed somehow. (Or that I'm missing something else!).

There is one thing that is actually suspicious but I missed it on my first code read-though. It's the following snippet in `executeTurn`:
```ts
	try {
		moveOutcomes = await dataSource.transaction(async (tx) => {
			const ships = await tx.findBy(Ship, { factionId, sunk: false });
			const shipsMap = Map(ships.map((ship) => [ship.id, ship]));
			const shipsWithMoves = shipsMap.map((ship): [Ship, Move] => [ship, moves.get(ship.id) ?? {}]);
			return await asyncBindMap(shipsWithMoves, async ([ship, move]) => (
				executeMove(tx, ship, move)
			));
		});
	} catch (e) {
		// player attempted something invalid, replace all of their moves with empty moves
		moveOutcomes = await dataSource.transaction(async (tx) => {
			const ships = await tx.findBy(Ship, { factionId, sunk: false });
			const shipsMap = Map(ships.map((ship) => [ship.id, ship]));
			return await asyncBindMap(shipsMap, async (ship) => (
				executeMove(tx, ship, {})
			));
		});
	}
```

The `asyncBindMap` function looks as follows:
```ts
export async function asyncBindMap<K, V1, V2>(
	map: Map<K, V1>,
	fn: (value: V1, key: K) => Promise<V2>
): Promise<Map<K, V2>> {
	const entries = map.entrySeq().toArray();
	const newEntries = await Promise.all(
		entries.map(async ([key, value]): Promise<[K, V2]> => {
			const newValue = await fn(value, key);
			return [key, newValue];
		})
	);
	return Map(newEntries);
}
```

This code basically updates all the ships of a given party in parallel. This could be just a performance optimization, or it could be a hint at some sort of bug. After all who needs performance in a CTF task :)

Maybe there's some way to raise an exception somewhere in a way that would not cause a revert and let the code in the `catch` block execute anyways? It sounds unlikely though. The code is ran in a transaction block, which should mean that if an exception is thrown the entire transaction should get reverted. Since I had no other clues however I decided to give it a try. (spoiler alert: the bug is there).

## Modifying the communication

There are several ways to cause the revert. The first one is shooting a cannonball when a ship has none. This is not normally possible to do with the normal client, as it will just not let do this.

This can be accompolished in two ways, either by editing the client code and then recompiling it, or by taking over the web socket instance in the existing client. I decided to go for the second way.

I edited the index.html file, in order to add a `<script>` tag that exposes the WebSocket to the Chrome console:
```js
const sockets = [];
const nativeWebSocket = window.WebSocket;
window.WebSocket = function(...args){
    const socket = new nativeWebSocket(...args);
    sockets.push(socket);
    return socket;
};
window.sockets=sockets;
```

This script can also be executed by setting a breakpoint on the very first instruction in the JavaScript file and pasting it into the Chrome console, or by using something like TamperMonkey.

Then I looked at the network communication on the socket and noticed the messages containing the game data are just serialized JSON prefixed with the string `42`.

I found out that I can send invalid fire input by sending a message using JavaScript like this:
```js
sockets[sockets.length-1].send('42["setMoves",{"id":2,"moves":[{"token":"Forward","fire":{"left":true}},{"token":"Forward","fire":{"left":true}},{"token":"Forward","fire":{"left":true}},{"token":"Forward","fire":{"left":true}}]}]')
```

I got rid of all my cannonballs on all the ships, tried to make all the ships move, and make the 2nd ship attempt to shoot a cannonball even though it had none (using the snippet above). This resulted in the first ship (Active Pike) moving! This definitely should not happen and shows that a bug related to rollback probably exists.

If an invalid JSON is sent, then the server restarts and starts a new game, which is probably the fastest way to start over.

## Using the bug

So we now know that something weird is happening, but why? I investigated this by adding some prints, and it _seems_ that everything should be fine. However, it seems that a single SQL query for some of the ships is getting committed to the database _after_ an exception is thrown in another ship's `executeMove` handler, and is not reverted. The next queries after that one seem to fail and throw a `QueryRunnerAlreadyReleasedError`. This suggests that there is some bug in the TypeORM library.

Since it seems to be some race nonetheless and we are quite limited in our options anyways, I decided to try to figure out a way to use this for our advantage through the power of observation. It seemed that we can use this bug in two ways:
- to duplicate points with all ships with indexes lower than the one that caused the rollback (the ship that caused the rollback must have attempted to shoot with no cannonball); the points are being counted twice. I think this only works in this configuration if the ships that want to have their points double counted are stationary.
- to shoot cannonballs without decrementing the cannonball counter with ships with lower indexes (the ship that caused the rollback must attempt to move and shoot a cannonball with none remaining). In this case only the query updating the damage on the enemy ship is being saved into the database.

These two primitives are pretty powerful and seem like are enough to win the game.

Which brings us to the worst part of this challenge... attempting and struggling to play this game.

## The real struggle

Attempting to use the client itself to do anything in this game is basically impossible. I instead wrote a script that parsed a text representation of the moves we want each ship to take and send it over the web socket. The client does not update the move table when we send movements on the side, however it'll properly update the game state when we send the next round command.

After a few hours of aligning ships (and having asked a fellow team player for help to get me out of this hell) we managed to get a path done that destroyed the enemy ships in a few turns and semi-optimally aligned the ships letting us just barely get the win. We also converted our scripts to use TamperMonkey. However there was just one problem left. The game actually has an element of randomness in it (WHY!!!), with the ships getting random move tokens (a token lets you move either to the left, right or straight) each round, meaning that a hardcoded path could fail. For testing we made this code always give us straight tokens. Therefore this meant that either we would have to improve our game or think of something. Guessing the RNG seemed counterproductive. I also attempted to reroute the ships in real time as I saw that I did not have enough move tokens, and I did manage to do it locally but it took around 15 minutes to win a game this way and was quite mistake prone.

The probability of getting a move token in a given direction was inversly proportional to the number of tokens we already had for it. So I changed some of the paths in order to have a better chance of getting them to work, however this was not enough. So I also created some detour alternative routes for some of the ships for the initial rounds and it seemed that now we had a chance of a few percent of getting this finish line without any manual intervention. So I ran it a bunch of times on the remote server, using the fact that you can reset the game by crashing the server, and managed to get the flag. Finally~!
