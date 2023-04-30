// ==UserScript==
// @name         New Userscript
// @namespace    http://tampermonkey.net/
// @version      0.1
// @description  try to take over the world!
// @author       You
// @match        http://*/*
// @icon         data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==
// @grant        none
// @run-at       document-start
// ==/UserScript==

(function() {
    'use strict';

    window.allRounds = [];
    if (localStorage.allRounds)
        window.allRounds = JSON.parse(localStorage.allRounds);

    const sockets = [];
    const nativeWebSocket = window.WebSocket;
    window.WebSocket = function(...args){
        const socket = new nativeWebSocket(...args);
        sockets.push(socket);

        socket.addEventListener('message', (ev) => {
            if (ev.data.startsWith("42[\"state\"")) {
                const roundData = JSON.parse(ev.data.substr(2))[1];

                window.allRounds = window.allRounds.slice(0, roundData.round - 35);
                window.allRounds.push(roundData);

                localStorage.allRounds = JSON.stringify(window.allRounds);
            }
        });

        return socket;
    };
    window.sockets=sockets;


    let cmds = new Array(40).fill([]);
function updateCmds() {
    cmds[0] = [
        // Active Pike
        ["adww"],
        // Lazy Grunion
        ["daww"],
        // Clever Bluegill
        ["wwwd"],
        // Grateful Salmon
        ["adww"],
        // Magnificent Marlin
        ["daad"],
        // Idealistic Halibut
        ["www_"]
    ]

    cmds[1] = [
        // Active Pike
        ["wdaa"],
        // Lazy Grunion
        ["ww>ad"],
        // Clever Bluegill
        ["awww"],
        // Grateful Salmon
        ["w>adw"],
        // Magnificent Marlin
        ["ww__"],
        // Idealistic Halibut
        ["ww__"]
    ]

    cmds[2] = [
        // Active Pike
        ["da>_>_>"],
        // Lazy Grunion
        ["daww>"],
        // Clever Bluegill
        ["wwdw"],
        // Grateful Salmon
        ["wwww"],
        // Magnificent Marlin
        ["w<wwa>"],
        // Idealistic Halibut
        ["w>_>_>w>"]
    ]

    if (window.allRounds.length > 1 && !validateMoves(window.allRounds[1], cmds[1][2][0], 2)) {
        // Clever Bluegill
        console.log('swap strategy for Clever Bluegill');
        cmds[1][2] = ["aadw"];
        cmds[2][2] = ["dadw"];
    }

    if (window.allRounds.length > 2 && !validateMoves(window.allRounds[2], cmds[2][3][0], 3)) {
        // Grateful Salmon
        console.log('swap strategy for Grateful Salmon');
        cmds[2][3] = ["daad"];
    }

    cmds[3] = [
        // Active Pike
        ["___>_>"],
        // Lazy Grunion
        ["ww<_<_<"],
        // Clever Bluegill
        ["ww<_<_<"],
        // Grateful Salmon
        ["w>_>_>_>"],
        // Magnificent Marlin
        ["__>_>_>"],
        // Idealistic Halibut
        ["w__<_<"]
    ]

    if (window.allRounds.length > 2 && !validateMoves(window.allRounds[2], cmds[2][5][0], 5)) {
        // Idealistic Halibut
        console.log('swap strategy for Idealistic Halibut');
        cmds[2][5] = ["w>_>_>_>"];
        cmds[3][5] = ["ww_<_<"];
    }

    cmds[4] = [
        // Active Pike
        ["_>_>_>_>"],
        // Lazy Grunion
        ["_<_<_<_<"],
        // Clever Bluegill
        ["_<_<_<_<"],
        // Grateful Salmon
        ["_>_>_>_>"],
        // Magnificent Marlin
        ["_>_>_>_>"],
        // Idealistic Halibut
        ["_<_<_<_<"]
    ]

    cmds[5] = [
        // Active Pike
        ["wwdw"],
        // Lazy Grunion
        ["dw_w"],
        // Clever Bluegill
        ["_<_<__"],
        // Grateful Salmon
        ["wdda"],
        // Magnificent Marlin
        ["ww__"],
        // Idealistic Halibut
        ["____"]
    ]

    cmds[6] = [
        // Active Pike
        ["wd_<_<"],
        // Lazy Grunion
        ["d__>_>"],
        // Clever Bluegill
        ["___<_<"],
        // Grateful Salmon
        ["w__<_<"],
        // Magnificent Marlin
        ["____"],
        // Idealistic Halibut
        ["___<_<"]
    ]

    cmds[7] = [
        // Active Pike
        ["_<_<_<_<"],
        // Lazy Grunion
        ["_>_>_>_>"],
        // Clever Bluegill
        ["_<_<_<_<"],
        // Grateful Salmon
        ["_<_<_<_<"],
        // Magnificent Marlin
        ["____"],
        // Idealistic Halibut
        ["_<_<_<_<"]
    ]

    cmds[8] = [
        // Active Pike
        ["__wa"],
        // Lazy Grunion
        ["_>_>dw"],
        // Clever Bluegill
        ["___a"],
        // Grateful Salmon
        ["__ww"],
        // Magnificent Marlin
        ["____"],
        // Idealistic Halibut
        ["_<_<__"]
    ]

    cmds[9] = [
        // Active Pike
        ["____"],
        // Lazy Grunion
        ["d___"],
        // Clever Bluegill
        ["a___"],
        // Grateful Salmon
        ["____"],
        // Magnificent Marlin
        ["____"],
        // Idealistic Halibut
        ["_w<w<w<"]
    ]

    cmds[10] = [
        // Active Pike
        ["____"],
        // Lazy Grunion
        ["____"],
        // Clever Bluegill
        ["wdaw"],
        // Grateful Salmon
        ["____"],
        // Magnificent Marlin
        ["____"],
        // Idealistic Halibut
        ["____"]
    ]

    cmds[11] = [
        // Active Pike
        ["____"],
        // Lazy Grunion
        ["____"],
        // Clever Bluegill
        ["w___"],
        // Grateful Salmon
        ["____"],
        // Magnificent Marlin
        ["____"],
        // Idealistic Halibut
        ["_w<w<w<"]
    ]

    for (let i = 12; i < 40; i++) {
        cmds[i] = [
            // Active Pike
            ["____"],
            // Lazy Grunion
            ["____"],
            // Clever Bluegill
            ["____"],
            // Grateful Salmon
            ["____"],
            // Magnificent Marlin
            ["____"],
            // Idealistic Halibut
            ["w<w<w<w<"]
        ];
    }
}

    updateCmds();

    function validateMoves(roundData, moves, shipNo) {
        let forwardNo = 0;
        let leftNo = 0;
        let rightNo = 0;
        for (const c of moves) {
            if (c == 'w') forwardNo++;
            if (c == 'a') leftNo++;
            if (c == 'd') rightNo++;
        }

        const shipData = roundData.ships[shipNo];
        return forwardNo <= shipData.forwardTokens && leftNo <= shipData.leftTokens && rightNo <= shipData.rightTokens;
    }


    let i = 0;
    function setTo(i) {
        console.log('setTo', i);
        updateCmds();
        const socket = sockets[sockets.length - 1];
        let valid = true;
        for (let j = 0; j < 6; j++) {
            let moves = [];
            for (const c of cmds[i][j][0]) {
                if (c == '_') moves.push({});
                if (c == 'w') moves.push({"token": "Forward"});
                if (c == 'a') moves.push({"token": "Left"});
                if (c == 'd') moves.push({"token": "Right"});
                if ((c == '<' || c == '>') && !moves[moves.length - 1].fire) moves[moves.length - 1].fire = {};
                if (c == '<') moves[moves.length - 1].fire.left = true;
                if (c == '>') moves[moves.length - 1].fire.right = true;
            }

            socket.send("42" + JSON.stringify([
                "setMoves",
                {"id": j + 1, "moves": moves}
            ]));
            if (!validateMoves(window.allRounds[i], cmds[i][j][0], j)) {
                console.log('error with ship', j);
                valid = false;
            }
        }
        return valid;
    }
    function toNext() {
        if (i >= allRounds.length) {
            setTimeout(toNext, 100);
            return;
        }

        const socket = sockets[sockets.length - 1];

        if (!setTo(i)) {
            console.log('mission abort');
            return;
        }

        socket.send("42" + JSON.stringify([
            "advanceRound",
            {"round": i + 36}
        ]));
        i++;
        if (i < 40)
            setTimeout(toNext, 100);
    }

    window.toNext = (x) => { i = x; toNext(); };
    window.setTo = setTo;
    window.reset = () => { sockets[sockets.length-1].send('42["setMoves",{"id":"asdf","moves":[{"fire":{"left":true,"right":true}},{"fire":{"left":true,"right":true}},{"fire":{"left":true,"right":true}},{"fire":{"left":true,"right":true}}]}]') };

    window.doPrep = () => {
        reset();
        setTimeout(() => {
            toNext();
        }, 5000);
    };

    setTimeout(() => {
        document.getElementsByClassName("_speed-slider_qfkp8_101")[0].value = 3;
        document.getElementsByClassName("_speed-slider_qfkp8_101")[0]._valueTracker.setValue('');

        const ev = new Event('change', { bubbles: true })
        ev.simulated = true
        document.getElementsByClassName("_speed-slider_qfkp8_101")[0].dispatchEvent(ev)
    }, 100);
})();
