#!/usr/bin/env node

// reference: generate several nonces using the algorithm from the task

const genNonce = ()=>"_".repeat(16).replace(/_/g,()=>"abcdefghijklmnopqrstuvwxyz0123456789".charAt(Math.random()*36));
[...Array(20)].map(_ => console.log(genNonce()))
