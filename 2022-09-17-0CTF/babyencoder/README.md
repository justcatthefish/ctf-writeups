# BabyEncoder challenge

The reverse engineering part was simple enough I don't think there's anything noteworthy to be said about it. I have manually cleaned the double operations up, and fixed the buffer sizes in the entrypoint a bit.

The decompiled source is available in chal.cpp. It might not be bit compatible with the official challenge due to the float cleanup but it does not matter for this solution.

## Solution

If you average every values in the arrays [i::16] for i in range(16) then you get a nice cosin funtion you can graph and then you can fit it with the function `scale * cos(x + x0) + offset` using `optimize.curve_fit`. This always works nicely and almost always gives the correct scale and offset for the 8th byte. The value of the 8th byte is simply scale and the o8 parameter is x0.

Then I thought it’d be nice if it worked for 7th byte and it didn’t (probably because you can't just group together values 0.05 apart on x and still expect averaging ys to work nicely). But it worked nicely for the 4th byte. It did not work nicely for the 2nd byte though, probably because of lack of data. 

Well, with the code written, I just spent a while guessing nice parameters that while barely produce cosin functions nice for the human, still allowed for somehow correct optimized solution. Eventually I got something that solves the result 40% of the time for a single block and gives close results otherwise. Since we are able to validate whether the results we got make sense (we should have reduced all the cosin functions and are just dealing with the rand() fn giving us a random offset), we can try to bruteforce the adjustement (called tweak in py) of some of the scales.

