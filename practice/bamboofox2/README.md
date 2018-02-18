# Solution
這題在`change_item`函式裡面有漏洞，可以造成heap buffer overflow <br />
先做出三塊大小為`0xa0`的chunk，然後我們在第二塊做overflow <br />
偽造第二塊和第三塊的chunk header，接著在`free`第三塊chunk <br />
這時候因為第二塊chunk是我們偽造的，第三塊chunk在free以後會和第二塊merge <br/>
此時存放第二塊chunk指標的位址(簡稱`&r`)現在會指向`&r - 0x18` <br />
`&r - 0x18`這個地方其實就是第一個item的位址，我們可以對第二個item做修改把它改成`atoi`的GOT <br/>
這時在使用`show item`的功能就可以leak出`atoi`的GOT位址 <br />
利用題目給的libc.so.6可以算出`system`的位址 <br />
這時因為第一個item已經指向`atoi`的GOT位址了，對第一個item的內容做修改等同於對`atoi`的GOT做修改，達到GOT hijacking <br />
把`atoi`的GOT改成`system`的GOT，這時候在下一次出現目錄選單請你輸入1~5其中一個數字的時候，輸入`/bin/sh`就可以拿到shell了
