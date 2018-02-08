# Solution
這題的overflow剛好可以蓋到return address <br/>
對於串ROP來說，這個溢位的長度實在是太短了 <br/>
但仔細觀察可以發現`main`裡面call`read`後會直接做`leave`和`ret` <br/>
這樣就可以做stack migration了 <br/> <br/>

我們在蓋掉RBP以後再把return address蓋成`main`裡面call`read`那邊 <br/>
這樣就可以把我們想寫的東西寫到指定的地方，達到任意寫入的目的 <br/>
但因為`read`一次只能讀`0x20`bytes的gadget，所以要分很多次來串我們的ROP <br/> <br/>

在寫ROP的時候會遇到一個問題，就是當我們在某一buffer中寫完一部分ROP以後 <br/>
如果直接在後面接上剩下的ROP chain，程式就會直接炸掉 <br/>
原因是在call`read`的時候，第二段ROP chain會把`read`的return address蓋掉 <br/>
導致程式會跳到錯誤的位置然後直接炸掉 <br/>
解決方法就是在找一塊buffer，當寫完一段ROP chain以後就先跳到那個buffer <br/>
然後再回來繼續把ROP chain完成，這樣就不會炸掉了。 <br/> <br/>

接著是要想辦法leak出libc的base address <br/>
方便我們之後跳到`one_gadget`或是呼叫`system('/bin/sh')`來拿shell <br/>
仔細觀察一下可以發現`read got`和`write got`只差最後一個byte <br/>
因此我們可以直接把`read`蓋成`write`，利用`write`來leak出write got entry <br/>
就能算出libc的base address了 <br/><br/>

剩下就是拿shell <br/>
可以利用`one_gadget`或是呼叫`system`
