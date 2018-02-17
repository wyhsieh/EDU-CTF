# Solution
這題有UAF漏洞，`free(notelist[idx])`這邊在free完之後指標沒有設成`NULL`  <br />
而我們的目標是`note`裡面`printnote`這個function pointer <br />
方法就是先add兩次note然後依序把它`free`掉，這時候因為這兩個note header的大小只有`0x20`，所以他們會被放在fast bin中 <br />
接著再新增一個note，content size是`0x10`(這樣chuck size就會是`0x20`) <br />
這時候這個note header就會被分到剛剛第二個被free掉的chunk <br />
而content則會被分到第一個被free掉的chuck <br />
這樣我們對content寫值就等於是在對剛剛第一個建立的note的function pointer寫值，也就是可以任意控制`RIP`了
