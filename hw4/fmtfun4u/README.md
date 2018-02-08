# Solution
這題有明顯地format string漏洞，利用它可以leak出libc base address和.text section base address<br/>
再用argv chain(```%11$p```和```%37$p```)可以對記憶體做任意讀寫 <br/>
因此可以把放在stack上的迴圈index改成100，讓我們能夠做足夠多次的```printf```<br/>
還有一個限制是我們用`%n`來寫記憶體的時候一次最多只能寫2個bytes，因為buffer的大小只有`0x10`這麼大 <br/>
若是要一次寫4或8個bytes除了I/O會爆掉以外，組好的format string也會太長。<br/> <br/>

接著要控制RIP <br/>
因為這題迴圈的index是`unsigned int`，代表他根本不會在`main`中return回```__libc_start_main```，因此hijack`main`的return address並不可行 <br/> <br/>
我們可以hijack`printf`的return address，但是不能直接把他的返回位址改成`one_gadget` <br/>
因為一次只能寫兩個byte，而原本的return address是在.text區段而`one_gadget`是在libc裡面 <br/>
這兩個地方差的byte數太多，沒辦法在一次format string中把他寫完。<br/>
如果要分多次寫又會爛掉，在下一次call`printf`時就會先Segmentation fault了。

但是我發現`ret`這個gadget也在.text區段中，他們只有最後兩個byte不一樣 <br/>
因此可以做partial overwrite，把`printf`返回位址改寫成`ret`這個gadget <br/>
然後在將`one_gadget`放在`ret`下面，這樣程式從`printf`返回時就會跳到`one_gadget`並成功拿到shell了
