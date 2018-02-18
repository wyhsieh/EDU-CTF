# Solution
這題和practice中的hacknote幾乎一樣，差別只是現在binary中`magic`這個函式被拔掉了 <br />
所以現在目標變成要想辦法leak出libc的base address，然後在call one_gadget來拿到shell <br />
和hacknote一樣只是現在多了一步，先利用UAF漏洞先leak出`puts`的GOT位址，再根據題目給的libc.so.6來算出libc的base address <br />
方式就是把function pointer先指向`puts`的GOT，這時候呼叫`print_note`就可以leak出`puts`的GOT位址 <br />
有了libc的位址以後就可以算出one_gadget的位址了，剩下的就跟hacknote方式一模一樣，讓function pointer去指向one_gadget，在呼叫`print_note`就可以拿到shell了
