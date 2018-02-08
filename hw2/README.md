# Solution
這題再輸入name的時候並不會被`NULL`截斷 <br/>
而在`check`這個函數裡面時會有一個`strlen`來得知你輸入的長度 <br/>
接著會call`isalnum`根據你輸入的長度一個字元一個字元來檢查是不是數字或英文字母 <br/>
關鍵在可以利用在輸入name時在一開始塞一個`NULL`進去來避開檢查，因為`strlen`只會檢查到`NULL`之前。 <br/><br/>

根據這件事，我們可以把shellcode放在name buffer中，只是要在shellcode前面先放一個`\x00`來繞過檢查 <br/>
然後就把puts got蓋成name buffer即可取得shell
