# Yeth Apis

public native byte[] call(String api, byte[] params) throws Exception
public native String createAccount(String passphrase)
public native Account find(byte[] address) throws Exception
public native Account importECDSAKey(byte[] key, String passphrase) throws Exception
public native String importKeyJson(byte[] keyJson, String passphrase, String newPassphrase) throws Exception
public native void lock(Address address) throws Exception
public native byte[] sendTransaction(Account account, Transaction tx) throws Exception
public native byte[] sendTransactionWithPassphrase(Account account, String passphrase, Transaction tx) throws Exception
public native byte[] sendTransactions(Account account, Transactions txs) throws Exception
public native byte[] sendTransactionsWithPassphrase(Account account, String passphrase, Transactions txs) throws Exception
public native void timedUnlock(Account account, String passphrase, long timeout) throws Exception
public native void unlock(Account account, String passphrase) throws Exception
public native void updateAccount(Account account, String passphrase, String newPassphrase) throws Exception


```
yeth, _ := NewYeth(nil)
var address string = yeth.CreateAccount("111111")
var account Account := yeth.find(address)
tx := new Transaction(nonce, toAddress, amount, long gasLimit, BigInt gasPrice, byte[] data)
yeth.sendTransactionWithPassphrase(account, "111111", tx)
```

## changelog
### 0917
1. Find(address *Address)接口修改参数类型 string -> *Address
2. GetBalance(address *Address) 参数类型 string -> *Address
3. NewAddress(address string) (*Address, error) 增加返回错误信息
