 # SSH permitted ciphers test

 ## Scope

 1. Make sure SSHv1 is disabled (not enabled) by default
 2. Preferred Ciphers: ["aes256-gcm@openssh.com"], permitted Ciphers: ["aes256-ctr", "aes192-ctr"] with hmac auth macs below
 3. preferred Macs: ['hmac-sha2-512-etm@openssh.com'], Permitted Mac: ['hmac-sha2-256-etm@openssh.com']
 4. Preferred Kex: [ 'ecdh-sha2-nistp384'], Permitted Kex: [ 'ecdh-sha2-nistp521']
 5. SSH to Device using all combinations of preferred Ciphers, Macs, and Kex and make sure SSH session works
 6. SSH to Device using non-permitted Ciphers, Macs, and Kex and make sure SSH session fails to negotiate

 >  Passing critera: Only preferred Ciphers/Mac/Kex should work without issues

 ## Test cases

 ### Test Case #1 - SSH Protocol veriosn

 SSH version 1 protocol is disabled by default at compile time since [OpenSSH 7.0](https://www.openssh.com/txt/release-7.0)

 Most systems are using OpenSSH versions above 7.0, after testing, protocol 1 can't be specified with these OpenSSH versions, both client and server. This makes it tricky to test the protocol via ssh connection.

 On the other hand, protocol 1 has been widely disabled. In my opinion, we only need to check whether SSH protocol 1 is specially supported, and we can make a conclusion

 #### Test Steps

 Use `ssh --version` **on DUT** to print help menu, and check if it has option '-1'

 ### Test Case #2 - SSH Permitted Ciphers

 #### Test Steps

 Use `ssh -c {perfered/permitted cipher} admin@{dut_ip}` on **test server** to test if it connects **successfully**

 ### Test Case #3 - SSH NOT Permitted Ciphers

 #### Test Steps

 Use `ssh -c {cipher not allowed} admin@{dut_ip}` on *test server* to test if it connects **failed**

 ### Test Case #4 - SSH Permitted MACs

 #### Test Steps

 Use `ssh -m {perfered/permitted MACs} admin@{dut_ip}` on **test server** to test if it connects **successfully**

  ### Test Case #5 - SSH NOT Permitted MACs

 #### Test Steps

 Use `ssh -m {MACs not allowed} admin@{dut_ip}` on **test server** to test if it connects **failed**

 ### Test Case #6 - SSH Permitted Kexs

 #### Test Steps

 Use `ssh -oKexAlgorithms={perfered/permitted Kex} admin@{dut_ip}` on **test server** to test if it connects **successfully**

  ### Test Case #7 - SSH Permitted Kexs

 #### Test Steps

 Use `ssh -oKexAlgorithms={Kex not allowed} admin@{dut_ip}` on **test server** to test if it connects **failed**
