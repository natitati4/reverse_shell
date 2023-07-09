# reverse_shell
A shellcode written in MASM assembly that connects to a server through TCP, creates a cmd.exe instance on the target machine and redirects it's streams to the socket, so the server side has a shell of the machine.
Works only on 32-bit processes, as of now.

How to use:
-You might (most likely) need to change the IP address. If so, just change it in the assembly (little endian), and recompile.
-Initialize a TCP server using `ncat -nvlp 9000`\
-Inject the shellcode into a vulnerable program (or use the shellcode loader i provided to just test it. Be sure to change the path, and run with admin priviliges).\
-Another option is to use the injector i provided, to inject it into a 32-bit process. Usage: injector.exe process_name

Now you have a shell of the remote machine.

Maybe in the future, add a custom server.
