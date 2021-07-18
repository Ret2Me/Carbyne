[bits 64]       ; allow 64-bit register names


default rel
section .data
    msg db "Thread with first firstWatchdog started", 0xd, 0xa, 0

section .text
    global _firstWatchdog
    global _secondWatchdog       ; watch
    global _killProcess          ; kill
    extern _CRT_INIT
    extern ExitProcess
    extern printf
    extern GetVersion
; ToDo: add better stack destroyer :)
_killProcess:
    sub     rsp, 40
    mov     rax, 1      ; return 1 to main 
    add     rsp, 80
    ret
    
     
_firstWatchdog:
    sub     rsp, 40


    ;Is debugger IsDebuggerPresent but in asm
    xor     rax, rax
    mov     rax, gs:0x60             ; get PEB address from TEB
    movzx   rbx, byte [rax + 0x2]    ; get BeingDebugged value from PEB
    test    rbx, rbx                 ; check is process debugged

    jne     _killProcess             ; urn appropriate value to main program
    


    ; ToDo: Add x64 support
    ; Kernel mode detection
    ; untested !
    ;mov eax, ds:[0x7ffe02d4]
    ;cmp eax, 3
    ;je _killProcess



    ; check is anti anti-debugger working
    ; 1. set isDebuggerPresent to true
    ; 2. chcek if isDebuggerPresent value is changed to zero
    ; 3. if yes killProcess

    mov     rax, gs:0x60        ; get PEB address from TEB
    xor     rbx, rbx            ; clear rbx register
    not     rbx                 ; negation of logical false
    mov     rcx, [rax + 0x2]    ; save previus isDebuggerPresent value
    mov     [rax + 0x2], rbx    ; set true value on PEB
    NOP
    NOP                         ; delay for debugger extension
    NOP


    cmp     [rax + 0x2], rbx    ; check is status changed
    jne     _killProcess

    xor     rbx, rbx            ; clear register
    mov     [rax + 0x2], rcx    ; urn false value to PEB idDebuggerPresent

   
    
    
    
    ; write next function here


    xor     rax, rax            ; urn 0 to main program (everythink is ok)
    add     rsp, 40
    ret


_secondWatchdog:
    sub     rsp, 40 
;
;     check NtGlobalFlag value
;     _____________________________________
;     NtGlobalFlag offset for 64bit = 0xBC
;     _____________________________________
;     FLG_HEAP_ENABLE_TAIL_CHECK 	   0x10
;     FLG_HEAP_ENABLE_FREE_CHECK 	   0x20
;     FLG_HEAP_VALIDATE_PARAMETERS     0x40
;     Total                            0x70
;
    xor     rax, rax           ; clear rax register
    mov     rax, gs:0x60       ; get PEB address from TEB


    mov     bl, 0x70
    mov     al, [rax + 0xBC]
    cmp     al, bl              ; compare actual NtGlobalFlag value with NtGlobalFlag when program is debugged
    
    je      _killProcess        ; if value are the same program will run killProcess function

    


    ; heap-flags
    mov rax, gs:0x60
    mov rbx, [rax+ 0x30] ;process heap
    call GetVersion
    cmp al, 6
    sbb rax, rax
    and al, 0a4h

    ;HEAP_GROWABLE
    ;+ HEAP_TAIL_CHECKING_ENABLED
    ;+ HEAP_FREE_CHECKING_ENABLED
    ;+ HEAP_VALIDATE_PARAMETERS_ENABLED
    mov  RCX, 0x40000062
    cmp  [rbx+rax+70h], RCX ;Flags
    je _killProcess


    xor rax, rax            ; return 0 to main program (every think is ok)
    add rsp, 40
    ret
    



