	.file	"fec.c"
	.text
	.p2align 4,,15
	.type	addmul1, @function
addmul1:
.LFB60:
	.cfi_startproc
	subl	$16, %ecx
	movzbl	%dl, %edx
	movq	%rsi, %r10
	movslq	%ecx, %rcx
	salq	$8, %rdx
	movq	%rdi, %r8
	leaq	1(%rdi,%rcx), %r9
	addq	$gf_mul_table, %rdx
	cmpq	%r9, %rdi
	jae	.L2
	movq	%rsi, %rcx
	movq	%rdi, %rax
	.p2align 4,,10
	.p2align 3
.L3:
	movzbl	(%rcx), %r10d
	movzbl	(%rdx,%r10), %r8d
	xorb	%r8b, (%rax)
	movzbl	1(%rcx), %r11d
	movzbl	(%rdx,%r11), %r10d
	xorb	%r10b, 1(%rax)
	movzbl	2(%rcx), %r8d
	movzbl	(%rdx,%r8), %r11d
	xorb	%r11b, 2(%rax)
	movzbl	3(%rcx), %r10d
	movzbl	(%rdx,%r10), %r8d
	xorb	%r8b, 3(%rax)
	movzbl	4(%rcx), %r11d
	movzbl	(%rdx,%r11), %r10d
	xorb	%r10b, 4(%rax)
	movzbl	5(%rcx), %r8d
	movzbl	(%rdx,%r8), %r11d
	xorb	%r11b, 5(%rax)
	movzbl	6(%rcx), %r10d
	movzbl	(%rdx,%r10), %r8d
	xorb	%r8b, 6(%rax)
	movzbl	7(%rcx), %r11d
	movzbl	(%rdx,%r11), %r10d
	xorb	%r10b, 7(%rax)
	movzbl	8(%rcx), %r8d
	movzbl	(%rdx,%r8), %r11d
	xorb	%r11b, 8(%rax)
	movzbl	9(%rcx), %r10d
	movzbl	(%rdx,%r10), %r8d
	xorb	%r8b, 9(%rax)
	movzbl	10(%rcx), %r11d
	movzbl	(%rdx,%r11), %r10d
	xorb	%r10b, 10(%rax)
	movzbl	11(%rcx), %r8d
	movzbl	(%rdx,%r8), %r11d
	xorb	%r11b, 11(%rax)
	movzbl	12(%rcx), %r10d
	movzbl	(%rdx,%r10), %r8d
	xorb	%r8b, 12(%rax)
	movzbl	13(%rcx), %r11d
	movzbl	(%rdx,%r11), %r10d
	xorb	%r10b, 13(%rax)
	movzbl	14(%rcx), %r8d
	movzbl	(%rdx,%r8), %r11d
	xorb	%r11b, 14(%rax)
	movzbl	15(%rcx), %r10d
	addq	$16, %rcx
	movzbl	(%rdx,%r10), %r8d
	xorb	%r8b, 15(%rax)
	addq	$16, %rax
	cmpq	%rax, %r9
	ja	.L3
	movq	%rdi, %rax
	notq	%rax
	addq	%r9, %rax
	andq	$-16, %rax
	leaq	16(%rax), %r10
	leaq	(%rdi,%r10), %r8
	addq	%rsi, %r10
.L2:
	addq	$15, %r9
	cmpq	%r8, %r9
	jbe	.L1
	movzbl	(%r10), %ecx
	movq	%r8, %rsi
	leaq	1(%r8), %rax
	notq	%rsi
	addq	%r9, %rsi
	andl	$7, %esi
	movzbl	(%rdx,%rcx), %edi
	leaq	1(%r10), %rcx
	xorb	%dil, (%r8)
	cmpq	%rax, %r9
	jbe	.L40
	testq	%rsi, %rsi
	je	.L7
	cmpq	$1, %rsi
	je	.L33
	cmpq	$2, %rsi
	je	.L34
	cmpq	$3, %rsi
	je	.L35
	cmpq	$4, %rsi
	je	.L36
	cmpq	$5, %rsi
	je	.L37
	cmpq	$6, %rsi
	je	.L38
	movzbl	(%rcx), %r11d
	movzbl	(%rdx,%r11), %ecx
	xorb	%cl, (%rax)
	leaq	2(%r8), %rax
	leaq	2(%r10), %rcx
.L38:
	movzbl	(%rcx), %r10d
	addq	$1, %rcx
	movzbl	(%rdx,%r10), %r8d
	xorb	%r8b, (%rax)
	addq	$1, %rax
.L37:
	movzbl	(%rcx), %esi
	addq	$1, %rcx
	movzbl	(%rdx,%rsi), %edi
	xorb	%dil, (%rax)
	addq	$1, %rax
.L36:
	movzbl	(%rcx), %r8d
	addq	$1, %rcx
	movzbl	(%rdx,%r8), %r11d
	xorb	%r11b, (%rax)
	addq	$1, %rax
.L35:
	movzbl	(%rcx), %edi
	addq	$1, %rcx
	movzbl	(%rdx,%rdi), %r10d
	xorb	%r10b, (%rax)
	addq	$1, %rax
.L34:
	movzbl	(%rcx), %r11d
	addq	$1, %rcx
	movzbl	(%rdx,%r11), %esi
	xorb	%sil, (%rax)
	addq	$1, %rax
.L33:
	movzbl	(%rcx), %r10d
	addq	$1, %rcx
	movzbl	(%rdx,%r10), %r8d
	xorb	%r8b, (%rax)
	addq	$1, %rax
	cmpq	%rax, %r9
	jbe	.L41
.L7:
	movzbl	(%rcx), %esi
	movzbl	(%rdx,%rsi), %edi
	xorb	%dil, (%rax)
	movzbl	1(%rcx), %r10d
	movzbl	(%rdx,%r10), %r8d
	xorb	%r8b, 1(%rax)
	movzbl	2(%rcx), %r11d
	movzbl	(%rdx,%r11), %esi
	xorb	%sil, 2(%rax)
	movzbl	3(%rcx), %edi
	movzbl	(%rdx,%rdi), %r10d
	xorb	%r10b, 3(%rax)
	movzbl	4(%rcx), %r8d
	movzbl	(%rdx,%r8), %r11d
	xorb	%r11b, 4(%rax)
	movzbl	5(%rcx), %esi
	movzbl	(%rdx,%rsi), %edi
	xorb	%dil, 5(%rax)
	movzbl	6(%rcx), %r10d
	movzbl	(%rdx,%r10), %r8d
	xorb	%r8b, 6(%rax)
	movzbl	7(%rcx), %r11d
	addq	$8, %rcx
	movzbl	(%rdx,%r11), %esi
	xorb	%sil, 7(%rax)
	addq	$8, %rax
	cmpq	%rax, %r9
	ja	.L7
.L1:
	rep
	ret
.L41:
	rep
	ret
.L40:
	.p2align 4,,11
	rep
	ret
	.cfi_endproc
.LFE60:
	.size	addmul1, .-addmul1
	.section	.rodata.str1.8,"aMS",@progbits,1
	.align 8
.LC0:
	.string	"-- malloc failure allocating %s\n"
	.section	.text.unlikely,"ax",@progbits
	.type	my_malloc.part.0, @function
my_malloc.part.0:
.LFB71:
	.cfi_startproc
	movq	%rdi, %rcx
	pushq	%rax
	.cfi_def_cfa_offset 16
	movq	stderr(%rip), %rdi
	movl	$.LC0, %edx
	movl	$1, %esi
	xorl	%eax, %eax
	call	__fprintf_chk
	movl	$1, %edi
	call	exit
	.cfi_endproc
.LFE71:
	.size	my_malloc.part.0, .-my_malloc.part.0
	.section	.rodata.str1.1,"aMS",@progbits,1
.LC1:
	.string	" ## __LINE__ ## "
	.text
	.p2align 4,,15
	.globl	invert_vdm
	.type	invert_vdm, @function
invert_vdm:
.LFB63:
	.cfi_startproc
	pushq	%r15
	.cfi_def_cfa_offset 16
	.cfi_offset 15, -16
	pushq	%r14
	.cfi_def_cfa_offset 24
	.cfi_offset 14, -24
	pushq	%r13
	.cfi_def_cfa_offset 32
	.cfi_offset 13, -32
	pushq	%r12
	.cfi_def_cfa_offset 40
	.cfi_offset 12, -40
	movl	%esi, %r12d
	pushq	%rbp
	.cfi_def_cfa_offset 48
	.cfi_offset 6, -48
	pushq	%rbx
	.cfi_def_cfa_offset 56
	.cfi_offset 3, -56
	subq	$40, %rsp
	.cfi_def_cfa_offset 96
	cmpl	$1, %esi
	movq	%rdi, (%rsp)
	je	.L44
	movslq	%esi, %rbx
	movq	%rbx, %rdi
	call	malloc
	testq	%rax, %rax
	movq	%rax, 8(%rsp)
	je	.L47
	movq	%rbx, %rdi
	call	malloc
	testq	%rax, %rax
	movq	%rax, %rbp
	je	.L47
	movq	%rbx, %rdi
	call	malloc
	testq	%rax, %rax
	movq	%rax, %r13
	je	.L47
	testl	%r12d, %r12d
	jle	.L49
	movq	8(%rsp), %rdi
	movl	%r12d, %edx
	xorl	%esi, %esi
	call	memset
	movq	(%rsp), %rdx
	leal	-1(%rbx), %ecx
	andl	$7, %ecx
	movzbl	1(%rdx), %eax
	addq	%rbx, %rdx
	cmpl	$1, %r12d
	movb	%al, 0(%r13)
	movl	$1, %eax
	jle	.L128
	testl	%ecx, %ecx
	je	.L50
	cmpl	$1, %ecx
	je	.L122
	cmpl	$2, %ecx
	.p2align 4,,3
	je	.L123
	cmpl	$3, %ecx
	.p2align 4,,2
	je	.L124
	cmpl	$4, %ecx
	.p2align 4,,2
	je	.L125
	cmpl	$5, %ecx
	.p2align 4,,2
	je	.L126
	cmpl	$6, %ecx
	.p2align 4,,2
	je	.L127
	movzbl	1(%rdx), %r8d
	movl	$2, %eax
	addq	%rbx, %rdx
	movb	%r8b, 1(%r13)
.L127:
	movzbl	1(%rdx), %r9d
	addq	%rbx, %rdx
	movb	%r9b, 0(%r13,%rax)
	addq	$1, %rax
.L126:
	movzbl	1(%rdx), %r10d
	addq	%rbx, %rdx
	movb	%r10b, 0(%r13,%rax)
	addq	$1, %rax
.L125:
	movzbl	1(%rdx), %r11d
	addq	%rbx, %rdx
	movb	%r11b, 0(%r13,%rax)
	addq	$1, %rax
.L124:
	movzbl	1(%rdx), %esi
	addq	%rbx, %rdx
	movb	%sil, 0(%r13,%rax)
	addq	$1, %rax
.L123:
	movzbl	1(%rdx), %ecx
	addq	%rbx, %rdx
	movb	%cl, 0(%r13,%rax)
	addq	$1, %rax
.L122:
	movzbl	1(%rdx), %r14d
	addq	%rbx, %rdx
	movb	%r14b, 0(%r13,%rax)
	addq	$1, %rax
	cmpl	%eax, %r12d
	jle	.L128
.L50:
	movzbl	1(%rdx), %r14d
	addq	%rbx, %rdx
	movzbl	1(%rdx), %r11d
	addq	%rbx, %rdx
	movzbl	1(%rdx), %r10d
	addq	%rbx, %rdx
	movzbl	1(%rdx), %r9d
	addq	%rbx, %rdx
	movzbl	1(%rdx), %r8d
	addq	%rbx, %rdx
	movb	%r14b, 0(%r13,%rax)
	movzbl	1(%rdx), %edi
	addq	%rbx, %rdx
	movb	%r11b, 1(%r13,%rax)
	movzbl	1(%rdx), %esi
	addq	%rbx, %rdx
	movb	%r10b, 2(%r13,%rax)
	movzbl	1(%rdx), %ecx
	movb	%r9b, 3(%r13,%rax)
	addq	%rbx, %rdx
	movb	%r8b, 4(%r13,%rax)
	movb	%dil, 5(%r13,%rax)
	movb	%sil, 6(%r13,%rax)
	movb	%cl, 7(%r13,%rax)
	addq	$8, %rax
	cmpl	%eax, %r12d
	jg	.L50
.L128:
	movq	8(%rsp), %r11
	leaq	-1(%rbx), %rax
	movzbl	1(%r13), %r10d
	leal	-2(%r12), %r15d
	movq	8(%rsp), %rdx
	movl	$1, %r8d
	movq	%rax, 16(%rsp)
	leal	-1(%r12), %r14d
	addq	%rax, %r11
	movzbl	0(%r13), %eax
	movl	%r15d, %r9d
	movl	%r15d, 28(%rsp)
	leaq	-2(%rdx,%rbx), %rdx
	xorl	%r10d, %eax
	testl	%r9d, %r9d
	movb	%al, (%r11)
	je	.L140
	.p2align 4,,10
	.p2align 3
.L54:
	cmpl	%r9d, %r14d
	movzbl	1(%r13,%r8), %r10d
	jle	.L52
	leaq	-1(%r8), %rdi
	movzbl	%r10b, %ecx
	xorl	%eax, %eax
	salq	$8, %rcx
	movzbl	(%rdx), %esi
	andl	$3, %edi
	je	.L53
	movzbl	1(%rdx), %r15d
	movzbl	%r15b, %eax
	xorb	gf_mul_table(%rcx,%rax), %sil
	cmpq	$1, %rdi
	movl	$1, %eax
	movb	%sil, (%rdx)
	movl	%r15d, %esi
	je	.L53
	cmpq	$2, %rdi
	je	.L121
	movzbl	2(%rdx), %edi
	movl	$2, %eax
	movzbl	%dil, %r15d
	xorb	gf_mul_table(%rcx,%r15), %sil
	movb	%sil, 1(%rdx)
	movl	%edi, %esi
.L121:
	movzbl	1(%rdx,%rax), %edi
	movzbl	%dil, %r15d
	xorb	gf_mul_table(%rcx,%r15), %sil
	movb	%sil, (%rdx,%rax)
	addq	$1, %rax
	movl	%edi, %esi
	jmp	.L53
	.p2align 4,,10
	.p2align 3
.L58:
	movzbl	1(%rdx,%rsi), %esi
	movzbl	%sil, %r15d
	xorb	gf_mul_table(%r15,%rcx), %dil
	movb	%dil, 1(%rdx,%rax)
	movzbl	3(%rdx,%rax), %edi
	movzbl	%dil, %r15d
	xorb	gf_mul_table(%rcx,%r15), %sil
	movb	%sil, 2(%rdx,%rax)
	movzbl	4(%rdx,%rax), %esi
	movzbl	%sil, %r15d
	xorb	gf_mul_table(%rcx,%r15), %dil
	movb	%dil, 3(%rdx,%rax)
	addq	$4, %rax
.L53:
	movzbl	1(%rdx,%rax), %edi
	movzbl	%dil, %r15d
	xorb	gf_mul_table(%rcx,%r15), %sil
	movb	%sil, (%rdx,%rax)
	leaq	1(%rax), %rsi
	cmpq	%r8, %rsi
	jne	.L58
	movzbl	(%r11), %eax
.L52:
	subl	$1, %r9d
	xorl	%r10d, %eax
	subq	$1, %rdx
	addq	$1, %r8
	testl	%r9d, %r9d
	movb	%al, (%r11)
	jne	.L54
.L140:
	movslq	28(%rsp), %r10
	movq	8(%rsp), %rcx
	leal	-2(%r12), %r8d
	movq	16(%rsp), %r11
	xorl	%r9d, %r9d
	movq	%rbx, 16(%rsp)
	notq	%r8
	leaq	(%rcx,%r10), %rdi
	leaq	0(%rbp,%r10), %rsi
	addq	%rbp, %r11
	.p2align 4,,10
	.p2align 3
.L57:
	movzbl	0(%r13,%r9), %ecx
	movb	$1, (%r11)
	movq	%r8, %r15
	movzbl	1(%rbp,%r10), %r14d
	notq	%r15
	movq	$-1, %rax
	andl	$3, %r15d
	salq	$8, %rcx
	movzbl	gf_mul_table(%r14,%rcx), %edx
	xorb	1(%rdi), %dl
	movl	%edx, %ebx
	xorb	gf_mul_table+1(%rcx), %bl
	cmpq	%r8, %rax
	movb	%dl, (%rsi)
	movl	%ebx, %r14d
	je	.L130
	testq	%r15, %r15
	je	.L135
	cmpq	$1, %r15
	je	.L119
	cmpq	$2, %r15
	je	.L120
	movzbl	%dl, %edx
	movzbl	%bl, %r15d
	movzbl	gf_mul_table(%rcx,%rdx), %edx
	xorb	(%rdi), %dl
	movl	%edx, %eax
	xorb	gf_mul_table(%rcx,%r15), %al
	movb	%dl, -1(%rsi)
	movl	%eax, %r14d
	movq	$-2, %rax
.L120:
	movzbl	%dl, %r15d
	movzbl	%r14b, %r14d
	movzbl	gf_mul_table(%rcx,%r15), %edx
	xorb	1(%rdi,%rax), %dl
	movl	%edx, %ebx
	xorb	gf_mul_table(%rcx,%r14), %bl
	movb	%dl, (%rsi,%rax)
	subq	$1, %rax
	movl	%ebx, %r14d
.L119:
	movzbl	%dl, %edx
	movzbl	%r14b, %r14d
	movzbl	gf_mul_table(%rcx,%rdx), %edx
	xorb	1(%rdi,%rax), %dl
	movl	%edx, %ebx
	xorb	gf_mul_table(%rcx,%r14), %bl
	movb	%dl, (%rsi,%rax)
	subq	$1, %rax
	cmpq	%r8, %rax
	movl	%ebx, %r14d
	je	.L130
.L135:
	movq	16(%rsp), %r15
.L55:
	movzbl	%dl, %edx
	movzbl	%r14b, %r14d
	movzbl	gf_mul_table(%rcx,%rdx), %edx
	xorb	1(%rdi,%rax), %dl
	movb	%dl, (%rsi,%rax)
	movl	%edx, %ebx
	movzbl	%dl, %edx
	movzbl	gf_mul_table(%rcx,%rdx), %edx
	xorb	gf_mul_table(%rcx,%r14), %bl
	xorb	(%rdi,%rax), %dl
	movzbl	%bl, %r14d
	movb	%dl, -1(%rsi,%rax)
	movl	%edx, %ebx
	movzbl	%dl, %edx
	movzbl	gf_mul_table(%rcx,%rdx), %edx
	xorb	gf_mul_table(%rcx,%r14), %bl
	xorb	-1(%rdi,%rax), %dl
	movzbl	%bl, %r14d
	movb	%dl, -2(%rsi,%rax)
	movl	%edx, %ebx
	movzbl	%dl, %edx
	xorb	gf_mul_table(%rcx,%r14), %bl
	movzbl	gf_mul_table(%rcx,%rdx), %edx
	xorb	-2(%rdi,%rax), %dl
	movzbl	%bl, %r14d
	movl	%edx, %ebx
	xorb	gf_mul_table(%rcx,%r14), %bl
	movb	%dl, -3(%rsi,%rax)
	subq	$4, %rax
	cmpq	%r8, %rax
	movl	%ebx, %r14d
	jne	.L55
	movq	%r15, 16(%rsp)
.L130:
	movzbl	%r14b, %ecx
	movzbl	0(%rbp), %r15d
	movq	(%rsp), %rdx
	movzbl	inverse(%rcx), %ecx
	leal	-1(%r12), %r14d
	addq	%r9, %rdx
	andl	$3, %r14d
	salq	$8, %rcx
	movzbl	gf_mul_table(%r15,%rcx), %eax
	movb	%al, (%rdx)
	addq	16(%rsp), %rdx
	cmpl	$1, %r12d
	movl	$1, %eax
	jle	.L131
	testl	%r14d, %r14d
	je	.L133
	cmpl	$1, %r14d
	je	.L117
	cmpl	$2, %r14d
	je	.L118
	movzbl	1(%rbp), %eax
	movzbl	gf_mul_table(%rcx,%rax), %ebx
	movl	$2, %eax
	movb	%bl, (%rdx)
	addq	16(%rsp), %rdx
.L118:
	movzbl	0(%rbp,%rax), %r15d
	addq	$1, %rax
	movzbl	gf_mul_table(%rcx,%r15), %r14d
	movb	%r14b, (%rdx)
	addq	16(%rsp), %rdx
.L117:
	movzbl	0(%rbp,%rax), %r14d
	addq	$1, %rax
	movzbl	gf_mul_table(%rcx,%r14), %ebx
	movb	%bl, (%rdx)
	addq	16(%rsp), %rdx
	cmpl	%eax, %r12d
	jle	.L131
.L133:
	movq	16(%rsp), %rbx
.L56:
	movzbl	0(%rbp,%rax), %r15d
	movzbl	gf_mul_table(%rcx,%r15), %r14d
	movzbl	1(%rbp,%rax), %r15d
	movb	%r14b, (%rdx)
	movzbl	gf_mul_table(%rcx,%r15), %r14d
	addq	%rbx, %rdx
	movzbl	2(%rbp,%rax), %r15d
	movb	%r14b, (%rdx)
	addq	%rbx, %rdx
	movzbl	gf_mul_table(%rcx,%r15), %r14d
	movzbl	3(%rbp,%rax), %r15d
	addq	$4, %rax
	movb	%r14b, (%rdx)
	movzbl	gf_mul_table(%rcx,%r15), %r14d
	addq	%rbx, %rdx
	movb	%r14b, (%rdx)
	addq	%rbx, %rdx
	cmpl	%eax, %r12d
	jg	.L56
	movq	%rbx, 16(%rsp)
.L131:
	addq	$1, %r9
	cmpl	%r9d, %r12d
	jg	.L57
.L49:
	movq	8(%rsp), %rdi
	call	free
	movq	%rbp, %rdi
	call	free
	movq	%r13, %rdi
	call	free
.L44:
	addq	$40, %rsp
	.cfi_remember_state
	.cfi_def_cfa_offset 56
	xorl	%eax, %eax
	popq	%rbx
	.cfi_def_cfa_offset 48
	popq	%rbp
	.cfi_def_cfa_offset 40
	popq	%r12
	.cfi_def_cfa_offset 32
	popq	%r13
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	ret
.L47:
	.cfi_restore_state
	movl	$.LC1, %edi
	call	my_malloc.part.0
	.cfi_endproc
.LFE63:
	.size	invert_vdm, .-invert_vdm
	.section	.rodata.str1.1
.LC2:
	.string	"bad parameters to fec_free\n"
	.text
	.p2align 4,,15
	.globl	fec_free
	.type	fec_free, @function
fec_free:
.LFB65:
	.cfi_startproc
	testq	%rdi, %rdi
	pushq	%rbx
	.cfi_def_cfa_offset 16
	.cfi_offset 3, -16
	movq	%rdi, %rbx
	je	.L142
	movl	8(%rbx), %eax
	xorl	12(%rbx), %eax
	movq	16(%rdi), %rdi
	xorl	$-20181524, %eax
	xorl	%edi, %eax
	cmpq	%rax, (%rbx)
	je	.L143
.L142:
	popq	%rbx
	.cfi_remember_state
	.cfi_def_cfa_offset 8
	movq	stderr(%rip), %rcx
	movl	$27, %edx
	movl	$1, %esi
	movl	$.LC2, %edi
	jmp	fwrite
	.p2align 4,,10
	.p2align 3
.L143:
	.cfi_restore_state
	call	free
	movq	%rbx, %rdi
	popq	%rbx
	.cfi_def_cfa_offset 8
	jmp	free
	.cfi_endproc
.LFE65:
	.size	fec_free, .-fec_free
	.section	.rodata.str1.8
	.align 8
.LC3:
	.string	"Invalid parameters k %d n %d GF_SIZE %d\n"
	.section	.rodata.str1.1
.LC4:
	.string	"new_code"
	.text
	.p2align 4,,15
	.globl	fec_new
	.type	fec_new, @function
fec_new:
.LFB66:
	.cfi_startproc
	pushq	%r15
	.cfi_def_cfa_offset 16
	.cfi_offset 15, -16
	pushq	%r14
	.cfi_def_cfa_offset 24
	.cfi_offset 14, -24
	movl	%esi, %r14d
	pushq	%r13
	.cfi_def_cfa_offset 32
	.cfi_offset 13, -32
	pushq	%r12
	.cfi_def_cfa_offset 40
	.cfi_offset 12, -40
	pushq	%rbp
	.cfi_def_cfa_offset 48
	.cfi_offset 6, -48
	pushq	%rbx
	.cfi_def_cfa_offset 56
	.cfi_offset 3, -56
	movl	%edi, %ebx
	subq	$24, %rsp
	.cfi_def_cfa_offset 80
	movl	fec_initialized(%rip), %edx
	testl	%edx, %edx
	je	.L373
.L145:
	cmpl	$256, %r14d
	jg	.L155
	cmpl	$256, %ebx
	jg	.L155
	cmpl	%r14d, %ebx
	jg	.L155
	movl	$24, %edi
	call	malloc
	testq	%rax, %rax
	movq	%rax, %r13
	je	.L374
	movl	%ebx, 8(%rax)
	movl	%r14d, 12(%rax)
	movl	%r14d, %eax
	imull	%ebx, %eax
	movslq	%eax, %rbp
	movq	%rbp, %rdi
	call	malloc
	testq	%rax, %rax
	je	.L372
	movl	%ebx, %edi
	movq	%rax, 16(%r13)
	xorl	$-20181524, %edi
	xorl	%r14d, %edi
	xorl	%eax, %edi
	movq	%rdi, 0(%r13)
	movq	%rbp, %rdi
	call	malloc
	testq	%rax, %rax
	movq	%rax, %r12
	je	.L372
	cmpl	$1, %ebx
	movb	$1, (%rax)
	jle	.L161
	movq	%rax, %rsi
	leal	-1(%rbx), %edi
	notq	%rsi
	andl	$15, %esi
	cmpl	%edi, %esi
	cmova	%edi, %esi
	testl	%esi, %esi
	movl	%esi, %r9d
	je	.L184
	leal	-1(%r9), %edx
	movb	$0, 1(%rax)
	movl	$2, %ecx
	movl	$1, %eax
	andl	$7, %edx
	cmpl	$1, %esi
	jbe	.L357
	testl	%edx, %edx
	je	.L163
	cmpl	$1, %edx
	je	.L350
	cmpl	$2, %edx
	.p2align 4,,3
	je	.L351
	cmpl	$3, %edx
	.p2align 4,,2
	je	.L352
	cmpl	$4, %edx
	.p2align 4,,2
	je	.L353
	cmpl	$5, %edx
	.p2align 4,,2
	je	.L354
	cmpl	$6, %edx
	.p2align 4,,2
	je	.L355
	movb	$0, 2(%r12)
	movl	$2, %eax
.L355:
	movb	$0, 1(%r12,%rax)
	addq	$1, %rax
.L354:
	movb	$0, 1(%r12,%rax)
	addq	$1, %rax
.L353:
	movb	$0, 1(%r12,%rax)
	addq	$1, %rax
.L352:
	movb	$0, 1(%r12,%rax)
	addq	$1, %rax
.L351:
	movb	$0, 1(%r12,%rax)
	addq	$1, %rax
.L350:
	movb	$0, 1(%r12,%rax)
	leal	2(%rax), %ecx
	addq	$1, %rax
	cmpl	%eax, %esi
	jbe	.L357
.L163:
	leaq	7(%rax), %rcx
	movb	$0, 1(%r12,%rax)
	movb	$0, 2(%r12,%rax)
	movb	$0, 3(%r12,%rax)
	movb	$0, 4(%r12,%rax)
	movb	$0, 5(%r12,%rax)
	movb	$0, 6(%r12,%rax)
	addl	$2, %ecx
	movb	$0, 7(%r12,%rax)
	movb	$0, 8(%r12,%rax)
	addq	$8, %rax
	cmpl	%eax, %esi
	ja	.L163
.L357:
	cmpl	%edi, %esi
	je	.L161
.L162:
	movl	%edi, %r10d
	subl	%esi, %r10d
	movl	%r10d, %edi
	shrl	$4, %edi
	movl	%edi, %r8d
	sall	$4, %r8d
	testl	%r8d, %r8d
	je	.L165
	pxor	%xmm0, %xmm0
	leal	-1(%rdi), %esi
	leaq	1(%r12,%r9), %r9
	movl	$1, %edx
	andl	$7, %esi
	cmpl	$1, %edi
	movdqa	%xmm0, (%r9)
	leaq	16(%r9), %rax
	jbe	.L358
	testl	%esi, %esi
	je	.L166
	cmpl	$1, %esi
	je	.L344
	cmpl	$2, %esi
	.p2align 4,,3
	je	.L345
	cmpl	$3, %esi
	.p2align 4,,2
	je	.L346
	cmpl	$4, %esi
	.p2align 4,,2
	je	.L347
	cmpl	$5, %esi
	.p2align 4,,2
	je	.L348
	cmpl	$6, %esi
	.p2align 4,,2
	je	.L349
	movdqa	%xmm0, (%rax)
	leaq	32(%r9), %rax
	movl	$2, %edx
.L349:
	movdqa	%xmm0, (%rax)
	addl	$1, %edx
	addq	$16, %rax
.L348:
	movdqa	%xmm0, (%rax)
	addl	$1, %edx
	addq	$16, %rax
.L347:
	movdqa	%xmm0, (%rax)
	addl	$1, %edx
	addq	$16, %rax
.L346:
	movdqa	%xmm0, (%rax)
	addl	$1, %edx
	addq	$16, %rax
.L345:
	movdqa	%xmm0, (%rax)
	addl	$1, %edx
	addq	$16, %rax
.L344:
	addl	$1, %edx
	movdqa	%xmm0, (%rax)
	addq	$16, %rax
	cmpl	%edx, %edi
	jbe	.L358
.L166:
	addl	$8, %edx
	movdqa	%xmm0, (%rax)
	movdqa	%xmm0, 16(%rax)
	movdqa	%xmm0, 32(%rax)
	movdqa	%xmm0, 48(%rax)
	movdqa	%xmm0, 64(%rax)
	movdqa	%xmm0, 80(%rax)
	movdqa	%xmm0, 96(%rax)
	movdqa	%xmm0, 112(%rax)
	subq	$-128, %rax
	cmpl	%edx, %edi
	ja	.L166
.L358:
	addl	%r8d, %ecx
	cmpl	%r8d, %r10d
	je	.L161
.L165:
	movl	%ecx, %esi
	leal	1(%rcx), %ebp
	movslq	%ecx, %rdx
	notl	%esi
	addq	%r12, %rdx
	movl	$1, %eax
	addl	%ebx, %esi
	movb	$0, (%rdx)
	andl	$7, %esi
	cmpl	%ebp, %ebx
	jle	.L161
	testl	%esi, %esi
	je	.L168
	cmpl	$1, %esi
	je	.L338
	cmpl	$2, %esi
	.p2align 4,,3
	je	.L339
	cmpl	$3, %esi
	.p2align 4,,2
	je	.L340
	cmpl	$4, %esi
	.p2align 4,,2
	je	.L341
	cmpl	$5, %esi
	.p2align 4,,2
	je	.L342
	cmpl	$6, %esi
	.p2align 4,,2
	je	.L343
	movb	$0, 1(%rdx)
	movl	$2, %eax
.L343:
	movb	$0, (%rdx,%rax)
	addq	$1, %rax
.L342:
	movb	$0, (%rdx,%rax)
	addq	$1, %rax
.L341:
	movb	$0, (%rdx,%rax)
	addq	$1, %rax
.L340:
	movb	$0, (%rdx,%rax)
	addq	$1, %rax
.L339:
	movb	$0, (%rdx,%rax)
	addq	$1, %rax
.L338:
	movb	$0, (%rdx,%rax)
	addq	$1, %rax
	leal	(%rcx,%rax), %r9d
	cmpl	%r9d, %ebx
	jle	.L161
.L168:
	movb	$0, (%rdx,%rax)
	movb	$0, 1(%rdx,%rax)
	movb	$0, 2(%rdx,%rax)
	movb	$0, 3(%rdx,%rax)
	movb	$0, 4(%rdx,%rax)
	movb	$0, 5(%rdx,%rax)
	movb	$0, 6(%rdx,%rax)
	movb	$0, 7(%rdx,%rax)
	addq	$8, %rax
	leal	(%rcx,%rax), %esi
	cmpl	%esi, %ebx
	jg	.L168
.L161:
	leal	-1(%r14), %r10d
	movslq	%ebx, %rbp
	testl	%r10d, %r10d
	jle	.L169
	leaq	(%r12,%rbp), %rdi
	leal	-1(%rbx), %ecx
	xorl	%esi, %esi
	leaq	1(%rdi,%rcx), %r8
.L170:
	testl	%ebx, %ebx
	jle	.L174
	leaq	1(%rdi), %rcx
	movl	%esi, %edx
	movq	%rdi, %r9
	xorl	%eax, %eax
.L175:
	movzbl	%al, %eax
	cmpq	%rcx, %r8
	movzbl	gf_exp(%rax), %r15d
	movb	%r15b, (%r9)
	je	.L174
	cmpl	$254, %edx
	movq	%rcx, %r9
	movl	%edx, %eax
	jle	.L171
	.p2align 4,,10
	.p2align 3
.L185:
	subl	$255, %eax
	movl	%eax, %r11d
	andl	$255, %eax
	sarl	$8, %r11d
	addl	%r11d, %eax
	cmpl	$254, %eax
	jg	.L185
.L171:
	addq	$1, %rcx
	addl	%esi, %edx
	jmp	.L175
.L184:
	movl	$1, %ecx
	jmp	.L162
	.p2align 4,,10
	.p2align 3
.L174:
	addl	$1, %esi
	addq	%rbp, %rdi
	addq	%rbp, %r8
	cmpl	%r10d, %esi
	jl	.L170
.L169:
	movq	%r12, %rdi
	movl	%ebx, %esi
	subl	%ebx, %r14d
	call	invert_vdm
	movl	%ebx, %r8d
	movq	16(%r13), %rdi
	imull	%ebx, %r8d
	testl	%r14d, %r14d
	movslq	%r8d, %rdx
	leaq	(%rdi,%rdx), %r10
	leaq	(%r12,%rdx), %rax
	jle	.L176
	subq	%r10, %rax
	xorl	%r11d, %r11d
	movq	%rax, 8(%rsp)
.L177:
	testl	%ebx, %ebx
	jle	.L180
	movq	8(%rsp), %rdi
	xorl	%r9d, %r9d
	addq	%r10, %rdi
.L179:
	leaq	(%r12,%r9), %rsi
	movzbl	(%rdi), %r15d
	leal	-1(%rbx), %r8d
	movzbl	(%rsi), %ecx
	andl	$3, %r8d
	addq	%rbp, %rsi
	salq	$8, %r15
	cmpl	$1, %ebx
	movzbl	gf_mul_table(%rcx,%r15), %eax
	movl	$1, %ecx
	jle	.L359
	testl	%r8d, %r8d
	je	.L178
	cmpl	$1, %r8d
	je	.L336
	cmpl	$2, %r8d
	je	.L337
	movzbl	1(%rdi), %ecx
	movzbl	(%rsi), %r8d
	addq	%rbp, %rsi
	salq	$8, %rcx
	xorb	gf_mul_table(%r8,%rcx), %al
	movl	$2, %ecx
.L337:
	movzbl	(%rdi,%rcx), %r8d
	movzbl	(%rsi), %r15d
	addq	$1, %rcx
	addq	%rbp, %rsi
	salq	$8, %r8
	xorb	gf_mul_table(%r15,%r8), %al
.L336:
	movzbl	(%rdi,%rcx), %r8d
	movzbl	(%rsi), %r15d
	addq	$1, %rcx
	addq	%rbp, %rsi
	salq	$8, %r8
	xorb	gf_mul_table(%r15,%r8), %al
	cmpl	%ecx, %ebx
	jle	.L359
.L178:
	movzbl	(%rdi,%rcx), %r8d
	movzbl	(%rsi), %r15d
	salq	$8, %r8
	xorb	gf_mul_table(%r15,%r8), %al
	leaq	(%rsi,%rbp), %r8
	movzbl	1(%rdi,%rcx), %esi
	movzbl	(%r8), %r15d
	addq	%rbp, %r8
	salq	$8, %rsi
	xorb	gf_mul_table(%r15,%rsi), %al
	movzbl	2(%rdi,%rcx), %esi
	movzbl	(%r8), %r15d
	addq	%rbp, %r8
	salq	$8, %rsi
	xorb	gf_mul_table(%r15,%rsi), %al
	movzbl	3(%rdi,%rcx), %esi
	addq	$4, %rcx
	movzbl	(%r8), %r15d
	salq	$8, %rsi
	xorb	gf_mul_table(%r15,%rsi), %al
	cmpl	%ecx, %ebx
	leaq	(%r8,%rbp), %rsi
	jg	.L178
.L359:
	movb	%al, (%r10,%r9)
	addq	$1, %r9
	cmpl	%r9d, %ebx
	jg	.L179
.L180:
	addl	$1, %r11d
	addq	%rbp, %r10
	cmpl	%r14d, %r11d
	jne	.L177
	movq	16(%r13), %rdi
.L176:
	xorl	%esi, %esi
	call	memset
	testl	%ebx, %ebx
	movq	16(%r13), %rax
	jle	.L181
	leal	-1(%rbx), %ecx
	addq	$1, %rbp
	movl	$1, %edx
	movb	$1, (%rax)
	addq	%rbp, %rax
	andl	$7, %ecx
	cmpl	%ebx, %edx
	je	.L181
	testl	%ecx, %ecx
	je	.L182
	cmpl	$1, %ecx
	je	.L330
	cmpl	$2, %ecx
	.p2align 4,,3
	je	.L331
	cmpl	$3, %ecx
	.p2align 4,,2
	je	.L332
	cmpl	$4, %ecx
	.p2align 4,,2
	je	.L333
	cmpl	$5, %ecx
	.p2align 4,,2
	je	.L334
	cmpl	$6, %ecx
	.p2align 4,,2
	je	.L335
	movb	$1, (%rax)
	movl	$2, %edx
	addq	%rbp, %rax
.L335:
	movb	$1, (%rax)
	addl	$1, %edx
	addq	%rbp, %rax
.L334:
	movb	$1, (%rax)
	addl	$1, %edx
	addq	%rbp, %rax
.L333:
	movb	$1, (%rax)
	addl	$1, %edx
	addq	%rbp, %rax
.L332:
	movb	$1, (%rax)
	addl	$1, %edx
	addq	%rbp, %rax
.L331:
	movb	$1, (%rax)
	addl	$1, %edx
	addq	%rbp, %rax
.L330:
	addl	$1, %edx
	movb	$1, (%rax)
	addq	%rbp, %rax
	cmpl	%ebx, %edx
	je	.L181
.L182:
	movb	$1, (%rax)
	addq	%rbp, %rax
	addl	$8, %edx
	movb	$1, (%rax)
	addq	%rbp, %rax
	movb	$1, (%rax)
	addq	%rbp, %rax
	movb	$1, (%rax)
	addq	%rbp, %rax
	movb	$1, (%rax)
	addq	%rbp, %rax
	movb	$1, (%rax)
	addq	%rbp, %rax
	movb	$1, (%rax)
	addq	%rbp, %rax
	movb	$1, (%rax)
	addq	%rbp, %rax
	cmpl	%ebx, %edx
	jne	.L182
.L181:
	movq	%r12, %rdi
	call	free
.L157:
	addq	$24, %rsp
	.cfi_remember_state
	.cfi_def_cfa_offset 56
	movq	%r13, %rax
	popq	%rbx
	.cfi_def_cfa_offset 48
	popq	%rbp
	.cfi_def_cfa_offset 40
	popq	%r12
	.cfi_def_cfa_offset 32
	popq	%r13
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	ret
.L372:
	.cfi_restore_state
	movl	$.LC1, %edi
	call	my_malloc.part.0
.L374:
	movl	$.LC4, %edi
	call	my_malloc.part.0
.L155:
	movq	stderr(%rip), %rdi
	movl	$255, %r9d
	movl	%r14d, %r8d
	movl	%ebx, %ecx
	movl	$.LC3, %edx
	movl	$1, %esi
	xorl	%eax, %eax
	xorl	%r13d, %r13d
	call	__fprintf_chk
	jmp	.L157
.L373:
	movb	$1, gf_exp(%rip)
	movl	$0, gf_log+4(%rip)
	xorl	%eax, %eax
	movb	$2, gf_exp+1(%rip)
	movl	$1, gf_log+8(%rip)
	movb	$4, gf_exp+2(%rip)
	movl	$2, gf_log+16(%rip)
	movb	$8, gf_exp+3(%rip)
	movl	$3, gf_log+32(%rip)
	movb	$16, gf_exp+4(%rip)
	movl	$4, gf_log+64(%rip)
	movb	$29, gf_exp+8(%rip)
	movb	$32, gf_exp+5(%rip)
	movl	$5, gf_log+128(%rip)
	movb	$64, gf_exp+6(%rip)
	movl	$6, gf_log+256(%rip)
	movb	$-128, gf_exp+7(%rip)
	movl	$7, gf_log+512(%rip)
	movl	$8, gf_log+116(%rip)
.L148:
	movzbl	gf_exp+8(%rax), %ecx
	leal	9(%rax), %esi
	cmpb	$-128, %cl
	leal	(%rcx,%rcx), %edx
	jb	.L147
	xorb	gf_exp+8(%rip), %dl
.L147:
	movl	%edx, %ecx
	movb	%dl, gf_exp+9(%rax)
	movzbl	%dl, %edi
	addq	$1, %rax
	cmpb	$-128, %cl
	movl	%esi, gf_log(,%rdi,4)
	leal	(%rcx,%rcx), %edx
	leal	9(%rax), %esi
	jb	.L315
	leal	(%rcx,%rcx), %edx
	xorb	gf_exp+8(%rip), %dl
.L315:
	movzbl	%dl, %r10d
	cmpb	$-128, %dl
	movb	%dl, gf_exp+9(%rax)
	movl	%esi, gf_log(,%r10,4)
	leaq	1(%rax), %rsi
	leal	(%rdx,%rdx), %ecx
	leal	9(%rsi), %edi
	jb	.L317
	xorb	gf_exp+8(%rip), %cl
.L317:
	movzbl	%cl, %edx
	movb	%cl, gf_exp+9(%rsi)
	leaq	2(%rax), %rcx
	movl	%edi, gf_log(,%rdx,4)
	movzbl	gf_exp+8(%rcx), %r12d
	leal	9(%rcx), %edi
	cmpb	$-128, %r12b
	leal	(%r12,%r12), %edx
	jb	.L319
	xorb	gf_exp+8(%rip), %dl
.L319:
	movb	%dl, gf_exp+9(%rcx)
	leaq	3(%rax), %rcx
	movzbl	%dl, %ebp
	movl	%edi, gf_log(,%rbp,4)
	movzbl	gf_exp+8(%rcx), %r13d
	leal	9(%rcx), %edi
	cmpb	$-128, %r13b
	leal	(%r13,%r13), %edx
	jb	.L321
	xorb	gf_exp+8(%rip), %dl
.L321:
	movb	%dl, gf_exp+9(%rcx)
	leaq	4(%rax), %rcx
	movzbl	%dl, %esi
	movl	%edi, gf_log(,%rsi,4)
	movzbl	gf_exp+8(%rcx), %r11d
	leal	9(%rcx), %edi
	cmpb	$-128, %r11b
	leal	(%r11,%r11), %edx
	jb	.L323
	xorb	gf_exp+8(%rip), %dl
.L323:
	addq	$5, %rax
	movb	%dl, gf_exp+9(%rcx)
	movzbl	%dl, %ecx
	cmpq	$246, %rax
	movl	%edi, gf_log(,%rcx,4)
	jne	.L148
	movzbl	gf_exp+240(%rip), %r8d
	movzbl	gf_exp+241(%rip), %ebp
	movdqa	gf_exp(%rip), %xmm14
	movl	$255, gf_log(%rip)
	movdqa	gf_exp+16(%rip), %xmm13
	movb	%r8b, gf_exp+495(%rip)
	movdqa	gf_exp+32(%rip), %xmm12
	movdqa	gf_exp+48(%rip), %xmm11
	movdqa	gf_exp+64(%rip), %xmm10
	movdqa	gf_exp+80(%rip), %xmm9
	movdqa	gf_exp+96(%rip), %xmm8
	movdqa	gf_exp+112(%rip), %xmm7
	movdqa	gf_exp+128(%rip), %xmm6
	movdqa	gf_exp+144(%rip), %xmm5
	movdqa	gf_exp+160(%rip), %xmm4
	movdqa	gf_exp+176(%rip), %xmm3
	movdqa	gf_exp+192(%rip), %xmm2
	movdqa	gf_exp+208(%rip), %xmm1
	movdqa	gf_exp+224(%rip), %xmm0
	movdqu	%xmm14, gf_exp+255(%rip)
	movdqu	%xmm13, gf_exp+271(%rip)
	movdqu	%xmm12, gf_exp+287(%rip)
	movdqu	%xmm11, gf_exp+303(%rip)
	movdqu	%xmm10, gf_exp+319(%rip)
	movdqu	%xmm9, gf_exp+335(%rip)
	movdqu	%xmm8, gf_exp+351(%rip)
	movdqu	%xmm7, gf_exp+367(%rip)
	movdqu	%xmm6, gf_exp+383(%rip)
	movdqu	%xmm5, gf_exp+399(%rip)
	movdqu	%xmm4, gf_exp+415(%rip)
	movdqu	%xmm3, gf_exp+431(%rip)
	movdqu	%xmm2, gf_exp+447(%rip)
	movdqu	%xmm1, gf_exp+463(%rip)
	movdqu	%xmm0, gf_exp+479(%rip)
	movb	%bpl, gf_exp+496(%rip)
	movzbl	gf_exp+246(%rip), %edx
	movzbl	gf_exp+242(%rip), %eax
	movzbl	gf_exp+243(%rip), %esi
	movzbl	gf_exp+244(%rip), %edi
	movzbl	gf_exp+245(%rip), %ecx
	movzbl	gf_exp+247(%rip), %r15d
	movzbl	gf_exp+248(%rip), %r13d
	movb	%dl, gf_exp+501(%rip)
	movl	$255, %edx
	movzbl	gf_exp+249(%rip), %r12d
	movb	%al, gf_exp+497(%rip)
	movl	%edx, %eax
	subl	gf_log+8(%rip), %eax
	movzbl	gf_exp+250(%rip), %r11d
	movzbl	gf_exp+251(%rip), %r10d
	movzbl	gf_exp+252(%rip), %r9d
	movzbl	gf_exp+253(%rip), %r8d
	movzbl	gf_exp+254(%rip), %ebp
	movb	%sil, gf_exp+498(%rip)
	cltq
	movb	%dil, gf_exp+499(%rip)
	movb	%cl, gf_exp+500(%rip)
	movb	%r15b, gf_exp+502(%rip)
	movb	%r13b, gf_exp+503(%rip)
	movb	%r12b, gf_exp+504(%rip)
	movb	%r11b, gf_exp+505(%rip)
	movb	%r10b, gf_exp+506(%rip)
	movb	%r9b, gf_exp+507(%rip)
	movb	%r8b, gf_exp+508(%rip)
	movb	%bpl, gf_exp+509(%rip)
	movzbl	gf_exp(%rax), %esi
	movl	%edx, %eax
	subl	gf_log+12(%rip), %eax
	movb	$0, inverse(%rip)
	movb	$1, inverse+1(%rip)
	cltq
	movb	%sil, inverse+2(%rip)
	movzbl	gf_exp(%rax), %eax
	movb	%al, inverse+3(%rip)
	movl	$2, %eax
.L149:
	leaq	2(%rax), %r15
	leaq	1(%rax), %rcx
	movl	%edx, %r10d
	movl	%edx, %r13d
	subl	gf_log+8(,%rax,4), %r10d
	movl	%edx, %ebp
	subl	gf_log+8(,%r15,4), %r13d
	subl	gf_log+8(,%rcx,4), %ebp
	leaq	4(%rax), %rcx
	movslq	%r10d, %r9
	leaq	3(%rax), %r10
	movslq	%r13d, %r12
	leaq	5(%rax), %r13
	movzbl	gf_exp(%r9), %r8d
	movslq	%ebp, %rsi
	movzbl	gf_exp(%r12), %r11d
	movl	%edx, %r9d
	movl	%edx, %r12d
	subl	gf_log+8(,%r10,4), %r9d
	subl	gf_log+8(,%r13,4), %r12d
	movzbl	gf_exp(%rsi), %edi
	movl	%edx, %esi
	subl	gf_log+8(,%rcx,4), %esi
	movb	%r8b, inverse+2(%rax)
	leaq	7(%rax), %rcx
	movb	%r11b, inverse+4(%rax)
	movslq	%r9d, %r8
	movslq	%r12d, %r11
	leaq	6(%rax), %r9
	leaq	8(%rax), %r12
	movb	%dil, inverse+3(%rax)
	movslq	%esi, %rdi
	movzbl	gf_exp(%r8), %ebp
	movzbl	gf_exp(%rdi), %r15d
	movl	%edx, %r8d
	movzbl	gf_exp(%r11), %r10d
	subl	gf_log+8(,%r9,4), %r8d
	movl	%edx, %edi
	movl	%edx, %r11d
	subl	gf_log+8(,%rcx,4), %edi
	subl	gf_log+8(,%r12,4), %r11d
	movb	%bpl, inverse+5(%rax)
	movb	%r15b, inverse+6(%rax)
	movb	%r10b, inverse+7(%rax)
	movslq	%r8d, %rbp
	movslq	%edi, %r15
	movslq	%r11d, %r10
	movzbl	gf_exp(%rbp), %esi
	movzbl	gf_exp(%r15), %r13d
	movzbl	gf_exp(%r10), %r9d
	movb	%sil, inverse+8(%rax)
	movb	%r13b, inverse+9(%rax)
	movb	%r9b, inverse+10(%rax)
	addq	$9, %rax
	cmpq	$254, %rax
	jne	.L149
	xorl	%r8d, %r8d
.L150:
	movl	gf_log(%r8), %edi
	movq	%r8, %rsi
	xorl	%ecx, %ecx
	salq	$6, %rsi
	.p2align 4,,10
	.p2align 3
.L153:
	movl	gf_log(,%rcx,4), %eax
	addl	%edi, %eax
	cmpl	$254, %eax
	jle	.L151
	.p2align 4,,10
	.p2align 3
.L186:
	subl	$255, %eax
	movl	%eax, %edx
	andl	$255, %eax
	sarl	$8, %edx
	addl	%edx, %eax
	cmpl	$254, %eax
	jg	.L186
.L151:
	movzbl	%al, %r11d
	movzbl	gf_exp(%r11), %eax
	movb	%al, gf_mul_table(%rsi,%rcx)
	addq	$1, %rcx
	cmpq	$256, %rcx
	jne	.L153
	addq	$4, %r8
	cmpq	$1024, %r8
	jne	.L150
	xorl	%eax, %eax
.L154:
	leaq	1(%rax), %r13
	movq	%rax, %r15
	leaq	2(%rax), %r11
	leaq	3(%rax), %r10
	leaq	4(%rax), %r8
	leaq	5(%rax), %rbp
	movq	%r13, %r12
	leaq	6(%rax), %rdi
	leaq	7(%rax), %r13
	salq	$8, %r15
	salq	$8, %r12
	movq	%r11, %rdx
	movb	$0, gf_mul_table(%r15)
	movq	%r10, %r9
	movb	$0, gf_mul_table(%rax)
	movq	%r8, %rcx
	movb	$0, gf_mul_table(%r12)
	movq	%rbp, %rsi
	movq	%rdi, %r15
	movq	%r13, %r12
	salq	$8, %rdx
	salq	$8, %r9
	salq	$8, %rcx
	salq	$8, %rsi
	salq	$8, %r15
	salq	$8, %r12
	movb	$0, gf_mul_table+1(%rax)
	movb	$0, gf_mul_table(%rdx)
	movb	$0, gf_mul_table+2(%rax)
	movb	$0, gf_mul_table(%r9)
	movb	$0, gf_mul_table+3(%rax)
	movb	$0, gf_mul_table(%rcx)
	movb	$0, gf_mul_table+4(%rax)
	movb	$0, gf_mul_table(%rsi)
	movb	$0, gf_mul_table+5(%rax)
	movb	$0, gf_mul_table(%r15)
	movb	$0, gf_mul_table+6(%rax)
	movb	$0, gf_mul_table(%r12)
	movb	$0, gf_mul_table+7(%rax)
	addq	$8, %rax
	cmpq	$256, %rax
	jne	.L154
	movl	$1, fec_initialized(%rip)
	jmp	.L145
	.cfi_endproc
.LFE66:
	.size	fec_new, .-fec_new
	.section	.rodata.str1.1
.LC5:
	.string	"Invalid index %d (max %d)\n"
	.text
	.p2align 4,,15
	.globl	fec_encode
	.type	fec_encode, @function
fec_encode:
.LFB67:
	.cfi_startproc
	movq	%rbx, -48(%rsp)
	movq	%rbp, -40(%rsp)
	movq	%rdx, %rbx
	.cfi_offset 6, -48
	.cfi_offset 3, -56
	movq	%r13, -24(%rsp)
	movq	%r14, -16(%rsp)
	movq	%rsi, %rbp
	movq	%r12, -32(%rsp)
	movq	%r15, -8(%rsp)
	subq	$72, %rsp
	.cfi_def_cfa_offset 80
	.cfi_offset 15, -16
	.cfi_offset 12, -40
	.cfi_offset 14, -24
	.cfi_offset 13, -32
	movl	8(%rdi), %r13d
	movl	%r8d, %r14d
	cmpl	%ecx, %r13d
	jg	.L429
	movl	12(%rdi), %r8d
	cmpl	%r8d, %ecx
	jge	.L377
	movl	%ecx, %r12d
	xorl	%esi, %esi
	movslq	%r14d, %rdx
	imull	%r13d, %r12d
	movslq	%r12d, %r12
	addq	16(%rdi), %r12
	movq	%rbx, %rdi
	call	memset
	testl	%r13d, %r13d
	jle	.L375
	movzbl	(%r12), %edx
	leal	-1(%r13), %eax
	andl	$7, %eax
	testb	%dl, %dl
	jne	.L430
.L382:
	cmpl	$1, %r13d
	movl	$1, %r15d
	jle	.L375
	testl	%eax, %eax
	je	.L380
	cmpl	$1, %eax
	je	.L420
	cmpl	$2, %eax
	.p2align 4,,3
	je	.L421
	cmpl	$3, %eax
	.p2align 4,,2
	je	.L422
	cmpl	$4, %eax
	.p2align 4,,2
	je	.L423
	cmpl	$5, %eax
	.p2align 4,,2
	je	.L424
	cmpl	$6, %eax
	.p2align 4,,2
	je	.L425
	movzbl	(%r12,%r15), %edx
	testb	%dl, %dl
	jne	.L431
.L384:
	addq	$1, %r15
.L425:
	movzbl	(%r12,%r15), %edx
	testb	%dl, %dl
	jne	.L432
.L387:
	addq	$1, %r15
.L424:
	movzbl	(%r12,%r15), %edx
	testb	%dl, %dl
	jne	.L433
.L390:
	addq	$1, %r15
.L423:
	movzbl	(%r12,%r15), %edx
	testb	%dl, %dl
	jne	.L434
.L393:
	addq	$1, %r15
.L422:
	movzbl	(%r12,%r15), %edx
	testb	%dl, %dl
	jne	.L435
.L396:
	addq	$1, %r15
.L421:
	movzbl	(%r12,%r15), %edx
	testb	%dl, %dl
	jne	.L436
.L399:
	addq	$1, %r15
.L420:
	movzbl	(%r12,%r15), %edx
	testb	%dl, %dl
	jne	.L437
.L402:
	addq	$1, %r15
	cmpl	%r15d, %r13d
	jg	.L380
.L375:
	movq	24(%rsp), %rbx
	movq	32(%rsp), %rbp
	movq	40(%rsp), %r12
	movq	48(%rsp), %r13
	movq	56(%rsp), %r14
	movq	64(%rsp), %r15
	addq	$72, %rsp
	.cfi_remember_state
	.cfi_def_cfa_offset 8
	ret
	.p2align 4,,10
	.p2align 3
.L377:
	.cfi_restore_state
	movq	stderr(%rip), %rdi
	movq	24(%rsp), %rbx
	subl	$1, %r8d
	movq	32(%rsp), %rbp
	movq	40(%rsp), %r12
	movl	$.LC5, %edx
	movq	48(%rsp), %r13
	movq	56(%rsp), %r14
	movl	$1, %esi
	movq	64(%rsp), %r15
	xorl	%eax, %eax
	addq	$72, %rsp
	.cfi_remember_state
	.cfi_def_cfa_offset 8
	jmp	__fprintf_chk
	.p2align 4,,10
	.p2align 3
.L445:
	.cfi_restore_state
	movq	0(%rbp,%r15,8), %rsi
	movzbl	%dl, %edx
	movl	%r14d, %ecx
	movq	%rbx, %rdi
	call	addmul1
	movzbl	1(%r12,%r15), %edx
	leaq	1(%r15), %rax
	testb	%dl, %dl
	jne	.L438
.L405:
	movzbl	1(%r12,%rax), %edx
	leaq	1(%rax), %rcx
	testb	%dl, %dl
	jne	.L439
.L407:
	movzbl	2(%r12,%rax), %edx
	leaq	2(%rax), %rcx
	testb	%dl, %dl
	jne	.L440
.L409:
	movzbl	3(%r12,%rax), %edx
	leaq	3(%rax), %rcx
	testb	%dl, %dl
	jne	.L441
.L411:
	movzbl	4(%r12,%rax), %edx
	leaq	4(%rax), %rcx
	testb	%dl, %dl
	jne	.L442
.L413:
	movzbl	5(%r12,%rax), %edx
	leaq	5(%rax), %rcx
	testb	%dl, %dl
	jne	.L443
.L415:
	movzbl	6(%r12,%rax), %edx
	leaq	6(%rax), %rcx
	testb	%dl, %dl
	jne	.L444
.L417:
	leaq	7(%rax), %r15
	cmpl	%r15d, %r13d
	jle	.L375
.L380:
	movzbl	(%r12,%r15), %edx
	testb	%dl, %dl
	jne	.L445
	movzbl	1(%r12,%r15), %edx
	leaq	1(%r15), %rax
	testb	%dl, %dl
	je	.L405
.L438:
	movq	0(%rbp,%rax,8), %rsi
	movzbl	%dl, %edx
	movl	%r14d, %ecx
	movq	%rbx, %rdi
	movq	%rax, 8(%rsp)
	call	addmul1
	movq	8(%rsp), %rax
	movzbl	1(%r12,%rax), %edx
	leaq	1(%rax), %rcx
	testb	%dl, %dl
	je	.L407
.L439:
	movq	0(%rbp,%rcx,8), %rsi
	movzbl	%dl, %edx
	movl	%r14d, %ecx
	movq	%rbx, %rdi
	movq	%rax, 8(%rsp)
	call	addmul1
	movq	8(%rsp), %rax
	movzbl	2(%r12,%rax), %edx
	leaq	2(%rax), %rcx
	testb	%dl, %dl
	je	.L409
.L440:
	movq	0(%rbp,%rcx,8), %rsi
	movzbl	%dl, %edx
	movl	%r14d, %ecx
	movq	%rbx, %rdi
	movq	%rax, 8(%rsp)
	call	addmul1
	movq	8(%rsp), %rax
	movzbl	3(%r12,%rax), %edx
	leaq	3(%rax), %rcx
	testb	%dl, %dl
	je	.L411
.L441:
	movq	0(%rbp,%rcx,8), %rsi
	movzbl	%dl, %edx
	movl	%r14d, %ecx
	movq	%rbx, %rdi
	movq	%rax, 8(%rsp)
	call	addmul1
	movq	8(%rsp), %rax
	movzbl	4(%r12,%rax), %edx
	leaq	4(%rax), %rcx
	testb	%dl, %dl
	je	.L413
.L442:
	movq	0(%rbp,%rcx,8), %rsi
	movzbl	%dl, %edx
	movl	%r14d, %ecx
	movq	%rbx, %rdi
	movq	%rax, 8(%rsp)
	call	addmul1
	movq	8(%rsp), %rax
	movzbl	5(%r12,%rax), %edx
	leaq	5(%rax), %rcx
	testb	%dl, %dl
	je	.L415
.L443:
	movq	0(%rbp,%rcx,8), %rsi
	movzbl	%dl, %edx
	movl	%r14d, %ecx
	movq	%rbx, %rdi
	movq	%rax, 8(%rsp)
	call	addmul1
	movq	8(%rsp), %rax
	movzbl	6(%r12,%rax), %edx
	leaq	6(%rax), %rcx
	testb	%dl, %dl
	je	.L417
.L444:
	movq	0(%rbp,%rcx,8), %rsi
	movzbl	%dl, %edx
	movl	%r14d, %ecx
	movq	%rbx, %rdi
	movq	%rax, 8(%rsp)
	call	addmul1
	movq	8(%rsp), %rax
	jmp	.L417
	.p2align 4,,10
	.p2align 3
.L429:
	movslq	%ecx, %rcx
	movq	%rbx, %rdi
	movq	32(%rsp), %rbp
	movq	(%rsi,%rcx,8), %rsi
	movq	24(%rsp), %rbx
	movslq	%r8d, %rdx
	movq	40(%rsp), %r12
	movq	48(%rsp), %r13
	movq	56(%rsp), %r14
	movq	64(%rsp), %r15
	addq	$72, %rsp
	.cfi_remember_state
	.cfi_def_cfa_offset 8
	jmp	memmove
	.p2align 4,,10
	.p2align 3
.L430:
	.cfi_restore_state
	movq	0(%rbp), %rsi
	movzbl	%dl, %edx
	movl	%r14d, %ecx
	movq	%rbx, %rdi
	movl	%eax, 8(%rsp)
	call	addmul1
	movl	8(%rsp), %eax
	jmp	.L382
	.p2align 4,,10
	.p2align 3
.L431:
	movq	0(%rbp,%r15,8), %rsi
	movzbl	%dl, %edx
	movl	%r14d, %ecx
	movq	%rbx, %rdi
	call	addmul1
	jmp	.L384
	.p2align 4,,10
	.p2align 3
.L437:
	movq	0(%rbp,%r15,8), %rsi
	movzbl	%dl, %edx
	movl	%r14d, %ecx
	movq	%rbx, %rdi
	call	addmul1
	jmp	.L402
	.p2align 4,,10
	.p2align 3
.L436:
	movq	0(%rbp,%r15,8), %rsi
	movzbl	%dl, %edx
	movl	%r14d, %ecx
	movq	%rbx, %rdi
	call	addmul1
	jmp	.L399
	.p2align 4,,10
	.p2align 3
.L435:
	movq	0(%rbp,%r15,8), %rsi
	movzbl	%dl, %edx
	movl	%r14d, %ecx
	movq	%rbx, %rdi
	call	addmul1
	jmp	.L396
	.p2align 4,,10
	.p2align 3
.L434:
	movq	0(%rbp,%r15,8), %rsi
	movzbl	%dl, %edx
	movl	%r14d, %ecx
	movq	%rbx, %rdi
	call	addmul1
	jmp	.L393
	.p2align 4,,10
	.p2align 3
.L433:
	movq	0(%rbp,%r15,8), %rsi
	movzbl	%dl, %edx
	movl	%r14d, %ecx
	movq	%rbx, %rdi
	call	addmul1
	jmp	.L390
	.p2align 4,,10
	.p2align 3
.L432:
	movq	0(%rbp,%r15,8), %rsi
	movzbl	%dl, %edx
	movl	%r14d, %ecx
	movq	%rbx, %rdi
	call	addmul1
	jmp	.L387
	.cfi_endproc
.LFE67:
	.size	fec_encode, .-fec_encode
	.section	.rodata.str1.8
	.align 8
.LC6:
	.string	"decode: invalid index %d (max %d)\n"
	.section	.rodata.str1.1
.LC7:
	.string	"indxc"
.LC8:
	.string	"indxr"
.LC9:
	.string	"ipiv"
.LC10:
	.string	"singular matrix\n"
.LC11:
	.string	"XXX pivot not found!\n"
.LC12:
	.string	"singular matrix 2\n"
.LC13:
	.string	"AARGH, indxr[col] %d\n"
.LC14:
	.string	"AARGH, indxc[col] %d\n"
.LC15:
	.string	"new pkt pointers"
.LC16:
	.string	"new pkt buffer"
	.text
	.p2align 4,,15
	.globl	fec_decode
	.type	fec_decode, @function
fec_decode:
.LFB70:
	.cfi_startproc
	pushq	%r15
	.cfi_def_cfa_offset 16
	.cfi_offset 15, -16
	pushq	%r14
	.cfi_def_cfa_offset 24
	.cfi_offset 14, -24
	movq	%rsi, %r14
	pushq	%r13
	.cfi_def_cfa_offset 32
	.cfi_offset 13, -32
	pushq	%r12
	.cfi_def_cfa_offset 40
	.cfi_offset 12, -40
	movq	%rdx, %r12
	pushq	%rbp
	.cfi_def_cfa_offset 48
	.cfi_offset 6, -48
	movq	%rdi, %rbp
	pushq	%rbx
	.cfi_def_cfa_offset 56
	.cfi_offset 3, -56
	subq	$168, %rsp
	.cfi_def_cfa_offset 224
	movl	8(%rdi), %ebx
	movl	%ecx, 44(%rsp)
	testl	%ebx, %ebx
	jle	.L515
	xorl	%eax, %eax
	jmp	.L452
	.p2align 4,,10
	.p2align 3
.L1018:
	cmpl	%edx, %eax
	je	.L448
	movslq	%edx, %rdi
	leaq	(%r12,%rdi,4), %r8
	movl	(%r8), %r9d
	cmpl	%r9d, %edx
	je	.L516
	movl	%r9d, (%rsi)
	leaq	(%r14,%rcx,8), %rcx
	movl	%edx, (%r8)
	leaq	(%r14,%rdi,8), %rdx
	cmpl	%eax, %ebx
	movq	(%rcx), %rsi
	movq	(%rdx), %rdi
	movq	%rdi, (%rcx)
	movq	%rsi, (%rdx)
	jle	.L1017
.L452:
	movslq	%eax, %rcx
	leaq	(%r12,%rcx,4), %rsi
	movl	(%rsi), %edx
	cmpl	%edx, %ebx
	jg	.L1018
.L448:
	addl	$1, %eax
	cmpl	%eax, %ebx
	jg	.L452
.L1017:
	movl	8(%rbp), %r13d
.L447:
	movl	%r13d, %edx
	imull	%r13d, %edx
	movslq	%edx, %rdi
	call	malloc
	testq	%rax, %rax
	movq	%rax, 32(%rsp)
	je	.L1016
	testl	%r13d, %r13d
	jle	.L512
	movslq	%r13d, %r15
	movl	(%r12), %ecx
	leal	-1(%r15), %r11d
	andl	$3, %r11d
	cmpl	%r13d, %ecx
	jl	.L1019
	movl	12(%rbp), %r8d
	cmpl	%r8d, %ecx
	jge	.L455
	imull	%r13d, %ecx
	movq	32(%rsp), %rdi
	movq	%r15, %rdx
	movslq	%ecx, %rsi
	addq	16(%rbp), %rsi
	movl	%r11d, 16(%rsp)
	call	memmove
	movl	16(%rsp), %r11d
	movq	32(%rsp), %r10
.L964:
	addq	%r15, %r10
	cmpl	$1, %r13d
	movl	$1, %r9d
	jle	.L512
	testl	%r11d, %r11d
	je	.L1010
	cmpl	$1, %r11d
	je	.L934
	cmpl	$2, %r11d
	je	.L935
	movl	(%r12,%r9,4), %ecx
	cmpl	%r13d, %ecx
	jl	.L1020
	movl	12(%rbp), %r8d
	cmpl	%r8d, %ecx
	jge	.L455
	imull	%r13d, %ecx
	movq	%r10, %rdi
	movq	%r15, %rdx
	movslq	%ecx, %rsi
	addq	16(%rbp), %rsi
	movq	%r9, 16(%rsp)
	movq	%r10, (%rsp)
	call	memmove
	movq	(%rsp), %r10
	movq	16(%rsp), %r9
.L965:
	addq	%r15, %r10
	addq	$1, %r9
.L935:
	movl	(%r12,%r9,4), %ecx
	cmpl	%r13d, %ecx
	jl	.L1021
	movl	12(%rbp), %r8d
	cmpl	%r8d, %ecx
	jge	.L455
	imull	%r13d, %ecx
	movq	%r10, %rdi
	movq	%r15, %rdx
	movslq	%ecx, %rsi
	addq	16(%rbp), %rsi
	movq	%r9, 16(%rsp)
	movq	%r10, (%rsp)
	call	memmove
	movq	(%rsp), %r10
	movq	16(%rsp), %r9
.L966:
	addq	%r15, %r10
	addq	$1, %r9
.L934:
	movl	(%r12,%r9,4), %ecx
	cmpl	%r13d, %ecx
	jl	.L1022
	movl	12(%rbp), %r8d
	cmpl	%r8d, %ecx
	jge	.L455
	imull	%r13d, %ecx
	movq	%r10, %rdi
	movq	%r15, %rdx
	movslq	%ecx, %rsi
	addq	16(%rbp), %rsi
	movq	%r9, 16(%rsp)
	movq	%r10, (%rsp)
	call	memmove
	movq	(%rsp), %r10
	movq	16(%rsp), %r9
.L967:
	addq	$1, %r9
	addq	%r15, %r10
	cmpl	%r9d, %r13d
	jle	.L512
.L1010:
	movq	%r14, 48(%rsp)
	movl	%ebx, 24(%rsp)
	movq	%r9, %r14
	jmp	.L520
	.p2align 4,,10
	.p2align 3
.L453:
	movl	12(%rbp), %r8d
	cmpl	%r8d, %ecx
	jge	.L455
	imull	%r13d, %ecx
	leaq	1(%r14), %rbx
	movq	%r10, %rdi
	movq	%r15, %rdx
	movslq	%ecx, %rsi
	addq	16(%rbp), %rsi
	movq	%r10, (%rsp)
	call	memmove
	movq	(%rsp), %r10
	movl	(%r12,%rbx,4), %ecx
	addq	%r15, %r10
	cmpl	%r13d, %ecx
	jl	.L1023
.L854:
	movl	12(%rbp), %r8d
	cmpl	%r8d, %ecx
	jge	.L455
	imull	%r13d, %ecx
	movq	%r10, %rdi
	movq	%r15, %rdx
	movslq	%ecx, %rsi
	addq	16(%rbp), %rsi
	movq	%r10, (%rsp)
	call	memmove
	movl	4(%r12,%rbx,4), %ecx
	movq	(%rsp), %r10
	cmpl	%r13d, %ecx
	leaq	(%r10,%r15), %r14
	jl	.L1024
.L856:
	movl	12(%rbp), %r8d
	cmpl	%r8d, %ecx
	jge	.L455
	imull	%r13d, %ecx
	movq	%r14, %rdi
	movq	%r15, %rdx
	addq	%r15, %r14
	movslq	%ecx, %rsi
	addq	16(%rbp), %rsi
	call	memmove
	movl	8(%r12,%rbx,4), %ecx
	cmpl	%r13d, %ecx
	jl	.L1025
.L858:
	movl	12(%rbp), %r8d
	cmpl	%r8d, %ecx
	jge	.L455
	imull	%r13d, %ecx
	movq	%r15, %rdx
	movq	%r14, %rdi
	movslq	%ecx, %rsi
	addq	16(%rbp), %rsi
	call	memmove
.L970:
	leaq	(%r14,%r15), %r10
	leaq	3(%rbx), %r14
	cmpl	%r14d, %r13d
	jle	.L1026
.L520:
	movl	(%r12,%r14,4), %ecx
	cmpl	%r13d, %ecx
	jge	.L453
	xorl	%esi, %esi
	movq	%r10, %rdi
	movq	%r15, %rdx
	movq	%r10, (%rsp)
	leaq	1(%r14), %rbx
	call	memset
	movq	(%rsp), %r10
	movb	$1, (%r10,%r14)
	movl	(%r12,%rbx,4), %ecx
	addq	%r15, %r10
	cmpl	%r13d, %ecx
	jge	.L854
.L1023:
	xorl	%esi, %esi
	movq	%r10, %rdi
	movq	%r15, %rdx
	movq	%r10, (%rsp)
	call	memset
	movq	(%rsp), %r10
	movb	$1, 1(%r10,%r14)
	movl	4(%r12,%rbx,4), %ecx
	leaq	(%r10,%r15), %r14
	cmpl	%r13d, %ecx
	jge	.L856
.L1024:
	xorl	%esi, %esi
	movq	%r14, %rdi
	movq	%r15, %rdx
	call	memset
	movb	$1, 1(%r14,%rbx)
	movl	8(%r12,%rbx,4), %ecx
	addq	%r15, %r14
	cmpl	%r13d, %ecx
	jge	.L858
.L1025:
	movq	%r15, %rdx
	xorl	%esi, %esi
	movq	%r14, %rdi
	call	memset
	movb	$1, 2(%r14,%rbx)
	jmp	.L970
.L1026:
	movl	24(%rsp), %ebx
	movq	48(%rsp), %r14
.L512:
	leal	0(,%r13,4), %ebp
	movslq	%ebp, %rbp
	movq	%rbp, %rdi
	call	malloc
	testq	%rax, %rax
	movq	%rax, 80(%rsp)
	je	.L1027
	movq	%rbp, %rdi
	call	malloc
	testq	%rax, %rax
	movq	%rax, 88(%rsp)
	je	.L1028
	movq	%rbp, %rdi
	call	malloc
	testq	%rax, %rax
	je	.L1029
	movslq	%r13d, %r10
	movq	%rax, 16(%rsp)
	movq	%r10, %rdi
	movq	%r10, (%rsp)
	call	malloc
	testq	%rax, %rax
	movq	%rax, 24(%rsp)
	movq	16(%rsp), %r9
	movq	(%rsp), %r10
	je	.L1016
	movq	%r10, %rdi
	movq	%r9, 16(%rsp)
	movq	%r10, (%rsp)
	call	malloc
	testq	%rax, %rax
	movq	%rax, 96(%rsp)
	movq	16(%rsp), %r9
	movq	(%rsp), %r10
	je	.L1016
	movq	24(%rsp), %rdi
	movq	%r10, %rdx
	xorl	%esi, %esi
	movq	%r9, 16(%rsp)
	movq	%r10, (%rsp)
	call	memset
	testl	%r13d, %r13d
	movq	16(%rsp), %r9
	movq	(%rsp), %r10
	jle	.L462
	movq	%r9, %rax
	andl	$15, %eax
	shrq	$2, %rax
	negq	%rax
	andl	$3, %eax
	cmpl	%eax, %r13d
	movl	%eax, %esi
	cmovbe	%r13d, %esi
	testl	%esi, %esi
	movl	%esi, %eax
	je	.L517
	leal	-1(%rsi), %edi
	movl	$0, (%r9)
	movl	$1, %edx
	leaq	4(%r9), %rcx
	andl	$7, %edi
	cmpl	$1, %esi
	jbe	.L938
	testl	%edi, %edi
	je	.L464
	cmpl	$1, %edi
	je	.L927
	cmpl	$2, %edi
	.p2align 4,,3
	je	.L928
	cmpl	$3, %edi
	.p2align 4,,2
	je	.L929
	cmpl	$4, %edi
	.p2align 4,,2
	je	.L930
	cmpl	$5, %edi
	.p2align 4,,2
	je	.L931
	cmpl	$6, %edi
	.p2align 4,,2
	je	.L932
	movl	$0, (%rcx)
	movl	$2, %edx
	addq	$4, %rcx
.L932:
	movl	$0, (%rcx)
	addl	$1, %edx
	addq	$4, %rcx
.L931:
	movl	$0, (%rcx)
	addl	$1, %edx
	addq	$4, %rcx
.L930:
	movl	$0, (%rcx)
	addl	$1, %edx
	addq	$4, %rcx
.L929:
	movl	$0, (%rcx)
	addl	$1, %edx
	addq	$4, %rcx
.L928:
	movl	$0, (%rcx)
	addl	$1, %edx
	addq	$4, %rcx
.L927:
	addl	$1, %edx
	movl	$0, (%rcx)
	addq	$4, %rcx
	cmpl	%edx, %esi
	jbe	.L938
.L464:
	addl	$8, %edx
	movl	$0, (%rcx)
	movl	$0, 4(%rcx)
	movl	$0, 8(%rcx)
	movl	$0, 12(%rcx)
	movl	$0, 16(%rcx)
	movl	$0, 20(%rcx)
	movl	$0, 24(%rcx)
	movl	$0, 28(%rcx)
	addq	$32, %rcx
	cmpl	%edx, %esi
	ja	.L464
.L938:
	cmpl	%esi, %r13d
	je	.L465
.L463:
	movl	%r13d, %ebp
	subl	%esi, %ebp
	movl	%ebp, %edi
	shrl	$2, %edi
	leal	0(,%rdi,4), %r8d
	testl	%r8d, %r8d
	je	.L466
	pxor	%xmm0, %xmm0
	leal	-1(%rdi), %esi
	leaq	(%r9,%rax,4), %r11
	movl	$1, %ecx
	andl	$7, %esi
	cmpl	%edi, %ecx
	movdqa	%xmm0, (%r11)
	leaq	16(%r11), %rax
	jae	.L939
	testl	%esi, %esi
	je	.L467
	cmpl	$1, %esi
	je	.L921
	cmpl	$2, %esi
	.p2align 4,,3
	je	.L922
	cmpl	$3, %esi
	.p2align 4,,2
	je	.L923
	cmpl	$4, %esi
	.p2align 4,,2
	je	.L924
	cmpl	$5, %esi
	.p2align 4,,2
	je	.L925
	cmpl	$6, %esi
	.p2align 4,,2
	je	.L926
	movdqa	%xmm0, (%rax)
	leaq	32(%r11), %rax
	movl	$2, %ecx
.L926:
	movdqa	%xmm0, (%rax)
	addl	$1, %ecx
	addq	$16, %rax
.L925:
	movdqa	%xmm0, (%rax)
	addl	$1, %ecx
	addq	$16, %rax
.L924:
	movdqa	%xmm0, (%rax)
	addl	$1, %ecx
	addq	$16, %rax
.L923:
	movdqa	%xmm0, (%rax)
	addl	$1, %ecx
	addq	$16, %rax
.L922:
	movdqa	%xmm0, (%rax)
	addl	$1, %ecx
	addq	$16, %rax
.L921:
	addl	$1, %ecx
	movdqa	%xmm0, (%rax)
	addq	$16, %rax
	cmpl	%edi, %ecx
	jae	.L939
.L467:
	addl	$8, %ecx
	movdqa	%xmm0, (%rax)
	movdqa	%xmm0, 16(%rax)
	movdqa	%xmm0, 32(%rax)
	movdqa	%xmm0, 48(%rax)
	movdqa	%xmm0, 64(%rax)
	movdqa	%xmm0, 80(%rax)
	movdqa	%xmm0, 96(%rax)
	movdqa	%xmm0, 112(%rax)
	subq	$-128, %rax
	cmpl	%edi, %ecx
	jb	.L467
.L939:
	addl	%r8d, %edx
	cmpl	%r8d, %ebp
	je	.L465
.L466:
	movl	%edx, %esi
	movslq	%edx, %r8
	leal	1(%rdx), %ecx
	notl	%esi
	leaq	(%r9,%r8,4), %rdi
	addl	%r13d, %esi
	andl	$7, %esi
	cmpl	%ecx, %r13d
	movl	$0, (%rdi)
	leaq	4(%rdi), %rax
	jle	.L465
	testl	%esi, %esi
	je	.L469
	cmpl	$1, %esi
	je	.L915
	cmpl	$2, %esi
	.p2align 4,,3
	je	.L916
	cmpl	$3, %esi
	.p2align 4,,2
	je	.L917
	cmpl	$4, %esi
	.p2align 4,,2
	je	.L918
	cmpl	$5, %esi
	.p2align 4,,2
	je	.L919
	cmpl	$6, %esi
	.p2align 4,,2
	je	.L920
	movl	$0, (%rax)
	leal	2(%rdx), %ecx
	leaq	8(%rdi), %rax
.L920:
	movl	$0, (%rax)
	addl	$1, %ecx
	addq	$4, %rax
.L919:
	movl	$0, (%rax)
	addl	$1, %ecx
	addq	$4, %rax
.L918:
	movl	$0, (%rax)
	addl	$1, %ecx
	addq	$4, %rax
.L917:
	movl	$0, (%rax)
	addl	$1, %ecx
	addq	$4, %rax
.L916:
	movl	$0, (%rax)
	addl	$1, %ecx
	addq	$4, %rax
.L915:
	addl	$1, %ecx
	movl	$0, (%rax)
	addq	$4, %rax
	cmpl	%ecx, %r13d
	jle	.L465
.L469:
	addl	$8, %ecx
	movl	$0, (%rax)
	movl	$0, 4(%rax)
	movl	$0, 8(%rax)
	movl	$0, 12(%rax)
	movl	$0, 16(%rax)
	movl	$0, 20(%rax)
	movl	$0, 24(%rax)
	movl	$0, 28(%rax)
	addq	$32, %rax
	cmpl	%ecx, %r13d
	jg	.L469
.L465:
	movq	32(%rsp), %r15
	movl	%r13d, %r11d
	leaq	1(%r10), %rdx
	shrl	$4, %r11d
	movq	%r14, 128(%rsp)
	movl	$0, 64(%rsp)
	movl	%r11d, 56(%rsp)
	sall	$4, %r11d
	movq	%rdx, 104(%rsp)
	movq	%r15, 48(%rsp)
	xorl	%r8d, %r8d
	movl	%r11d, 120(%rsp)
	movl	%ebx, 124(%rsp)
	movq	%r9, %r14
	movq	%r12, 136(%rsp)
.L493:
	movl	(%r14,%r8,4), %eax
	movl	%r8d, %esi
	cmpl	$1, %eax
	je	.L473
	movq	48(%rsp), %rbx
	cmpb	$0, (%rbx)
	je	.L473
	movslq	64(%rsp), %r12
	addl	$1, %eax
	movq	%r8, %rbx
	movl	%eax, (%r14,%r8,4)
	movl	%r8d, %ebp
.L482:
	addq	32(%rsp), %r12
	movq	88(%rsp), %rcx
	movl	%esi, (%rcx,%r8,4)
	movq	80(%rsp), %rsi
	leaq	(%r12,%rbx), %rcx
	movzbl	(%rcx), %eax
	movl	%ebp, (%rsi,%r8,4)
	testb	%al, %al
	je	.L1030
	cmpb	$1, %al
	je	.L488
	movzbl	%al, %edx
	movb	$1, (%rcx)
	movzbl	(%r12), %eax
	movzbl	inverse(%rdx), %edx
	leal	-1(%r13), %ecx
	andl	$7, %ecx
	salq	$8, %rdx
	cmpl	$1, %r13d
	movzbl	gf_mul_table(%rax,%rdx), %edi
	movl	$1, %eax
	movb	%dil, (%r12)
	jle	.L488
	testl	%ecx, %ecx
	je	.L489
	cmpl	$1, %ecx
	je	.L894
	cmpl	$2, %ecx
	.p2align 4,,3
	je	.L895
	cmpl	$3, %ecx
	.p2align 4,,2
	je	.L896
	cmpl	$4, %ecx
	.p2align 4,,2
	je	.L897
	cmpl	$5, %ecx
	.p2align 4,,2
	je	.L898
	cmpl	$6, %ecx
	.p2align 4,,2
	je	.L899
	movzbl	1(%r12), %edi
	movl	$2, %eax
	movzbl	gf_mul_table(%rdx,%rdi), %r15d
	movb	%r15b, 1(%r12)
.L899:
	movzbl	(%r12,%rax), %ecx
	movzbl	gf_mul_table(%rdx,%rcx), %esi
	movb	%sil, (%r12,%rax)
	addq	$1, %rax
.L898:
	movzbl	(%r12,%rax), %r9d
	movzbl	gf_mul_table(%rdx,%r9), %r11d
	movb	%r11b, (%r12,%rax)
	addq	$1, %rax
.L897:
	movzbl	(%r12,%rax), %edi
	movzbl	gf_mul_table(%rdx,%rdi), %r15d
	movb	%r15b, (%r12,%rax)
	addq	$1, %rax
.L896:
	movzbl	(%r12,%rax), %ecx
	movzbl	gf_mul_table(%rdx,%rcx), %esi
	movb	%sil, (%r12,%rax)
	addq	$1, %rax
.L895:
	movzbl	(%r12,%rax), %r9d
	movzbl	gf_mul_table(%rdx,%r9), %r11d
	movb	%r11b, (%r12,%rax)
	addq	$1, %rax
.L894:
	movzbl	(%r12,%rax), %edi
	movzbl	gf_mul_table(%rdx,%rdi), %r15d
	movb	%r15b, (%r12,%rax)
	addq	$1, %rax
	cmpl	%eax, %r13d
	jle	.L488
.L489:
	movzbl	(%r12,%rax), %esi
	movzbl	1(%r12,%rax), %r15d
	movzbl	2(%r12,%rax), %edi
	movzbl	gf_mul_table(%rdx,%rsi), %r9d
	movzbl	gf_mul_table(%rdx,%r15), %r11d
	movzbl	3(%r12,%rax), %esi
	movzbl	4(%r12,%rax), %r15d
	movzbl	gf_mul_table(%rdx,%rdi), %ecx
	movzbl	5(%r12,%rax), %edi
	movb	%r9b, (%r12,%rax)
	movb	%r11b, 1(%r12,%rax)
	movzbl	gf_mul_table(%rdx,%rsi), %r9d
	movzbl	gf_mul_table(%rdx,%r15), %r11d
	movzbl	6(%r12,%rax), %esi
	movzbl	7(%r12,%rax), %r15d
	movb	%cl, 2(%r12,%rax)
	movzbl	gf_mul_table(%rdx,%rdi), %ecx
	movb	%r9b, 3(%r12,%rax)
	movb	%r11b, 4(%r12,%rax)
	movzbl	gf_mul_table(%rdx,%rsi), %r9d
	movzbl	gf_mul_table(%rdx,%r15), %r11d
	movb	%cl, 5(%r12,%rax)
	movb	%r9b, 6(%r12,%rax)
	movb	%r11b, 7(%r12,%rax)
	addq	$8, %rax
	cmpl	%eax, %r13d
	jg	.L489
	.p2align 4,,10
	.p2align 3
.L488:
	movq	24(%rsp), %rax
	movq	24(%rsp), %rsi
	movq	%r10, %rdx
	movq	%r12, %rdi
	addq	%rbx, %rax
	movb	$1, (%rax)
	movq	%rax, 72(%rsp)
	movq	%r8, 8(%rsp)
	movq	%r10, (%rsp)
	call	bcmp
	testl	%eax, %eax
	movq	8(%rsp), %r8
	movq	(%rsp), %r10
	je	.L490
	leal	-1(%r13), %r9d
	andl	$7, %r9d
	testl	%ebp, %ebp
	je	.L634
	movq	32(%rsp), %rax
	movzbl	(%rax,%rbx), %edx
	movb	$0, (%rax,%rbx)
	testb	%dl, %dl
	jne	.L1031
.L634:
	movq	32(%rsp), %r15
	movl	$1, %eax
	addq	%r10, %r15
	cmpl	%r13d, %eax
	je	.L490
	testl	%r9d, %r9d
	je	.L979
	cmpl	$1, %r9d
	je	.L888
	cmpl	$2, %r9d
	je	.L889
	cmpl	$3, %r9d
	je	.L890
	cmpl	$4, %r9d
	je	.L891
	cmpl	$5, %r9d
	je	.L892
	cmpl	$6, %r9d
	je	.L893
	cmpl	$1, %ebp
	je	.L636
	movzbl	(%r15,%rbx), %edx
	movb	$0, (%r15,%rbx)
	testb	%dl, %dl
	jne	.L1032
.L636:
	addl	$1, %eax
	addq	%r10, %r15
.L893:
	cmpl	%eax, %ebp
	je	.L639
	movzbl	(%r15,%rbx), %edx
	movb	$0, (%r15,%rbx)
	testb	%dl, %dl
	jne	.L1033
.L639:
	addl	$1, %eax
	addq	%r10, %r15
.L892:
	cmpl	%eax, %ebp
	je	.L642
	movzbl	(%r15,%rbx), %edx
	movb	$0, (%r15,%rbx)
	testb	%dl, %dl
	jne	.L1034
.L642:
	addl	$1, %eax
	addq	%r10, %r15
.L891:
	cmpl	%eax, %ebp
	je	.L645
	movzbl	(%r15,%rbx), %edx
	movb	$0, (%r15,%rbx)
	testb	%dl, %dl
	jne	.L1035
.L645:
	addl	$1, %eax
	addq	%r10, %r15
.L890:
	cmpl	%eax, %ebp
	je	.L648
	movzbl	(%r15,%rbx), %edx
	movb	$0, (%r15,%rbx)
	testb	%dl, %dl
	jne	.L1036
.L648:
	addl	$1, %eax
	addq	%r10, %r15
.L889:
	cmpl	%eax, %ebp
	je	.L651
	movzbl	(%r15,%rbx), %edx
	movb	$0, (%r15,%rbx)
	testb	%dl, %dl
	jne	.L1037
.L651:
	addl	$1, %eax
	addq	%r10, %r15
.L888:
	cmpl	%eax, %ebp
	je	.L654
	movzbl	(%r15,%rbx), %edx
	movb	$0, (%r15,%rbx)
	testb	%dl, %dl
	jne	.L1038
.L654:
	addl	$1, %eax
	addq	%r10, %r15
	cmpl	%r13d, %eax
	je	.L490
.L979:
	movq	%r14, 152(%rsp)
	movq	%r8, 144(%rsp)
	movq	%r10, %r14
	movq	%r12, 112(%rsp)
	jmp	.L492
	.p2align 4,,10
	.p2align 3
.L491:
	leal	1(%rax), %r12d
	addq	%r14, %r15
	cmpl	%r12d, %ebp
	je	.L657
	movzbl	(%r15,%rbx), %edx
	movb	$0, (%r15,%rbx)
	testb	%dl, %dl
	jne	.L1039
.L657:
	leal	1(%r12), %esi
	addq	%r14, %r15
	cmpl	%esi, %ebp
	je	.L659
	movzbl	(%r15,%rbx), %edx
	movb	$0, (%r15,%rbx)
	testb	%dl, %dl
	jne	.L1040
.L659:
	leal	2(%r12), %eax
	addq	%r14, %r15
	cmpl	%eax, %ebp
	je	.L661
	movzbl	(%r15,%rbx), %edx
	movb	$0, (%r15,%rbx)
	testb	%dl, %dl
	jne	.L1041
.L661:
	leal	3(%r12), %edx
	addq	%r14, %r15
	cmpl	%edx, %ebp
	je	.L663
	movzbl	(%r15,%rbx), %edx
	movb	$0, (%r15,%rbx)
	testb	%dl, %dl
	jne	.L1042
.L663:
	leal	4(%r12), %ecx
	addq	%r14, %r15
	cmpl	%ecx, %ebp
	je	.L665
	movzbl	(%r15,%rbx), %edx
	movb	$0, (%r15,%rbx)
	testb	%dl, %dl
	jne	.L1043
.L665:
	leal	5(%r12), %r11d
	addq	%r14, %r15
	cmpl	%r11d, %ebp
	je	.L667
	movzbl	(%r15,%rbx), %edx
	movb	$0, (%r15,%rbx)
	testb	%dl, %dl
	jne	.L1044
.L667:
	leal	6(%r12), %r9d
	addq	%r14, %r15
	cmpl	%r9d, %ebp
	je	.L669
	movzbl	(%r15,%rbx), %edx
	movb	$0, (%r15,%rbx)
	testb	%dl, %dl
	jne	.L1045
.L669:
	leal	7(%r12), %eax
	addq	%r14, %r15
	cmpl	%r13d, %eax
	je	.L1046
.L492:
	cmpl	%eax, %ebp
	je	.L491
	movzbl	(%r15,%rbx), %edx
	movb	$0, (%r15,%rbx)
	testb	%dl, %dl
	je	.L491
	movq	112(%rsp), %rsi
	movzbl	%dl, %edx
	movl	%r13d, %ecx
	movq	%r15, %rdi
	movl	%eax, 16(%rsp)
	call	addmul1
	movl	16(%rsp), %eax
	jmp	.L491
.L1046:
	movq	%r14, %r10
	movq	144(%rsp), %r8
	movq	152(%rsp), %r14
	.p2align 4,,10
	.p2align 3
.L490:
	movq	72(%rsp), %rbx
	addq	$1, %r8
	addl	%r13d, 64(%rsp)
	movq	104(%rsp), %rbp
	addq	%rbp, 48(%rsp)
	cmpl	%r8d, %r13d
	movb	$0, (%rbx)
	jg	.L493
	movq	%r14, %r9
	movl	124(%rsp), %ebx
	movq	128(%rsp), %r14
	movq	136(%rsp), %r12
.L462:
	movl	%r13d, %eax
	subl	$1, %eax
	js	.L494
	movq	88(%rsp), %r15
	movl	%eax, %edx
	cltq
	salq	$2, %rax
	negq	%rdx
	movl	%ebx, 64(%rsp)
	leaq	-4(,%rdx,4), %r8
	xorl	%ebp, %ebp
	movq	%r9, 72(%rsp)
	addq	%rax, %r15
	addq	80(%rsp), %rax
	movq	%r10, %rbx
	movq	%r8, 48(%rsp)
	movq	%rax, 56(%rsp)
.L501:
	movl	(%r15,%rbp), %ecx
	testl	%ecx, %ecx
	js	.L495
	cmpl	%ecx, %r13d
	jle	.L495
	movq	56(%rsp), %r10
	movl	(%r10,%rbp), %edx
	testl	%edx, %edx
	js	.L498
	cmpl	%edx, %r13d
	jle	.L498
	cmpl	%edx, %ecx
	je	.L497
	movq	32(%rsp), %rax
	movslq	%ecx, %rsi
	movslq	%edx, %rdx
	leal	-1(%r13), %edi
	addq	%rsi, %rax
	andl	$7, %edi
	movq	%rax, %rcx
	movzbl	(%rax), %r11d
	subq	%rsi, %rcx
	movzbl	(%rcx,%rdx), %r9d
	movb	%r9b, (%rax)
	movb	%r11b, (%rcx,%rdx)
	movl	$1, %ecx
	addq	%rbx, %rax
	cmpl	%r13d, %ecx
	je	.L497
	testl	%edi, %edi
	je	.L500
	cmpl	$1, %edi
	je	.L881
	cmpl	$2, %edi
	.p2align 4,,3
	je	.L882
	cmpl	$3, %edi
	.p2align 4,,2
	je	.L883
	cmpl	$4, %edi
	.p2align 4,,2
	je	.L884
	cmpl	$5, %edi
	.p2align 4,,2
	je	.L885
	cmpl	$6, %edi
	.p2align 4,,2
	je	.L886
	movq	%rax, %r10
	movzbl	(%rax), %edi
	movl	$2, %ecx
	subq	%rsi, %r10
	movzbl	(%r10,%rdx), %r8d
	movb	%r8b, (%rax)
	movb	%dil, (%r10,%rdx)
	addq	%rbx, %rax
.L886:
	movq	%rax, %r11
	movzbl	(%rax), %r10d
	addl	$1, %ecx
	subq	%rsi, %r11
	movzbl	(%r11,%rdx), %r9d
	movb	%r9b, (%rax)
	movb	%r10b, (%r11,%rdx)
	addq	%rbx, %rax
.L885:
	movq	%rax, %rdi
	movzbl	(%rax), %r8d
	addl	$1, %ecx
	subq	%rsi, %rdi
	movzbl	(%rdi,%rdx), %r11d
	movb	%r11b, (%rax)
	movb	%r8b, (%rdi,%rdx)
	addq	%rbx, %rax
.L884:
	movq	%rax, %r10
	movzbl	(%rax), %edi
	addl	$1, %ecx
	subq	%rsi, %r10
	movzbl	(%r10,%rdx), %r9d
	movb	%r9b, (%rax)
	movb	%dil, (%r10,%rdx)
	addq	%rbx, %rax
.L883:
	movq	%rax, %r11
	movzbl	(%rax), %r8d
	addl	$1, %ecx
	subq	%rsi, %r11
	movzbl	(%r11,%rdx), %r10d
	movb	%r10b, (%rax)
	movb	%r8b, (%r11,%rdx)
	addq	%rbx, %rax
.L882:
	movq	%rax, %rdi
	movzbl	(%rax), %r11d
	addl	$1, %ecx
	subq	%rsi, %rdi
	movzbl	(%rdi,%rdx), %r9d
	movb	%r9b, (%rax)
	movb	%r11b, (%rdi,%rdx)
	addq	%rbx, %rax
.L881:
	movq	%rax, %r10
	movzbl	(%rax), %r8d
	addl	$1, %ecx
	subq	%rsi, %r10
	movzbl	(%r10,%rdx), %edi
	movb	%dil, (%rax)
	addq	%rbx, %rax
	cmpl	%r13d, %ecx
	movb	%r8b, (%r10,%rdx)
	je	.L497
.L500:
	movq	%rax, %r11
	movzbl	(%rax), %edi
	addl	$8, %ecx
	subq	%rsi, %r11
	movzbl	(%r11,%rdx), %r9d
	movb	%r9b, (%rax)
	addq	%rbx, %rax
	movb	%dil, (%r11,%rdx)
	movq	%rax, %rdi
	movzbl	(%rax), %r8d
	subq	%rsi, %rdi
	movzbl	(%rdi,%rdx), %r10d
	movb	%r10b, (%rax)
	addq	%rbx, %rax
	movb	%r8b, (%rdi,%rdx)
	movq	%rax, %r10
	movzbl	(%rax), %r11d
	subq	%rsi, %r10
	movzbl	(%r10,%rdx), %r9d
	movb	%r9b, (%rax)
	addq	%rbx, %rax
	movb	%r11b, (%r10,%rdx)
	movq	%rax, %r11
	movzbl	(%rax), %r8d
	subq	%rsi, %r11
	movzbl	(%r11,%rdx), %edi
	movb	%dil, (%rax)
	addq	%rbx, %rax
	movb	%r8b, (%r11,%rdx)
	movq	%rax, %rdi
	movzbl	(%rax), %r10d
	subq	%rsi, %rdi
	movzbl	(%rdi,%rdx), %r9d
	movb	%r9b, (%rax)
	addq	%rbx, %rax
	movb	%r10b, (%rdi,%rdx)
	movq	%rax, %r10
	movzbl	(%rax), %r8d
	subq	%rsi, %r10
	movzbl	(%r10,%rdx), %r11d
	movb	%r11b, (%rax)
	addq	%rbx, %rax
	movb	%r8b, (%r10,%rdx)
	movq	%rax, %r11
	movzbl	(%rax), %edi
	subq	%rsi, %r11
	movzbl	(%r11,%rdx), %r9d
	movb	%r9b, (%rax)
	addq	%rbx, %rax
	movb	%dil, (%r11,%rdx)
	movq	%rax, %rdi
	movzbl	(%rax), %r8d
	subq	%rsi, %rdi
	movzbl	(%rdi,%rdx), %r10d
	movb	%r10b, (%rax)
	addq	%rbx, %rax
	cmpl	%r13d, %ecx
	movb	%r8b, (%rdi,%rdx)
	jne	.L500
.L497:
	subq	$4, %rbp
	cmpq	48(%rsp), %rbp
	jne	.L501
	movl	64(%rsp), %ebx
	movq	72(%rsp), %r9
.L494:
	movq	80(%rsp), %rdi
	movq	%r9, 16(%rsp)
	leal	0(,%rbx,8), %ebp
	call	free
	movq	88(%rsp), %rdi
	call	free
	movq	16(%rsp), %r8
	movq	%r8, %rdi
	call	free
	movq	24(%rsp), %rdi
	call	free
	movq	96(%rsp), %rdi
	call	free
	movslq	%ebp, %rdi
	call	malloc
	testq	%rax, %rax
	movq	%rax, 64(%rsp)
	je	.L1047
	testl	%ebx, %ebx
	jle	.L503
	movslq	44(%rsp), %r15
	movslq	%ebx, %r13
	movq	32(%rsp), %rbp
	movq	%r13, 48(%rsp)
	movq	%r12, 24(%rsp)
	xorl	%r13d, %r13d
	movq	%r15, 56(%rsp)
	jmp	.L508
	.p2align 4,,10
	.p2align 3
.L504:
	addq	$1, %r13
	addq	48(%rsp), %rbp
	cmpl	%r13d, %ebx
	jle	.L1048
.L508:
	movq	24(%rsp), %r12
	cmpl	(%r12,%r13,4), %ebx
	jg	.L504
	movq	56(%rsp), %rdi
	call	malloc
	testq	%rax, %rax
	movq	%rax, %r12
	je	.L1049
	movq	64(%rsp), %rsi
	movq	56(%rsp), %rdx
	movq	%rax, %rdi
	movq	%rax, (%rsi,%r13,8)
	xorl	%esi, %esi
	call	memset
	movzbl	0(%rbp), %edx
	leal	-1(%rbx), %eax
	andl	$7, %eax
	testb	%dl, %dl
	jne	.L1050
.L575:
	cmpl	$1, %ebx
	movl	$1, %r15d
	jle	.L504
	testl	%eax, %eax
	je	.L975
	cmpl	$1, %eax
	je	.L875
	cmpl	$2, %eax
	.p2align 4,,3
	je	.L876
	cmpl	$3, %eax
	.p2align 4,,2
	je	.L877
	cmpl	$4, %eax
	.p2align 4,,2
	je	.L878
	cmpl	$5, %eax
	.p2align 4,,2
	je	.L879
	cmpl	$6, %eax
	.p2align 4,,2
	je	.L880
	movzbl	1(%rbp), %edx
	testb	%dl, %dl
	jne	.L1051
.L577:
	addq	$1, %r15
.L880:
	movzbl	0(%rbp,%r15), %edx
	testb	%dl, %dl
	jne	.L1052
.L580:
	addq	$1, %r15
.L879:
	movzbl	0(%rbp,%r15), %edx
	testb	%dl, %dl
	jne	.L1053
.L583:
	addq	$1, %r15
.L878:
	movzbl	0(%rbp,%r15), %edx
	testb	%dl, %dl
	jne	.L1054
.L586:
	addq	$1, %r15
.L877:
	movzbl	0(%rbp,%r15), %edx
	testb	%dl, %dl
	jne	.L1055
.L589:
	addq	$1, %r15
.L876:
	movzbl	0(%rbp,%r15), %edx
	testb	%dl, %dl
	jne	.L1056
.L592:
	addq	$1, %r15
.L875:
	movzbl	0(%rbp,%r15), %edx
	testb	%dl, %dl
	jne	.L1057
.L595:
	addq	$1, %r15
	cmpl	%r15d, %ebx
	jle	.L504
.L975:
	movq	%r13, 72(%rsp)
	movl	%ebx, %r13d
	movq	%r12, %rbx
	jmp	.L507
	.p2align 4,,10
	.p2align 3
.L506:
	movzbl	1(%rbp,%r15), %edx
	leaq	1(%r15), %r12
	testb	%dl, %dl
	jne	.L1058
.L598:
	movzbl	1(%rbp,%r12), %edx
	leaq	1(%r12), %rax
	testb	%dl, %dl
	jne	.L1059
.L600:
	movzbl	2(%rbp,%r12), %edx
	leaq	2(%r12), %rax
	testb	%dl, %dl
	jne	.L1060
.L602:
	movzbl	3(%rbp,%r12), %edx
	leaq	3(%r12), %rax
	testb	%dl, %dl
	jne	.L1061
.L604:
	movzbl	4(%rbp,%r12), %edx
	leaq	4(%r12), %rax
	testb	%dl, %dl
	jne	.L1062
.L606:
	movzbl	5(%rbp,%r12), %edx
	leaq	5(%r12), %rax
	testb	%dl, %dl
	jne	.L1063
.L608:
	movzbl	6(%rbp,%r12), %edx
	leaq	6(%r12), %rax
	testb	%dl, %dl
	jne	.L1064
.L610:
	leaq	7(%r12), %r15
	cmpl	%r15d, %r13d
	jle	.L1065
.L507:
	movzbl	0(%rbp,%r15), %edx
	testb	%dl, %dl
	je	.L506
	movq	(%r14,%r15,8), %rsi
	movl	44(%rsp), %ecx
	movzbl	%dl, %edx
	movq	%rbx, %rdi
	leaq	1(%r15), %r12
	call	addmul1
	movzbl	1(%rbp,%r15), %edx
	testb	%dl, %dl
	je	.L598
.L1058:
	movq	(%r14,%r12,8), %rsi
	movl	44(%rsp), %ecx
	movzbl	%dl, %edx
	movq	%rbx, %rdi
	call	addmul1
	movzbl	1(%rbp,%r12), %edx
	leaq	1(%r12), %rax
	testb	%dl, %dl
	je	.L600
.L1059:
	movq	(%r14,%rax,8), %rsi
	movl	44(%rsp), %ecx
	movzbl	%dl, %edx
	movq	%rbx, %rdi
	call	addmul1
	movzbl	2(%rbp,%r12), %edx
	leaq	2(%r12), %rax
	testb	%dl, %dl
	je	.L602
.L1060:
	movq	(%r14,%rax,8), %rsi
	movl	44(%rsp), %ecx
	movzbl	%dl, %edx
	movq	%rbx, %rdi
	call	addmul1
	movzbl	3(%rbp,%r12), %edx
	leaq	3(%r12), %rax
	testb	%dl, %dl
	je	.L604
.L1061:
	movq	(%r14,%rax,8), %rsi
	movl	44(%rsp), %ecx
	movzbl	%dl, %edx
	movq	%rbx, %rdi
	call	addmul1
	movzbl	4(%rbp,%r12), %edx
	leaq	4(%r12), %rax
	testb	%dl, %dl
	je	.L606
.L1062:
	movq	(%r14,%rax,8), %rsi
	movl	44(%rsp), %ecx
	movzbl	%dl, %edx
	movq	%rbx, %rdi
	call	addmul1
	movzbl	5(%rbp,%r12), %edx
	leaq	5(%r12), %rax
	testb	%dl, %dl
	je	.L608
.L1063:
	movq	(%r14,%rax,8), %rsi
	movl	44(%rsp), %ecx
	movzbl	%dl, %edx
	movq	%rbx, %rdi
	call	addmul1
	movzbl	6(%rbp,%r12), %edx
	leaq	6(%r12), %rax
	testb	%dl, %dl
	je	.L610
.L1064:
	movq	(%r14,%rax,8), %rsi
	movl	44(%rsp), %ecx
	movzbl	%dl, %edx
	movq	%rbx, %rdi
	call	addmul1
	jmp	.L610
	.p2align 4,,10
	.p2align 3
.L473:
	movq	32(%rsp), %rdi
	xorl	%r15d, %r15d
	xorl	%r9d, %r9d
.L471:
	cmpl	$1, (%r14,%r9,4)
	movl	%r9d, %esi
	je	.L474
	movl	(%r14), %ecx
	leal	-1(%r13), %edx
	xorl	%ebx, %ebx
	xorl	%ebp, %ebp
	movq	%r14, %rax
	andl	$7, %edx
	testl	%ecx, %ecx
	jne	.L725
	cmpb	$0, (%rdi)
	jne	.L476
.L726:
	cmpl	$1, %r13d
	movl	$1, %ebx
	leaq	4(%r14), %rax
	jle	.L474
	testl	%edx, %edx
	je	.L479
	cmpl	$1, %edx
	je	.L909
	cmpl	$2, %edx
	.p2align 4,,3
	je	.L910
	cmpl	$3, %edx
	.p2align 4,,2
	je	.L911
	cmpl	$4, %edx
	.p2align 4,,2
	je	.L912
	cmpl	$5, %edx
	.p2align 4,,2
	je	.L913
	cmpl	$6, %edx
	.p2align 4,,2
	je	.L914
	movl	4(%r14), %edx
	movl	$1, %ebp
	testl	%edx, %edx
	je	.L951
	cmpl	$1, %edx
	jg	.L1014
.L729:
	addq	$1, %rbx
	addq	$4, %rax
.L914:
	movl	(%rax), %edx
	movl	%ebx, %ebp
	testl	%edx, %edx
	je	.L952
	cmpl	$1, %edx
	jg	.L1014
.L733:
	addq	$1, %rbx
	addq	$4, %rax
.L913:
	movl	(%rax), %edx
	movl	%ebx, %ebp
	testl	%edx, %edx
	je	.L953
	cmpl	$1, %edx
	jg	.L1014
.L737:
	addq	$1, %rbx
	addq	$4, %rax
.L912:
	movl	(%rax), %edx
	movl	%ebx, %ebp
	testl	%edx, %edx
	je	.L954
	cmpl	$1, %edx
	jg	.L1014
.L741:
	addq	$1, %rbx
	addq	$4, %rax
.L911:
	movl	(%rax), %edx
	movl	%ebx, %ebp
	testl	%edx, %edx
	je	.L955
	cmpl	$1, %edx
	jg	.L1014
.L745:
	addq	$1, %rbx
	addq	$4, %rax
.L910:
	movl	(%rax), %edx
	movl	%ebx, %ebp
	testl	%edx, %edx
	je	.L956
	cmpl	$1, %edx
	jg	.L1014
.L749:
	addq	$1, %rbx
	addq	$4, %rax
.L909:
	movl	(%rax), %edx
	movl	%ebx, %ebp
	testl	%edx, %edx
	je	.L957
	cmpl	$1, %edx
	jg	.L1014
.L753:
	addq	$1, %rbx
	addq	$4, %rax
	cmpl	%ebx, %r13d
	jle	.L474
.L479:
	movl	(%rax), %edx
	movl	%ebx, %ebp
	testl	%edx, %edx
	jne	.L475
	cmpb	$0, (%rdi,%rbx)
	jne	.L476
.L477:
	leaq	4(%rax), %rdx
	leaq	1(%rbx), %rcx
	movl	(%rdx), %r11d
	movq	%rcx, %rbx
	movq	%rdx, %rax
	movl	%ecx, %ebp
	testl	%r11d, %r11d
	jne	.L756
	cmpb	$0, (%rdi,%rcx)
	jne	.L476
.L757:
	movl	4(%rdx), %r11d
	leaq	1(%rcx), %rbx
	leaq	4(%rdx), %rax
	movl	%ebx, %ebp
	testl	%r11d, %r11d
	je	.L958
	cmpl	$1, %r11d
	jg	.L1014
.L760:
	movl	8(%rdx), %r11d
	leaq	2(%rcx), %rbx
	leaq	8(%rdx), %rax
	movl	%ebx, %ebp
	testl	%r11d, %r11d
	je	.L959
	cmpl	$1, %r11d
	jg	.L1014
.L763:
	movl	12(%rdx), %r11d
	leaq	3(%rcx), %rbx
	leaq	12(%rdx), %rax
	movl	%ebx, %ebp
	testl	%r11d, %r11d
	je	.L960
	cmpl	$1, %r11d
	jg	.L1014
.L766:
	movl	16(%rdx), %r11d
	leaq	4(%rcx), %rbx
	leaq	16(%rdx), %rax
	movl	%ebx, %ebp
	testl	%r11d, %r11d
	je	.L961
	cmpl	$1, %r11d
	jg	.L1014
.L769:
	movl	20(%rdx), %r11d
	leaq	5(%rcx), %rbx
	leaq	20(%rdx), %rax
	movl	%ebx, %ebp
	testl	%r11d, %r11d
	je	.L962
	cmpl	$1, %r11d
	jg	.L1014
.L772:
	movl	24(%rdx), %r11d
	leaq	6(%rcx), %rbx
	leaq	24(%rdx), %rax
	movl	%ebx, %ebp
	testl	%r11d, %r11d
	je	.L963
	cmpl	$1, %r11d
	jg	.L1014
.L775:
	leaq	7(%rcx), %rbx
	leaq	28(%rdx), %rax
	cmpl	%ebx, %r13d
	jg	.L479
	.p2align 4,,10
	.p2align 3
.L474:
	addq	$1, %r9
	addl	%r13d, %r15d
	addq	%r10, %rdi
	cmpl	%r9d, %r13d
	jg	.L471
	movq	stderr(%rip), %rcx
	movl	$21, %edx
	movl	$1, %esi
	movl	$.LC11, %edi
	movq	%r14, 16(%rsp)
	call	fwrite
	movq	16(%rsp), %r9
	jmp	.L478
	.p2align 4,,10
	.p2align 3
.L475:
	cmpl	$1, %edx
	jle	.L477
	.p2align 4,,10
	.p2align 3
.L1014:
	movq	stderr(%rip), %rcx
	movl	$16, %edx
	movl	$1, %esi
	movl	$.LC10, %edi
	movq	%r14, 16(%rsp)
	call	fwrite
	movq	16(%rsp), %r9
.L478:
	movq	80(%rsp), %rdi
	movq	%r9, 16(%rsp)
	call	free
	movq	88(%rsp), %rdi
	call	free
	movq	16(%rsp), %r14
	movq	%r14, %rdi
	call	free
	movq	24(%rsp), %rdi
	call	free
	movq	96(%rsp), %rdi
	call	free
	movq	32(%rsp), %rdi
	call	free
	movl	$1, %eax
	.p2align 4,,10
	.p2align 3
.L451:
	addq	$168, %rsp
	.cfi_remember_state
	.cfi_def_cfa_offset 56
	popq	%rbx
	.cfi_def_cfa_offset 48
	popq	%rbp
	.cfi_def_cfa_offset 40
	popq	%r12
	.cfi_def_cfa_offset 32
	popq	%r13
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	ret
	.p2align 4,,10
	.p2align 3
.L756:
	.cfi_restore_state
	cmpl	$1, %r11d
	jle	.L757
	jmp	.L1014
	.p2align 4,,10
	.p2align 3
.L958:
	cmpb	$0, 1(%rdi,%rcx)
	je	.L760
	.p2align 4,,10
	.p2align 3
.L476:
.L480:
	movl	%r13d, %r12d
	movl	$1, (%rax)
	imull	%ebp, %r12d
	cmpl	%esi, %ebp
	je	.L1066
	movq	32(%rsp), %rcx
	movq	32(%rsp), %rdx
	movslq	%r15d, %r15
	movl	120(%rsp), %edi
	movslq	%r12d, %r12
	addq	%r15, %rcx
	addq	%r12, %rdx
	testl	%edi, %edi
	je	.L518
	leaq	16(%rdx), %rax
	leaq	16(%rcx), %rdi
	cmpq	%rax, %rcx
	seta	%al
	cmpq	%rdi, %rdx
	seta	%r9b
	orl	%r9d, %eax
	cmpl	$15, %r13d
	seta	%r11b
	testb	%r11b, %al
	je	.L518
	movl	56(%rsp), %r9d
	movl	$1, %edi
	movl	$16, %eax
	movdqu	(%rcx), %xmm0
	subl	$1, %r9d
	movdqu	(%rdx), %xmm1
	andl	$7, %r9d
	cmpl	$1, 56(%rsp)
	movdqu	%xmm1, (%rcx)
	movdqu	%xmm0, (%rdx)
	jbe	.L942
	testl	%r9d, %r9d
	je	.L484
	cmpl	$1, %r9d
	je	.L902
	cmpl	$2, %r9d
	je	.L903
	cmpl	$3, %r9d
	je	.L904
	cmpl	$4, %r9d
	je	.L905
	cmpl	$5, %r9d
	je	.L906
	cmpl	$6, %r9d
	je	.L907
	movdqu	16(%rcx), %xmm2
	movl	$2, %edi
	movl	$32, %eax
	movdqu	16(%rdx), %xmm3
	movdqu	%xmm3, 16(%rcx)
	movdqu	%xmm2, 16(%rdx)
.L907:
	movdqu	(%rcx,%rax), %xmm4
	addl	$1, %edi
	movdqu	(%rdx,%rax), %xmm5
	movdqu	%xmm5, (%rcx,%rax)
	movdqu	%xmm4, (%rdx,%rax)
	addq	$16, %rax
.L906:
	movdqu	(%rcx,%rax), %xmm6
	addl	$1, %edi
	movdqu	(%rdx,%rax), %xmm7
	movdqu	%xmm7, (%rcx,%rax)
	movdqu	%xmm6, (%rdx,%rax)
	addq	$16, %rax
.L905:
	movdqu	(%rcx,%rax), %xmm8
	addl	$1, %edi
	movdqu	(%rdx,%rax), %xmm9
	movdqu	%xmm9, (%rcx,%rax)
	movdqu	%xmm8, (%rdx,%rax)
	addq	$16, %rax
.L904:
	movdqu	(%rcx,%rax), %xmm10
	addl	$1, %edi
	movdqu	(%rdx,%rax), %xmm11
	movdqu	%xmm11, (%rcx,%rax)
	movdqu	%xmm10, (%rdx,%rax)
	addq	$16, %rax
.L903:
	movdqu	(%rcx,%rax), %xmm12
	addl	$1, %edi
	movdqu	(%rdx,%rax), %xmm13
	movdqu	%xmm13, (%rcx,%rax)
	movdqu	%xmm12, (%rdx,%rax)
	addq	$16, %rax
.L902:
	movdqu	(%rcx,%rax), %xmm14
	addl	$1, %edi
	movdqu	(%rdx,%rax), %xmm15
	movdqu	%xmm15, (%rcx,%rax)
	movdqu	%xmm14, (%rdx,%rax)
	addq	$16, %rax
	cmpl	%edi, 56(%rsp)
	jbe	.L942
.L484:
	movdqu	(%rcx,%rax), %xmm0
	addl	$8, %edi
	movdqu	(%rdx,%rax), %xmm1
	movdqu	%xmm1, (%rcx,%rax)
	movdqu	%xmm0, (%rdx,%rax)
	movdqu	16(%rdx,%rax), %xmm15
	movdqu	16(%rcx,%rax), %xmm14
	movdqu	%xmm15, 16(%rcx,%rax)
	movdqu	%xmm14, 16(%rdx,%rax)
	movdqu	32(%rdx,%rax), %xmm13
	movdqu	32(%rcx,%rax), %xmm12
	movdqu	%xmm13, 32(%rcx,%rax)
	movdqu	%xmm12, 32(%rdx,%rax)
	movdqu	48(%rdx,%rax), %xmm11
	movdqu	48(%rcx,%rax), %xmm10
	movdqu	%xmm11, 48(%rcx,%rax)
	movdqu	%xmm10, 48(%rdx,%rax)
	movdqu	64(%rdx,%rax), %xmm9
	movdqu	64(%rcx,%rax), %xmm8
	movdqu	%xmm9, 64(%rcx,%rax)
	movdqu	%xmm8, 64(%rdx,%rax)
	movdqu	80(%rdx,%rax), %xmm7
	movdqu	80(%rcx,%rax), %xmm6
	movdqu	%xmm7, 80(%rcx,%rax)
	movdqu	%xmm6, 80(%rdx,%rax)
	movdqu	96(%rdx,%rax), %xmm5
	movdqu	96(%rcx,%rax), %xmm4
	movdqu	%xmm5, 96(%rcx,%rax)
	movdqu	%xmm4, 96(%rdx,%rax)
	movdqu	112(%rdx,%rax), %xmm3
	movdqu	112(%rcx,%rax), %xmm2
	movdqu	%xmm3, 112(%rcx,%rax)
	movdqu	%xmm2, 112(%rdx,%rax)
	subq	$-128, %rax
	cmpl	%edi, 56(%rsp)
	ja	.L484
.L942:
	movl	120(%rsp), %edi
	cmpl	%r13d, %edi
	je	.L482
.L483:
	movslq	%edi, %rdx
	movq	32(%rsp), %rcx
	movl	%edi, %r9d
	addq	%rdx, %r15
	addq	%r12, %rdx
	addq	32(%rsp), %rdx
	notl	%r9d
	addq	%r15, %rcx
	leal	1(%rdi), %r15d
	addl	%r13d, %r9d
	movzbl	(%rcx), %eax
	andl	$3, %r9d
	movzbl	(%rdx), %r11d
	cmpl	%r15d, %r13d
	movb	%r11b, (%rcx)
	movb	%al, (%rdx)
	movl	$1, %eax
	jle	.L482
	testl	%r9d, %r9d
	je	.L486
	cmpl	$1, %r9d
	je	.L900
	cmpl	$2, %r9d
	je	.L901
	movzbl	1(%rcx), %eax
	movzbl	1(%rdx), %r11d
	movb	%r11b, 1(%rcx)
	movb	%al, 1(%rdx)
	movl	$2, %eax
.L901:
	movzbl	(%rcx,%rax), %r9d
	movzbl	(%rdx,%rax), %r15d
	movb	%r15b, (%rcx,%rax)
	movb	%r9b, (%rdx,%rax)
	addq	$1, %rax
.L900:
	movzbl	(%rcx,%rax), %r9d
	movzbl	(%rdx,%rax), %r15d
	movb	%r15b, (%rcx,%rax)
	movb	%r9b, (%rdx,%rax)
	addq	$1, %rax
	leal	(%rdi,%rax), %r11d
	cmpl	%r11d, %r13d
	jle	.L482
.L486:
	movzbl	(%rcx,%rax), %r15d
	movzbl	(%rdx,%rax), %r9d
	movb	%r9b, (%rcx,%rax)
	movb	%r15b, (%rdx,%rax)
	movzbl	1(%rdx,%rax), %r11d
	movzbl	1(%rcx,%rax), %r9d
	movb	%r11b, 1(%rcx,%rax)
	movb	%r9b, 1(%rdx,%rax)
	movzbl	2(%rdx,%rax), %r15d
	movzbl	2(%rcx,%rax), %r9d
	movb	%r15b, 2(%rcx,%rax)
	movb	%r9b, 2(%rdx,%rax)
	movzbl	3(%rdx,%rax), %r11d
	movzbl	3(%rcx,%rax), %r15d
	movb	%r11b, 3(%rcx,%rax)
	movb	%r15b, 3(%rdx,%rax)
	addq	$4, %rax
	leal	(%rdi,%rax), %r9d
	cmpl	%r9d, %r13d
	jg	.L486
	jmp	.L482
	.p2align 4,,10
	.p2align 3
.L959:
	cmpb	$0, 2(%rdi,%rcx)
	je	.L763
	.p2align 4,,6
	jmp	.L476
	.p2align 4,,10
	.p2align 3
.L960:
	cmpb	$0, 3(%rdi,%rcx)
	je	.L766
	.p2align 4,,6
	jmp	.L476
	.p2align 4,,10
	.p2align 3
.L961:
	cmpb	$0, 4(%rdi,%rcx)
	je	.L769
	.p2align 4,,6
	jmp	.L476
	.p2align 4,,10
	.p2align 3
.L962:
	cmpb	$0, 5(%rdi,%rcx)
	je	.L772
	.p2align 4,,6
	jmp	.L476
	.p2align 4,,10
	.p2align 3
.L963:
	cmpb	$0, 6(%rdi,%rcx)
	je	.L775
	.p2align 4,,6
	jmp	.L476
	.p2align 4,,10
	.p2align 3
.L725:
	cmpl	$1, %ecx
	jle	.L726
	.p2align 4,,8
	jmp	.L1014
	.p2align 4,,10
	.p2align 3
.L951:
	cmpb	$0, 1(%rdi)
	je	.L729
	.p2align 4,,7
	jmp	.L476
	.p2align 4,,10
	.p2align 3
.L952:
	cmpb	$0, (%rdi,%rbx)
	je	.L733
	.p2align 4,,7
	jmp	.L476
	.p2align 4,,10
	.p2align 3
.L953:
	cmpb	$0, (%rdi,%rbx)
	je	.L737
	.p2align 4,,7
	jmp	.L476
	.p2align 4,,10
	.p2align 3
.L954:
	cmpb	$0, (%rdi,%rbx)
	je	.L741
	.p2align 4,,7
	jmp	.L476
	.p2align 4,,10
	.p2align 3
.L955:
	cmpb	$0, (%rdi,%rbx)
	je	.L745
	.p2align 4,,7
	jmp	.L476
	.p2align 4,,10
	.p2align 3
.L956:
	cmpb	$0, (%rdi,%rbx)
	je	.L749
	.p2align 4,,7
	jmp	.L476
	.p2align 4,,10
	.p2align 3
.L957:
	cmpb	$0, (%rdi,%rbx)
	je	.L753
	.p2align 4,,7
	jmp	.L476
	.p2align 4,,10
	.p2align 3
.L516:
	movl	$1, %eax
	jmp	.L451
	.p2align 4,,10
	.p2align 3
.L455:
	movq	stderr(%rip), %rdi
	subl	$1, %r8d
	movl	$.LC6, %edx
	movl	$1, %esi
	xorl	%eax, %eax
	call	__fprintf_chk
	movq	32(%rsp), %rdi
	call	free
	movl	$1, %eax
	jmp	.L451
.L1019:
	movq	32(%rsp), %rdi
	movq	%r15, %rdx
	xorl	%esi, %esi
	movl	%r11d, 16(%rsp)
	call	memset
	movq	32(%rsp), %r10
	movb	$1, (%r10)
	movl	16(%rsp), %r11d
	jmp	.L964
.L1020:
	movq	%r10, %rdi
	movq	%r15, %rdx
	xorl	%esi, %esi
	movq	%r9, 16(%rsp)
	movq	%r10, (%rsp)
	call	memset
	movq	16(%rsp), %r9
	movq	(%rsp), %r10
	movb	$1, (%r10,%r9)
	jmp	.L965
.L1021:
	movq	%r10, %rdi
	movq	%r15, %rdx
	xorl	%esi, %esi
	movq	%r9, 16(%rsp)
	movq	%r10, (%rsp)
	call	memset
	movq	16(%rsp), %r9
	movq	(%rsp), %r10
	movb	$1, (%r10,%r9)
	jmp	.L966
.L1022:
	movq	%r10, %rdi
	movq	%r15, %rdx
	xorl	%esi, %esi
	movq	%r9, 16(%rsp)
	movq	%r10, (%rsp)
	call	memset
	movq	16(%rsp), %r9
	movq	(%rsp), %r10
	movb	$1, (%r10,%r9)
	jmp	.L967
.L503:
	movq	64(%rsp), %rdi
	call	free
	movq	32(%rsp), %rdi
	call	free
	xorl	%eax, %eax
	jmp	.L451
	.p2align 4,,10
	.p2align 3
.L1048:
	movq	24(%rsp), %r12
	leal	-1(%rbx), %r13d
	movslq	44(%rsp), %r15
	andl	$7, %r13d
	cmpl	(%r12), %ebx
	jle	.L1067
.L538:
	cmpl	$1, %ebx
	movl	$1, %ebp
	jle	.L503
	testl	%r13d, %r13d
	je	.L973
	cmpl	$1, %r13d
	je	.L868
	cmpl	$2, %r13d
	je	.L869
	cmpl	$3, %r13d
	je	.L870
	cmpl	$4, %r13d
	je	.L871
	cmpl	$5, %r13d
	je	.L872
	cmpl	$6, %r13d
	je	.L873
	cmpl	(%r12,%rbp,4), %ebx
	jle	.L1068
.L540:
	addq	$1, %rbp
.L873:
	cmpl	(%r12,%rbp,4), %ebx
	jle	.L1069
.L543:
	addq	$1, %rbp
.L872:
	cmpl	(%r12,%rbp,4), %ebx
	jle	.L1070
.L546:
	addq	$1, %rbp
.L871:
	cmpl	(%r12,%rbp,4), %ebx
	jle	.L1071
.L549:
	addq	$1, %rbp
.L870:
	cmpl	(%r12,%rbp,4), %ebx
	jle	.L1072
.L552:
	addq	$1, %rbp
.L869:
	cmpl	(%r12,%rbp,4), %ebx
	jle	.L1073
.L555:
	addq	$1, %rbp
.L868:
	cmpl	(%r12,%rbp,4), %ebx
	jle	.L1074
.L558:
	addq	$1, %rbp
	cmpl	%ebp, %ebx
	jle	.L503
.L973:
	movq	64(%rsp), %r13
	jmp	.L510
	.p2align 4,,10
	.p2align 3
.L509:
	addq	$1, %rbp
	cmpl	(%r12,%rbp,4), %ebx
	jle	.L1075
.L561:
	leaq	1(%rbp), %rax
	cmpl	(%r12,%rax,4), %ebx
	jle	.L1076
.L563:
	leaq	2(%rbp), %rax
	cmpl	(%r12,%rax,4), %ebx
	jle	.L1077
.L565:
	leaq	3(%rbp), %rax
	cmpl	(%r12,%rax,4), %ebx
	jle	.L1078
.L567:
	leaq	4(%rbp), %rax
	cmpl	(%r12,%rax,4), %ebx
	jle	.L1079
.L569:
	leaq	5(%rbp), %rax
	cmpl	(%r12,%rax,4), %ebx
	jle	.L1080
.L571:
	leaq	6(%rbp), %rax
	cmpl	(%r12,%rax,4), %ebx
	jle	.L1081
.L573:
	addq	$7, %rbp
	cmpl	%ebp, %ebx
	jle	.L503
.L510:
	cmpl	(%r12,%rbp,4), %ebx
	jg	.L509
	movq	0(%r13,%rbp,8), %rcx
	movq	(%r14,%rbp,8), %rdi
	movq	%r15, %rdx
	movq	%rcx, %rsi
	movq	%rcx, 16(%rsp)
	call	memmove
	movq	16(%rsp), %rax
	movq	%rax, %rdi
	call	free
	jmp	.L509
	.p2align 4,,10
	.p2align 3
.L1050:
	movq	(%r14), %rsi
	movl	44(%rsp), %ecx
	movzbl	%dl, %edx
	movq	%r12, %rdi
	movl	%eax, 16(%rsp)
	call	addmul1
	movl	16(%rsp), %eax
	jmp	.L575
	.p2align 4,,10
	.p2align 3
.L1056:
	movq	(%r14,%r15,8), %rsi
	movl	44(%rsp), %ecx
	movzbl	%dl, %edx
	movq	%r12, %rdi
	call	addmul1
	jmp	.L592
	.p2align 4,,10
	.p2align 3
.L1057:
	movq	(%r14,%r15,8), %rsi
	movl	44(%rsp), %ecx
	movzbl	%dl, %edx
	movq	%r12, %rdi
	call	addmul1
	jmp	.L595
	.p2align 4,,10
	.p2align 3
.L1052:
	movq	(%r14,%r15,8), %rsi
	movl	44(%rsp), %ecx
	movzbl	%dl, %edx
	movq	%r12, %rdi
	call	addmul1
	jmp	.L580
	.p2align 4,,10
	.p2align 3
.L1053:
	movq	(%r14,%r15,8), %rsi
	movl	44(%rsp), %ecx
	movzbl	%dl, %edx
	movq	%r12, %rdi
	call	addmul1
	jmp	.L583
	.p2align 4,,10
	.p2align 3
.L1054:
	movq	(%r14,%r15,8), %rsi
	movl	44(%rsp), %ecx
	movzbl	%dl, %edx
	movq	%r12, %rdi
	call	addmul1
	jmp	.L586
	.p2align 4,,10
	.p2align 3
.L1055:
	movq	(%r14,%r15,8), %rsi
	movl	44(%rsp), %ecx
	movzbl	%dl, %edx
	movq	%r12, %rdi
	call	addmul1
	jmp	.L589
	.p2align 4,,10
	.p2align 3
.L1051:
	movq	8(%r14), %rsi
	movl	44(%rsp), %ecx
	movzbl	%dl, %edx
	movq	%r12, %rdi
	call	addmul1
	jmp	.L577
.L1078:
	movq	0(%r13,%rax,8), %r8
	movq	(%r14,%rax,8), %rdi
	movq	%r15, %rdx
	movq	%r8, %rsi
	movq	%r8, 16(%rsp)
	call	memmove
	movq	16(%rsp), %rsi
	movq	%rsi, %rdi
	call	free
	jmp	.L567
.L1077:
	movq	0(%r13,%rax,8), %rcx
	movq	(%r14,%rax,8), %rdi
	movq	%r15, %rdx
	movq	%rcx, %rsi
	movq	%rcx, 16(%rsp)
	call	memmove
	movq	16(%rsp), %rdi
	call	free
	jmp	.L565
.L1076:
	movq	0(%r13,%rax,8), %r9
	movq	(%r14,%rax,8), %rdi
	movq	%r15, %rdx
	movq	%r9, %rsi
	movq	%r9, 16(%rsp)
	call	memmove
	movq	16(%rsp), %r11
	movq	%r11, %rdi
	call	free
	jmp	.L563
.L1075:
	movq	0(%r13,%rbp,8), %r10
	movq	(%r14,%rbp,8), %rdi
	movq	%r15, %rdx
	movq	%r10, %rsi
	movq	%r10, 16(%rsp)
	call	memmove
	movq	16(%rsp), %r8
	movq	%r8, %rdi
	call	free
	jmp	.L561
.L1080:
	movq	0(%r13,%rax,8), %r11
	movq	(%r14,%rax,8), %rdi
	movq	%r15, %rdx
	movq	%r11, %rsi
	movq	%r11, 16(%rsp)
	call	memmove
	movq	16(%rsp), %rdx
	movq	%rdx, %rdi
	call	free
	jmp	.L571
.L1079:
	movq	0(%r13,%rax,8), %r10
	movq	(%r14,%rax,8), %rdi
	movq	%r15, %rdx
	movq	%r10, %rsi
	movq	%r10, 16(%rsp)
	call	memmove
	movq	16(%rsp), %rax
	movq	%rax, %rdi
	call	free
	jmp	.L569
.L1081:
	movq	0(%r13,%rax,8), %rcx
	movq	(%r14,%rax,8), %rdi
	movq	%r15, %rdx
	movq	%rcx, %rsi
	movq	%rcx, 16(%rsp)
	call	memmove
	movq	16(%rsp), %r9
	movq	%r9, %rdi
	call	free
	jmp	.L573
.L1065:
	movl	%r13d, %ebx
	movq	72(%rsp), %r13
	jmp	.L504
.L1067:
	movq	64(%rsp), %r10
	movq	(%r14), %rdi
	movq	%r15, %rdx
	movq	(%r10), %rbp
	movq	%rbp, %rsi
	call	memmove
	movq	%rbp, %rdi
	call	free
	jmp	.L538
.L495:
	movq	stderr(%rip), %rdi
	movl	$.LC13, %edx
	movl	$1, %esi
	xorl	%eax, %eax
	call	__fprintf_chk
	jmp	.L497
.L1073:
	movq	64(%rsp), %rcx
	movq	(%r14,%rbp,8), %rdi
	movq	%r15, %rdx
	movq	(%rcx,%rbp,8), %r13
	movq	%r13, %rsi
	call	memmove
	movq	%r13, %rdi
	call	free
	jmp	.L555
.L1074:
	movq	64(%rsp), %rdx
	movq	(%r14,%rbp,8), %rdi
	movq	(%rdx,%rbp,8), %r13
	movq	%r15, %rdx
	movq	%r13, %rsi
	call	memmove
	movq	%r13, %rdi
	call	free
	jmp	.L558
.L1069:
	movq	64(%rsp), %rdi
	movq	%r15, %rdx
	movq	(%rdi,%rbp,8), %r13
	movq	(%r14,%rbp,8), %rdi
	movq	%r13, %rsi
	call	memmove
	movq	%r13, %rdi
	call	free
	jmp	.L543
.L1070:
	movq	64(%rsp), %r9
	movq	(%r14,%rbp,8), %rdi
	movq	%r15, %rdx
	movq	(%r9,%rbp,8), %r13
	movq	%r13, %rsi
	call	memmove
	movq	%r13, %rdi
	call	free
	jmp	.L546
.L1071:
	movq	64(%rsp), %rsi
	movq	(%r14,%rbp,8), %rdi
	movq	%r15, %rdx
	movq	(%rsi,%rbp,8), %r13
	movq	%r13, %rsi
	call	memmove
	movq	%r13, %rdi
	call	free
	jmp	.L549
.L1072:
	movq	64(%rsp), %rax
	movq	(%r14,%rbp,8), %rdi
	movq	%r15, %rdx
	movq	(%rax,%rbp,8), %r13
	movq	%r13, %rsi
	call	memmove
	movq	%r13, %rdi
	call	free
	jmp	.L552
.L1068:
	movq	64(%rsp), %r11
	movq	(%r14,%rbp,8), %rdi
	movq	%r15, %rdx
	movq	(%r11,%rbp,8), %r13
	movq	%r13, %rsi
	call	memmove
	movq	%r13, %rdi
	call	free
	jmp	.L540
.L515:
	movl	%ebx, %r13d
	.p2align 4,,2
	jmp	.L447
.L1045:
	movq	112(%rsp), %rsi
	movzbl	%dl, %edx
	movl	%r13d, %ecx
	movq	%r15, %rdi
	call	addmul1
	jmp	.L669
.L1044:
	movq	112(%rsp), %rsi
	movzbl	%dl, %edx
	movl	%r13d, %ecx
	movq	%r15, %rdi
	call	addmul1
	jmp	.L667
.L1043:
	movq	112(%rsp), %rsi
	movzbl	%dl, %edx
	movl	%r13d, %ecx
	movq	%r15, %rdi
	call	addmul1
	jmp	.L665
.L1042:
	movq	112(%rsp), %rsi
	movzbl	%dl, %edx
	movl	%r13d, %ecx
	movq	%r15, %rdi
	call	addmul1
	jmp	.L663
.L1041:
	movq	112(%rsp), %rsi
	movzbl	%dl, %edx
	movl	%r13d, %ecx
	movq	%r15, %rdi
	call	addmul1
	jmp	.L661
.L1040:
	movq	112(%rsp), %rsi
	movzbl	%dl, %edx
	movl	%r13d, %ecx
	movq	%r15, %rdi
	call	addmul1
	jmp	.L659
.L1039:
	movq	112(%rsp), %rsi
	movzbl	%dl, %edx
	movl	%r13d, %ecx
	movq	%r15, %rdi
	call	addmul1
	jmp	.L657
.L1031:
	movzbl	%dl, %edx
	movl	%r13d, %ecx
	movq	%r12, %rsi
	movq	%rax, %rdi
	movq	%r8, 8(%rsp)
	movl	%r9d, 16(%rsp)
	movq	%r10, (%rsp)
	call	addmul1
	movq	(%rsp), %r10
	movl	16(%rsp), %r9d
	movq	8(%rsp), %r8
	jmp	.L634
.L1033:
	movzbl	%dl, %edx
	movl	%r13d, %ecx
	movq	%r12, %rsi
	movq	%r15, %rdi
	movl	%eax, 16(%rsp)
	movq	%r8, 8(%rsp)
	movq	%r10, (%rsp)
	call	addmul1
	movq	(%rsp), %r10
	movq	8(%rsp), %r8
	movl	16(%rsp), %eax
	jmp	.L639
.L1032:
	movzbl	%dl, %edx
	movl	%r13d, %ecx
	movq	%r12, %rsi
	movq	%r15, %rdi
	movl	%eax, 16(%rsp)
	movq	%r8, 8(%rsp)
	movq	%r10, (%rsp)
	call	addmul1
	movq	(%rsp), %r10
	movq	8(%rsp), %r8
	movl	16(%rsp), %eax
	jmp	.L636
.L1038:
	movzbl	%dl, %edx
	movl	%r13d, %ecx
	movq	%r12, %rsi
	movq	%r15, %rdi
	movl	%eax, 16(%rsp)
	movq	%r8, 8(%rsp)
	movq	%r10, (%rsp)
	call	addmul1
	movq	(%rsp), %r10
	movq	8(%rsp), %r8
	movl	16(%rsp), %eax
	jmp	.L654
.L1037:
	movzbl	%dl, %edx
	movl	%r13d, %ecx
	movq	%r12, %rsi
	movq	%r15, %rdi
	movl	%eax, 16(%rsp)
	movq	%r8, 8(%rsp)
	movq	%r10, (%rsp)
	call	addmul1
	movq	(%rsp), %r10
	movq	8(%rsp), %r8
	movl	16(%rsp), %eax
	jmp	.L651
.L1036:
	movzbl	%dl, %edx
	movl	%r13d, %ecx
	movq	%r12, %rsi
	movq	%r15, %rdi
	movl	%eax, 16(%rsp)
	movq	%r8, 8(%rsp)
	movq	%r10, (%rsp)
	call	addmul1
	movq	(%rsp), %r10
	movq	8(%rsp), %r8
	movl	16(%rsp), %eax
	jmp	.L648
.L1035:
	movzbl	%dl, %edx
	movl	%r13d, %ecx
	movq	%r12, %rsi
	movq	%r15, %rdi
	movl	%eax, 16(%rsp)
	movq	%r8, 8(%rsp)
	movq	%r10, (%rsp)
	call	addmul1
	movq	(%rsp), %r10
	movq	8(%rsp), %r8
	movl	16(%rsp), %eax
	jmp	.L645
.L1034:
	movzbl	%dl, %edx
	movl	%r13d, %ecx
	movq	%r12, %rsi
	movq	%r15, %rdi
	movl	%eax, 16(%rsp)
	movq	%r8, 8(%rsp)
	movq	%r10, (%rsp)
	call	addmul1
	movq	(%rsp), %r10
	movq	8(%rsp), %r8
	movl	16(%rsp), %eax
	jmp	.L642
.L498:
	movq	stderr(%rip), %rdi
	movl	%edx, %ecx
	movl	$1, %esi
	movl	$.LC14, %edx
	xorl	%eax, %eax
	call	__fprintf_chk
	jmp	.L497
.L1030:
	movq	stderr(%rip), %rcx
	movl	$18, %edx
	movl	$1, %esi
	movl	$.LC12, %edi
	movq	%r14, 16(%rsp)
	call	fwrite
	movq	16(%rsp), %r9
	jmp	.L478
.L518:
	xorl	%edi, %edi
	jmp	.L483
.L1049:
	movl	$.LC16, %edi
	call	my_malloc.part.0
.L1047:
	movl	$.LC15, %edi
	call	my_malloc.part.0
.L1028:
	movl	$.LC8, %edi
	call	my_malloc.part.0
.L1066:
	movslq	%r12d, %r12
	jmp	.L482
.L1029:
	movl	$.LC9, %edi
	call	my_malloc.part.0
.L517:
	xorl	%edx, %edx
	jmp	.L463
.L1027:
	movl	$.LC7, %edi
	call	my_malloc.part.0
.L1016:
	movl	$.LC1, %edi
	call	my_malloc.part.0
	.cfi_endproc
.LFE70:
	.size	fec_decode, .-fec_decode
	.local	gf_mul_table
	.comm	gf_mul_table,65536,32
	.local	inverse
	.comm	inverse,256,32
	.local	fec_initialized
	.comm	fec_initialized,4,16
	.local	gf_log
	.comm	gf_log,1024,32
	.local	gf_exp
	.comm	gf_exp,510,32
	.ident	"GCC: (Ubuntu/Linaro 4.6.3-1ubuntu5) 4.6.3"
	.section	.note.GNU-stack,"",@progbits
