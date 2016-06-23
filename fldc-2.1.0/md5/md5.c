/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

/* ====================================================================
 * Copyright (c) 1999-2002 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

// No idea where they think size_t comes from if not from here!

#include "platform.h"
#include <stddef.h>

#ifdef LINUX
#include <linux/types.h>
#else
# pragma warning(disable: 4267)
# pragma warning(disable: 4127)
#endif  /* LINUX */
#include "md5.h"

#ifdef __KERNEL__
#include <linux/module.h>
#endif // __KERNEL__


/* Implemented from RFC1321 The MD5 Message-Digest Algorithm
 */

#define MD5_ASM

#ifdef MD5_ASM
# if defined(__i386) || defined(__i386__) || defined(_M_IX86) || defined(__INTEL__) || defined(__x86_64) || defined(__x86_64__)
#  if !defined(B_ENDIAN)
#   define md5_block_host_order md5_block_asm_host_order
asm (                                                       \
    ".text\n\t"			                                    \
    ".align 16\n\t"			                                \
    "\n"                                                    \
    ".globl md5_block_asm_host_order\n\t"                   \
    ".type md5_block_asm_host_order,@function\n\t"			\
    "md5_block_asm_host_order:\n\t"	                        \
        "pushq	%rbp\n\t"			                        \
        "pushq	%rbx\n\t"			                        \
        "pushq	%r14\n\t"			                        \
        "pushq	%r15\n\t"			                        \
    "\n"                                                    \
        "movq	%rdi,%rbp\n\t"		                        \
        "shlq	$6,%rdx\n\t"		                        \
        "leaq	(%rsi,%rdx,1),%rdi\n\t"	                    \
        "movl	0(%rbp),%eax\n\t"	                        \
        "movl	4(%rbp),%ebx\n\t"	                        \
        "movl	8(%rbp),%ecx\n\t"	                        \
        "movl	12(%rbp),%edx\n\t"	                        \
    "\n"                                                    \
        "cmpq	%rdi,%rsi\n\t"		                        \
        "je	.Lend\n\t"			                            \
    "\n"                                                    \
    ".Lloop:\n\t"			                                \
        "movl	%eax,%r8d\n\t"			                    \
        "movl	%ebx,%r9d\n\t"			                    \
        "movl	%ecx,%r14d\n\t"			                    \
        "movl	%edx,%r15d\n\t"			                    \
        "movl	0(%rsi),%r10d\n\t"		                    \
        "movl	%edx,%r11d\n\t"			                    \
        "xorl	%ecx,%r11d\n\t"			                    \
        "leal	-680876936(%rax,%r10,1),%eax\n\t"			\
        "andl	%ebx,%r11d\n\t"			                    \
        "xorl	%edx,%r11d\n\t"			                    \
        "movl	4(%rsi),%r10d\n\t"		                    \
        "addl	%r11d,%eax\n\t"			                    \
        "roll	$7,%eax\n\t"			                    \
        "movl	%ecx,%r11d\n\t"			                    \
        "addl	%ebx,%eax\n\t"			                    \
        "xorl	%ebx,%r11d\n\t"			                    \
        "leal	-389564586(%rdx,%r10,1),%edx\n\t"			\
        "andl	%eax,%r11d\n\t"			                    \
        "xorl	%ecx,%r11d\n\t"			                    \
        "movl	8(%rsi),%r10d\n\t"		                    \
        "addl	%r11d,%edx\n\t"			                    \
        "roll	$12,%edx\n\t"			                    \
        "movl	%ebx,%r11d\n\t"			                    \
        "addl	%eax,%edx\n\t"			                    \
        "xorl	%eax,%r11d\n\t"			                    \
        "leal	606105819(%rcx,%r10,1),%ecx\n\t"			\
        "andl	%edx,%r11d\n\t"			                    \
        "xorl	%ebx,%r11d\n\t"			                    \
        "movl	12(%rsi),%r10d\n\t"		                    \
        "addl	%r11d,%ecx\n\t"			                    \
        "roll	$17,%ecx\n\t"			                    \
        "movl	%eax,%r11d\n\t"			                    \
        "addl	%edx,%ecx\n\t"			                    \
        "xorl	%edx,%r11d\n\t"			                    \
        "leal	-1044525330(%rbx,%r10,1),%ebx\n\t"			\
        "andl	%ecx,%r11d\n\t"			                    \
        "xorl	%eax,%r11d\n\t"			                    \
        "movl	16(%rsi),%r10d\n\t"		                    \
        "addl	%r11d,%ebx\n\t"			                    \
        "roll	$22,%ebx\n\t"			                    \
        "movl	%edx,%r11d\n\t"			                    \
        "addl	%ecx,%ebx\n\t"			                    \
        "xorl	%ecx,%r11d\n\t"			                    \
        "leal	-176418897(%rax,%r10,1),%eax\n\t"			\
        "andl	%ebx,%r11d\n\t"			                    \
        "xorl	%edx,%r11d\n\t"			                    \
        "movl	20(%rsi),%r10d\n\t"		                    \
        "addl	%r11d,%eax\n\t"			                    \
        "roll	$7,%eax\n\t"			                    \
        "movl	%ecx,%r11d\n\t"			                    \
        "addl	%ebx,%eax\n\t"			                    \
        "xorl	%ebx,%r11d\n\t"			                    \
        "leal	1200080426(%rdx,%r10,1),%edx\n\t"			\
        "andl	%eax,%r11d\n\t"			                    \
        "xorl	%ecx,%r11d\n\t"			                    \
        "movl	24(%rsi),%r10d\n\t"		                    \
        "addl	%r11d,%edx\n\t"			                    \
        "roll	$12,%edx\n\t"			                    \
        "movl	%ebx,%r11d\n\t"			                    \
        "addl	%eax,%edx\n\t"			                    \
        "xorl	%eax,%r11d\n\t"			                    \
        "leal	-1473231341(%rcx,%r10,1),%ecx\n\t"			\
        "andl	%edx,%r11d\n\t"			                    \
        "xorl	%ebx,%r11d\n\t"			                    \
        "movl	28(%rsi),%r10d\n\t"		                    \
        "addl	%r11d,%ecx\n\t"			                    \
        "roll	$17,%ecx\n\t"			                    \
        "movl	%eax,%r11d\n\t"			                    \
        "addl	%edx,%ecx\n\t"			                    \
        "xorl	%edx,%r11d\n\t"			                    \
        "leal	-45705983(%rbx,%r10,1),%ebx\n\t"			\
        "andl	%ecx,%r11d\n\t"			                    \
        "xorl	%eax,%r11d\n\t"			                    \
        "movl	32(%rsi),%r10d\n\t"		                    \
        "addl	%r11d,%ebx\n\t"			                    \
        "roll	$22,%ebx\n\t"			                    \
        "movl	%edx,%r11d\n\t"			                    \
        "addl	%ecx,%ebx\n\t"			                    \
        "xorl	%ecx,%r11d\n\t"			                    \
        "leal	1770035416(%rax,%r10,1),%eax\n\t"			\
        "andl	%ebx,%r11d\n\t"			                    \
        "xorl	%edx,%r11d\n\t"			                    \
        "movl	36(%rsi),%r10d\n\t"		                    \
        "addl	%r11d,%eax\n\t"			                    \
        "roll	$7,%eax\n\t"			                    \
        "movl	%ecx,%r11d\n\t"			                    \
        "addl	%ebx,%eax\n\t"			                    \
        "xorl	%ebx,%r11d\n\t"			                    \
        "leal	-1958414417(%rdx,%r10,1),%edx\n\t"			\
        "andl	%eax,%r11d\n\t"			                    \
        "xorl	%ecx,%r11d\n\t"			                    \
        "movl	40(%rsi),%r10d\n\t"		                    \
        "addl	%r11d,%edx\n\t"			                    \
        "roll	$12,%edx\n\t"			                    \
        "movl	%ebx,%r11d\n\t"			                    \
        "addl	%eax,%edx\n\t"			                    \
        "xorl	%eax,%r11d\n\t"			                    \
        "leal	-42063(%rcx,%r10,1),%ecx\n\t"			\
        "andl	%edx,%r11d\n\t"			                    \
        "xorl	%ebx,%r11d\n\t"			                    \
        "movl	44(%rsi),%r10d\n\t"		                    \
        "addl	%r11d,%ecx\n\t"			                    \
        "roll	$17,%ecx\n\t"			                    \
        "movl	%eax,%r11d\n\t"			                    \
        "addl	%edx,%ecx\n\t"			                    \
        "xorl	%edx,%r11d\n\t"			                    \
        "leal	-1990404162(%rbx,%r10,1),%ebx\n\t"			\
        "andl	%ecx,%r11d\n\t"			                    \
        "xorl	%eax,%r11d\n\t"			                    \
        "movl	48(%rsi),%r10d\n\t"		                    \
        "addl	%r11d,%ebx\n\t"			                    \
        "roll	$22,%ebx\n\t"			                    \
        "movl	%edx,%r11d\n\t"			                    \
        "addl	%ecx,%ebx\n\t"			                    \
        "xorl	%ecx,%r11d\n\t"			                    \
        "leal	1804603682(%rax,%r10,1),%eax\n\t"			\
        "andl	%ebx,%r11d\n\t"			                    \
        "xorl	%edx,%r11d\n\t"			                    \
        "movl	52(%rsi),%r10d\n\t"		                    \
        "addl	%r11d,%eax\n\t"			                    \
        "roll	$7,%eax\n\t"			                    \
        "movl	%ecx,%r11d\n\t"			                    \
        "addl	%ebx,%eax\n\t"			                    \
        "xorl	%ebx,%r11d\n\t"			                    \
        "leal	-40341101(%rdx,%r10,1),%edx\n\t"			\
        "andl	%eax,%r11d\n\t"			                    \
        "xorl	%ecx,%r11d\n\t"			                    \
        "movl	56(%rsi),%r10d\n\t"		                    \
        "addl	%r11d,%edx\n\t"			                    \
        "roll	$12,%edx\n\t"			                    \
        "movl	%ebx,%r11d\n\t"			                    \
        "addl	%eax,%edx\n\t"			                    \
        "xorl	%eax,%r11d\n\t"			                    \
        "leal	-1502002290(%rcx,%r10,1),%ecx\n\t"			\
        "andl	%edx,%r11d\n\t"			                    \
        "xorl	%ebx,%r11d\n\t"			                    \
        "movl	60(%rsi),%r10d\n\t"		                    \
        "addl	%r11d,%ecx\n\t"			                    \
        "roll	$17,%ecx\n\t"			                    \
        "movl	%eax,%r11d\n\t"			                    \
        "addl	%edx,%ecx\n\t"			                    \
        "xorl	%edx,%r11d\n\t"			                    \
        "leal	1236535329(%rbx,%r10,1),%ebx\n\t"			\
        "andl	%ecx,%r11d\n\t"			                    \
        "xorl	%eax,%r11d\n\t"			                    \
        "movl	0(%rsi),%r10d\n\t"		                    \
        "addl	%r11d,%ebx\n\t"			                    \
        "roll	$22,%ebx\n\t"			                    \
        "movl	%edx,%r11d\n\t"			                    \
        "addl	%ecx,%ebx\n\t"			                    \
        "movl	4(%rsi),%r10d\n\t"		                    \
        "movl	%ecx,%r11d\n\t"			                    \
        "xorl	%ebx,%r11d\n\t"			                    \
        "leal	-165796510(%rax,%r10,1),%eax\n\t"			\
        "andl	%edx,%r11d\n\t"			                    \
        "xorl	%ecx,%r11d\n\t"			                    \
        "movl	24(%rsi),%r10d\n\t"		                    \
        "addl	%r11d,%eax\n\t"			                    \
        "roll	$5,%eax\n\t"			                    \
        "movl	%ebx,%r11d\n\t"			                    \
        "addl	%ebx,%eax\n\t"			                    \
        "xorl	%eax,%r11d\n\t"			                    \
        "leal	-1069501632(%rdx,%r10,1),%edx\n\t"			\
        "andl	%ecx,%r11d\n\t"			                    \
        "xorl	%ebx,%r11d\n\t"			                    \
        "movl	44(%rsi),%r10d\n\t"		                    \
        "addl	%r11d,%edx\n\t"			                    \
        "roll	$9,%edx\n\t"			                    \
        "movl	%eax,%r11d\n\t"			                    \
        "addl	%eax,%edx\n\t"			                    \
        "xorl	%edx,%r11d\n\t"			                    \
        "leal	643717713(%rcx,%r10,1),%ecx\n\t"			\
        "andl	%ebx,%r11d\n\t"			                    \
        "xorl	%eax,%r11d\n\t"			                    \
        "movl	0(%rsi),%r10d\n\t"		                    \
        "addl	%r11d,%ecx\n\t"			                    \
        "roll	$14,%ecx\n\t"			                    \
        "movl	%edx,%r11d\n\t"			                    \
        "addl	%edx,%ecx\n\t"			                    \
        "xorl	%ecx,%r11d\n\t"			                    \
        "leal	-373897302(%rbx,%r10,1),%ebx\n\t"			\
        "andl	%eax,%r11d\n\t"			                    \
        "xorl	%edx,%r11d\n\t"			                    \
        "movl	20(%rsi),%r10d\n\t"		                    \
        "addl	%r11d,%ebx\n\t"			                    \
        "roll	$20,%ebx\n\t"			                    \
        "movl	%ecx,%r11d\n\t"			                    \
        "addl	%ecx,%ebx\n\t"			                    \
        "xorl	%ebx,%r11d\n\t"			                    \
        "leal	-701558691(%rax,%r10,1),%eax\n\t"			\
        "andl	%edx,%r11d\n\t"			                    \
        "xorl	%ecx,%r11d\n\t"			                    \
        "movl	40(%rsi),%r10d\n\t"		                    \
        "addl	%r11d,%eax\n\t"			                    \
        "roll	$5,%eax\n\t"			                    \
        "movl	%ebx,%r11d\n\t"			                    \
        "addl	%ebx,%eax\n\t"			                    \
        "xorl	%eax,%r11d\n\t"			                    \
        "leal	38016083(%rdx,%r10,1),%edx\n\t"			    \
        "andl	%ecx,%r11d\n\t"			                    \
        "xorl	%ebx,%r11d\n\t"			                    \
        "movl	60(%rsi),%r10d\n\t"		                    \
        "addl	%r11d,%edx\n\t"			                    \
        "roll	$9,%edx\n\t"			                    \
        "movl	%eax,%r11d\n\t"			                    \
        "addl	%eax,%edx\n\t"			                    \
        "xorl	%edx,%r11d\n\t"			                    \
        "leal	-660478335(%rcx,%r10,1),%ecx\n\t"			\
        "andl	%ebx,%r11d\n\t"			                    \
        "xorl	%eax,%r11d\n\t"			                    \
        "movl	16(%rsi),%r10d\n\t"		                    \
        "addl	%r11d,%ecx\n\t"			                    \
        "roll	$14,%ecx\n\t"			                    \
        "movl	%edx,%r11d\n\t"			                    \
        "addl	%edx,%ecx\n\t"			                    \
        "xorl	%ecx,%r11d\n\t"			                    \
        "leal	-405537848(%rbx,%r10,1),%ebx\n\t"			\
        "andl	%eax,%r11d\n\t"			                    \
        "xorl	%edx,%r11d\n\t"			                    \
        "movl	36(%rsi),%r10d\n\t"		                    \
        "addl	%r11d,%ebx\n\t"			                    \
        "roll	$20,%ebx\n\t"			                    \
        "movl	%ecx,%r11d\n\t"			                    \
        "addl	%ecx,%ebx\n\t"			                    \
        "xorl	%ebx,%r11d\n\t"			                    \
        "leal	568446438(%rax,%r10,1),%eax\n\t"			\
        "andl	%edx,%r11d\n\t"			                    \
        "xorl	%ecx,%r11d\n\t"			                    \
        "movl	56(%rsi),%r10d\n\t"		                    \
        "addl	%r11d,%eax\n\t"			                    \
        "roll	$5,%eax\n\t"			                    \
        "movl	%ebx,%r11d\n\t"			                    \
        "addl	%ebx,%eax\n\t"			                    \
        "xorl	%eax,%r11d\n\t"			                    \
        "leal	-1019803690(%rdx,%r10,1),%edx\n\t"			\
        "andl	%ecx,%r11d\n\t"			                    \
        "xorl	%ebx,%r11d\n\t"			                    \
        "movl	12(%rsi),%r10d\n\t"		                    \
        "addl	%r11d,%edx\n\t"			                    \
        "roll	$9,%edx\n\t"			                    \
        "movl	%eax,%r11d\n\t"			                    \
        "addl	%eax,%edx\n\t"			                    \
        "xorl	%edx,%r11d\n\t"			                    \
        "leal	-187363961(%rcx,%r10,1),%ecx\n\t"			\
        "andl	%ebx,%r11d\n\t"			                    \
        "xorl	%eax,%r11d\n\t"			                    \
        "movl	32(%rsi),%r10d\n\t"		                    \
        "addl	%r11d,%ecx\n\t"			                    \
        "roll	$14,%ecx\n\t"			                    \
        "movl	%edx,%r11d\n\t"			                    \
        "addl	%edx,%ecx\n\t"			                    \
        "xorl	%ecx,%r11d\n\t"			                    \
        "leal	1163531501(%rbx,%r10,1),%ebx\n\t"			\
        "andl	%eax,%r11d\n\t"			                    \
        "xorl	%edx,%r11d\n\t"			                    \
        "movl	52(%rsi),%r10d\n\t"		                    \
        "addl	%r11d,%ebx\n\t"			                    \
        "roll	$20,%ebx\n\t"			                    \
        "movl	%ecx,%r11d\n\t"			                    \
        "addl	%ecx,%ebx\n\t"			                    \
        "xorl	%ebx,%r11d\n\t"			                    \
        "leal	-1444681467(%rax,%r10,1),%eax\n\t"			\
        "andl	%edx,%r11d\n\t"			                    \
        "xorl	%ecx,%r11d\n\t"			                    \
        "movl	8(%rsi),%r10d\n\t"		                    \
        "addl	%r11d,%eax\n\t"			                    \
        "roll	$5,%eax\n\t"			                    \
        "movl	%ebx,%r11d\n\t"			                    \
        "addl	%ebx,%eax\n\t"			                    \
        "xorl	%eax,%r11d\n\t"			                    \
        "leal	-51403784(%rdx,%r10,1),%edx\n\t"			\
        "andl	%ecx,%r11d\n\t"			                    \
        "xorl	%ebx,%r11d\n\t"			                    \
        "movl	28(%rsi),%r10d\n\t"		                    \
        "addl	%r11d,%edx\n\t"			                    \
        "roll	$9,%edx\n\t"			                    \
        "movl	%eax,%r11d\n\t"			                    \
        "addl	%eax,%edx\n\t"			                    \
        "xorl	%edx,%r11d\n\t"			                    \
        "leal	1735328473(%rcx,%r10,1),%ecx\n\t"			\
        "andl	%ebx,%r11d\n\t"			                    \
        "xorl	%eax,%r11d\n\t"			                    \
        "movl	48(%rsi),%r10d\n\t"		                    \
        "addl	%r11d,%ecx\n\t"			                    \
        "roll	$14,%ecx\n\t"			                    \
        "movl	%edx,%r11d\n\t"			                    \
        "addl	%edx,%ecx\n\t"			                    \
        "xorl	%ecx,%r11d\n\t"			                    \
        "leal	-1926607734(%rbx,%r10,1),%ebx\n\t"			\
        "andl	%eax,%r11d\n\t"			                    \
        "xorl	%edx,%r11d\n\t"			                    \
        "movl	0(%rsi),%r10d\n\t"		                    \
        "addl	%r11d,%ebx\n\t"			                    \
        "roll	$20,%ebx\n\t"			                    \
        "movl	%ecx,%r11d\n\t"			                    \
        "addl	%ecx,%ebx\n\t"			                    \
        "movl	20(%rsi),%r10d\n\t"		                    \
        "movl	%ecx,%r11d\n\t"			                    \
        "leal	-378558(%rax,%r10,1),%eax\n\t"			\
        "movl	32(%rsi),%r10d\n\t"		                    \
        "xorl	%edx,%r11d\n\t"			                    \
        "xorl	%ebx,%r11d\n\t"			                    \
        "addl	%r11d,%eax\n\t"			                    \
        "roll	$4,%eax\n\t"			                    \
        "movl	%ebx,%r11d\n\t"			                    \
        "addl	%ebx,%eax\n\t"			                    \
        "leal	-2022574463(%rdx,%r10,1),%edx\n\t"			\
        "movl	44(%rsi),%r10d\n\t"		                    \
        "xorl	%ecx,%r11d\n\t"			                    \
        "xorl	%eax,%r11d\n\t"			                    \
        "addl	%r11d,%edx\n\t"			                    \
        "roll	$11,%edx\n\t"			                    \
        "movl	%eax,%r11d\n\t"			                    \
        "addl	%eax,%edx\n\t"			                    \
        "leal	1839030562(%rcx,%r10,1),%ecx\n\t"			\
        "movl	56(%rsi),%r10d\n\t"		                    \
        "xorl	%ebx,%r11d\n\t"			                    \
        "xorl	%edx,%r11d\n\t"			                    \
        "addl	%r11d,%ecx\n\t"			                    \
        "roll	$16,%ecx\n\t"			                    \
        "movl	%edx,%r11d\n\t"			                    \
        "addl	%edx,%ecx\n\t"			                    \
        "leal	-35309556(%rbx,%r10,1),%ebx\n\t"			\
        "movl	4(%rsi),%r10d\n\t"		                    \
        "xorl	%eax,%r11d\n\t"			                    \
        "xorl	%ecx,%r11d\n\t"			                    \
        "addl	%r11d,%ebx\n\t"			                    \
        "roll	$23,%ebx\n\t"			                    \
        "movl	%ecx,%r11d\n\t"			                    \
        "addl	%ecx,%ebx\n\t"			                    \
        "leal	-1530992060(%rax,%r10,1),%eax\n\t"			\
        "movl	16(%rsi),%r10d\n\t"		                    \
        "xorl	%edx,%r11d\n\t"			                    \
        "xorl	%ebx,%r11d\n\t"			                    \
        "addl	%r11d,%eax\n\t"			                    \
        "roll	$4,%eax\n\t"			                    \
        "movl	%ebx,%r11d\n\t"			                    \
        "addl	%ebx,%eax\n\t"			                    \
        "leal	1272893353(%rdx,%r10,1),%edx\n\t"			\
        "movl	28(%rsi),%r10d\n\t"		                    \
        "xorl	%ecx,%r11d\n\t"			                    \
        "xorl	%eax,%r11d\n\t"			                    \
        "addl	%r11d,%edx\n\t"			                    \
        "roll	$11,%edx\n\t"			                    \
        "movl	%eax,%r11d\n\t"			                    \
        "addl	%eax,%edx\n\t"			                    \
        "leal	-155497632(%rcx,%r10,1),%ecx\n\t"			\
        "movl	40(%rsi),%r10d\n\t"		                    \
        "xorl	%ebx,%r11d\n\t"			                    \
        "xorl	%edx,%r11d\n\t"			                    \
        "addl	%r11d,%ecx\n\t"			                    \
        "roll	$16,%ecx\n\t"			                    \
        "movl	%edx,%r11d\n\t"			                    \
        "addl	%edx,%ecx\n\t"			                    \
        "leal	-1094730640(%rbx,%r10,1),%ebx\n\t"			\
        "movl	52(%rsi),%r10d\n\t"		                    \
        "xorl	%eax,%r11d\n\t"			                    \
        "xorl	%ecx,%r11d\n\t"			                    \
        "addl	%r11d,%ebx\n\t"			                    \
        "roll	$23,%ebx\n\t"			                    \
        "movl	%ecx,%r11d\n\t"			                    \
        "addl	%ecx,%ebx\n\t"			                    \
        "leal	681279174(%rax,%r10,1),%eax\n\t"			\
        "movl	0(%rsi),%r10d\n\t"		                    \
        "xorl	%edx,%r11d\n\t"			                    \
        "xorl	%ebx,%r11d\n\t"			                    \
        "addl	%r11d,%eax\n\t"			                    \
        "roll	$4,%eax\n\t"			                    \
        "movl	%ebx,%r11d\n\t"			                    \
        "addl	%ebx,%eax\n\t"			                    \
        "leal	-358537222(%rdx,%r10,1),%edx\n\t"			\
        "movl	12(%rsi),%r10d\n\t"		                    \
        "xorl	%ecx,%r11d\n\t"			                    \
        "xorl	%eax,%r11d\n\t"			                    \
        "addl	%r11d,%edx\n\t"			                    \
        "roll	$11,%edx\n\t"			                    \
        "movl	%eax,%r11d\n\t"			                    \
        "addl	%eax,%edx\n\t"			                    \
        "leal	-722521979(%rcx,%r10,1),%ecx\n\t"			\
        "movl	24(%rsi),%r10d\n\t"		                    \
        "xorl	%ebx,%r11d\n\t"			                    \
        "xorl	%edx,%r11d\n\t"			                    \
        "addl	%r11d,%ecx\n\t"			                    \
        "roll	$16,%ecx\n\t"			                    \
        "movl	%edx,%r11d\n\t"			                    \
        "addl	%edx,%ecx\n\t"			                    \
        "leal	76029189(%rbx,%r10,1),%ebx\n\t"			    \
        "movl	36(%rsi),%r10d\n\t"		                    \
        "xorl	%eax,%r11d\n\t"			                    \
        "xorl	%ecx,%r11d\n\t"			                    \
        "addl	%r11d,%ebx\n\t"			                    \
        "roll	$23,%ebx\n\t"			                    \
        "movl	%ecx,%r11d\n\t"			                    \
        "addl	%ecx,%ebx\n\t"			                    \
        "leal	-640364487(%rax,%r10,1),%eax\n\t"			\
        "movl	48(%rsi),%r10d\n\t"		                    \
        "xorl	%edx,%r11d\n\t"			                    \
        "xorl	%ebx,%r11d\n\t"			                    \
        "addl	%r11d,%eax\n\t"			                    \
        "roll	$4,%eax\n\t"			                    \
        "movl	%ebx,%r11d\n\t"			                    \
        "addl	%ebx,%eax\n\t"			                    \
        "leal	-421815835(%rdx,%r10,1),%edx\n\t"			\
        "movl	60(%rsi),%r10d\n\t"		                    \
        "xorl	%ecx,%r11d\n\t"			                    \
        "xorl	%eax,%r11d\n\t"			                    \
        "addl	%r11d,%edx\n\t"			                    \
        "roll	$11,%edx\n\t"			                    \
        "movl	%eax,%r11d\n\t"			                    \
        "addl	%eax,%edx\n\t"			                    \
        "leal	530742520(%rcx,%r10,1),%ecx\n\t"			\
        "movl	8(%rsi),%r10d\n\t"		                    \
        "xorl	%ebx,%r11d\n\t"			                    \
        "xorl	%edx,%r11d\n\t"			                    \
        "addl	%r11d,%ecx\n\t"			                    \
        "roll	$16,%ecx\n\t"			                    \
        "movl	%edx,%r11d\n\t"			                    \
        "addl	%edx,%ecx\n\t"			                    \
        "leal	-995338651(%rbx,%r10,1),%ebx\n\t"			\
        "movl	0(%rsi),%r10d\n\t"		                    \
        "xorl	%eax,%r11d\n\t"			                    \
        "xorl	%ecx,%r11d\n\t"			                    \
        "addl	%r11d,%ebx\n\t"			                    \
        "roll	$23,%ebx\n\t"			                    \
        "movl	%ecx,%r11d\n\t"			                    \
        "addl	%ecx,%ebx\n\t"			                    \
        "movl	0(%rsi),%r10d\n\t"		                    \
        "movl	$0xffffffff,%r11d\n\t"	                    \
        "xorl	%edx,%r11d\n\t"			                    \
        "leal	-198630844(%rax,%r10,1),%eax\n\t"			\
        "orl	%ebx,%r11d\n\t"			                    \
        "xorl	%ecx,%r11d\n\t"			                    \
        "addl	%r11d,%eax\n\t"			                    \
        "movl	28(%rsi),%r10d\n\t"		                    \
        "movl	$0xffffffff,%r11d\n\t"	                    \
        "roll	$6,%eax\n\t"			                    \
        "xorl	%ecx,%r11d\n\t"			                    \
        "addl	%ebx,%eax\n\t"			                    \
        "leal	1126891415(%rdx,%r10,1),%edx\n\t"			\
        "orl	%eax,%r11d\n\t"			                    \
        "xorl	%ebx,%r11d\n\t"			                    \
        "addl	%r11d,%edx\n\t"			                    \
        "movl	56(%rsi),%r10d\n\t"		                    \
        "movl	$0xffffffff,%r11d\n\t"	                    \
        "roll	$10,%edx\n\t"			                    \
        "xorl	%ebx,%r11d\n\t"			                    \
        "addl	%eax,%edx\n\t"			                    \
        "leal	-1416354905(%rcx,%r10,1),%ecx\n\t"			\
        "orl	%edx,%r11d\n\t"			                    \
        "xorl	%eax,%r11d\n\t"			                    \
        "addl	%r11d,%ecx\n\t"			                    \
        "movl	20(%rsi),%r10d\n\t"		                    \
        "movl	$0xffffffff,%r11d\n\t"	                    \
        "roll	$15,%ecx\n\t"			                    \
        "xorl	%eax,%r11d\n\t"			                    \
        "addl	%edx,%ecx\n\t"			                    \
        "leal	-57434055(%rbx,%r10,1),%ebx\n\t"			\
        "orl	%ecx,%r11d\n\t"			                    \
        "xorl	%edx,%r11d\n\t"			                    \
        "addl	%r11d,%ebx\n\t"			                    \
        "movl	48(%rsi),%r10d\n\t"		                    \
        "movl	$0xffffffff,%r11d\n\t"	                    \
        "roll	$21,%ebx\n\t"			                    \
        "xorl	%edx,%r11d\n\t"			                    \
        "addl	%ecx,%ebx\n\t"			                    \
        "leal	1700485571(%rax,%r10,1),%eax\n\t"			\
        "orl	%ebx,%r11d\n\t"			                    \
        "xorl	%ecx,%r11d\n\t"			                    \
        "addl	%r11d,%eax\n\t"			                    \
        "movl	12(%rsi),%r10d\n\t"		                    \
        "movl	$0xffffffff,%r11d\n\t"	                    \
        "roll	$6,%eax\n\t"			                    \
        "xorl	%ecx,%r11d\n\t"			                    \
        "addl	%ebx,%eax\n\t"			                    \
        "leal	-1894986606(%rdx,%r10,1),%edx\n\t"			\
        "orl	%eax,%r11d\n\t"			                    \
        "xorl	%ebx,%r11d\n\t"			                    \
        "addl	%r11d,%edx\n\t"			                    \
        "movl	40(%rsi),%r10d\n\t"		                    \
        "movl	$0xffffffff,%r11d\n\t"	                    \
        "roll	$10,%edx\n\t"			                    \
        "xorl	%ebx,%r11d\n\t"			                    \
        "addl	%eax,%edx\n\t"			                    \
        "leal	-1051523(%rcx,%r10,1),%ecx\n\t"			\
        "orl	%edx,%r11d\n\t"			                    \
        "xorl	%eax,%r11d\n\t"			                    \
        "addl	%r11d,%ecx\n\t"			                    \
        "movl	4(%rsi),%r10d\n\t"		                    \
        "movl	$0xffffffff,%r11d\n\t"	                    \
        "roll	$15,%ecx\n\t"			                    \
        "xorl	%eax,%r11d\n\t"			                    \
        "addl	%edx,%ecx\n\t"			                    \
        "leal	-2054922799(%rbx,%r10,1),%ebx\n\t"			\
        "orl	%ecx,%r11d\n\t"			                    \
        "xorl	%edx,%r11d\n\t"			                    \
        "addl	%r11d,%ebx\n\t"			                    \
        "movl	32(%rsi),%r10d\n\t"		                    \
        "movl	$0xffffffff,%r11d\n\t"	                    \
        "roll	$21,%ebx\n\t"			                    \
        "xorl	%edx,%r11d\n\t"			                    \
        "addl	%ecx,%ebx\n\t"			                    \
        "leal	1873313359(%rax,%r10,1),%eax\n\t"			\
        "orl	%ebx,%r11d\n\t"			                    \
        "xorl	%ecx,%r11d\n\t"			                    \
        "addl	%r11d,%eax\n\t"			                    \
        "movl	60(%rsi),%r10d\n\t"		                    \
        "movl	$0xffffffff,%r11d\n\t"	                    \
        "roll	$6,%eax\n\t"			                    \
        "xorl	%ecx,%r11d\n\t"			                    \
        "addl	%ebx,%eax\n\t"			                    \
        "leal	-30611744(%rdx,%r10,1),%edx\n\t"			\
        "orl	%eax,%r11d\n\t"			                    \
        "xorl	%ebx,%r11d\n\t"			                    \
        "addl	%r11d,%edx\n\t"			                    \
        "movl	24(%rsi),%r10d\n\t"		                    \
        "movl	$0xffffffff,%r11d\n\t"	                    \
        "roll	$10,%edx\n\t"			                    \
        "xorl	%ebx,%r11d\n\t"			                    \
        "addl	%eax,%edx\n\t"			                    \
        "leal	-1560198380(%rcx,%r10,1),%ecx\n\t"			\
        "orl	%edx,%r11d\n\t"			                    \
        "xorl	%eax,%r11d\n\t"			                    \
        "addl	%r11d,%ecx\n\t"			                    \
        "movl	52(%rsi),%r10d\n\t"		                    \
        "movl	$0xffffffff,%r11d\n\t"	                    \
        "roll	$15,%ecx\n\t"			                    \
        "xorl	%eax,%r11d\n\t"			                    \
        "addl	%edx,%ecx\n\t"			                    \
        "leal	1309151649(%rbx,%r10,1),%ebx\n\t"			\
        "orl	%ecx,%r11d\n\t"			                    \
        "xorl	%edx,%r11d\n\t"			                    \
        "addl	%r11d,%ebx\n\t"			                    \
        "movl	16(%rsi),%r10d\n\t"		                    \
        "movl	$0xffffffff,%r11d\n\t"	                    \
        "roll	$21,%ebx\n\t"			                    \
        "xorl	%edx,%r11d\n\t"			                    \
        "addl	%ecx,%ebx\n\t"			                    \
        "leal	-145523070(%rax,%r10,1),%eax\n\t"			\
        "orl	%ebx,%r11d\n\t"			                    \
        "xorl	%ecx,%r11d\n\t"			                    \
        "addl	%r11d,%eax\n\t"			                    \
        "movl	44(%rsi),%r10d\n\t"		                    \
        "movl	$0xffffffff,%r11d\n\t"	                    \
        "roll	$6,%eax\n\t"			                    \
        "xorl	%ecx,%r11d\n\t"			                    \
        "addl	%ebx,%eax\n\t"			                    \
        "leal	-1120210379(%rdx,%r10,1),%edx\n\t"			\
        "orl	%eax,%r11d\n\t"			                    \
        "xorl	%ebx,%r11d\n\t"			                    \
        "addl	%r11d,%edx\n\t"			                    \
        "movl	8(%rsi),%r10d\n\t"		                    \
        "movl	$0xffffffff,%r11d\n\t"	                    \
        "roll	$10,%edx\n\t"			                    \
        "xorl	%ebx,%r11d\n\t"			                    \
        "addl	%eax,%edx\n\t"			                    \
        "leal	718787259(%rcx,%r10,1),%ecx\n\t"			\
        "orl	%edx,%r11d\n\t"			                    \
        "xorl	%eax,%r11d\n\t"			                    \
        "addl	%r11d,%ecx\n\t"			                    \
        "movl	36(%rsi),%r10d\n\t"		                    \
        "movl	$0xffffffff,%r11d\n\t"	                    \
        "roll	$15,%ecx\n\t"			                    \
        "xorl	%eax,%r11d\n\t"			                    \
        "addl	%edx,%ecx\n\t"			                    \
        "leal	-343485551(%rbx,%r10,1),%ebx\n\t"			\
        "orl	%ecx,%r11d\n\t"			                    \
        "xorl	%edx,%r11d\n\t"			                    \
        "addl	%r11d,%ebx\n\t"			                    \
        "movl	0(%rsi),%r10d\n\t"		                    \
        "movl	$0xffffffff,%r11d\n\t"	                    \
        "roll	$21,%ebx\n\t"			                    \
        "xorl	%edx,%r11d\n\t"			                    \
        "addl	%ecx,%ebx\n\t"			                    \
    "\n"                                                    \
        "addl	%r8d,%eax\n\t"			                    \
        "addl	%r9d,%ebx\n\t"			                    \
        "addl	%r14d,%ecx\n\t"			                    \
        "addl	%r15d,%edx\n\t"			                    \
    "\n"                                                    \
        "addq	$64,%rsi\n\t"			                    \
        "cmpq	%rdi,%rsi\n\t"			                    \
        "jb	.Lloop				\n\t"	                    \
    "\n"                                                    \
    ".Lend:\n\t"			                                \
        "movl	%eax,0(%rbp)\n\t"		                    \
        "movl	%ebx,4(%rbp)\n\t"		                    \
        "movl	%ecx,8(%rbp)\n\t"		                    \
        "movl	%edx,12(%rbp)\n\t"		                    \
    "\n"                                                    \
        "popq	%r15\n\t"			                        \
        "popq	%r14\n\t"			                        \
        "popq	%rbx\n\t"			                        \
        "popq	%rbp\n\t"			                        \
        ".byte	0xf3,0xc3\n\t"			                    \
    ".size md5_block_asm_host_order,.-md5_block_asm_host_order\n\t"	\
);
#  endif
# endif
#endif

void md5_block_host_order (MD5_CTX *c, const void *p,size_t num);
void md5_block_data_order (MD5_CTX *c, const void *p,size_t num);

#if defined(__i386) || defined(__i386__) || defined(_M_IX86) || defined(__INTEL__) || defined(__x86_64) || defined(__x86_64__)
# if !defined(B_ENDIAN)
/*
 * *_block_host_order is expected to handle aligned data while
 * *_block_data_order - unaligned. As algorithm and host (x86)
 * are in this case of the same "endianness" these two are
 * otherwise indistinguishable. But normally you don't want to
 * call the same function because unaligned access in places
 * where alignment is expected is usually a "Bad Thing". Indeed,
 * on RISCs you get punished with BUS ERROR signal or *severe*
 * performance degradation. Intel CPUs are in turn perfectly
 * capable of loading unaligned data without such drastic side
 * effect. Yes, they say it's slower than aligned load, but no
 * exception is generated and therefore performance degradation
 * is *incomparable* with RISCs. What we should weight here is
 * costs of unaligned access against costs of aligning data.
 * According to my measurements allowing unaligned access results
 * in ~9% performance improvement on Pentium II operating at
 * 266MHz. I won't be surprised if the difference will be higher
 * on faster systems:-)
 *
 *				<appro@fy.chalmers.se>
 */
# define md5_block_data_order md5_block_host_order
# endif
#endif

#define DATA_ORDER_IS_LITTLE_ENDIAN

#define HASH_LONG		MD5_LONG
#define HASH_LONG_LOG2		MD5_LONG_LOG2
#define HASH_CTX		MD5_CTX
#define HASH_CBLOCK		MD5_CBLOCK
#define HASH_LBLOCK		MD5_LBLOCK
#define HASH_UPDATE		MD5_Update
#define HASH_TRANSFORM		MD5_Transform
#define HASH_FINAL		MD5_Final


#define	HASH_MAKE_STRING(c,s)	do {	\
	unsigned long ll;		\
	ll=(c)->A; HOST_l2c(ll,(s));	\
	ll=(c)->B; HOST_l2c(ll,(s));	\
	ll=(c)->C; HOST_l2c(ll,(s));	\
	ll=(c)->D; HOST_l2c(ll,(s));	\
	} while (0)


#define HASH_BLOCK_HOST_ORDER	md5_block_host_order
#if !defined(L_ENDIAN) || defined(md5_block_data_order)
#define	HASH_BLOCK_DATA_ORDER	md5_block_data_order
/*
 * Little-endians (Intel and Alpha) feel better without this.
 * It looks like memcpy does better job than generic
 * md5_block_data_order on copying-n-aligning input data.
 * But frankly speaking I didn't expect such result on Alpha.
 * On the other hand I've got this with egcs-1.0.2 and if
 * program is compiled with another (better?) compiler it
 * might turn out other way around.
 *
 *				<appro@fy.chalmers.se>
 */
#endif

/*
 * This is a generic 32 bit "collector" for message digest algorithms.
 * Whenever needed it collects input character stream into chunks of
 * 32 bit values and invokes a block function that performs actual hash
 * calculations.
 *
 * Porting guide.
 *
 * Obligatory macros:
 *
 * DATA_ORDER_IS_BIG_ENDIAN or DATA_ORDER_IS_LITTLE_ENDIAN
 *	this macro defines byte order of input stream.
 * HASH_CBLOCK
 *	size of a unit chunk HASH_BLOCK operates on.
 * HASH_LONG
 *	has to be at lest 32 bit wide, if it's wider, then
 *	HASH_LONG_LOG2 *has to* be defined along
 * HASH_CTX
 *	context structure that at least contains following
 *	members:
 *		typedef struct {
 *			...
 *			HASH_LONG	Nl,Nh;
 *			HASH_LONG	data[HASH_LBLOCK];
 *			unsigned int	num;
 *			...
 *			} HASH_CTX;
 * HASH_UPDATE
 *	name of "Update" function, implemented here.
 * HASH_TRANSFORM
 *	name of "Transform" function, implemented here.
 * HASH_FINAL
 *	name of "Final" function, implemented here.
 * HASH_BLOCK_HOST_ORDER
 *	name of "block" function treating *aligned* input message
 *	in host byte order, implemented externally.
 * HASH_BLOCK_DATA_ORDER
 *	name of "block" function treating *unaligned* input message
 *	in original (data) byte order, implemented externally (it
 *	actually is optional if data and host are of the same
 *	"endianess").
 * HASH_MAKE_STRING
 *	macro convering context variables to an ASCII hash string.
 *
 * Optional macros:
 *
 * B_ENDIAN or L_ENDIAN
 *	defines host byte-order.
 * HASH_LONG_LOG2
 *	defaults to 2 if not states otherwise.
 * HASH_LBLOCK
 *	assumed to be HASH_CBLOCK/4 if not stated otherwise.
 * HASH_BLOCK_DATA_ORDER_ALIGNED
 *	alternative "block" function capable of treating
 *	aligned input message in original (data) order,
 *	implemented externally.
 *
 * MD5 example:
 *
 *	#define DATA_ORDER_IS_LITTLE_ENDIAN
 *
 *	#define HASH_LONG		MD5_LONG
 *	#define HASH_LONG_LOG2		MD5_LONG_LOG2
 *	#define HASH_CTX		MD5_CTX
 *	#define HASH_CBLOCK		MD5_CBLOCK
 *	#define HASH_LBLOCK		MD5_LBLOCK
 *	#define HASH_UPDATE		MD5_Update
 *	#define HASH_TRANSFORM		MD5_Transform
 *	#define HASH_FINAL		MD5_Final
 *	#define HASH_BLOCK_HOST_ORDER	md5_block_host_order
 *	#define HASH_BLOCK_DATA_ORDER	md5_block_data_order
 *
 *					<appro@fy.chalmers.se>
 */

#if !defined(DATA_ORDER_IS_BIG_ENDIAN) && !defined(DATA_ORDER_IS_LITTLE_ENDIAN)
#error "DATA_ORDER must be defined!"
#endif

#ifndef HASH_CBLOCK
#error "HASH_CBLOCK must be defined!"
#endif
#ifndef HASH_LONG
#error "HASH_LONG must be defined!"
#endif
#ifndef HASH_CTX
#error "HASH_CTX must be defined!"
#endif

#ifndef HASH_UPDATE
#error "HASH_UPDATE must be defined!"
#endif
#ifndef HASH_TRANSFORM
#error "HASH_TRANSFORM must be defined!"
#endif
#ifndef HASH_FINAL
#error "HASH_FINAL must be defined!"
#endif

#ifndef HASH_BLOCK_HOST_ORDER
#error "HASH_BLOCK_HOST_ORDER must be defined!"
#endif

#if 0
/*
 * Moved below as it's required only if HASH_BLOCK_DATA_ORDER_ALIGNED
 * isn't defined.
 */
#ifndef HASH_BLOCK_DATA_ORDER
#error "HASH_BLOCK_DATA_ORDER must be defined!"
#endif
#endif

#ifndef HASH_LBLOCK
#define HASH_LBLOCK	(HASH_CBLOCK/4)
#endif

#ifndef HASH_LONG_LOG2
#define HASH_LONG_LOG2	2
#endif

/*
 * Engage compiler specific rotate intrinsic function if available.
 */
#undef ROTATE
#ifndef PEDANTIC
# if defined(_MSC_VER) || defined(__ICC)
#  define ROTATE(a,n)	_lrotl(a,n)
# elif defined(__MWERKS__)
#  if defined(__POWERPC__)
#   define ROTATE(a,n)	__rlwinm(a,n,0,31)
#  elif defined(__MC68K__)
    /* Motorola specific tweak. <appro@fy.chalmers.se> */
#   define ROTATE(a,n)	( n<24 ? __rol(a,n) : __ror(a,32-n) )
#  else
#   define ROTATE(a,n)	__rol(a,n)
#  endif
# elif defined(__GNUC__) && __GNUC__>=2 && !defined(OPENSSL_NO_ASM) && !defined(OPENSSL_NO_INLINE_ASM)
  /*
   * Some GNU C inline assembler templates. Note that these are
   * rotates by *constant* number of bits! But that's exactly
   * what we need here...
   * 					<appro@fy.chalmers.se>
   */
#  if defined(__i386) || defined(__i386__) || defined(__x86_64) || defined(__x86_64__)
#   define ROTATE(a,n)	({ register unsigned int ret;	\
				asm (			\
				"roll %1,%0"		\
				: "=r"(ret)		\
				: "I"(n), "0"(a)	\
				: "cc");		\
			   ret;				\
			})
#  elif defined(__powerpc) || defined(__ppc__) || defined(__powerpc64__)
#   define ROTATE(a,n)	({ register unsigned int ret;	\
				asm (			\
				"rlwinm %0,%1,%2,0,31"	\
				: "=r"(ret)		\
				: "r"(a), "I"(n));	\
			   ret;				\
			})
#  endif
# endif
#endif /* PEDANTIC */

#if HASH_LONG_LOG2==2	/* Engage only if sizeof(HASH_LONG)== 4 */
/* A nice byte order reversal from Wei Dai <weidai@eskimo.com> */
#ifdef ROTATE
/* 5 instructions with rotate instruction, else 9 */
#define REVERSE_FETCH32(a,l)	(					\
		l=*(const HASH_LONG *)(a),				\
		((ROTATE(l,8)&0x00FF00FF)|(ROTATE((l&0x00FF00FF),24)))	\
				)
#else
/* 6 instructions with rotate instruction, else 8 */
#define REVERSE_FETCH32(a,l)	(				\
		l=*(const HASH_LONG *)(a),			\
		l=(((l>>8)&0x00FF00FF)|((l&0x00FF00FF)<<8)),	\
		ROTATE(l,16)					\
				)
/*
 * Originally the middle line started with l=(((l&0xFF00FF00)>>8)|...
 * It's rewritten as above for two reasons:
 *	- RISCs aren't good at long constants and have to explicitely
 *	  compose 'em with several (well, usually 2) instructions in a
 *	  register before performing the actual operation and (as you
 *	  already realized:-) having same constant should inspire the
 *	  compiler to permanently allocate the only register for it;
 *	- most modern CPUs have two ALUs, but usually only one has
 *	  circuitry for shifts:-( this minor tweak inspires compiler
 *	  to schedule shift instructions in a better way...
 *
 *				<appro@fy.chalmers.se>
 */
#endif
#endif

#ifndef ROTATE
#define ROTATE(a,n)     (((a)<<(n))|(((a)&0xffffffff)>>(32-(n))))
#endif

/*
 * Make some obvious choices. E.g., HASH_BLOCK_DATA_ORDER_ALIGNED
 * and HASH_BLOCK_HOST_ORDER ought to be the same if input data
 * and host are of the same "endianess". It's possible to mask
 * this with blank #define HASH_BLOCK_DATA_ORDER though...
 *
 *				<appro@fy.chalmers.se>
 */
#if defined(B_ENDIAN)
#  if defined(DATA_ORDER_IS_BIG_ENDIAN)
#    if !defined(HASH_BLOCK_DATA_ORDER_ALIGNED) && HASH_LONG_LOG2==2
#      define HASH_BLOCK_DATA_ORDER_ALIGNED	HASH_BLOCK_HOST_ORDER
#    endif
#  endif
#elif defined(L_ENDIAN)
#  if defined(DATA_ORDER_IS_LITTLE_ENDIAN)
#    if !defined(HASH_BLOCK_DATA_ORDER_ALIGNED) && HASH_LONG_LOG2==2
#      define HASH_BLOCK_DATA_ORDER_ALIGNED	HASH_BLOCK_HOST_ORDER
#    endif
#  endif
#endif

#if !defined(HASH_BLOCK_DATA_ORDER_ALIGNED)
#ifndef HASH_BLOCK_DATA_ORDER
#error "HASH_BLOCK_DATA_ORDER must be defined!"
#endif
#endif

#if defined(DATA_ORDER_IS_BIG_ENDIAN)

#ifndef PEDANTIC
# if defined(__GNUC__) && __GNUC__>=2 && !defined(OPENSSL_NO_ASM) && !defined(OPENSSL_NO_INLINE_ASM)
#  if ((defined(__i386) || defined(__i386__)) && !defined(I386_ONLY)) || \
      (defined(__x86_64) || defined(__x86_64__))
    /*
     * This gives ~30-40% performance improvement in SHA-256 compiled
     * with gcc [on P4]. Well, first macro to be frank. We can pull
     * this trick on x86* platforms only, because these CPUs can fetch
     * unaligned data without raising an exception.
     */
#   define HOST_c2l(c,l)	({ unsigned int r=*((const unsigned int *)(c));	\
				   asm ("bswapl %0":"=r"(r):"0"(r));	\
				   (c)+=4; (l)=r;			})
#   define HOST_l2c(l,c)	({ unsigned int r=(l);			\
				   asm ("bswapl %0":"=r"(r):"0"(r));	\
				   *((unsigned int *)(c))=r; (c)+=4; r;	})
#  endif
# endif
#endif

#ifndef HOST_c2l
#define HOST_c2l(c,l)	(l =(((unsigned long)(*((c)++)))<<24),		\
			 l|=(((unsigned long)(*((c)++)))<<16),		\
			 l|=(((unsigned long)(*((c)++)))<< 8),		\
			 l|=(((unsigned long)(*((c)++)))    ),		\
			 l)
#endif
#define HOST_p_c2l(c,l,n)	{					\
			switch (n) {					\
			case 0: l =((unsigned long)(*((c)++)))<<24;	\
			case 1: l|=((unsigned long)(*((c)++)))<<16;	\
			case 2: l|=((unsigned long)(*((c)++)))<< 8;	\
			case 3: l|=((unsigned long)(*((c)++)));		\
				} }
#define HOST_p_c2l_p(c,l,sc,len) {					\
			switch (sc) {					\
			case 0: l =((unsigned long)(*((c)++)))<<24;	\
				if (--len == 0) break;			\
			case 1: l|=((unsigned long)(*((c)++)))<<16;	\
				if (--len == 0) break;			\
			case 2: l|=((unsigned long)(*((c)++)))<< 8;	\
				} }
/* NOTE the pointer is not incremented at the end of this */
#define HOST_c2l_p(c,l,n)	{					\
			l=0; (c)+=n;					\
			switch (n) {					\
			case 3: l =((unsigned long)(*(--(c))))<< 8;	\
			case 2: l|=((unsigned long)(*(--(c))))<<16;	\
			case 1: l|=((unsigned long)(*(--(c))))<<24;	\
				} }
#ifndef HOST_l2c
#define HOST_l2c(l,c)	(*((c)++)=(unsigned char)(((l)>>24)&0xff),	\
			 *((c)++)=(unsigned char)(((l)>>16)&0xff),	\
			 *((c)++)=(unsigned char)(((l)>> 8)&0xff),	\
			 *((c)++)=(unsigned char)(((l)    )&0xff),	\
			 l)
#endif

#elif defined(DATA_ORDER_IS_LITTLE_ENDIAN)

#if defined(__i386) || defined(__i386__) || defined(__x86_64) || defined(__x86_64__)
# ifndef B_ENDIAN
   /* See comment in DATA_ORDER_IS_BIG_ENDIAN section. */
#  define HOST_c2l(c,l)	((l)=*((const unsigned int *)(c)), (c)+=4, l)
#  define HOST_l2c(l,c)	(*((unsigned int *)(c))=(l), (c)+=4, l)
# endif
#endif

#ifndef HOST_c2l
#define HOST_c2l(c,l)	(l =(((unsigned long)(*((c)++)))    ),		\
			 l|=(((unsigned long)(*((c)++)))<< 8),		\
			 l|=(((unsigned long)(*((c)++)))<<16),		\
			 l|=(((unsigned long)(*((c)++)))<<24),		\
			 l)
#endif
#define HOST_p_c2l(c,l,n)	{					\
			switch (n) {					\
			case 0: l =((unsigned long)(*((c)++)));		\
			case 1: l|=((unsigned long)(*((c)++)))<< 8;	\
			case 2: l|=((unsigned long)(*((c)++)))<<16;	\
			case 3: l|=((unsigned long)(*((c)++)))<<24;	\
				} }
#define HOST_p_c2l_p(c,l,sc,len) {					\
			switch (sc) {					\
			case 0: l =((unsigned long)(*((c)++)));		\
				if (--len == 0) break;			\
			case 1: l|=((unsigned long)(*((c)++)))<< 8;	\
				if (--len == 0) break;			\
			case 2: l|=((unsigned long)(*((c)++)))<<16;	\
				} }
/* NOTE the pointer is not incremented at the end of this */
#define HOST_c2l_p(c,l,n)	{					\
			l=0; (c)+=n;					\
			switch (n) {					\
			case 3: l =((unsigned long)(*(--(c))))<<16;	\
			case 2: l|=((unsigned long)(*(--(c))))<< 8;	\
			case 1: l|=((unsigned long)(*(--(c))));		\
				} }
#ifndef HOST_l2c
#define HOST_l2c(l,c)	(*((c)++)=(unsigned char)(((l)    )&0xff),	\
			 *((c)++)=(unsigned char)(((l)>> 8)&0xff),	\
			 *((c)++)=(unsigned char)(((l)>>16)&0xff),	\
			 *((c)++)=(unsigned char)(((l)>>24)&0xff),	\
			 l)
#endif

#endif

/*
 * Time for some action:-)
 */

int HASH_UPDATE (HASH_CTX *c, const void *data_, size_t len)
	{
	const unsigned char *data=data_;
	register HASH_LONG * p;
	register HASH_LONG l;
	size_t sw,sc,ew,ec;

	if (len==0) return 1;

	l=(c->Nl+(((HASH_LONG)len)<<3))&0xffffffffUL;
	/* 95-05-24 eay Fixed a bug with the overflow handling, thanks to
	 * Wei Dai <weidai@eskimo.com> for pointing it out. */
	if (l < c->Nl) /* overflow */
		c->Nh++;
	c->Nh+=(len>>29);	/* might cause compiler warning on 16-bit */
	c->Nl=l;

	if (c->num != 0)
		{
		p=c->data;
		sw=c->num>>2;
		sc=c->num&0x03;

		if ((c->num+len) >= HASH_CBLOCK)
			{
			l=p[sw]; HOST_p_c2l(data,l,sc); p[sw++]=l;
			for (; sw<HASH_LBLOCK; sw++)
				{
				HOST_c2l(data,l); p[sw]=l;
				}
			HASH_BLOCK_HOST_ORDER (c,p,1);
			len-=(HASH_CBLOCK-c->num);
			c->num=0;
			/* drop through and do the rest */
			}
		else
			{
			c->num+=(unsigned int)len;
			if ((sc+len) < 4) /* ugly, add char's to a word */
				{
				l=p[sw]; HOST_p_c2l_p(data,l,sc,len); p[sw]=l;
				}
			else
				{
				ew=(c->num>>2);
				ec=(c->num&0x03);
				if (sc)
					l=p[sw];
				HOST_p_c2l(data,l,sc);
				p[sw++]=l;
				for (; sw < ew; sw++)
					{
					HOST_c2l(data,l); p[sw]=l;
					}
				if (ec)
					{
					HOST_c2l_p(data,l,ec); p[sw]=l;
					}
				}
			return 1;
			}
		}

	sw=len/HASH_CBLOCK;
	if (sw > 0)
		{
#if defined(HASH_BLOCK_DATA_ORDER_ALIGNED)
		/*
		 * Note that HASH_BLOCK_DATA_ORDER_ALIGNED gets defined
		 * only if sizeof(HASH_LONG)==4.
		 */
		if ((((size_t)data)%4) == 0)
			{
			/* data is properly aligned so that we can cast it: */
			HASH_BLOCK_DATA_ORDER_ALIGNED (c,(const HASH_LONG *)data,sw);
			sw*=HASH_CBLOCK;
			data+=sw;
			len-=sw;
			}
		else
#if !defined(HASH_BLOCK_DATA_ORDER)
			while (sw--)
				{
				memcpy (p=c->data,data,HASH_CBLOCK);
				HASH_BLOCK_DATA_ORDER_ALIGNED(c,p,1);
				data+=HASH_CBLOCK;
				len-=HASH_CBLOCK;
				}
#endif
#endif
#if defined(HASH_BLOCK_DATA_ORDER)
			{
			HASH_BLOCK_DATA_ORDER(c,data,sw);
			sw*=HASH_CBLOCK;
			data+=sw;
			len-=sw;
			}
#endif
		}

	if (len!=0)
		{
		p = c->data;
		c->num = len;
		ew=len>>2;	/* words to copy */
		ec=len&0x03;
		for (; ew; ew--,p++)
			{
			HOST_c2l(data,l); *p=l;
			}
		HOST_c2l_p(data,l,ec);
		*p=l;
		}
	return 1;
	}


void HASH_TRANSFORM (HASH_CTX *c, const unsigned char *data)
	{
#if defined(HASH_BLOCK_DATA_ORDER_ALIGNED)
	if ((((size_t)data)%4) == 0)
		/* data is properly aligned so that we can cast it: */
		HASH_BLOCK_DATA_ORDER_ALIGNED (c,(const HASH_LONG *)data,1);
	else
#if !defined(HASH_BLOCK_DATA_ORDER)
		{
		memcpy (c->data,data,HASH_CBLOCK);
		HASH_BLOCK_DATA_ORDER_ALIGNED (c,c->data,1);
		}
#endif
#endif
#if defined(HASH_BLOCK_DATA_ORDER)
	HASH_BLOCK_DATA_ORDER (c,data,1);
#endif
	}


int HASH_FINAL (unsigned char *md, HASH_CTX *c)
	{
	register HASH_LONG *p;
	register unsigned long l;
	register int i,j;
	static const unsigned char end[4]={0x80,0x00,0x00,0x00};
	const unsigned char *cp=end;

	/* c->num should definitly have room for at least one more byte. */
	p=c->data;
	i=c->num>>2;
	j=c->num&0x03;

#if 0
	/* purify often complains about the following line as an
	 * Uninitialized Memory Read.  While this can be true, the
	 * following p_c2l macro will reset l when that case is true.
	 * This is because j&0x03 contains the number of 'valid' bytes
	 * already in p[i].  If and only if j&0x03 == 0, the UMR will
	 * occur but this is also the only time p_c2l will do
	 * l= *(cp++) instead of l|= *(cp++)
	 * Many thanks to Alex Tang <altitude@cic.net> for pickup this
	 * 'potential bug' */
#ifdef PURIFY
	if (j==0) p[i]=0; /* Yeah, but that's not the way to fix it:-) */
#endif
	l=p[i];
#else
	l = (j==0) ? 0 : p[i];
#endif
	HOST_p_c2l(cp,l,j); p[i++]=l; /* i is the next 'undefined word' */

	if (i>(HASH_LBLOCK-2)) /* save room for Nl and Nh */
		{
		if (i<HASH_LBLOCK) p[i]=0;
		HASH_BLOCK_HOST_ORDER (c,p,1);
		i=0;
		}
	for (; i<(HASH_LBLOCK-2); i++)
		p[i]=0;

#if   defined(DATA_ORDER_IS_BIG_ENDIAN)
	p[HASH_LBLOCK-2]=c->Nh;
	p[HASH_LBLOCK-1]=c->Nl;
#elif defined(DATA_ORDER_IS_LITTLE_ENDIAN)
	p[HASH_LBLOCK-2]=c->Nl;
	p[HASH_LBLOCK-1]=c->Nh;
#endif
	HASH_BLOCK_HOST_ORDER (c,p,1);

#ifndef HASH_MAKE_STRING
#error "HASH_MAKE_STRING must be defined!"
#else

/* Windows kernel compiler hates do...while(0) loops.  Rather than goof with macros
 * just tell it to shut up */
#if defined(WINDOWS_KERNEL) || defined(WINDOWS_USER)
    #pragma warning(push)
    #pragma warning(disable:4127)   /* constant conditional expr just fine here */
#endif /* WINDOWS */

	HASH_MAKE_STRING(c,md);

#if defined(WINDOWS_KERNEL) || defined(WINDOWS_USER)
    #pragma warning(pop)
#endif /* WINDOWS */


#endif

	c->num=0;
    /* clear stuff, HASH_BLOCK may be leaving some stuff on the stack
     * but I'm not worried :-)
    OPENSSL_cleanse((void *)c,sizeof(HASH_CTX));
     */
	return 1;
	}

#ifndef MD32_REG_T
#define MD32_REG_T long
/*
 * This comment was originaly written for MD5, which is why it
 * discusses A-D. But it basically applies to all 32-bit digests,
 * which is why it was moved to common header file.
 *
 * In case you wonder why A-D are declared as long and not
 * as MD5_LONG. Doing so results in slight performance
 * boost on LP64 architectures. The catch is we don't
 * really care if 32 MSBs of a 64-bit register get polluted
 * with eventual overflows as we *save* only 32 LSBs in
 * *either* case. Now declaring 'em long excuses the compiler
 * from keeping 32 MSBs zeroed resulting in 13% performance
 * improvement under SPARC Solaris7/64 and 5% under AlphaLinux.
 * Well, to be honest it should say that this *prevents* 
 * performance degradation.
 *				<appro@fy.chalmers.se>
 * Apparently there're LP64 compilers that generate better
 * code if A-D are declared int. Most notably GCC-x86_64
 * generates better code.
 *				<appro@fy.chalmers.se>
 */
#endif

/*
#define	F(x,y,z)	(((x) & (y))  |  ((~(x)) & (z)))
#define	G(x,y,z)	(((x) & (z))  |  ((y) & (~(z))))
*/

/* As pointed out by Wei Dai <weidai@eskimo.com>, the above can be
 * simplified to the code below.  Wei attributes these optimizations
 * to Peter Gutmann's SHS code, and he attributes it to Rich Schroeppel.
 */
#define	F(b,c,d)	((((c) ^ (d)) & (b)) ^ (d))
#define	G(b,c,d)	((((b) ^ (c)) & (d)) ^ (c))
#define	H(b,c,d)	((b) ^ (c) ^ (d))
#define	I(b,c,d)	(((~(d)) | (b)) ^ (c))

#define R0(a,b,c,d,k,s,t) { \
	a+=((k)+(t)+F((b),(c),(d))); \
	a=ROTATE(a,s); \
	a+=b; };\

#define R1(a,b,c,d,k,s,t) { \
	a+=((k)+(t)+G((b),(c),(d))); \
	a=ROTATE(a,s); \
	a+=b; };

#define R2(a,b,c,d,k,s,t) { \
	a+=((k)+(t)+H((b),(c),(d))); \
	a=ROTATE(a,s); \
	a+=b; };

#define R3(a,b,c,d,k,s,t) { \
	a+=((k)+(t)+I((b),(c),(d))); \
	a=ROTATE(a,s); \
	a+=b; };

#define INIT_DATA_A (unsigned long)0x67452301L
#define INIT_DATA_B (unsigned long)0xefcdab89L
#define INIT_DATA_C (unsigned long)0x98badcfeL
#define INIT_DATA_D (unsigned long)0x10325476L

void MD5_Init(MD5_CTX *c)
	{
	c->A=INIT_DATA_A;
	c->B=INIT_DATA_B;
	c->C=INIT_DATA_C;
	c->D=INIT_DATA_D;
	c->Nl=0;
	c->Nh=0;
	c->num=0;
	}

#ifndef md5_block_host_order
void md5_block_host_order (MD5_CTX *c, const void *data, size_t num)
	{
	const MD5_LONG *X=data;
	register unsigned MD32_REG_T A,B,C,D;

	A=c->A;
	B=c->B;
	C=c->C;
	D=c->D;

	for (;num--;X+=HASH_LBLOCK)
		{
	/* Round 0 */
	R0(A,B,C,D,X[ 0], 7,0xd76aa478L);
	R0(D,A,B,C,X[ 1],12,0xe8c7b756L);
	R0(C,D,A,B,X[ 2],17,0x242070dbL);
	R0(B,C,D,A,X[ 3],22,0xc1bdceeeL);
	R0(A,B,C,D,X[ 4], 7,0xf57c0fafL);
	R0(D,A,B,C,X[ 5],12,0x4787c62aL);
	R0(C,D,A,B,X[ 6],17,0xa8304613L);
	R0(B,C,D,A,X[ 7],22,0xfd469501L);
	R0(A,B,C,D,X[ 8], 7,0x698098d8L);
	R0(D,A,B,C,X[ 9],12,0x8b44f7afL);
	R0(C,D,A,B,X[10],17,0xffff5bb1L);
	R0(B,C,D,A,X[11],22,0x895cd7beL);
	R0(A,B,C,D,X[12], 7,0x6b901122L);
	R0(D,A,B,C,X[13],12,0xfd987193L);
	R0(C,D,A,B,X[14],17,0xa679438eL);
	R0(B,C,D,A,X[15],22,0x49b40821L);
	/* Round 1 */
	R1(A,B,C,D,X[ 1], 5,0xf61e2562L);
	R1(D,A,B,C,X[ 6], 9,0xc040b340L);
	R1(C,D,A,B,X[11],14,0x265e5a51L);
	R1(B,C,D,A,X[ 0],20,0xe9b6c7aaL);
	R1(A,B,C,D,X[ 5], 5,0xd62f105dL);
	R1(D,A,B,C,X[10], 9,0x02441453L);
	R1(C,D,A,B,X[15],14,0xd8a1e681L);
	R1(B,C,D,A,X[ 4],20,0xe7d3fbc8L);
	R1(A,B,C,D,X[ 9], 5,0x21e1cde6L);
	R1(D,A,B,C,X[14], 9,0xc33707d6L);
	R1(C,D,A,B,X[ 3],14,0xf4d50d87L);
	R1(B,C,D,A,X[ 8],20,0x455a14edL);
	R1(A,B,C,D,X[13], 5,0xa9e3e905L);
	R1(D,A,B,C,X[ 2], 9,0xfcefa3f8L);
	R1(C,D,A,B,X[ 7],14,0x676f02d9L);
	R1(B,C,D,A,X[12],20,0x8d2a4c8aL);
	/* Round 2 */
	R2(A,B,C,D,X[ 5], 4,0xfffa3942L);
	R2(D,A,B,C,X[ 8],11,0x8771f681L);
	R2(C,D,A,B,X[11],16,0x6d9d6122L);
	R2(B,C,D,A,X[14],23,0xfde5380cL);
	R2(A,B,C,D,X[ 1], 4,0xa4beea44L);
	R2(D,A,B,C,X[ 4],11,0x4bdecfa9L);
	R2(C,D,A,B,X[ 7],16,0xf6bb4b60L);
	R2(B,C,D,A,X[10],23,0xbebfbc70L);
	R2(A,B,C,D,X[13], 4,0x289b7ec6L);
	R2(D,A,B,C,X[ 0],11,0xeaa127faL);
	R2(C,D,A,B,X[ 3],16,0xd4ef3085L);
	R2(B,C,D,A,X[ 6],23,0x04881d05L);
	R2(A,B,C,D,X[ 9], 4,0xd9d4d039L);
	R2(D,A,B,C,X[12],11,0xe6db99e5L);
	R2(C,D,A,B,X[15],16,0x1fa27cf8L);
	R2(B,C,D,A,X[ 2],23,0xc4ac5665L);
	/* Round 3 */
	R3(A,B,C,D,X[ 0], 6,0xf4292244L);
	R3(D,A,B,C,X[ 7],10,0x432aff97L);
	R3(C,D,A,B,X[14],15,0xab9423a7L);
	R3(B,C,D,A,X[ 5],21,0xfc93a039L);
	R3(A,B,C,D,X[12], 6,0x655b59c3L);
	R3(D,A,B,C,X[ 3],10,0x8f0ccc92L);
	R3(C,D,A,B,X[10],15,0xffeff47dL);
	R3(B,C,D,A,X[ 1],21,0x85845dd1L);
	R3(A,B,C,D,X[ 8], 6,0x6fa87e4fL);
	R3(D,A,B,C,X[15],10,0xfe2ce6e0L);
	R3(C,D,A,B,X[ 6],15,0xa3014314L);
	R3(B,C,D,A,X[13],21,0x4e0811a1L);
	R3(A,B,C,D,X[ 4], 6,0xf7537e82L);
	R3(D,A,B,C,X[11],10,0xbd3af235L);
	R3(C,D,A,B,X[ 2],15,0x2ad7d2bbL);
	R3(B,C,D,A,X[ 9],21,0xeb86d391L);

	A = c->A += A;
	B = c->B += B;
	C = c->C += C;
	D = c->D += D;
		}
	}
#endif

#ifndef md5_block_data_order
#ifdef X
#undef X
#endif
void md5_block_data_order (MD5_CTX *c, const void *data_, size_t num)
	{
	const unsigned char *data=data_;
	register unsigned MD32_REG_T A,B,C,D,l;
#ifndef MD32_XARRAY
	/* See comment in crypto/sha/sha_locl.h for details. */
	unsigned MD32_REG_T	XX0, XX1, XX2, XX3, XX4, XX5, XX6, XX7,
				XX8, XX9,XX10,XX11,XX12,XX13,XX14,XX15;
# define X(i)	XX##i
#else
	MD5_LONG XX[MD5_LBLOCK];
# define X(i)	XX[i]
#endif

	A=c->A;
	B=c->B;
	C=c->C;
	D=c->D;

	for (;num--;)
		{
	HOST_c2l(data,l); X( 0)=l;		HOST_c2l(data,l); X( 1)=l;
	/* Round 0 */
	R0(A,B,C,D,X( 0), 7,0xd76aa478L);	HOST_c2l(data,l); X( 2)=l;
	R0(D,A,B,C,X( 1),12,0xe8c7b756L);	HOST_c2l(data,l); X( 3)=l;
	R0(C,D,A,B,X( 2),17,0x242070dbL);	HOST_c2l(data,l); X( 4)=l;
	R0(B,C,D,A,X( 3),22,0xc1bdceeeL);	HOST_c2l(data,l); X( 5)=l;
	R0(A,B,C,D,X( 4), 7,0xf57c0fafL);	HOST_c2l(data,l); X( 6)=l;
	R0(D,A,B,C,X( 5),12,0x4787c62aL);	HOST_c2l(data,l); X( 7)=l;
	R0(C,D,A,B,X( 6),17,0xa8304613L);	HOST_c2l(data,l); X( 8)=l;
	R0(B,C,D,A,X( 7),22,0xfd469501L);	HOST_c2l(data,l); X( 9)=l;
	R0(A,B,C,D,X( 8), 7,0x698098d8L);	HOST_c2l(data,l); X(10)=l;
	R0(D,A,B,C,X( 9),12,0x8b44f7afL);	HOST_c2l(data,l); X(11)=l;
	R0(C,D,A,B,X(10),17,0xffff5bb1L);	HOST_c2l(data,l); X(12)=l;
	R0(B,C,D,A,X(11),22,0x895cd7beL);	HOST_c2l(data,l); X(13)=l;
	R0(A,B,C,D,X(12), 7,0x6b901122L);	HOST_c2l(data,l); X(14)=l;
	R0(D,A,B,C,X(13),12,0xfd987193L);	HOST_c2l(data,l); X(15)=l;
	R0(C,D,A,B,X(14),17,0xa679438eL);
	R0(B,C,D,A,X(15),22,0x49b40821L);
	/* Round 1 */
	R1(A,B,C,D,X( 1), 5,0xf61e2562L);
	R1(D,A,B,C,X( 6), 9,0xc040b340L);
	R1(C,D,A,B,X(11),14,0x265e5a51L);
	R1(B,C,D,A,X( 0),20,0xe9b6c7aaL);
	R1(A,B,C,D,X( 5), 5,0xd62f105dL);
	R1(D,A,B,C,X(10), 9,0x02441453L);
	R1(C,D,A,B,X(15),14,0xd8a1e681L);
	R1(B,C,D,A,X( 4),20,0xe7d3fbc8L);
	R1(A,B,C,D,X( 9), 5,0x21e1cde6L);
	R1(D,A,B,C,X(14), 9,0xc33707d6L);
	R1(C,D,A,B,X( 3),14,0xf4d50d87L);
	R1(B,C,D,A,X( 8),20,0x455a14edL);
	R1(A,B,C,D,X(13), 5,0xa9e3e905L);
	R1(D,A,B,C,X( 2), 9,0xfcefa3f8L);
	R1(C,D,A,B,X( 7),14,0x676f02d9L);
	R1(B,C,D,A,X(12),20,0x8d2a4c8aL);
	/* Round 2 */
	R2(A,B,C,D,X( 5), 4,0xfffa3942L);
	R2(D,A,B,C,X( 8),11,0x8771f681L);
	R2(C,D,A,B,X(11),16,0x6d9d6122L);
	R2(B,C,D,A,X(14),23,0xfde5380cL);
	R2(A,B,C,D,X( 1), 4,0xa4beea44L);
	R2(D,A,B,C,X( 4),11,0x4bdecfa9L);
	R2(C,D,A,B,X( 7),16,0xf6bb4b60L);
	R2(B,C,D,A,X(10),23,0xbebfbc70L);
	R2(A,B,C,D,X(13), 4,0x289b7ec6L);
	R2(D,A,B,C,X( 0),11,0xeaa127faL);
	R2(C,D,A,B,X( 3),16,0xd4ef3085L);
	R2(B,C,D,A,X( 6),23,0x04881d05L);
	R2(A,B,C,D,X( 9), 4,0xd9d4d039L);
	R2(D,A,B,C,X(12),11,0xe6db99e5L);
	R2(C,D,A,B,X(15),16,0x1fa27cf8L);
	R2(B,C,D,A,X( 2),23,0xc4ac5665L);
	/* Round 3 */
	R3(A,B,C,D,X( 0), 6,0xf4292244L);
	R3(D,A,B,C,X( 7),10,0x432aff97L);
	R3(C,D,A,B,X(14),15,0xab9423a7L);
	R3(B,C,D,A,X( 5),21,0xfc93a039L);
	R3(A,B,C,D,X(12), 6,0x655b59c3L);
	R3(D,A,B,C,X( 3),10,0x8f0ccc92L);
	R3(C,D,A,B,X(10),15,0xffeff47dL);
	R3(B,C,D,A,X( 1),21,0x85845dd1L);
	R3(A,B,C,D,X( 8), 6,0x6fa87e4fL);
	R3(D,A,B,C,X(15),10,0xfe2ce6e0L);
	R3(C,D,A,B,X( 6),15,0xa3014314L);
	R3(B,C,D,A,X(13),21,0x4e0811a1L);
	R3(A,B,C,D,X( 4), 6,0xf7537e82L);
	R3(D,A,B,C,X(11),10,0xbd3af235L);
	R3(C,D,A,B,X( 2),15,0x2ad7d2bbL);
	R3(B,C,D,A,X( 9),21,0xeb86d391L);

	A = c->A += A;
	B = c->B += B;
	C = c->C += C;
	D = c->D += D;
		}
	}
#endif

void MD5(const unsigned char *d, size_t n, unsigned char *md)
	{
	MD5_CTX c;
	static unsigned char m[MD5_DIGEST_LENGTH];

	if (md == NULL) md=m;
	MD5_Init(&c);
	MD5_Update(&c,d,n);
	MD5_Final(md,&c);
    /*
     * RNA: The following line is commented out, because there's no security
     * issue for our usage (we're computing the hash of a known pathname for
     * MD selection and hash table lookup purposes) and it adds significant
     * overhead.
     *
     * OPENSSL_cleanse(&c,sizeof(c)); // security consideration
     *
     */
	}

#ifdef __KERNEL__
/* EXPORTED SYMBOLS */

EXPORT_SYMBOL(MD5_Init);
EXPORT_SYMBOL(MD5_Update);
EXPORT_SYMBOL(MD5_Final);
EXPORT_SYMBOL(MD5);
EXPORT_SYMBOL(MD5_Transform);

/* MODULE REGISTRATION */

MODULE_LICENSE("GPL");

#endif // __KERNEL__
