;;
;;  startup.asm
;;  polycypt
;;
;;  Created by logic.yan on 16/3/28.
;;  Copyright © 2016年 nagain. All rights reserved.
;;

@_start:
;; read io port 0 data size
mov r4, 0
int 2
;; if r5 is 0, then exit
cmp r5, 0
je @exit
;; r5 is data len, algin 4 bytes
;; ~3u & (3 + v)
mov r7, r5
add r7, 3
mov r6, 3
not r6
and r7, r6
;; alloc memory
sub sp, r7
int 0

;; algorithm
call @algorithm

@output2io:
;; write data to io port 0 after encrypt sp to encrypt data r5 is cipher data len
mov r4, 0
int 1
;; set output io 0 data len
mov r4, 0
int 3
;; exit
@exit:
;; free memory
add sp, r7
int 9
