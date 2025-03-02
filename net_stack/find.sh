#!/bin/bash
ADDR=ffff8000813b9cc8  # 입력: 특정 커널 함수 주소
SYM_FILE="/proc/kallsyms"

# 가장 가까운(작거나 같은) 함수 찾기
SYM_LINE=$(awk -v addr="$ADDR" '$1 <= addr { last=$0 } END { print last }' $SYM_FILE)

# 함수 이름과 기본 주소 추출
SYM_ADDR=$(echo $SYM_LINE | awk '{print $1}')
SYM_NAME=$(echo $SYM_LINE | awk '{print $3}')

# 오프셋 계산
OFFSET=$(( 0x$ADDR - 0x$SYM_ADDR ))

echo "Address: $ADDR"
echo "Function: $SYM_NAME + 0x$(printf "%x" $OFFSET)"