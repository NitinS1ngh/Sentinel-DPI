#!/bin/bash
cat << 'LLDB_CMDS' > lldb_script.txt
run
bt all
quit
LLDB_CMDS
lldb -s lldb_script.txt ./build/backend/sentineldpi -- en0
