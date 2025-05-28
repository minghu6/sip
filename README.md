
## Debug

### Run LLDB Server

In `${workspaceFolder}`

`sudo lldb-server platform --server --listen 0.0.0.0:8081`

### Send Signal to CodeLLDB Target program

LLDB Debug Console:

`process signal SIGINT`
