# Native Bridge

PWA probes http://127.0.0.1:51820/health with 1000ms timeout.
If responds: isMock=false, delegate to /status and /command.
If not: isMock=true.
