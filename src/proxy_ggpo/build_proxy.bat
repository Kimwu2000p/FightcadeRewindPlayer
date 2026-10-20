@echo off
gcc -m32 -shared -O2 proxy_ggpo.c ggponet.def -o ggponet.dll -lws2_32
pause

