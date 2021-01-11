# eofstrip

Extracts data appended to PE files (malware config, etc)

## Compiling

Compile using
```
gcc eofstrip.c -std=c99
```
## Usage
```
eofstrip <input.exe> [output]
default [output] is <input.exe>.eof
```
![Sample eofstrip output](https://i.imgur.com/dMpBCpK.png)
