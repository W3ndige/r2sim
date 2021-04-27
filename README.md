# r2sim

Hacked script to show similarities between two samples using radare2 framework. 

## Setup

**Step 1:** clone the repo.

```
git clone https://github.com/W3ndige/r2sim
```

**Step 2:** cd into the repo.

```
cd r2sim
```

**Step 3:** install package.

```
pip install .
```


## Usage

Usage guide.

```
Usage: r2sim [OPTIONS] FILENAME_1 FILENAME_2

Options:
  -d, --diff  Switch for printing diffs between matching functions.
  --help      Show this message and exit.
```

## Examples

```
r2sim generic.wannacry.win_dll.0b352401619b8b6375dd37ba94a8b73526f428631ac12145858a94ce354b5ddc generic.wannacry.win_dll.0bf03d84ce97a6f5efa5fee889cc6de6ef892a0312fdbbdc1aafc7ed87ca574a
INFO:root:File generic.wannacry.win_dll.0b352401619b8b6375dd37ba94a8b73526f428631ac12145858a94ce354b5ddc contains 4 functions
INFO:root:File generic.wannacry.win_dll.0bf03d84ce97a6f5efa5fee889cc6de6ef892a0312fdbbdc1aafc7ed87ca574a contains 4 functions
INFO:r2sim:Functions entry0 and entry0 are similar with score 1.0
INFO:r2sim:Functions fcn.10001016 and fcn.10001016 are similar with score 1.0
INFO:r2sim:Functions fcn.100010ab and fcn.100010ab are similar with score 1.0
INFO:r2sim:Functions fcn.1000113e and fcn.1000113e are similar with score 1.0
INFO:r2sim:Number of matching functions: 4
```

Example of diff between functions.

```
INFO:r2sim:Printing diff between fcn.0040efdf and fcn.0040be37
        --- fcn.0040efdf

        +++ fcn.0040be37

        @@ -2,7 +2,7 @@

         push ebp
         mov ebp, esp
         sub esp, 0x20
        -mov eax, dword [0x41a110]
        +mov eax, dword [0x42e260]
         xor eax, ebp
         mov dword [ebp - 4], eax
         push ebx
        @@ -10,131 +10,135 @@

         push esi
         mov esi, dword [ebp + 8]
         push edi
        -call 0x40ef63
        +call 0x40bdbb
         mov edi, eax
         xor esi, esi
         mov dword [ebp + 8], edi
          
         ...
          
         xor eax, eax
         movzx ecx, ax
        @@ -145,15 +149,15 @@

         stosd dword es:[edi], eax
         stosd dword es:[edi], eax
         stosd dword es:[edi], eax
        -jmp 0x40f151
        -cmp dword [0x41c070], esi
        -jne 0x40f00a
        +jmp 0x40bfa6
        +cmp dword [0x4303d0], esi
        +jne 0x40be62
         or eax, 0xffffffff
         mov ecx, dword [ebp - 4]
         pop edi
         pop esi
         xor ecx, ebp
         pop ebx
        -call 0x4074d1
        +call 0x4054b3
         leave
         ret
```

