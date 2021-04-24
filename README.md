# r2sim

Hacked script to show similarities between two samples using radare2 framework. 


## Usage



```
python r2sim generic.wannacry.win_dll.0b352401619b8b6375dd37ba94a8b73526f428631ac12145858a94ce354b5ddc generic.wannacry.win_dll.28bd6f6c1958e833685188e58afeb6177691d18b3915ee2bb85b98e72aaa0452
[*] Analyzing similarity between generic.wannacry.win_dll.0b352401619b8b6375dd37ba94a8b73526f428631ac12145858a94ce354b5ddc and generic.wannacry.win_dll.28bd6f6c1958e833685188e58afeb6177691d18b3915ee2bb85b98e72aaa0452

[*] File /generic.wannacry.win_dll.0b352401619b8b6375dd37ba94a8b73526f428631ac12145858a94ce354b5ddc contains 4 functions

[*] File /generic.wannacry.win_dll.28bd6f6c1958e833685188e58afeb6177691d18b3915ee2bb85b98e72aaa0452 contains 4 functions

[*] Functions entry0 and entry0 are similar with coefficient equal to 1.0
[*] Functions fcn.10001016 and fcn.10001016 are similar with coefficient equal to 1.0
[*] Functions fcn.100010ab and fcn.100010ab are similar with coefficient equal to 1.0
[*] Functions fcn.1000113e and fcn.1000113e are similar with coefficient equal to 1.0

[*] Number of matching functions: 4
```
