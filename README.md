## Pull Docker Image
```bash 
sudo docker pull rmg0070/tcppacketdropper:latest
```
## RUNNING THE PULLED IMAGE
``` bash
sudo docker run --privileged -it -p 80:80 --name ebpf rmg0070/tcppacketdropper:latest /bin/bash
```

## IP BLOCKING AND PORT BLOCING 
ENTER IP THAT HAS TO BE BLOCKED 
```BASH
cargo task run --ip-address=192.168.1.100 --port=80
```


