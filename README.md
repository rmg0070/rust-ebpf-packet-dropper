## Pull Docker Image
```bash 
sudo docker pull rmg0070/tcppacketdropper:latest
```
## RUNNING THE PULLED IMAGE
``` bash
sudo docker run --privileged -it -p 80:80 --name ebpf rmg0070/tcppacketdropper:latest /bin/bash
```

## IP BLOCKING
ENTER IP THAT HAS TO BE BLOCKED 
```BASH
RUST_LOG=info cargo task run --ip-address=172.20.10.2
```

## PORT BLOCKING

ENTER THE PORT NUMBER THAT HAS BE BLOCKED FOR INCOMMING TRAFFIC

```bash
RUST_LOG=info cargo task run --ip-address=172.20.10.2
```
