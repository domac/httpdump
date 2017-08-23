# httpdump

### 介绍

本工具类似tcpdump,单专门嗅探和抓取http请求信息

### 构建

```
go build -o httpdump
```

### 使用 

> 需要使用root权限

```
sudo ./httpdump
```

### 运行结果

```

...

SrcIP: 192.168.139.1
SrcPort: 53546
DstIP: 192.168.139.104
DstPort: 80
ReqSize: 0
Method: GET
Url: /testplatform/v1/download/?sys_id=tester


SrcIP: 192.168.139.1
SrcPort: 53547
DstIP: 92.168.139.104
DstPort: 80
ReqSize: 0
Method: GET
Url: /test/query?sys_name=demo&key=123456

...

```

