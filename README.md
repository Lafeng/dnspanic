# DNSPanic

DNSPanic is a multi-backend DNS relay. It can rework DNS records with rule-based filters.

Features:

- Filter polluted DNS records.
- Block certain domains.
- Read records from zone files.

# Usage

```
// build
go get -u -v github.com/Lafeng/dnspanic

// run
sudo ./dnspanic [-c config.conf]

// format config
./dnspanic -format
```

# 中文说明

这是一个DNS中继服务器，在基于规则的过滤器上实现对DNS记录的加工。

主要用于面对这些需求场景：

- 过滤网络运营商的虚假伪造DNS记录；
- 广告或隐私采集类域名拦截；
- 自定义zone解析；

![dnspanic](https://i.imgur.com/s58mydr.png)
