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

这是一个DNS中继服务器，以基于规则的过滤器加工DNS记录。

主要用于这些场景：

- 过滤网络运营商的伪造DNS记录；
- 广告和隐私采集类域名的拦截；
- 自定义zone解析。

![dnspanic](https://i.imgur.com/s58mydr.png)
