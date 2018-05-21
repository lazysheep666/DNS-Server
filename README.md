## An assignment in Intemet Application course.

### Requirment:

1. 实现中文域名的解析，例如：主页.北邮.教育.中国（与 www.bupt.edu.cn 对应）；
数据库记录示例：
主页.北邮.教育.中国，86400，IN，A，192.168.1.25
北邮.教育.中国，86400，IN ，MX，邮件服务器.北邮.教育.中国
邮件服务器.北邮.教育.中国，86400，IN ，A，192.168.1.37
2. 至少支持 4 个顶级域，至少实现三级域名的解析。程序需要实现的实体有：client、
至少 6 个 DNS server。
4 个顶级域名：中国、组织、商业、美国
二-三级域名：自定义（例如：教育.中国，北邮.教育.中国）
DNS server 的部署架构可参考下图的示例：
3. 支持的 Resource Record 类型：A、MX、CNAME；对于 MX 类型的查询，要求在
Additional Section 中携带对应 IP 地址；
4. 支持的解析方法：迭代解析；
5. 支持 cache，打印查询的 trace 记录（查询路径、服务器响应时间）；
6. 传输层协议：
client 与 local DNS server 之间：TCP；
DNS server 之间：UDP；
7. 应用层协议：DNS
要求通信过程中使用的所有 DNS 报文必须能够用 wireshark 正确解析；
8. server 的数据维护方式可采用文件；
2
9. 书写完整的设计文档，参考 Sample-Project-Report.pdf；
10. 程序中应包含详细的代码注释，使用良好的编程风格；
11. 程序运行稳定，支持错误处理，如：命令无效、参数缺失、同名处理、空白字符；