### 功夫再高也怕菜刀
打开附件是一个pcap包，使用foremost分析发现存在一个zip文件，打开发现需要密码。在pcap数据包中搜索.zip关键字，发现存在好几个包，对应两种响应内容，其中一个多了6666.jpg，分析这个流找到生成这个文件的php代码，逆向解析得到这个图片文件，打开图片得到密码。
