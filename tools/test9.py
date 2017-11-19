#coding=utf-8

from lxml import etree

html = '''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="description" content="帮助老司机们情报收集、测试系统边界的在线域名情报收集系统">
    <meta name="author" content="dave.fang@outlook.com">
    <meta name="keywords" content="子域名, 域名信息, fuzz, fuzzall, 域名情报收集">
    <meta name="csrf-token" content="t6ZBKtxcvyHtPva0coGX2ot72i9h5atRfajORCwo">
    <title>qq.com | 搜索结果 | 域名情报收集系统 - Fuzz</title>
    <meta name="robots" content="nofollow" />
    <meta name="google-site-verification" content="256Gfx2r305b10kLMjz9dlmTZwg_FgvSVGFfBZb2FVE" />
    <meta name="baidu-site-verification" content="BhBS3Mje0i" />

    <!-- Favicons -->
    <link rel="shortcut icon" href="http://www.fuzzall.com/favicon.ico" type="image/x-icon">

    <!-- Bootstrap Core CSS -->
    <link media="all" type="text/css" rel="stylesheet" href="http://www.fuzzall.com/css/bootstrap.min.css">


    <!-- Custom CSS -->
    <link media="all" type="text/css" rel="stylesheet" href="http://www.fuzzall.com/css/offcanvas.css">

    <link media="all" type="text/css" rel="stylesheet" href="http://www.fuzzall.com/css/patch.css">

    
    <!-- Custom Fonts -->
    <link media="all" type="text/css" rel="stylesheet" href="http://www.fuzzall.com/font-awesome/css/font-awesome.min.css">


</head>

<body>
<nav class="navbar navbar-fixed-top navbar-inverse">
    <div class="container">
        <div class="navbar-header">
            <a class="navbar-brand" href="http://www.fuzzall.com">Fuzz</a>
        </div>
        <div id="navbar" class="collapse navbar-collapse">
            <ul class="nav navbar-nav">
                <li ><a href="http://www.fuzzall.com">首页</a></li>
                <li ><a href="http://www.fuzzall.com/lab">实验室</a></li>
                <li ><a href="http://www.fuzzall.com/about">关于</a></li>
            </ul>
            <ul class="nav navbar-nav navbar-right">
                                    <li class="dropdown">
                        <a href="#" class="dropdown-toggle" data-toggle="dropdown" role="button" aria-haspopup="true" aria-expanded="false">evileo <span class="caret"></span></a>
                        <ul class="dropdown-menu">
                            <li><a href="http://www.fuzzall.com/user/dashboard">仪表盘</a></li>
                            <li><a href="http://www.fuzzall.com/user/submit">域名提交</a></li>
                            <li role="separator" class="divider"></li>
                            <li><a href="#">设置</a></li>
                            <li><a href="http://www.fuzzall.com/logout">注销</a></li>
                        </ul>
                    </li>
                            </ul>
        </div><!-- /.nav-collapse -->
    </div><!-- /.container -->
</nav><!-- /.navbar -->


<div class="container">

    
    <div class="row row-offcanvas row-offcanvas-left">

        <div class="col-md-3 sidebar-offcanvas" id="sidebar">
            <form method="get" action="http://www.fuzzall.com/search">
                <div class="input-group">
                    <span class="input-group-addon" style="background-color: #fff;"><i
                                class="glyphicon glyphicon-screenshot"></i></span>
                    <input type="text" name="q" class="form-control" placeholder="example.com"
                           value="qq.com"/>
                    <span class="input-group-btn">
                        <button class="btn btn-default" type="submit">Go!</button>
                    </span>
                </div><!-- /input-group -->
            </form>
            <hr/>
            <div class="panel panel-info">
                <div class="panel-heading"><h3 class="panel-title text-center">DNS服务器记录</h3></div>
                <table class="table text-center">
                    <tbody>
                                                                        <tr>
                                <td>ns3.qq.com</td>
                            </tr>
                                                    <tr>
                                <td>ns4.qq.com</td>
                            </tr>
                                                    <tr>
                                <td>ns1.qq.com</td>
                            </tr>
                                                    <tr>
                                <td>ns2.qq.com</td>
                            </tr>
                                                                </tbody>

                </table>
            </div>

            <div class="panel panel-info">
                <div class="panel-heading"><h3 class="panel-title text-center">相关域名</h3></div>
                <div class="list-group text-center">
                    <a href="#" class="list-group-item">暂无数据</a>
                </div>
            </div>
        </div><!--/.sidebar-offcanvas-->
        <div class="col-md-9">
            <p class="pull-right visible-xs">
                <button type="button" class="btn btn-primary btn-xs" data-toggle="offcanvas">Toggle nav</button>
            </p>
            <ol class="breadcrumb">
                <li><a href="http://www.fuzzall.com">Fuzz</a></li>
                <li><a href="#">域名</a></li>
                <li class="active">结果</li>
                <p class="pull-right text-info">收录数: 1764</p>
            </ol>

            <div class="jumbotron">
                                    <h2>腾讯网<small><a href="http://www.fuzzall.com/report/qq.com">&nbsp;查看报告</a></small></h2>
                    <p> 腾讯网是中国浏览量最大的中文门户网站，是腾讯公司推出的集新闻信息、互动社区、娱乐产品和基础服务为一体的大型综合门户网站。</p>
                            </div>

            <div class="panel panel-success">
                <!-- Default panel contents -->
                <div class="panel-heading text-center">子域名结果</div>
                <table class="table table-striped" style="table-layout: fixed;">
                    <thead>
                    <tr>
                        <th width="80" class="text-center">#</th>
                        <th width="160">子域名</th>
                        <th>IP</th>
                        <th width="160">收录时间</th>
                    </tr>
                    </thead>
                    <tbody>
                                                                        <tr>
                                <td class="text-center">510251</td>
                                <td title="cmu.qq.com" class="table-dot">
                                    <a href="http://cmu.qq.com" target="_blank" rel="nofollow">cmu.qq.com</a>
                                </td>
                                <td>[&quot;1.1.1.1&quot;]</td>
                                <td>2016-04-27 08:40:06</td>
                            </tr>
                                                    <tr>
                                <td class="text-center">447861</td>
                                <td title="xxy.qq.com" class="table-dot">
                                    <a href="http://xxy.qq.com" target="_blank" rel="nofollow">xxy.qq.com</a>
                                </td>
                                <td>[&quot;1.1.1.1&quot;]</td>
                                <td>2016-04-24 02:22:35</td>
                            </tr>
                                                    <tr>
                                <td class="text-center">447859</td>
                                <td title="slg.qq.com" class="table-dot">
                                    <a href="http://slg.qq.com" target="_blank" rel="nofollow">slg.qq.com</a>
                                </td>
                                <td>[&quot;1.1.1.1&quot;]</td>
                                <td>2016-04-24 02:16:37</td>
                            </tr>
                                                    <tr>
                                <td class="text-center">447858</td>
                                <td title="qwe.qq.com" class="table-dot">
                                    <a href="http://qwe.qq.com" target="_blank" rel="nofollow">qwe.qq.com</a>
                                </td>
                                <td>[&quot;14.17.31.229&quot;]</td>
                                <td>2016-04-24 02:14:42</td>
                            </tr>
                                                    <tr>
                                <td class="text-center">447847</td>
                                <td title="hx.qq.com" class="table-dot">
                                    <a href="http://hx.qq.com" target="_blank" rel="nofollow">hx.qq.com</a>
                                </td>
                                <td>[&quot;1.1.1.1&quot;]</td>
                                <td>2016-04-24 02:06:11</td>
                            </tr>
                                                    <tr>
                                <td class="text-center">447846</td>
                                <td title="hss.qq.com" class="table-dot">
                                    <a href="http://hss.qq.com" target="_blank" rel="nofollow">hss.qq.com</a>
                                </td>
                                <td>[&quot;1.1.1.1&quot;]</td>
                                <td>2016-04-24 02:06:08</td>
                            </tr>
                                                    <tr>
                                <td class="text-center">447844</td>
                                <td title="ddt.qq.com" class="table-dot">
                                    <a href="http://ddt.qq.com" target="_blank" rel="nofollow">ddt.qq.com</a>
                                </td>
                                <td>[&quot;1.1.1.1&quot;]</td>
                                <td>2016-04-24 02:04:59</td>
                            </tr>
                                                    <tr>
                                <td class="text-center">447843</td>
                                <td title="bsw.qq.com" class="table-dot">
                                    <a href="http://bsw.qq.com" target="_blank" rel="nofollow">bsw.qq.com</a>
                                </td>
                                <td>[&quot;1.1.1.1&quot;]</td>
                                <td>2016-04-24 02:04:37</td>
                            </tr>
                                                    <tr>
                                <td class="text-center">447842</td>
                                <td title="adn.qq.com" class="table-dot">
                                    <a href="http://adn.qq.com" target="_blank" rel="nofollow">adn.qq.com</a>
                                </td>
                                <td>[&quot;1.1.1.1&quot;]</td>
                                <td>2016-04-24 02:04:13</td>
                            </tr>
                                                    <tr>
                                <td class="text-center">19130</td>
                                <td title="zw.qq.com" class="table-dot">
                                    <a href="http://zw.qq.com" target="_blank" rel="nofollow">zw.qq.com</a>
                                </td>
                                <td>[&quot;203.205.151.215&quot;, &quot;203.205.151.216&quot;]</td>
                                <td>2016-04-14 12:58:09</td>
                            </tr>
                                                    <tr>
                                <td class="text-center">19129</td>
                                <td title="zyx.qq.com" class="table-dot">
                                    <a href="http://zyx.qq.com" target="_blank" rel="nofollow">zyx.qq.com</a>
                                </td>
                                <td>[&quot;113.108.1.90&quot;, &quot;123.151.43.51&quot;, &quot;183.60.62.158&quot;]</td>
                                <td>2016-04-14 12:58:00</td>
                            </tr>
                                                    <tr>
                                <td class="text-center">19128</td>
                                <td title="zy.qq.com" class="table-dot">
                                    <a href="http://zy.qq.com" target="_blank" rel="nofollow">zy.qq.com</a>
                                </td>
                                <td>[&quot;203.205.151.215&quot;, &quot;203.205.151.216&quot;]</td>
                                <td>2016-04-14 12:58:00</td>
                            </tr>
                                                    <tr>
                                <td class="text-center">19127</td>
                                <td title="zx.qq.com" class="table-dot">
                                    <a href="http://zx.qq.com" target="_blank" rel="nofollow">zx.qq.com</a>
                                </td>
                                <td>[&quot;203.205.151.215&quot;, &quot;203.205.151.216&quot;]</td>
                                <td>2016-04-14 12:57:59</td>
                            </tr>
                                                    <tr>
                                <td class="text-center">19126</td>
                                <td title="ztj.qq.com" class="table-dot">
                                    <a href="http://ztj.qq.com" target="_blank" rel="nofollow">ztj.qq.com</a>
                                </td>
                                <td>[&quot;203.205.151.215&quot;, &quot;203.205.151.216&quot;]</td>
                                <td>2016-04-14 12:57:56</td>
                            </tr>
                                                    <tr>
                                <td class="text-center">19125</td>
                                <td title="ztc.qq.com" class="table-dot">
                                    <a href="http://ztc.qq.com" target="_blank" rel="nofollow">ztc.qq.com</a>
                                </td>
                                <td>[&quot;1.1.1.1&quot;]</td>
                                <td>2016-04-14 12:57:56</td>
                            </tr>
                                                    <tr>
                                <td class="text-center">19124</td>
                                <td title="zt.qq.com" class="table-dot">
                                    <a href="http://zt.qq.com" target="_blank" rel="nofollow">zt.qq.com</a>
                                </td>
                                <td>[&quot;203.205.151.215&quot;, &quot;203.205.151.216&quot;]</td>
                                <td>2016-04-14 12:57:56</td>
                            </tr>
                                                    <tr>
                                <td class="text-center">19123</td>
                                <td title="zsj.qq.com" class="table-dot">
                                    <a href="http://zsj.qq.com" target="_blank" rel="nofollow">zsj.qq.com</a>
                                </td>
                                <td>[&quot;203.205.149.164&quot;, &quot;203.205.149.29&quot;, &quot;203.205.150.120&quot;, &quot;203.205.150.121&quot;, &quot;203.205.150.17&quot;, &quot;203.205.150.18&quot;, &quot;203.205.150.19&quot;, &quot;203.205.150.26&quot;, &quot;203.205.150.27&quot;]</td>
                                <td>2016-04-14 12:57:56</td>
                            </tr>
                                                    <tr>
                                <td class="text-center">19122</td>
                                <td title="zt2.qq.com" class="table-dot">
                                    <a href="http://zt2.qq.com" target="_blank" rel="nofollow">zt2.qq.com</a>
                                </td>
                                <td>[&quot;1.1.1.1&quot;]</td>
                                <td>2016-04-14 12:57:56</td>
                            </tr>
                                                    <tr>
                                <td class="text-center">19121</td>
                                <td title="zs.qq.com" class="table-dot">
                                    <a href="http://zs.qq.com" target="_blank" rel="nofollow">zs.qq.com</a>
                                </td>
                                <td>[&quot;1.1.1.1&quot;]</td>
                                <td>2016-04-14 12:57:55</td>
                            </tr>
                                                    <tr>
                                <td class="text-center">19120</td>
                                <td title="zsh.qq.com" class="table-dot">
                                    <a href="http://zsh.qq.com" target="_blank" rel="nofollow">zsh.qq.com</a>
                                </td>
                                <td>[&quot;101.227.160.20&quot;]</td>
                                <td>2016-04-14 12:57:55</td>
                            </tr>
                                                    <tr>
                                <td class="text-center">19119</td>
                                <td title="zsg.qq.com" class="table-dot">
                                    <a href="http://zsg.qq.com" target="_blank" rel="nofollow">zsg.qq.com</a>
                                </td>
                                <td>[&quot;1.1.1.1&quot;]</td>
                                <td>2016-04-14 12:57:55</td>
                            </tr>
                                                    <tr>
                                <td class="text-center">19118</td>
                                <td title="zsm.qq.com" class="table-dot">
                                    <a href="http://zsm.qq.com" target="_blank" rel="nofollow">zsm.qq.com</a>
                                </td>
                                <td>[&quot;1.1.1.1&quot;]</td>
                                <td>2016-04-14 12:57:55</td>
                            </tr>
                                                    <tr>
                                <td class="text-center">19117</td>
                                <td title="zrr.qq.com" class="table-dot">
                                    <a href="http://zrr.qq.com" target="_blank" rel="nofollow">zrr.qq.com</a>
                                </td>
                                <td>[&quot;10.134.9.176&quot;]</td>
                                <td>2016-04-14 12:57:55</td>
                            </tr>
                                                    <tr>
                                <td class="text-center">19116</td>
                                <td title="zou.qq.com" class="table-dot">
                                    <a href="http://zou.qq.com" target="_blank" rel="nofollow">zou.qq.com</a>
                                </td>
                                <td>[&quot;1.1.1.1&quot;]</td>
                                <td>2016-04-14 12:57:52</td>
                            </tr>
                                                    <tr>
                                <td class="text-center">19115</td>
                                <td title="zone.qq.com" class="table-dot">
                                    <a href="http://zone.qq.com" target="_blank" rel="nofollow">zone.qq.com</a>
                                </td>
                                <td>[&quot;1.1.1.1&quot;]</td>
                                <td>2016-04-14 12:57:52</td>
                            </tr>
                                                                </tbody>
                </table>
            </div>
                                                <div class="text-center">
                        <ul class="pagination"><li class="disabled"><span>&laquo;</span></li> <li class="active"><span>1</span></li><li><a href="http://www.fuzzall.com/search/qq.com?page=2">2</a></li><li><a href="http://www.fuzzall.com/search/qq.com?page=3">3</a></li><li><a href="http://www.fuzzall.com/search/qq.com?page=4">4</a></li><li><a href="http://www.fuzzall.com/search/qq.com?page=5">5</a></li><li><a href="http://www.fuzzall.com/search/qq.com?page=6">6</a></li><li><a href="http://www.fuzzall.com/search/qq.com?page=7">7</a></li><li><a href="http://www.fuzzall.com/search/qq.com?page=8">8</a></li><li class="disabled"><span>...</span></li><li><a href="http://www.fuzzall.com/search/qq.com?page=70">70</a></li><li><a href="http://www.fuzzall.com/search/qq.com?page=71">71</a></li> <li><a href="http://www.fuzzall.com/search/qq.com?page=2" rel="next">&raquo;</a></li></ul>
                    </div>
                            

        </div><!--/.col-xs-12.col-sm-9-->

    </div><!--/row-->


</div><!--/.container-->


<!-- jQuery JavaScript -->
<script src="http://www.fuzzall.com/js/jquery-2.2.1.min.js"></script>


<!-- Bootstrap Core JavaScript -->
<script src="http://www.fuzzall.com/js/bootstrap.min.js"></script>

<script src="http://www.fuzzall.com/js/offcanvas.js"></script>

<script src="http://www.fuzzall.com/js/patch.js"></script>



<script>
    (function(i,s,o,g,r,a,m){i['GoogleAnalyticsObject']=r;i[r]=i[r]||function(){
                (i[r].q=i[r].q||[]).push(arguments)},i[r].l=1*new Date();a=s.createElement(o),
            m=s.getElementsByTagName(o)[0];a.async=1;a.src=g;m.parentNode.insertBefore(a,m)
    })(window,document,'script','https://www.google-analytics.com/analytics.js','ga');

    ga('create', 'UA-76680005-1', 'auto');
    ga('send', 'pageview');
</script>

</body>
</html>'''

#page = etree.HTML(html.lower().decode('utf-8'))

import lxml.html
import ast
import MySQLdb
db = MySQLdb.connect("127.0.0.1","root","wenjunnengyoujiduochou","xlcscan" )
cursor = db.cursor()

def _to_db(html,db,cursor,domain_name):
    html = lxml.html.fromstring(html)

    rows = html.xpath('//table')

    list_dns = []
    elements = rows[0].xpath('.//tr')
    for k in elements:
        c =  k.xpath('.//td//text()')
        #print c
        list_dns.append(c[0])
    print list_dns

    dic_domain = {}
    elements = rows[1].xpath('.//tr')
    if  len(elements) < 1:
        return 3
    for k in elements:
        c =  k.xpath('.//td//text()')
        
        if len(c) >1:
            for ip in ast.literal_eval(str(c[4])):
                
            #print c[0]
                dic_domain['id'] = int(c[0])
                dic_domain['sub_domain_name'] = c[2]
                dic_domain['ip'] = ip
                    
                dic_domain['find_time'] =c[5]
                #print dic_domain
                sql = "INSERT INTO app_subdomainbrute(domain_name, \
                       sub_domain, sub_ip, fuzz_time, fuzzall_id) \
                       VALUES ('%s', '%s', '%s', '%s', '%d' )" % \
                       (domain_name, dic_domain['sub_domain_name'], dic_domain['ip'], dic_domain['find_time'], dic_domain['id'])
                print sql
                cursor.execute(sql)
  
    db.commit()
                



        
_to_db(html,db,cursor,'qq.com')


db.close()
