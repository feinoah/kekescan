#!/usr/bin/env python
# -*- coding: utf-8 -*-  
from django import template
register = template.Library()
#from app.utils import *
#from app.forms import SCAN_DEPTH_LIST
#try:
#    from json import json
#except ImportError:
#    import json
#import  oldjson
#import json
from os import path
from django.conf import settings




STATUS = {   'WAITTING': {'desc': u'等待执行',
                           'icon': 'glyphicon glyphicon-time'},
             'RUNNING':  {'desc': u'正在执行',
                           'icon': 'glyphicon glyphicon-refresh'},
             'END':      {'desc': u'运行结束',
                            'icon': 'glyphicon glyphicon-stop'},
             'PAUSED':    {'desc': u'已经暂停',
                           'icon': 'glyphicon glyphicon-pause'},
             'NEED_PAUSE': {'desc': u'等待暂停',
                           'icon': 'glyphicon glyphicon-info-sign'},
             'NEED_END': {'desc': u'等待结束',
                           'icon': 'glyphicon glyphicon-info-sign'}}

from urllib import unquote
@register.filter
def getheader(html):
    """只显示http返回头"""
    try:
       
        header = html.split('html')[0]
        header = unquote(header)
        return header
    except:
        return html
                           
@register.filter
def status(stat):
    """任务状态中文描述"""
    try:
        stat=stat.strip()
        return STATUS[stat]['desc']
    except:
        return 'error desc'

    #return stat
 
@register.filter
def statusIcon(stat):
    """任务状态对应的图标"""
    try:
        stat=stat.strip()
        return STATUS[stat]['icon']
    except:
        return 'glyphicon glyphicon-info-sign'


    #return stat

@register.filter
def htmlString(string):
    """使得字符串中的html标签有效"""
    from django.utils.safestring import mark_safe
    return mark_safe(string)


htmlString.is_safe = True
htmlString.need_autoescape = False


@register.filter
def rootUrl(urls, maxlen = '128'):
    """task.root_url如果多项返回第一项, url不超过maxlen字节 """
    maxlen = int(maxlen)
    us = urls.split('<!>')
    url = us[0]
    if len(url) > maxlen:
        url = url[0:maxlen] + '...'
    if len(us) > 1:
        url = url + ',...'
    if us[0] == url:
        return url
    else:
        return htmlString('<span title="%s">%s</span>' % (us[0], url))

