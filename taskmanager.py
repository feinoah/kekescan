#!/usr/bin/env python
# -*- coding: utf-8 -*-  

import os
import django

os.environ.setdefault(
        "DJANGO_SETTINGS_MODULE",
        "kekescan.settings"
    )

django.setup()

import time
from app.models import *
from django.db import transaction
from django.utils import timezone
from app.tasks import *
from app.lib.utils import get_ip_list

RUNNING_TASK = {}
 
def manage_subtask():
    _tasklist = Task.objects.filter(status='WAITTING')
    for _task  in _tasklist:
        attack_type = _task.attack_type
        attack_target =  _task.attack_target
        
        if attack_type == 'fnascan':
			 
            attack_target_list = get_ip_list(attack_target)
			  
            print  ">>>>>>>attack_target_list",attack_target_list
            size = 10 #每一个任务的ip数量
            lol = lambda lst, sz: [lst[i:i+sz] for i in range(0, len(lst), sz)]
             
            for i in lol(attack_target_list,size):
                i = ','.join(i)
                _subtask = SubTask(attack_target = i, attack_type = attack_type,task_name = '', status = 'WAITTING', parameter = '') 
                _subtask.save()
            #设置主任务状态为running
            _maintask  = Task.objects.get(id = _task.id)
            _maintask.status = 'RUNNING'
            _maintask.save()
        transaction.commit()
        
        if attack_type == 'bugscan':
            attack_target_list = [attack_target,] 
            print  ">>>bugscan>>>>attack_target_list",attack_target_list
            _t = run_bugscan.delay(attack_target_list) ##
            _maintask  = Task.objects.get(id = _task.id)
            _maintask.status = 'RUNNING'
            _maintask.save()
        transaction.commit()
        
def run_subtask(task_id):
    _task = SubTask.objects.get(id=task_id)
    attack_type = _task.attack_type
    attack_target =  _task.attack_target
    #print ">>>Run Task>>",attack_type,attack_target
    
    if attack_type == 'fnascan':
        _t = run_fnascan.delay(attack_target) ##221.226.15.243-221.226.15.245 , 221.226.15.243,221.226.15.2
        _task.status='RUNNING'
        _task.start_time = timezone.now()
    if attack_type == 'subdomainbrute':
        _t = run_subdomainbrute.delay(attack_target) ##
        _task.status='RUNNING'
        _task.start_time = timezone.now()
    if attack_type == 'test':
        _t = add.delay(attack_target)
        _task.status='RUNNING'
        _task.start_time = timezone.now()
    
    #attck_type以ATK开头的多模块扫描
    if attack_type == 'ATK_K0':
        pass
    #attack_type无法识别的情况，返回函数
    try:
        _t  
    except:
        _task.except_message = 'Can not identify scantype'
        _task.save()
        transaction.commit()
        return
    _task.task_id = _t.id
    _task.save()
    transaction.commit()
    
    RUNNING_TASK[task_id] = _t
    #为了方便task_id后面加个下划线就是attack——type
    RUNNING_TASK[str(task_id) + '_'] = attack_type
   
   
def _get_detail(dic_m,ip,port):
    dic_key = "%s:%s" % (ip,port)    
    try:
        detail = dic_m[dic_key]      
    except:
        detail = "undefine"
    return detail
    
#celery运行的任务结果入库    
def result_2_db(task_id,attack_type,task_obj):
    
    #task_obj == RUNNING_TASK[key]
    #获得指定task_id运行输出
    _templist = task_obj.get() 
    if "The" in _templist[0][:5]:
        _templist[0] = _templist[1]
        _templist[1] = _templist[2]
    
    _simple_dic = eval(_templist[0])
    _detail_dic = eval(_templist[1])
    #_templist[0] = {'221.226.15.246': ['443', '80 web \xe5\x8d\x97\xe7\x91\x9e\xe7\xbb\xa7\xe4\xbf\x9dVPN\xe7\x99\xbb\xe9\x99\x86'], '221.226.15.249': ['8081 web Apache Tomcat/7.0.57'], '221.226.15.250': ['80'], '221.226.15.243': ['80', '9200 Elasticsearch(default)', '8000 web']}
    #print _simple_dic,_detail_dic
    for _ip in _simple_dic.keys():
        for  service_name in _simple_dic[_ip]:
            _port = service_name.split(' ')[0]
            ip_port =  '%s:%s' % (_ip,_port)
            web_title = ''
            if len(service_name.split(' ')) > 2:
                web_title = service_name.split(' ')[-1]
            detail = _get_detail(_detail_dic,_ip,_port)
            #入库
            _result = FnascanResult(task_id=task_id,ip=_ip,port = _port ,service_name = service_name,service_detail = detail,web_title = web_title)
            _result.save()
            
    if attack_type == 'subdomainbrute':
        print _templist
        
    transaction.commit()
    
 

    
def check_task():
    for key in RUNNING_TASK.keys():
        #task_id后面加个下划线
        if  str(key)[-1] != '_':
        
            if RUNNING_TASK[key].ready():
                # 如果程序执行完成
                _end_task = Task.objects.get(id=key)
                if RUNNING_TASK[key].failed():
                    _end_task.status = 'FAILURE'
                else:
                    _end_task.status = 'SUCCESS'
                    attack_type = RUNNING_TASK[str(key)+'_']
                    task_id = key
                    result_2_db(task_id,attack_type,RUNNING_TASK[key])
                    
                _end_task.end_time =  timezone.now()
                _tmp_task  = Result(task_id = _end_task.task_id,detail =RUNNING_TASK[key].get() )
                
                _end_task.save()
                _tmp_task.save()
                transaction.commit()
                del RUNNING_TASK[key]
                
    #如果数据库中状态为运行，而任务不在RUNNING_TASK里面，则运行失败      
    '''    
    RUNNING_TASK_IN_DB = Task.objects.filter(Q(status = 'RUNNING'))
    for  _i in RUNNING_TASK_IN_DB:
        if _i.id not in  RUNNING_TASK.keys():
            _i.status = 'FAILURE'
            _i.except_message = 'Something error when check_task()'
            #_i.end_time =  timezone.now()
        _i.save()
    #RUNNING_TASK_IN_DB.save()
    transaction.commit()
            '''
    
#三秒钟查询一次数据库查看任务
CHECK_TIME = 3 
def task_sched():
    while True:
        time.sleep(CHECK_TIME)
        tasklist = SubTask.objects.filter(status='WAITTING')
        #打印正在运行的task
        #print '>>>>>>RUNNING_TASK',RUNNING_TASK
        for _task in tasklist:
            #_task.status='RUNNING'
            #_task.start_time = timezone.now()
            #_task.save()
            #transaction.commit()
            run_subtask(_task.id)
        manage_subtask()
        check_task()

            
if __name__ == '__main__':
    task_sched()
