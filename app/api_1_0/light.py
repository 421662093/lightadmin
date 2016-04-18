#!/usr/bin/env python
#-*- coding: utf-8 -*-
'''
API类
'''

from flask import make_response, request, current_app, url_for
from flask import g
from .authentication import auth
from . import api
from .decorators import permission_required
from ..models import Light
from ..core.common import jsonify
from ..core import common
import logging
import json

@api.route('/light/update', methods=['GET'])
#@auth.login_required
def light_update():
    '''
    light定时访问 心跳包

    URL:/light/update
    GET 参数:
        did -- 设备ID
        type --上报状态或向下发送命令
        action -- 开启或者关闭 锁
    '''
    #data = request.get_json()

    did = request.args.get('did',0)
    action = request.args.get('action',0)
    if len(did)>0:
        Light.update(did)
        return jsonify(ret=1)
    else:
        return jsonify(ret=-1)#系统异常

@api.route('/light/list', methods=['GET'])
@auth.login_required
def light_list():
    '''
    获取当前用户设备列表

    URL:/light/list
    GET 参数:
        none
    '''

    _list = Light.getlist(userid=g.current_user._id)
    return jsonify(list=[item.to_json() for item in _list])
