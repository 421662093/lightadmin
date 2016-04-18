#!/usr/bin/env python
#-*- coding: utf-8 -*-
from flask import render_template, redirect, url_for, abort, flash, request,\
    current_app, make_response, flash
from flask import g
from .authentication import auth
from werkzeug import secure_filename
from flask.ext.login import login_required, current_user, logout_user
from . import admin
from .decorators import permission_required
from .forms import EditUserForm,EditTopicForm,EditInventoryForm,EditRoleForm,EditAdForm
from ..models import collection,Light,User
from .. import conf#searchwhoosh,rs
from ..core import common
import logging
import time

@admin.route('/logout')
@auth.login_required
def logout():
    logout_user()
    return jsonify(msg='用户已登出')


@admin.route('/lightlist',methods=['GET', 'POST'])
#@admin.route('/topiclist/<string:uid>', methods=['GET', 'POST'])
@admin.route('/lightlist/<int:index>', methods=['GET', 'POST'])
#@auth.login_required
def light_list(index=1):
    if request.method == 'POST':
        pass
    else:
        '''
        user = User()
        user.name = ""
        user.username = "clr110"
        user.password = "123456"
        user.saveinfo()
        '''

        '''
        light = Light()
        light._id = 4
        light._type = 1
        light.user_id = 1
        light.device_id = "122.225.69.52"
        light.activa_data = "1460938613"
        light.state = 1
        light.saveinfo()
        '''

    	pagesize = 8
    	count = Light.getcount()
        print str(count)
    	pcount = common.getpagecount(count,pagesize)
    	if index>pcount:
    		index = pcount
    	if index<1:
    		index=1
        '''
        lock = Lock()
        lock.park_id = 1
        lock.gateway_id = 1
        lock.device_id = 1
        lock.state = 1
        lock.saveinfo()
        '''
        lightlist = Light.getlist(index=index,count=pagesize)
        func = {'stamp2time': common.stamp2time,'getlightstate':common.getlockstate,'can': common.can}

        return render_template('admin/light_list.html',lightlist=lightlist, func=func,pagecount=pcount,index=index)#,uinfo=g.current_user

@admin.route('/lightedit',methods=['GET', 'POST'])
@admin.route('/lightedit/<int:id>', methods=['GET', 'POST'])
@admin.route('/lightedit/<int:id>/<int:pindex>', methods=['GET', 'POST'])
#@auth.login_required
def light_edit(id=0,pindex=1):
    if request.method == 'POST':
        light = Light()
        light._id = id
        light.device_id = request.form.get('device_id',0)
        light.saveinfo()
        return redirect(url_for('.light_list',index=pindex))
    else:
        islight = False
        light = None
        if id > 0 :
            light = Light.getinfo(id)
            if light:
                islight = True
        return render_template('admin/light_edit.html',light=light,id=id, islight=islight,pindex=pindex)#,uinfo=g.current_user
