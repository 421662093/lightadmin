#!/usr/bin/env python
#-*- coding: utf-8 -*-
from datetime import datetime
from mongoengine import EmbeddedDocument, EmbeddedDocumentField,Q
from mongoengine import *
from flask import g
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import (
    TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)
import hashlib

'''
from markdown import markdown
import bleach  # html 清除工具
'''
from app.exceptions import ValidationError
from flask import current_app, request, url_for
from flask.ext.login import UserMixin, AnonymousUserMixin
from . import db,conf,scheduler, login_manager#,searchwhoosh
from core import common
import json
import logging
#import cpickle as pickle

Q_SOUYUN_ACTION = 'DataManipulation' #添加操作 云搜
Q_SOUYUN_SEARCH = 'DataSearch' #搜索操作 云搜

class Permission:
    VIEW = 0x01 # 查看
    EDIT = 0x02 # 编辑
    DELETE = 0x04 # 删除
    ADMINISTER = 0x80

class RolePermissions(EmbeddedDocument):  # 角色权限
    user = IntField(default=0, db_field='u') #用户
    topic = IntField(default=0, db_field='t') #话题
    inventory = IntField(default=0, db_field='i') #清单
    appointment = IntField(default=0, db_field='a') #预约
    ad = IntField(default=0, db_field='ad') #广告
    role = IntField(default=0, db_field='r') #角色
    log = IntField(default=0, db_field='l') #日志

    def to_json(self):
        json_rp = {
            'user': self.user,
            'topic': self.topic,
            'inventory': self.inventory,
            'appointment': self.appointment,
            'ad': self.ad,
            'role': self.role,
            'log': self.log
        }
        return json_rp

class Role( Document):
    __tablename__ = 'roles'
    meta = {
        'collection': __tablename__,
    }
    _id = IntField(primary_key=True)
    name = StringField(max_length=64, required=True,db_field='n')
    default = BooleanField(default=False, db_field='d')
    permissions = EmbeddedDocumentField(
        RolePermissions, default=RolePermissions(), db_field='p')  # 统计
    CACHEKEY = {
        'list':'rolelist',
        'item':'roleitem'
    }
    @staticmethod
    def insert_roles():
        roles = {
            'User': (Permission.VIEW | Permission.EDIT | Permission.DELETE | Permission.ADMINISTER, True),
            'Administrator': (0xff, False)
        }
        for r in roles:
            role = Role()
            role.permissions = roles[r][0]
            role.default = roles[r][1]
            role._id = collection.get_next_id('role')
            role.name = '12@qq.com'
            role.save()
    @staticmethod
    def getlist():
            rv = mc.get(Role.CACHEKEY['list'])
            # rv = rs.get(Role.CACHEKEY['list'])
            if rv is None:
                rv = Role.objects().limit(30)
                temp =  json.dumps([item.to_json() for item in rv])
                try:
                    mc.set(Role.CACHEKEY['list'],temp)
                except Exception,e:
                    logging.debug(e)
                    return rv
                #rs.set(Role.CACHEKEY['list'],temp)
            else:
                rv = json.loads(rv)
            return rv #Role.objects().limit(30)

    def editinfo(self):
        mc.delete(Role.CACHEKEY['list'])
        if self._id > 0:
            update = {}
            # update.append({'set__email': self.email})

            if len(self.name) > 0:
                update['set__name'] = self.name
            update['set__default'] = self.default
            update['set__permissions'] = self.permissions
            Role.objects(_id=self._id).update_one(**update)
            return 1
        else:
            self._id = collection.get_next_id(self.__tablename__)
            self.save()
            return self._id

    @staticmethod
    def getinfo(rid):
        #获取指定id 角色信息
        #return Role.objects(_id=rid).first()
        #'''
        if rid>0:
            rlist = Role.getlist()
            for item in rlist:
                if item['_id']==rid:
                    return item
            return None
        else:
            return None
        #'''
    def to_json(self):
        json_role = {
            '_id': self.id,
            'name': self.name.encode('utf-8'),
            'default': self.default,
            'permissions': self.permissions.to_json()
        }
        return json_role
    '''
    def __repr__(self):
        return '<Role %r>' % self.name # 角色权限
    '''

class UserStats( EmbeddedDocument):  # 会员统计
    meet = IntField(default=0, db_field='m') #见面次数
    comment_count = IntField(default=0, db_field='cc')  # 评论人数
    comment_total = IntField(default=0, db_field='ct')  # 评论总分
    lastaction = IntField(default=0, db_field='la')  # 最后更新时间
    rand = IntField(default=common.getrandom(), db_field='r')  # 随机数 用于随机获取专家列表
    message_count = 0  # 消息个数
    baidu = IntField(default=0, db_field='b')  # 百度关注数
    weixin = IntField(default=0, db_field='w')  # 微信关注数
    zhihu = IntField(default=0, db_field='z')  # 知乎关注数
    sina = IntField(default=0, db_field='s')  # 新浪关注数
    oldx = IntField(default=0, db_field='x')  # 旧字段 无效

    def to_json(self):
        json_us = {
            'meet': self.meet
        }
        return json_us

class User(UserMixin,  Document):  # 会员
    __tablename__ = 'users'
    meta = {
        'collection': __tablename__,
    }
    _id =  IntField(primary_key=True)
    name =  StringField(
        default='', max_length=64, required=True, db_field='n')  # 姓名
    username =  StringField(
        default='', max_length=64, required=True, db_field='un')  # 帐号
    password_hash =  StringField(
        default='', required=True, max_length=128, db_field='p')  # 密码
    role_id =  IntField(default=0, db_field='r')  # 用户组id 1管理员 2专家用户 3普通用户
    role = None  # 用户组权限
    geo =  PointField(default=[0, 0], db_field='ge')  # 坐标
    stats =  EmbeddedDocumentField(
        UserStats, default=UserStats(), db_field='st')  # 统计
    date =  IntField(default=common.getstamp(), db_field='d')  # 创建时间
    intro =  StringField(default='', db_field='i')  # 简介

    state =  IntField(default=1, db_field='sta')# 状态 1 正常  -1新增  -2待审核 0暂停

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.role is None:
            #if self.email == current_app.config['FLASK_ADMIN']:
            #    self.role = Role.objects(permissions=0xff).first()
            if self.role is None:
                self.role = Role.objects(default=True).first()
        '''
        if self.email is not None and self.avatar_hash is None:
            self.avatar_hash = hashlib.md5(
                self.email.encode('utf-8')).hexdigest()
        '''
    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_confirmation_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'confirm': self.id})

    def confirm(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('confirm') != self.id:
            return False
        self.confirmed = True
        session.add(self)
        return True

    def generate_reset_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'reset': self.id})

    def reset_password(self, token, new_password):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('reset') != self.id:
            return False
        self.password = new_password

        update = {}
        update['set__password_hash'] = self.password_hash
        update['set__stats__lastaction'] = common.getstamp()
        User.objects(_id=self._id).update_one(**update)

        return True

    def generate_email_change_token(self, new_email, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'change_email': self.id, 'new_email': new_email})

    def can(self,name, permissions):
        #return self.role is not None and (getattr(self.role['permissions'],name) & permissions) == permissions
        return self.role is not None and (self.role['permissions'][name] & permissions) == permissions

    def is_administrator(self):
        return self.can(Permission.ADMINISTER)
    '''

    def ping(self):
        self.last_seen = datetime.utcnow()
         session.add(self)
    '''

    def gravatar(self, size=100, default='identicon', rating='g'):
        if request.is_secure:
            url = 'https://secure.gravatar.com/avatar'
        else:
            url = 'http://www.gravatar.com/avatar'
        hash = self.avatar_hash or hashlib.md5(
            self.email.encode('utf-8')).hexdigest()
        return '{url}/{hash}?s={size}&d={default}&r={rating}'.format(
            url=url, hash=hash, size=size, default=default, rating=rating)

    @staticmethod
    def getinfo_app(username):
        # 获取指定id 用户(APP)

        query = Q(username=username) # & (Q(role_id=2) | Q(role_id=3))

        u_info = User.objects(query).first()

        if u_info is not None:
            u_info.role = Role.getinfo(u_info.role_id)
        return u_info

    def saveinfo(self):
        if self._id > 0:
            pass
            return 1
        else:
            self._id = collection.get_next_id(self.__tablename__)
            self.date = common.getstamp()
            self.save()
            return self._id

    def to_json(self):

        json_user = {
            '_id': self.id,
            'name': self.name.encode('utf-8'),
            'geo': [self.geo['coordinates'][1], self.geo['coordinates'][0]],
            'intro': self.intro.encode('utf-8'),
            
            'role_id':self.role_id
        }

        return json_user

    def generate_auth_token(self, expiration):
        s = Serializer(current_app.config['SECRET_KEY'],
                       expires_in=expiration)
        return s.dumps({'id': self.id}).decode('ascii')

    @staticmethod
    def verify_auth_token(token):
        # token =
        # 'eyJhbGciOiJIUzI1NiIsImV4cCI6MTQzMzkzMDUwNiwiaWF0IjoxNDMzOTI2OTA2fQ.eyJpZCI6NH0.kf4L_xi-7vF655_g6-y7XgajANtzkPsFVnxYDp8g0ZY'

        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None  # valid token, but expired
        except BadSignature:
            return None  # invalid token
        return User.objects().get(_id=data['id'])

    def __repr__(self):
        return '<User %r>' % self.username

class Light( Document):  # 设备
    __tablename__ = 'client'
    meta = {
        'collection': __tablename__,
    }

    _id =  IntField(primary_key=True)
    _type =  IntField(default=0, db_field='t')  # 类型
    user_id =  IntField(default=0, db_field='u')  # 创建时间
    date =  IntField(default=common.getstamp(), db_field='d')  # 创建时间
    device_id =  StringField(
        default='', max_length=64, required=True, db_field='di')
    activa_data =  IntField(default=0, db_field='ad')  # 最后活动时间
    state =  IntField(default=0, db_field='s')  # 状态

    @staticmethod
    def getinfo(id):
        return Light.objects(_id=id).first()

    @staticmethod
    def getlist(userid=0,index=1, count=10,state=-10):
        # 获取列表
        pageindex =(index-1)*count
        query=None
        if state>-10:
            query = Q(state=state)
        if userid>0:
            if query is None:
                query = Q(user_id=userid)
            else:
                query = query & Q(user_id=userid)
        if query is None:
            return Light.objects.order_by("-_id").skip(pageindex).limit(count)
        else:
            return Light.objects(query).order_by("-_id").skip(pageindex).limit(count)

    @staticmethod
    def getcount(state=-10):
        query=None
        if state>-10:
            query = Q(state=state)

        if query is None:
            return Light.objects.count()
        else:
            return Light.objects(query).count()

    def saveinfo(self):
        if self._id > 0:
            update = {}
            # update.append({'set__email': self.email})

            update['set___type'] = self._type
            update['set__user_id'] = self.user_id
            update['set__device_id'] = self.device_id
            update['set__activa_data'] = common.getstamp()
            update['set__state'] = self.state
            #update['set__lockstate'] = self.lockstate
            #update['set__state'] = self.state

            Light.objects(_id=self._id).update_one(**update)
            return 1
        else:
            self._id = collection.get_next_id(self.__tablename__)
            self.activa_data = common.getstamp()
            self.save()
            return self._id

    @staticmethod
    def update(did):
        #更新锁状态
        update = {}
       
        update['set__activa_data'] = common.getstamp()
        update['set__state'] = 1
        return Light.objects(device_id=did).update_one(**update)

    @staticmethod
    @scheduler.scheduled_job('cron', id='my_job_id', second='*/3', hour='*')
    def clearonline():
        #清理不在线设备
        logging.debug('已清理')
        nowtime = common.getstamp()
        update = {}
        #update['set__lockstate'] = action
        update['set__activa_data'] = nowtime
        update['set__state'] = 0
        #print str(nowtime-450)
        return Light.objects(state=1,activa_data__lt=nowtime-8).update(**update)

    def to_json(self):
        json = {
            '_id': self.id,
            'user_id': self.user_id,
            'date': self.date,
            'device_id': self.device_id.encode('utf-8'),
            'activa_data': self.activa_data,  # self.auth.vip
            'state': self.state
        }
        return json

class AnonymousUser(AnonymousUserMixin):

    confirmed=True #允许访问公共api

    def can(self, permissions):
        return False

    def is_administrator(self):
        return False # 游客

login_manager.anonymous_user = AnonymousUser


@login_manager.user_loader
def load_user(user_id):
    return User.objects(id=user_id)


class collection( Document):
    meta = {
        'collection': 'collection',
    }
    name =  StringField(max_length=30, required=True)
    index =  IntField(required=True)

    @staticmethod
    def get_next_id(tablename):
        doc = collection.objects(name=tablename).modify(inc__index=1)
        if doc:
            return doc.index + 1
        else:
            collection(name=tablename, index=1).save()
            return 1 # 自增id