# -*- coding: utf-8 -*-

import os

from datetime import datetime
from flask_wtf import FlaskForm
from flask_sqlalchemy import SQLAlchemy
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from flask import Flask, render_template, redirect, url_for, flash, request, make_response, session, jsonify

app = Flask(__name__)

db = SQLAlchemy(app)
app.config['SECRET_KEY'] = "lllllllllllll"
app.config['DEBUG'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:////' + os.path.join(app.root_path,
                                                                                               'DatabaseName.db'))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True
app.config['UPLOAD_PATH'] = os.path.join(app.root_path, 'uploads')


class User(db.Model):
    __tablename__ = 'user'
    username = db.Column(db.String, nullable=False)
    password = db.Column(db.String)
    ID = db.Column(db.Integer, primary_key=True)


class Message(db.Model):
    __tablename__ = 'message'
    body = db.Column(db.TEXT)
    time = db.Column(db.DATETIME)
    ID = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String)


class Birth(db.Model):
    __tablename__ = 'BIRTH'
    time = db.Column(db.DATETIME)
    ID = db.Column(db.Integer, primary_key=True)


class WriteForm(FlaskForm):
    body = StringField('文本', validators=[DataRequired()])
    submit = SubmitField('留言')


class LoginForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired()])
    password = PasswordField('密码', validators={DataRequired(), Length(6, 20, message='密码只能在6~20个字符之间'), })
    remember = BooleanField('记住密码')
    submit = SubmitField('立即登录')


class RegisterForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired(message='用户名不能为空')])
    password = PasswordField('密码', validators=[DataRequired(message='密码不能为空'), Length(6, 20, message='密码只能在6~20个字符之间')])
    confirm = PasswordField('确认密码', validators=[EqualTo('password', message='两次密码不一致')])
    submit = SubmitField('立即注册')

    # 自定义用户名验证器
    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('用户名已注册，请选用其它名称')


@app.route('/reg', methods=['GET', 'POST'])
def reg():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User(
            username=username,
            password=password
        )
        db.session.add(user)
        db.session.commit()
        flash('Your id is saved.')
        return render_template('index.html')
    return render_template('reg.html', form=form)


@app.route('/log', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        u = User.query.filter_by(username=form.username.data).first()
        if not u:
            flash('无效的用户名')
        elif u.password == form.password.data:
            flash('登录成功')
            mess = WriteForm()
            session['username'] = u.username
            return redirect(url_for('message', form=mess))
        else:
            flash('无效的密码')
        return render_template('login.html', form=form)
    return render_template('login.html', form=form)


@app.route('/', methods=['GET', 'POST'])
def index():
    messages = Message.query.all()
    return render_template('index.html', messages=messages)


@app.route('/mess', methods=['GET', 'POST'])
def message():
    if session.get('username') is None:
        return redirect(url_for('login'))

    form = WriteForm()
    name = session.get('username')
    if form.validate_on_submit():
        mess = Message(
            body=form.body.data,
            username=name,
            time=datetime.now()
        )
        db.session.add(mess)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('mess.html', form=form)


@app.route('/birth', methods=['GET', 'POST'])
def birth():
    birth = Birth(
        time=datetime.now()
    )
    db.session.add(birth)
    db.session.commit()
    qwerty = Birth.query.all()
    for bir in qwerty:
        print(bir.ID)
    return jsonify(bir.ID)
