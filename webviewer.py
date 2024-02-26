from flask import Flask, flash, render_template, request,redirect, session, Response, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from flask_bcrypt import Bcrypt
import os
import json
import random
import string
import csv
import io
 
from distutils.log import debug 
from fileinput import filename 
from flask import *  

from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {'csv', 'evtx'}

DIR_RESULT = "result"
DIR_DATA = "data_log"

app=Flask(__name__)
app.config["SECRET_KEY"]='65b0b774279de460f1cc5c92'
app.config['SQLALCHEMY_DATABASE_URI']="sqlite:///ums.sqlite"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
app.config["SESSION_PERMANENT"]=False
app.config["SESSION_TYPE"]='filesystem'
db=SQLAlchemy(app)
app.app_context().push()
bcrypt=Bcrypt(app)
Session(app)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_random_string(length=30):
    characters = string.ascii_letters + string.digits
    random_string = ''.join(random.choice(characters) for _ in range(length))
    return random_string

# User Class
class User(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    fname=db.Column(db.String(255), nullable=False)
    lname=db.Column(db.String(255), nullable=False)
    email=db.Column(db.String(255), nullable=False)
    username=db.Column(db.String(255), nullable=False)
    token=db.Column(db.String(255), nullable=False)
    password=db.Column(db.String(255), nullable=False)
    status=db.Column(db.Integer,default=0, nullable=False)

    def __repr__(self):
        return f'User("{self.id}","{self.fname}","{self.lname}","{self.email}","{self.token}","{self.username}","{self.status}")'

# create admin Class
class Admin(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    username=db.Column(db.String(255), nullable=False)
    password=db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return f'Admin("{self.username}","{self.id}")'

# create table
db.create_all()

# insert admin data one time only one time insert this data
# latter will check the condition
#print(bcrypt.generate_password_hash('Test123',10))
#admin=Admin(username='elonmusk888',password=bcrypt.generate_password_hash('hilal123',10))
#db.session.add(admin)
#db.session.commit()

"""
# main index 
@app.route('/')
def index():
    return render_template('/user/index.html',title="")
"""

# admin loign
@app.route('/admin/',methods=["POST","GET"])
def adminIndex():
    # chect the request is post or not
    if request.method == 'POST':
        # get the value of field
        username = request.form.get('username')
        password = request.form.get('password')
        # check the value is not empty
        if username=="" and password=="":
            flash('Please fill all the field','danger')
            return redirect('/admin/')
        else:
            # login admin by username 
            # print(bcrypt.check_password_hash("a"))
            admins=Admin().query.filter_by(username=username).first()
            if admins and bcrypt.check_password_hash(admins.password,password):
                session['admin_id']=admins.id
                session['admin_name']=admins.username
                flash('Login Successfully','success')
                return redirect('/admin/dashboard')
            else:
                flash('Invalid Email and Password','danger')
                return redirect('/admin/')
    else:
        return render_template('admin/index.html',title="Admin Login")

# admin Dashboard
@app.route('/admin/dashboard')
def adminDashboard():
    if not session.get('admin_id'):
        return redirect('/admin/')
    totalUser=User.query.count()
    totalApprove=User.query.filter_by(status=1).count()
    NotTotalApprove=User.query.filter_by(status=0).count()
    return render_template('admin/dashboard.html',title="Admin Dashboard",totalUser=totalUser,totalApprove=totalApprove,NotTotalApprove=NotTotalApprove)

# admin get all user 
@app.route('/admin/get-all-user', methods=["POST","GET"])
def adminGetAllUser():
    if not session.get('admin_id'):
        return redirect('/admin/')
    if request.method== "POST":
        search=request.form.get('search')
        users=User.query.filter(User.username.like('%'+search+'%')).all()
        return render_template('admin/all-user.html',title='Approve User',users=users)
    else:
        users=User.query.all()
        return render_template('admin/all-user.html',title='Approve User',users=users)

@app.route('/admin/approve-user/<int:id>')
def adminApprove(id):
    if not session.get('admin_id'):
        return redirect('/admin/')

    User().query.filter_by(id=id).update(dict(status=1, token=generate_random_string()))
    db.session.commit()
    flash('Approve Successfully','success')
    return redirect('/admin/get-all-user')

# change admin password
@app.route('/admin/change-admin-password',methods=["POST","GET"])
def adminChangePassword():
    admin=Admin.query.get(1)
    if request.method == 'POST':
        username=request.form.get('username')
        password=request.form.get('password')
        if username == "" or password=="":
            flash('Please fill the field','danger')
            return redirect('/admin/change-admin-password')
        else:
            Admin().query.filter_by(username=username).update(dict(password=bcrypt.generate_password_hash(password,10)))
            db.session.commit()
            flash('Admin Password update successfully','success')
            return redirect('/admin/change-admin-password')
    else:
        return render_template('admin/admin-change-password.html',title='Admin Change Password',admin=admin)

# admin logout
@app.route('/admin/logout')
def adminLogout():
    if not session.get('admin_id'):
        return redirect('/admin/')
    if session.get('admin_id'):
        session['admin_id']=None
        session['admin_name']=None
        return redirect('/')
# -------------------------user area----------------------------


# User login
@app.route('/',methods=["POST","GET"])
@app.route('/user/',methods=["POST","GET"])
def userIndex():
    if  session.get('user_id'):
        return redirect('/user/dashboard/runtime')
    if request.method=="POST":
        # get the name of the field
        email=request.form.get('email')
        password=request.form.get('password')
        # check user exist in this email or not
        users=User().query.filter_by(email=email).first()
        if users and bcrypt.check_password_hash(users.password,password):
            # check the admin approve your account are not
            is_approve=User.query.filter_by(id=users.id).first()
            # first return the is_approve:
            if is_approve.status == 0:
                flash('Your Account is not approved by Admin','danger')
                return redirect('/user/')
            else:
                session['user_id']=users.id
                session['username']=users.username
                flash('Login Successfully','success')
                return redirect('/user/dashboard/runtime')
        else:
            flash('Invalid Email and Password','danger')
            return redirect('/user/')
    else:
        return render_template('user/index.html',title="User Login")

# User Register
@app.route('/user/signup',methods=['POST','GET'])
def userSignup():
    if  session.get('user_id'):
        return redirect('/user/dashboard/runtime')
    if request.method=='POST':
        # get all input field name
        fname=request.form.get('fname')
        lname=request.form.get('lname')
        email=request.form.get('email')
        username=request.form.get('username')
        # edu=request.form.get('edu')
        password=request.form.get('password')
        # check all the field is filled are not
        if fname =="" or lname=="" or email=="" or password=="" or username=="":
            flash('Please fill all the field','danger')
            return redirect('/user/signup')
        else:
            is_email=User().query.filter_by(email=email).first()
            if is_email:
                flash('Email already Exist','danger')
                return redirect('/user/signup')
            else:
                hash_password=bcrypt.generate_password_hash(password,10)
                user=User(fname=fname,lname=lname,email=email,password=hash_password,token="",username=username)
                db.session.add(user)
                db.session.commit()
                flash('Account Create Successfully Admin Will approve your account in 10 to 30 mint ','success')
                return redirect('/user/')
    else:
        return render_template('user/signup.html',title="User Signup")


@app.route('/admin/delete_user', methods=['POST'])
def delete_user():
    if not session.get('admin_id'):
        return redirect('/admin/')

    user_id = request.json['id']
    User.query.filter_by(id=user_id).delete()
    db.session.commit()

    return jsonify({'status': 'success', 'message': 'User deleted successfully'})

def read_file(filepath):
    str_content = ""
    if os.path.isfile(filepath):
        f = open(filepath, mode="r", encoding="utf-8")
        str_content = f.read()
        f.close()
    else:
        print("[-] error: no exist " + filepath)
        exit(0)

    return str_content

# user dashboard
@app.route('/user/dashboard')
@app.route('/user/dashboard/runtime')
def userDashboardRuntime():
    if not session.get('user_id'):
        return redirect('/user/')

    if session.get('user_id'):
        id=session.get('user_id')
    
    users=User.query.get(id)
    table1_data = []
    table2_data = []

    if users.token == "":
        flash('no token','error')
        return render_template('user/dashboard.html', table1_data=table1_data, table2_data=table2_data, result_type="runtime", token="")

    token = users.token
    if os.path.isdir(DIR_RESULT) == False:
        flash('no result','error')
        print("[-] error: no exist dir " + DIR_RESULT)
        return render_template('user/dashboard.html', table1_data=table1_data, table2_data=table2_data, result_type="runtime", token=token)

    dir_result_user = os.path.join(DIR_RESULT, users.token)

    if os.path.isdir(dir_result_user) == False:
        flash('no result','error')
        print("[-] error: no exist dir " + dir_result_user)
        return render_template('user/dashboard.html', table1_data=table1_data, table2_data=table2_data, result_type="runtime", token=token)

    file_rule = os.path.join(dir_result_user, "rule_runtime.txt")
    if os.path.exists(file_rule) == False:
        flash('no result','error')
        print("[-] error: no exist file " + file_rule)
        return render_template('user/dashboard.html', table1_data=table1_data, table2_data=table2_data, result_type="runtime", token=token)

    file_event = os.path.join(dir_result_user, "event_runtime.txt")
    if os.path.exists(file_event) == False:
        flash('no result','error')
        print("[-] error: no exist file " + file_event)
        return render_template('user/dashboard.html', table1_data=table1_data, table2_data=table2_data, result_type="runtime", token=token)
    
    str_tmp = read_file(file_rule)
    if len(str_tmp) > 0:
        table1_data = json.loads(str_tmp)

    str_tmp = read_file(file_event)
    if len(str_tmp) > 0:
        table2_data = json.loads(str_tmp)

    return render_template('user/dashboard.html', table1_data=table1_data, table2_data=table2_data, result_type="runtime", token=token)

# user dashboard
@app.route('/user/dashboard/static')
def userDashboardStatic():
    if not session.get('user_id'):
        return redirect('/user/')

    if session.get('user_id'):
        id=session.get('user_id')
    
    users=User.query.get(id)
    table1_data = []
    table2_data = []

    if users.token == "":
        flash('no token','error')
        return render_template('user/dashboard.html', table1_data=table1_data, table2_data=table2_data, result_type="static", token="")

    token = users.token

    if os.path.isdir(DIR_RESULT) == False:
        flash('no result','error')
        print("[-] error: no exist dir " + DIR_RESULT)
        return render_template('user/dashboard.html', table1_data=table1_data, table2_data=table2_data, result_type="static", token=token)

    dir_result_user = os.path.join(DIR_RESULT, users.token)

    if os.path.isdir(dir_result_user) == False:
        flash('no result','error')
        print("[-] error: no exist dir " + dir_result_user)
        return render_template('user/dashboard.html', table1_data=table1_data, table2_data=table2_data, result_type="static", token=token)

    file_rule = os.path.join(dir_result_user, "rule.txt")
    if os.path.exists(file_rule) == False:
        flash('no result','error')
        print("[-] error: no exist file " + file_rule)
        return render_template('user/dashboard.html', table1_data=table1_data, table2_data=table2_data, result_type="static", token=token)

    file_event = os.path.join(dir_result_user, "event.txt")
    if os.path.exists(file_event) == False:
        flash('no result','error')
        print("[-] error: no exist file " + file_event)
        return render_template('user/dashboard.html', table1_data=table1_data, table2_data=table2_data, result_type="static", token=token)
    
    str_tmp = read_file(file_rule)
    if len(str_tmp) > 0:
        table1_data = json.loads(str_tmp)

    str_tmp = read_file(file_event)
    if len(str_tmp) > 0:
        table2_data = json.loads(str_tmp)
    return render_template('user/dashboard.html', table1_data=table1_data, table2_data=table2_data, result_type="static", token=token)

# user logout
@app.route('/user/logout')
def userLogout():
    if not session.get('user_id'):
        return redirect('/user/')

    if session.get('user_id'):
        session['user_id'] = None
        session['username'] = None
        return redirect('/user/')

@app.route('/user/change-password',methods=["POST","GET"])
def userChangePassword():
    if not session.get('user_id'):
        return redirect('/user/')
    if request.method == 'POST':
        email=request.form.get('email')
        password=request.form.get('password')
        if email == "" or password == "":
            flash('Please fill the field','danger')
            return redirect('/user/change-password')
        else:
            users=User.query.filter_by(email=email).first()
            if users:
               hash_password=bcrypt.generate_password_hash(password,10)
               User.query.filter_by(email=email).update(dict(password=hash_password))
               db.session.commit()
               flash('Password Change Successfully','success')
               return redirect('/user/change-password')
            else:
                flash('Invalid Email','danger')
                return redirect('/user/change-password')

    else:
        return render_template('user/change-password.html',title="Change Password")

# user update profile
@app.route('/user/update-profile', methods=["POST","GET"])
def userUpdateProfile():
    if not session.get('user_id'):
        return redirect('/user/')
    if session.get('user_id'):
        id=session.get('user_id')
    users=User.query.get(id)
    if request.method == 'POST':
        # get all input field name
        fname=request.form.get('fname')
        lname=request.form.get('lname')
        email=request.form.get('email')
        username=request.form.get('username')
        #token=request.form.get('token')
        if fname =="" or lname=="" or email=="" or username=="":
            flash('Please fill all the field','danger')
            return redirect('/user/update-profile')
        else:
            session['username']=None
            User.query.filter_by(id=id).update(dict(fname=fname,lname=lname,email=email,username=username))
            db.session.commit()
            session['username']=username
            flash('Profile update Successfully','success')
            return redirect('/user/dashboard/runtime')
    else:
        return render_template('user/update-profile.html',title="Update Profile",users=users)

@app.route('/user/upload', methods=['POST'])
def upload_file():
    if not session.get('user_id'):
        return redirect('/user/')

    if session.get('user_id'):
        id=session.get('user_id')
    users=User.query.get(id)
    if users.token == "":
        return redirect('/user/')
    save_dir = "data_log"
    os.makedirs(save_dir, exist_ok=True)
    save_dir = os.path.join(save_dir, users.token)
    os.makedirs(save_dir, exist_ok=True)
    save_dir = os.path.join(save_dir, "static")
    os.makedirs(save_dir, exist_ok=True)

    if request.method == 'POST':
        if 'file[]' not in request.files:
            return redirect('/user/dashboard/static')

        uploaded_files = request.files.getlist('file[]')

        for file in uploaded_files:
            # Save the file to a location or perform desired operations
            if file.filename == '':
                return redirect('/user/dashboard/static')

            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(save_dir, filename))
            else:
                flash('File type not allowed','error')

        flash('Upload Successfully','success')

    return redirect('/user/dashboard/static')  # Replace with your HTML file

@app.route('/user/upload_folder', methods=['POST'])
def upload_folder():
    if not session.get('user_id'):
        return redirect('/user/')

    if session.get('user_id'):
        id=session.get('user_id')

    users=User.query.get(id)

    if users.token == "":
        return redirect('/user/')

    save_dir = "data_log"
    os.makedirs(save_dir, exist_ok=True)
    save_dir = os.path.join(save_dir, users.token)
    os.makedirs(save_dir, exist_ok=True)
    save_dir = os.path.join(save_dir, "static")
    os.makedirs(save_dir, exist_ok=True)

    if 'files[]' not in request.files:
        flash('No files were uploaded','error')
        return redirect('/user/dashboard/static')

    files = request.files.getlist('files[]')

    if len(files) == 0:
        flash('No files were uploaded','error')
        return redirect('/user/dashboard/static')

    for file in files:
        # Save the file to a location or perform desired operations
        if file.filename == '':
            return redirect('/user/dashboard/static')

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(save_dir, filename))
        else:
            flash('File type not allowed','error')

    flash('Upload Successfully','success')

    return redirect('/user/dashboard/static')  # Replace with your HTML file


if __name__=="__main__":
    app.run(host='127.0.0.1', port=5000, debug=True)
    #app.run(host='66.135.27.15', port=80)