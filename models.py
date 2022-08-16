from datetime import datetime
from email.policy import default
from enum import unique
from application import db , login_manager
from flask_login import UserMixin

#Login function
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model,UserMixin):
    id = db.Column(db.Integer,primary_key=True)
    name = db.Column(db.String(20),nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    phone = db.Column(db.Integer,nullable=False)
    role = db.Column(db.String(30),nullable=False)
    state = db.Column(db.String(30),nullable=False)
    city = db.Column(db.String(20), nullable=False)
    org_name = db.Column(db.String(20), nullable=False)
    aadhar = db.Column(db.Integer, unique=True, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    permission = db.Column(db.Boolean, default=False, nullable=False)

    def __repr__(self):
         return f"User('{self.name}', '{self.email}', '{self.role}')"

class form_1(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(25), nullable=False)
    email = db.Column(db.String(25), nullable=False)
    add1 = db.Column(db.String(25), nullable=False)
    add2 = db.Column(db.String(25), nullable=False)
    phone = db.Column(db.String(25), nullable=False)
    state = db.Column(db.String(15), nullable=False) 
    pincode = db.Column(db.Integer)

    def __repr__(self) -> str:
        return f"Form_1('{self.id} - {self.name}')"
    
class Form_2(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(25), nullable=False)
    add1 = db.Column(db.String(25), nullable=False)
    add2 = db.Column(db.String(25), nullable=False)
    email = db.Column(db.String(25), nullable=False)
    mot = db.Column(db.String(10), nullable=False) 
    mot_name = db.Column(db.String(25), nullable=False)
    mot_add1 = db.Column(db.String(25), nullable=False)
    mot_add2 = db.Column(db.String(25), nullable=False)
    distance = db.Column(db.Integer, nullable=False)
    area = db.Column(db.Integer, nullable=False)
    cop = db.Column(db.String(25), nullable=False) #classification of Project
    type = db.Column(db.String(25), nullable=False) 
    other_type = db.Column(db.String(15), nullable=False)
    ownership = db.Column(db.String(10), nullable=False) 
    availability = db.Column(db.String(10), nullable=False) 
    utilities = db.Column(db.ARRAY(db.String(30)), nullable=False) 
    category = db.Column(db.String(50), nullable=False) 
    other_cat = db.Column(db.String(50), nullable=False)
    ancillary = db.Column(db.ARRAY(db.String(100)), nullable=False)
    cost = db.Column(db.Integer, nullable=False)
    share = db.Column(db.Integer, nullable=False)
    m1 = db.Column(db.Integer)
    m2 = db.Column(db.Integer)
    m3 = db.Column(db.Integer)
    m4 = db.Column(db.Integer)
    m5 = db.Column(db.Integer)
    m6 = db.Column(db.Integer)
    m7 = db.Column(db.Integer)
    m8 = db.Column(db.Integer)
    m9 = db.Column(db.Integer)
    tot = db.Column(db.Integer)
    
    def __repr__(self) -> str:
        return f"Form_2('{self.id} - {self.name}')"

class Form_3(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    inc = db.Column(db.String(3), nullable = False) #innovative and creative methods
    asi = db.Column(db.ARRAY(db.String(50)), nullable=False) #available sports infra
    noc = db.Column(db.Integer, nullable=False) #no of centres
    nop = db.Column(db.Integer, nullable=False) #no of players
    ub = db.Column(db.Integer, nullable=False) #userbase
    m1 = db.Column(db.Integer)
    m2 = db.Column(db.Integer)
    m3 = db.Column(db.Integer)
    m4 = db.Column(db.Integer)
    m5 = db.Column(db.Integer)
    m6 = db.Column(db.Integer)
    m7 = db.Column(db.Integer)
    m8 = db.Column(db.Integer)
    m9 = db.Column(db.Integer)
    m10 = db.Column(db.Integer)
    tot = db.Column(db.Integer)
    def __repr__(self) -> str:
        return f"('Form_3{self.id}')"

class Form_4(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nd = db.Column(db.String(3), nullable = False) #natural disaster
    demand = db.Column(db.String(3), nullable = False) 
    pg = db.Column(db.String(3), nullable = False) #population growth
    apo = db.Column(db.String(3), nullable = False) #additional programming oppurtunities
    m1 = db.Column(db.Integer)
    m2 = db.Column(db.Integer)
    m3 = db.Column(db.Integer)
    m4 = db.Column(db.Integer)
    m5 = db.Column(db.Integer)
    m6 = db.Column(db.Integer)
    m7 = db.Column(db.Integer)
    m8 = db.Column(db.Integer)
    tot = db.Column(db.Integer)

    def __repr__(self) -> str:
        return f"('Form_4{self.id}')"

class Form_5(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    prev = db.Column(db.String(3), nullable = False) #previous projects
    od = db.Column(db.String(3), nullable = False) #overdue projects
    comp = db.Column(db.String(3), nullable = False) #completed projects
    sub_time = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self) -> str:
        return f"('Form_5{self.id}')"