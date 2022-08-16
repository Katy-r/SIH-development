from application import app, db, bcrypt
from application import ALLOWED_EXTENSIONS
from flask import render_template, redirect, url_for, request, flash
from application.models import User
from flask_login import login_required, login_user, logout_user, current_user
import os
from werkzeug.utils import secure_filename

#File import function
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/")
@app.route("/home")
def home():
    return render_template('index.html')


@app.route("/register", methods=['POST','GET'])
def register():
    if request.method == 'POST' :

        #Snippet to input file and store in local directory
        # if 'file' not in request.files:
        #     flash('No file part')
        # file = request.files['file']
        # if file.filename == '':
        #     flash('No selected file')
        # if file and allowed_file(file.filename):
        #     filename = secure_filename(file.filename)
        #     file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        #Data from form stored in Database
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        phone = request.form['phone']
        role = request.form['role']
        state = request.form['state']
        city = request.form['city']
        org_name = request.form['org_name']
        aadhar = request.form['aadhar']

        #Hasing Password
        hashed_pwd = bcrypt.generate_password_hash(password).decode('utf-8')

        #Storing in DB
        user = User(name=name, email=email, password=hashed_pwd, phone=phone, role=role, state=state, city=city, org_name=org_name,aadhar=aadhar)
        db.session.add(user)
        db.session.commit()

        return redirect(url_for('login'))
    return render_template('register.html')


@app.route("/login",methods=['POST','GET'])
def login():

    if request.method == 'POST' :
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password=password):
            if user.role == "Proponent":
                login_user(user)
                return redirect(url_for('proponent'))
            elif user.role == "Tech":
                login_user(user)
                return redirect(url_for('committee'))
            elif user.role == "Admin":
                login_user(user)
                return redirect(url_for('admin'))
            else:
                return redirect(url_for('login'))

    return render_template('login.html')


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route("/proponent")
@login_required
def proponent():
    if not current_user.role == "Proponent":
        return redirect(url_for('error'))
    return render_template('/proponent/profile.html')


@app.route("/committee")
@login_required
def committee():
    if not current_user.role == "Tech":
        return redirect(url_for('error'))
    return render_template('/committee/profile.html')

@app.route("/admin")
@login_required
def admin():
    if not current_user.role == "Admin":
        return redirect(url_for('error'))
    return render_template('/admin/profile.html')


@app.route("/error")
def error():
    return render_template('/errors/403.html')


#Form routes
@app.route("/form_1",methods=['POST','GET'])
@login_required
def form_1():
    if not current_user.role == "Proponent":
        return redirect(url_for('error'))
    if request.method == 'POST' :
        #Form input
        name = request.form['name']
        email = request.form['email']
        add1 = request.form['add1']
        add2 = request.form['add2']
        phone = request.form['phone']
        state = request.form['state']
        pincode = request.form['pincode']

        #DB commits
        form_1 = Form_1(name=name, email=email, add1=add1, add2=add2, phone=phone, state=state, pincode=pincode)
        db.session.add(form_1)
        db.session.commit()
        return redirect(url_for('form_2'))
    allp = Form_1.query.all()
    print(form_1)
    return render_template('/proponent/form_1.html',allp=allp)


@app.route("/form_2",methods=['POST','GET'])
@login_required
def form_2():
    if not current_user.role == "Proponent":
        return redirect(url_for('error'))
    if request.method == 'POST' :
        #Form input
        if 'files[]' not in request.files:
            flash('No file part')
        files = request.files.getlist['files[]']
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        name = request.form['name']
        add1 = request.form['add1']
        add2 = request.form['add2']
        mot = request.form['mot']
        mot_name = request.form['mot_name']
        mot_add1 = request.form['mot_add1']
        mot_add2 = request.form['mot_add2']
        distance = request.form['distance']
        area = request.form['area']
        cop = request.form['cop']
        type = request.form['type']
        if(type == "Others"):
          other_type = request.form['other_type']
        ownership = request.form['ownership']
        availability = request.form['availabilty']
        utilities = request.form.getlist('utilities')
        category = request.form['category']
        other_cat = request.form['other_cat']
        ancillary = request.form['ancillary']
        cost = request.form['cost']
        share = request.form['share']

        #DB commits
        form_2 = Form_2(name=name, add1=add1, add2=add2, mot=mot, mot_add1=mot_add1, mot_add2=mot_add2, distance=distance, area=area, type=type, other_type=other_type, ownership=ownership, availability=availability, utilities=utilities, category=category, other_cat=other_cat, ancillary=ancillary, cost=cost, share=share)
        db.session.add(form_2)
        db.session.commit()
        return redirect(url_for('form_3'))
    allq = Form_2.query.all()
    print(form_2)
    return render_template('/proponent/form_2.html',allq=allq)

@app.route("/form_3",methods=['POST','GET'])
@login_required
def form_3():
    if not current_user.role == "Proponent":
        return redirect(url_for('error'))
    if request.method == 'POST' :
        #Form input
        if 'files[]' not in request.files:
            flash('No file part')
        files = request.files.getlist['files[]']
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        inc = request.form['inc']
        asi = request.form.getlist('asi')
        noc = request.form['noc']
        nop = request.form['nop']
        ub = request.form['ub']

        #DB commits
        form_3 = Form_3(inc=inc, asi=asi, noc=noc, nop=nop, ub=ub)
        db.session.add(form_3)
        db.session.commit()
        return redirect(url_for('form_4'))
    allr = Form_3.query.all()
    print(form_3)
    return render_template('/proponent/form_3.html',alllr=allr)

@app.route("/form_4",methods=['POST','GET'])
@login_required
def form_4():
    if not current_user.role == "Proponent":
        return redirect(url_for('error'))
    if request.method == 'POST' :
        #Form input
        if 'files[]' not in request.files:
            flash('No file part')
        files = request.files.getlist['files[]']
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        nd = request.form['nd']
        demand = request.form['demand']
        pg = request.form['pg']
        apo = request.form['apo']

        #DB commits
        form_4 = Form_4(nd=nd, demand=demand, pg=pg, apo=apo)
        db.session.add(form_4)
        db.session.commit()
        return redirect(url_for('form_5'))
    alls = Form_4.query.all()
    print(form_4)
    return render_template('/proponent/form_4.html',alls=alls)

@app.route("/form_5",methods=['POST','GET'])
@login_required
def form_5():
    if not current_user.role == "Proponent":
        return redirect(url_for('error'))
    if request.method == 'POST' :
        #Form input
        if 'files[]' not in request.files:
            flash('No file part')
        files = request.files.getlist['files[]']
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        prev = request.form['prev']
        od = request.form['od']
        comp = request.form['comp']

        #DB commits
        form_5 = Form_5(prev=prev, od=od, comp=comp)
        db.session.add(form_5)
        db.session.commit()
        return redirect(url_for('proponent'))
    allt = Form_5.query.all()
    print(form_5)
    return render_template('/proponent/form_5.html',allt=allt)

@app.route('/dpr/<int:id>', methods=['GET','POST'])
def show(id):
    p = Form_1.query.filter_by(id=id).first()
    q = Form_2.query.filter_by(id=id).first()
    r = Form_3.query.filter_by(id=id).first()
    s = Form_4.query.filter_by(id=id).first()
    t = Form_5.query.filter_by(id=id).first()
    return render_template('dpr.html',p=p,q=q,r=r,s=s,t=t)

@app.route('/projects', methods=['GET','POST'])
def show(id):
    allq = Form_2.query.all()
    print(allq)
    return render_template('projects.html',allq=allq)