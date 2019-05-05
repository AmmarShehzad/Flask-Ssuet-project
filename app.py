from flask import Flask , render_template ,request ,flash , redirect , url_for , session
from flask_mysqldb import MySQL
from passlib.hash import sha256_crypt
from wtforms import Form , StringField , TextAreaField, PasswordField , validators
from functools import wraps

app = Flask(__name__)

# Config MySQL
app.config['MYSQL_HOST'] = "localhost"
app.config['MYSQL_USER'] = "root"
app.config['MYSQL_PASSWORD'] = "123456"
app.config['MYSQL_DB'] = "myFlaskApp"
app.config['MYSQL_CURSORCLASS'] = "DictCursor"

# Init database
mysql = MySQL(app)


@app.route("/")
def hello():
    return render_template('home.html')

class RegisterForm(Form):
    name = StringField('Name' , [validators.Length(min=1 , max=50)])
    username = StringField('Username' , [validators.Length(min=4 , max=25)])
    email = StringField('Email' , [validators.Length(min=6 , max=50)])
    password = PasswordField('Password' , [
        validators.DataRequired(),
        validators.EqualTo('confirm' , message = 'Password do not match')
        ])
    confirm = PasswordField('Confirm Password')


@app.route('/register' , methods=['GET' , "POST"])
def register():
    form =  RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name =  form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        # create cursor
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users(name , email , username , password) VALUES(%s, %s , %s , %s)" ,
        (name , email , username , password))
        
        # commit to db
        mysql.connection.commit()

        # close connectioin
        cur.close()

        flash("You are now registered and can login" , "success")
        return redirect(url_for('login'))

    return render_template("register.html"  , form = form)




@app.route('/login' , methods=['GET' , 'POST'])
def login():
    if request.method == 'POST':
        #GET FORM FIELDS
        username = request.form['username']
        password_candid = request.form['password']

        #CREATE CURSOR
        cur = mysql.connection.cursor()
        #GET USER BY USERNAME
        result = cur.execute("SELECT * FROM users WHERE username = %s" ,[username])

        if result > 0:
            #GET STORED HASH
            data = cur.fetchone()
            password = data['password']
            if sha256_crypt.verify(password_candid , password):
                #passed
                session['logged_in'] = True
                session['username'] = username

                flash("You are now logged in " , 'success')
                return redirect(url_for('dashboard'))
            else:
                error = "Invalid LOgin"
                return render_template('login.html' , error=error)
            cur.close()
        else:
            error = "Username not found"
            return render_template('login.html' , error = error)
    return render_template('login.html')



def is_logged_in(g):
    @wraps(g)
    def wrap(*args , **kwargs):
        if 'logged_in' in session:
            return g(*args , **kwargs)
        else:
            flash("Un authorized, Please login " , "danger")
            return redirect(url_for('login'))
    return wrap


@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash("You are now logged out" , "success")
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.secret_key = 'secret123'
    app.run(debug=True , port=3000)
