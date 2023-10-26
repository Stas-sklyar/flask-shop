import os
from flask import Flask, render_template, request, redirect
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join('data.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class Product(db.Model):
    product_id = db.Column(db.Integer, primary_key=True)
    product_name = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(100))
    price = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'Product(product_id={self.product_id}, product_name={self.product_name}, description={self.description}, price={self.price}, date={self.date})'


class AppUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(100))
    role = db.Column(db.String(100))

    def __repr__(self):
        return f'Product(id={self.id}, email={self.email}, password={self.password}, role={self.role})'


with app.app_context():
    db.create_all()


@app.route('/')
def home():
    products = Product.query.order_by(Product.date.desc()).all()
    return render_template('home.html', products=products)


@app.route('/admin')
def admin():
    return render_template('admin.html')


@app.route('/create-product', methods=['POST', 'GET'])
def create_product():
    if request.method == 'POST':
        product_name = request.form['product_name']
        description = request.form['description']
        price = request.form['price']

        new_product = Product(product_name=product_name, description=description, price=price)

        db.session.add(new_product)
        db.session.commit()
        return redirect('/product')
    else:
        return render_template('create-product.html')


@app.route('/edit-product/<int:product_id>')
def edit_product(product_id):
    return render_template('edit-product.html', product_id=product_id)


@app.route('/product/<int:product_id>')
def product_detail(product_id):
    product = Product.query.get(product_id)
    return render_template('product.html', product=product)


@app.route('/product/<int:product_id>/delete')
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)

    try:
        db.session.delete(product)
        db.session.commit()
        return redirect('/')
    except:
        return 'error'


@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/registration')
def registration():
    return render_template('registration.html')
