import os
from flask import Flask, render_template, request, redirect, url_for, session, Response
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_bcrypt import Bcrypt
from decorators import login_required
from functools import wraps

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join('data.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'my_secret_key_12345'
db = SQLAlchemy(app)


@app.context_processor
def inject_logged_in():
    if 'user_id' in session:
        logged_in = True
        user = AppUser.query.get(session['user_id'])
    else:
        logged_in = False
        user = None
    return dict(logged_in=logged_in, user=user)


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
    email = db.Column(db.VARCHAR(50), nullable=False, unique=True)
    password = db.Column(db.VARCHAR(100), nullable=False)
    role = db.Column(db.VARCHAR(100), nullable=False)
    favorite_products = db.relationship('Product', secondary='user_favorite_products')

    def __repr__(self):
        return f'Product(id={self.id}, email={self.email}, password={self.password}, role={self.role})'


user_favorite_products = db.Table(
    'user_favorite_products',
    db.Column('user_id', db.Integer, db.ForeignKey('app_user.id'), primary_key=True),
    db.Column('product_id', db.Integer, db.ForeignKey('product.product_id'), primary_key=True)
)

with app.app_context():
    db.create_all()


def admin_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if 'user_id' in session:
            user = AppUser.query.get(session['user_id'])
            if user and user.role == 'admin':
                return view(*args, **kwargs)
        return 'You are not admin'

    return wrapped_view


@app.route('/')
def home():
    products = Product.query.order_by(Product.date.desc()).all()
    return render_template('home.html', products=products)


@app.route('/admin')
@admin_required
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


@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = AppUser.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['user_role'] = user.role
            return redirect(url_for('profile'))
    return render_template('login.html')


@app.route('/registration', methods=['POST', 'GET'])
def registration_client():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        new_client = AppUser(email=email, password=hashed_password, role='client')

        try:
            db.session.add(new_client)
            db.session.commit()
            return redirect('/login')
        except:
            return 'error during registration'
    else:
        return render_template('registration.html')


@app.route('/my-profile')
@login_required
def profile():
    user = AppUser.query.get(session['user_id'])
    favorite_products = user.favorite_products
    return render_template('profile.html', favorite_products=favorite_products)


@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    session.pop('user_role', None)
    return redirect(url_for('login'))


@app.route('/change-password', methods=['POST'])
@login_required
def change_password():
    old_password = request.form['old_password']
    new_password = request.form['new_password']

    user = AppUser.query.get(session['user_id'])

    if user:
        if bcrypt.check_password_hash(user.password, old_password):
            user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            db.session.commit()
            return Response('Password updated successfully', status=200)
        else:
            return 'Incorrect old password'
    else:
        return 'User not found'


@app.route('/create-admin', methods=['POST'])
@login_required
@admin_required
def create_admin():
    email = request.form['email']
    password = request.form['password']
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    new_admin = AppUser(email=email, password=hashed_password, role='admin')

    try:
        db.session.add(new_admin)
        db.session.commit()
        return 'success'
    except:
        return ('error during create new admin')


@app.route('/add-to-cart/<int:product_id>', methods=['POST'])
@login_required
def add_to_cart(product_id):
    if 'cart' not in session:
        session['cart'] = {}

    product_id = str(product_id)
    if product_id in session['cart']:
        session['cart'][product_id] += 1
    else:
        session['cart'][product_id] = 1

    session.modified = True

    return redirect(url_for('cart'))


@app.route('/increment-cart/<int:product_id>', methods=['POST'])
@login_required
def increment_cart(product_id):
    if 'cart' in session:
        product_id = str(product_id)

        if product_id in session['cart']:
            session['cart'][product_id] += 1
            session.modified = True

    return redirect(url_for('cart'))


@app.route('/decrement-cart/<int:product_id>', methods=['POST'])
@login_required
def decrement_cart(product_id):
    if 'cart' in session:
        product_id = str(product_id)

        if product_id in session['cart']:
            if not session['cart'][product_id] == 1:
                session['cart'][product_id] -= 1
            session.modified = True

    return redirect(url_for('cart'))


@app.route('/remove-from-cart/<int:product_id>', methods=['POST'])
def remove_from_cart(product_id):
    if 'cart' in session:
        product_id = str(product_id)

        if product_id in session['cart']:
            del session['cart'][product_id]
            session.modified = True

    return redirect(url_for('cart'))


@app.route('/cart')
def cart():
    cart_contents = {}
    if 'cart' in session:
        for product_id, quantity in session['cart'].items():
            product = Product.query.get(product_id)
            cart_contents[product] = quantity

    return render_template('cart.html', cart_contents=cart_contents)


@app.route('/add-to-favorites/<int:product_id>', methods=['POST'])
@login_required
def add_to_favorites(product_id):
    user = AppUser.query.get(session['user_id'])
    product = Product.query.get(product_id)

    if product:
        user.favorite_products.append(product)
        db.session.commit()
        return 'Product added to favorites'

    return 'Product not found', 404


@app.route('/remove-from-favorites/<int:product_id>', methods=['POST'])
@login_required
def remove_from_favorites(product_id):
    user = AppUser.query.get(session['user_id'])
    product = Product.query.get(product_id)

    if product:
        user.favorite_products.remove(product)
        db.session.commit()
        return 'Product removed from favorites'

    return 'Product not found', 404


@app.route('/checkout')
def checkout():
    cart_contents = session.get('cart', {})
    total_price = 0

    for product_id, quantity in cart_contents.items():
        product = Product.query.get(int(product_id))
        if product:
            total_price += product.price * quantity

    return render_template('checkout.html', total_price=total_price)


@app.route('/confirm-order', methods=['GET', 'POST'])
def confirm_order():
    if request.method == 'POST':
        if 'cart' in session:
            session.pop('cart')

        return redirect('order-successfully-confirmed')
    else:
        return render_template('confirm-order.html')

@app.route('/order-successfully-confirmed')
def order_successfully_confirmed():
    return render_template('order-successfully-confirmed.html')
