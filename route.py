import pandas as pd
from flask import Blueprint
from flask import render_template, request, redirect, jsonify
import csv
import yfinance as yf
from models import Users,InvestmentDatabase,db, login_manager,login_required, TransactionDatabase
from app import blockchain
brokarage  = Blueprint('store', __name__) 

# Dummy data for products (replace with database or real data)
products = [
	{'id': 1, 'name': 'Product 1', 'price': 10.0},
	{'id': 2, 'name': 'Product 2', 'price': 20.0},
	{'id': 3, 'name': 'Product 3', 'price': 30.0},
]

@brokarage.route('/index')
def index():
	return render_template('store.html', products=products)

@brokarage.route('/product/<int:id>')
def product(id):
	product = next((p for p in products if p['id'] == id), None)
	if product:
		return render_template('product.html', product=product)
	return 'Product not found'

@login_required
@brokarage.route('/show')
def show_db():
	db = pd.read_csv('/Users/nivmasagao/nmc Dropbox/Nic Masagao/Mac (2)/Desktop/appdemo/app/portfolio/database.csv')
	html = db.to_html()
	header = "<h1><a href='/'> Home </a></h1>"
	return f"{header}{html}"

@login_required
@brokarage.route('/get/<owner>/<ticker>')
def process_ticker_logic(owner,ticker):
	db = pd.read_csv('/Users/nivmasagao/nmc Dropbox/Nic Masagao/Mac (2)/Desktop/appdemo/app/portfolio/database.csv')
	df = db.groupby('owner').get_group(owner)
	tdf = df.groupby('ticker').get_group(ticker)
	value = sum(tdf['quantity'])
	return f"<h1>{ticker}</h1> <h4>{value}</h4>"

@login_required
@brokarage.route('/get/myport')
def name():
    return render_template('get-my-port.html')


@brokarage.route('/make/investment',methods=['GET','POST'])
def buy_or_sell():
	if request.method == "POST":
		f = open('portfolio/database.csv', 'a')
		name = request.form['name']
		ticker = request.form['ticker']
		qt = request.form['qt']
		users = Users.query.all()
		users_ls = [user.username for user in users]
		if name in users_ls:
			h = yf.Ticker(ticker.upper()).history()['Close']
			price = h[-1]
			value = price*float(qt)
			data = [ticker,qt,name, price,value]
			receipt = str(data).encode()
			writer = csv.writer(f)
			writer.writerow(data)
			new_transaction = {'name':name,'ticker':ticker,'data':data,'value':value}
			blockchain.add_transaction(new_transaction)
			new_investment = InvestmentDatabase(investment_name=ticker,market_cap=price,receipt=receipt,investors=name.encode())
			db.session.add(new_investment)
			db.session.commit()
		else:
			pass
			return redirect('/broke/show')
	return render_template('make-investment-page.html')

