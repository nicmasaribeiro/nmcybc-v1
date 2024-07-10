import matplotlib.pyplot as plt
from matplotlib.pyplot import figure
import mpld3
import yfinance as yf
import numpy as np
import math


class GeometricBrownianMotion:
	
	def simulate_paths(self):
		while(self.T - self.dt > 0):
			dWt = np.random.normal(0, math.sqrt(self.dt))  # Brownian motion
			dYt = self.drift*self.dt + self.volatility*dWt  # Change in price
			self.current_price += dYt  # Add the change to the current price
			self.prices.append(self.current_price)  # Append new price to series
			self.T -= self.dt  # Accound for the step in time
			
	def __init__(self, initial_price, drift, volatility, dt, T):
		self.current_price = initial_price
		self.initial_price = initial_price
		self.drift = drift
		self.volatility = volatility
		self.dt = dt
		self.T = T
		self.prices = []
		self.simulate_paths()
		
def graph(t):
	ticker = yf.Ticker(t.upper())
	df = ticker.history(period = '1d', interval='1m')
	print(df)
	stock = df['Close']
	ret = stock.pct_change()[1:]
	paths = 50
	initial_price = stock[-1]
	drift = np.mean(ret)
	volatility = np.std(stock)*np.sqrt(420)#*np.sqrt(256)
	dt = 1/420
	T = 1
	fig = figure()
	ax = fig.gca()
	price_paths = []
	for i in range(0, paths):
		price_paths.append(GeometricBrownianMotion(initial_price, drift, volatility, dt, T).prices)
	for price_path in price_paths:
		ax.plot(price_path)
	mpld3.save_html(fig,'graph.html')