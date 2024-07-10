#!/usr/bin/env python3

#!/usr/bin/env 
import matplotlib.pyplot as plt
import numpy as np
import math
import yfinance as yf
import datetime as dt

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
		
#t = input("ticker <<\t").upper()
#ticker = yf.Ticker(f'{t}')
#df = ticker.history(start='2020-1-1',end=dt.date.today(),interval='1d')
#stock = df['Close']
#ret = stock.pct_change()[1:]
#
##		Model Parameters
#paths = 100
#initial_price = stock[-1]
#drift = np.mean(ret)*np.sqrt(256)
#volatility = np.std(stock)#*np.sqrt(256)
#dt = 1/365
#T = .25
#price_paths = []
#
## Generate a set of sample paths
#for i in range(0, paths):
#	price_paths.append(GeometricBrownianMotion(initial_price, drift, volatility, dt, T).prices)
#	
#for price_path in price_paths:
#	plt.plot(price_path)
#plt.plot()
#plt.show()

