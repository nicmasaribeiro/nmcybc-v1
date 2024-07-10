#!/usr/bin/env python3

import yfinance as yf
import numpy as np
import pandas as pd
import random

#random.choice(<#seq#>)

def bin_stats_df(ticker,period='1d',interval='1m'):
	ticker = yf.Ticker(ticker.upper())
	history = ticker.history(period=period,interval=interval)
	df = history[['Close','Open']]
	up = []
	down = []
	for i in range(0, len(df)):
		direction = df["Close"][i] - df['Open'][i]
		if direction > 0:
			up.append(direction)
		else:
			down.append(direction)
	
	prob_up = len(up)/(len(up)+len(down))
	mean_up = np.mean(up)
	std_up = np.std(up)
	prob_down = len(down)/(len(up)+len(down))
	mean_down = np.mean(down)
	std_down = np.std(down)
	
	data = pd.DataFrame({'prob':[prob_down,prob_up],'mean':[mean_down,mean_up],'std':[std_down,std_up]},index=['down','up'])
	return data.T
df = bin_stats_df('ibm')

def pi(df,m,label):	
	n = 1 
	for i in range(0,m):
		n *= df[label][0]*df[label][1] 
		n += df[label][2]
	return n

ls_up = [pi(df, i, 'up') for i in range(10)]
print(ls_up)

ls_down = [-float(pi(df, i, 'down')) for i in range(10)]
print(ls_down)