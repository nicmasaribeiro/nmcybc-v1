
import plotly.graph_objects as go
import numpy as np
import pandas as pd

def binomial_tree(S0, u, d, p, n):
	# S0: initial stock price
	# u: factor by which the price increases
	# d: factor by which the price decreases
	# p: probability of an up move
	# n: number of steps
	
	# Initialize the stock price tree
	tree = np.zeros((n + 1, n + 1))
	tree[0, 0] = S0
	
	# Build the tree
	for i in range(1, n + 1):
		for j in range(i + 1):
			tree[j, i] = S0 * (u ** (i - j)) * (d ** j)
			
	return tree

## Parameters
#S0 = 100  # initial stock price
#u = 1.1   # up factor
#d = 0.9   # down factor
#p = 0.5   # probability of up move
#n = 10    # number of steps
#
## Generate the binomial tree
#tree = binomial_tree(S0, u, d, p, n)
#print(pd.DataFrame(tree).to_html())