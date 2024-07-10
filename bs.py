import math
import numpy as np

def norm_cdf(x):
    """Calculate the cumulative distribution function of the standard normal distribution."""
    return (1.0 + math.erf(x / math.sqrt(2.0))) / 2.0

def black_scholes(S, K, T, r, sigma, option_type='call'):
    """
    Calculate Black-Scholes option price.
    
    S: spot price
    K: strike price
    T: time to maturity (in years)
    r: risk-free rate
    sigma: volatility (standard deviation of stock's returns)
    option_type: 'call' or 'put'
    """
    d1 = (np.log(S / K) + (r + 0.5 * sigma**2) * T) / (sigma * np.sqrt(T))
    d2 = d1 - sigma * np.sqrt(T)
    
    if option_type == 'call':
        price = S * norm_cdf(d1) - K * np.exp(-r * T) * norm_cdf(d2)
    elif option_type == 'put':
        price = K * np.exp(-r * T) * norm_cdf(-d2) - S * norm_cdf(-d1)
    else:
        raise ValueError("option_type must be 'call' or 'put'")
    
    return price
