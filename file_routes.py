#!/usr/bin/env python3
import pandas as pd
from flask import Blueprint
from flask import render_template, request, redirect, url_for
import csv
from werkzeug.utils import secure_filename
import yfinance as yf
import os

files  = Blueprint('files', __name__) 


