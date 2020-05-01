"""This module is to configure app to connect with database."""

from pymongo import MongoClient

DATABASE = MongoClient()['tarangdb']  # DB_NAME
DEBUG = True
SECRET_KEY = 'lm-secret'
client = MongoClient('localhost', 27017)
