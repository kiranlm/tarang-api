"""This module is to configure app to connect with database."""

from pymongo import MongoClient

DATABASE = MongoClient()['athletedb'] # DB_NAME
DEBUG = True
client = MongoClient('localhost', 27017)
