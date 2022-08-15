
from mongoengine import *
#from mongoengine.fields import BooleanField, ListField
import pymongo
import time
import datetime
CONN_STR="mongodb://lucas:050596@10.39.0.11:1457/?authSource=admin"
def connectMongo():
    conn = connect(host=CONN_STR, alias='core', db='AIVC_Labels',serverSelectionTimeoutMS=100) 
    try:
        conn.server_info()
        return True
    except pymongo.errors.ServerSelectionTimeoutError:
        print(f"Failed to connect {CONN_STR}")
        return False
        
class MReview(EmbeddedDocument):
    user = StringField(required=True)
    passed = BooleanField(required=True)
    comment=StringField()

class MLabel(Document):
    #imgPath = StringField(required=True)#F40L1LIwhite0_50.jpg
    source = StringField(required=True,unique=True)#original name
    acquireFrom = StringField(required=True)
    color = StringField(required=True)
    AIClass=IntField(max=20,required=True)
    labelUser = StringField(required=True)
    reviews = EmbeddedDocumentListField(MReview)
    toRelabel=BooleanField(default=False)
    occupied=BooleanField(default=False)
    error=IntField(default=0)
    exception=StringField()
    createdAt=DateTimeField(default=datetime.datetime.now)
    meta={
        'db_alias':"core",
        'collection':"Labels"
    }
class MUser(Document):
    email = StringField(required=True,unique=True)
    # first_name = StringField(max_length=50)
    # last_name = StringField(max_length=50)
    # badgeID = IntField()
    labeledImgNum=IntField(default=0)
    reviewedImgNum=IntField(default=0)
    falseLabelNum=IntField(default=0)
    relabeledImgNum=IntField(default=0)
    createdAt=DateTimeField(default=datetime.datetime.now)

    meta={
        'db_alias':"core",
        'collection':"Users"
    }