
import re
import hashlib
from passlib.hash import pbkdf2_sha256
import datetime
import functools
import jwt
from flask import Flask, request
from flask_mail import Mail, Message
from flask_restful import Resource, Api, abort
from werkzeug.security import generate_password_hash, check_password_hash
import config
from flask_pymongo import PyMongo
from ecdsa import SigningKey, SECP256k1
import sha3
import json
import erc20token
import ethereum


app = Flask(__name__)
app.config.from_object('config')
api = Api(app)

mail = Mail(app)

app.config['MONGO_DBNAME'] = 'tbiswallet'
app.config['MONGO_URI'] = 'mongodb://dtyagi:deepanshu179@ds217310.mlab.com:17310/tbiswallet'
provider_endpoint_url='https://rinkeby.infura.io/P1AUQKva1yYl24wfeDwn'
contract_address='0x531afe8d913136d1b9af34bf8a507b7b9b17abdc'
contract_abi_tbar=json.loads('[ { "anonymous": false, "inputs": [ { "indexed": true, "name": "_owner", "type": "address" }, { "indexed": true, "name": "_spender", "type": "address" }, { "indexed": false, "name": "_value", "type": "uint256" } ], "name": "Approval", "type": "event" }, { "constant": false, "inputs": [ { "name": "_spender", "type": "address" }, { "name": "_value", "type": "uint256" } ], "name": "approve", "outputs": [ { "name": "success", "type": "bool" } ], "payable": false, "stateMutability": "nonpayable", "type": "function" }, { "constant": false, "inputs": [], "name": "buyToken", "outputs": [], "payable": true, "stateMutability": "payable", "type": "function" }, { "anonymous": false, "inputs": [ { "indexed": true, "name": "_from", "type": "address" }, { "indexed": true, "name": "_to", "type": "address" }, { "indexed": false, "name": "_value", "type": "uint256" } ], "name": "Transfer", "type": "event" }, { "anonymous": false, "inputs": [ { "indexed": true, "name": "_to", "type": "address" }, { "indexed": false, "name": "_value", "type": "uint256" } ], "name": "Mint", "type": "event" }, { "anonymous": false, "inputs": [ { "indexed": true, "name": "_to", "type": "address" }, { "indexed": false, "name": "_value", "type": "uint256" } ], "name": "CreateHLTD", "type": "event" }, { "constant": false, "inputs": [ { "name": "_to", "type": "address" }, { "name": "_amount", "type": "uint256" } ], "name": "mint", "outputs": [ { "name": "", "type": "bool" } ], "payable": false, "stateMutability": "nonpayable", "type": "function" }, { "constant": false, "inputs": [], "name": "PPCToken", "outputs": [], "payable": false, "stateMutability": "nonpayable", "type": "function" }, { "constant": false, "inputs": [ { "name": "_to", "type": "address" }, { "name": "_value", "type": "uint256" } ], "name": "transfer", "outputs": [ { "name": "success", "type": "bool" } ], "payable": false, "stateMutability": "nonpayable", "type": "function" }, { "constant": false, "inputs": [ { "name": "_from", "type": "address" }, { "name": "_to", "type": "address" }, { "name": "_value", "type": "uint256" } ], "name": "transferFrom", "outputs": [ { "name": "success", "type": "bool" } ], "payable": false, "stateMutability": "nonpayable", "type": "function" }, { "constant": false, "inputs": [ { "name": "newOwner", "type": "address" } ], "name": "transferOwnership", "outputs": [], "payable": false, "stateMutability": "nonpayable", "type": "function" }, { "payable": true, "stateMutability": "payable", "type": "fallback" }, { "constant": true, "inputs": [ { "name": "_owner", "type": "address" }, { "name": "_spender", "type": "address" } ], "name": "allowance", "outputs": [ { "name": "remaining", "type": "uint256" } ], "payable": false, "stateMutability": "view", "type": "function" }, { "constant": true, "inputs": [ { "name": "_owner", "type": "address" } ], "name": "balanceOf", "outputs": [ { "name": "balance", "type": "uint256" } ], "payable": false, "stateMutability": "view", "type": "function" }, { "constant": true, "inputs": [], "name": "decimals", "outputs": [ { "name": "", "type": "uint256" } ], "payable": false, "stateMutability": "view", "type": "function" }, { "constant": true, "inputs": [], "name": "ethFundDeposit", "outputs": [ { "name": "", "type": "address" } ], "payable": false, "stateMutability": "view", "type": "function" }, { "constant": true, "inputs": [], "name": "minTokenPurchaseAmount", "outputs": [ { "name": "", "type": "uint256" } ], "payable": false, "stateMutability": "view", "type": "function" }, { "constant": true, "inputs": [], "name": "name", "outputs": [ { "name": "", "type": "string" } ], "payable": false, "stateMutability": "view", "type": "function" }, { "constant": true, "inputs": [], "name": "owner", "outputs": [ { "name": "", "type": "address" } ], "payable": false, "stateMutability": "view", "type": "function" }, { "constant": true, "inputs": [], "name": "symbol", "outputs": [ { "name": "", "type": "string" } ], "payable": false, "stateMutability": "view", "type": "function" }, { "constant": true, "inputs": [], "name": "tokenCreationCap", "outputs": [ { "name": "", "type": "uint256" } ], "payable": false, "stateMutability": "view", "type": "function" }, { "constant": true, "inputs": [], "name": "tokenPrice", "outputs": [ { "name": "", "type": "uint256" } ], "payable": false, "stateMutability": "view", "type": "function" }, { "constant": true, "inputs": [], "name": "totalSupply", "outputs": [ { "name": "", "type": "uint256" } ], "payable": false, "stateMutability": "view", "type": "function" }, { "constant": true, "inputs": [], "name": "version", "outputs": [ { "name": "", "type": "string" } ], "payable": false, "stateMutability": "view", "type": "function" } ]')
    

mongo = PyMongo(app)

def login_required(method):
    @functools.wraps(method)
    def wrapper(self):
        users = mongo.db.Alphawallet
        header = request.headers.get('Authorization')
        _, token = header.split()
        try:
            decoded = jwt.decode(token, app.config['KEY'], algorithms='HS256')
        except jwt.DecodeError:
            abort(400, message='Token is not valid.')
        except jwt.ExpiredSignatureError:
            abort(400, message='Token is expired.')
        email = decoded['email']
        if users.find({'email': email}).count() == 0:
            abort(400, message='User is not found.')
        user = users.find_one({'email': email})
        return method(self, user)
    return wrapper

class Register(Resource):
    def post(self):
        users = mongo.db.Alphawallet
        email = request.json['email']
        password = request.json['password']
        if not re.match(r'^[A-Za-z0-9\.\+_-]+@[A-Za-z0-9\._-]+\.[a-zA-Z]*$', email):
            abort(400, message='email is not valid.')
        if len(password) < 6:
            abort(400, message='password is too short.')
        if users.find({'email': email}).count() != 0:
            if users.find_one({'email': email})['active'] == True:
                abort(400, message='email is alread used.')
        else:
            users.insert_one({'email': email, 'password': generate_password_hash(password), 'active': False})
        exp = datetime.datetime.utcnow() + datetime.timedelta(days=app.config['ACTIVATION_EXPIRE_DAYS'])
        encoded = jwt.encode({'email': email, 'exp': exp},
                             app.config['KEY'], algorithm='HS256')
        message = 'Tbis_account\nactivation_code={}'.format(encoded.decode('utf-8'))
        msg = Message(recipients=[email],
                      body=message,
                      subject='Activation Code')
        mail.send(msg) 
        return {'email': email}

class Activate(Resource):
    def put(self):
        users = mongo.db.Alphawallet
        activation_code = request.json['activation_code']
        try:
            decoded = jwt.decode(activation_code, app.config['KEY'], algorithms='HS256')
        except jwt.DecodeError:
            abort(400, message='Activation code is not valid.')
        except jwt.ExpiredSignatureError:
            abort(400, message='Activation code is expired.')
        email = decoded['email']
        users.update({'email': email}, {'$set': {'active': True}})
        return {'email': email}

class Login(Resource):
    def get(self):
        users = mongo.db.Alphawallet
        email = request.json['email']
        password = request.json['password']
        if users.find({'email': email}).count() == 0:
            abort(400, message='User is not found.')
        user = users.find_one({'email': email})
        if not check_password_hash(user['password'], password):
            abort(400, message='Password is incorrect.')
        exp = datetime.datetime.utcnow() + datetime.timedelta(hours=app.config['TOKEN_EXPIRE_HOURS'])
        encoded = jwt.encode({'email': email, 'exp': exp},
                             app.config['KEY'], algorithm='HS256')
        return {'email': email, 'token': encoded.decode('utf-8')}



class userWallet(Resource):
    #@login_required
    def  put(self):
        # decoded = jwt.decode(token, app.config['KEY'], algorithms='HS256')
        users=mongo.db.Alphawallet
        email=request.json["email"]
        if users.find_one({"email":email})and users.find_one({"address_eth":{"$exists":False}}):
            keccak = sha3.keccak_256()
            priv = SigningKey.generate(curve=SECP256k1)
            pub = priv.get_verifying_key().to_string()
            keccak.update(pub)
            address = keccak.hexdigest()[24:]
            private_key=priv.to_string().hex()
            public_key=pub.hex()
            Address="0x" + address
            users.update({"email":email},{'$set': {'address_eth': Address}})
            key=str(private_key)
            hash_key=pbkdf2_sha256.encrypt(key, rounds=90000, salt_size=900)
            users.update({"email":email},{"$set":{'private_key_eth':hash_key}})
            return {"Private_key":private_key,"Public_key":public_key,"Address_eth":Address}
         
       
   
    # @login_required
    def post(self):
        users=mongo.db.Alphawallet
        email=request.json["email"]
        return users.find_one({"email":email})["address_eth"]


class transactEth(Resource):
    #@login_required
    def put(self):
        users=mongo.db.Alphawallet
        email=request.json["email"]
        amount=request.json["amount"]
        to_address=request.json["address"]
        private_key=request.json["Private_key"]
        hash_key=users.find_one({'email':email})["private_key_eth"]
        if users.find_one({"email":email})and pbkdf2_sha256.verify(private_key, hash_key)==True :
                token_sdk = erc20token.SDK(provider_endpoint_uri=provider_endpoint_url, 
                       private_key=private_key,
                       contract_address=contract_address, 
                       contract_abi=contract_abi_tbar)
                eth_balance = token_sdk.get_ether_balance()
                if eth_balance >= int(amount):
                    tx_id = token_sdk.send_ether(to_address,int(amount))
                    users.update({"email":email},{'$set': {'tx_id': tx_id}})
                    return {"tx_id":tx_id}
        else:
            abort(400, message='Something went wrong')
    
    
    #@login_required
    def post(self):
        users=mongo.db.Alphawallet
        email=request.json["email"]
        tx_id=request.json["tx_id"]
        if users.find_one({"email":email})and users.find_one({"tx_id":tx_id}):
                token_sdk = erc20token.SDK(provider_endpoint_uri=provider_endpoint_url, 
                       contract_address=contract_address, 
                       contract_abi=contract_abi_tbar)
                tx_status = token_sdk.get_transaction_status(tx_id)
                if tx_status == 0:
                    return {"tx_status":"Unknown"}
                if tx_status == 1:
                    return {"tx_status":"Pending"}
                if tx_status == 2:
                    return {"tx_status":"Sucess"}
                if tx_status == 3:
                    return {"tx_status":"Failed"}

                
class transactTbar(Resource):
    #@login_required
    def put(self,user):
        users=mongo.db.Alphawallet
        email=request.json["email"]
        amount=request.json["amount"]
        to_address=request.json["address"]
        private_key=request.json["Private_key"]
        hash_key=users.find_one({'email':email})["private_key_eth"]
        if users.find_one({"email":email})and pbkdf2_sha256.verify(private_key, hash_key)==True :
                token_sdk = erc20token.SDK(provider_endpoint_uri=provider_endpoint_url, 
                       private_key=private_key,
                       contract_address=contract_address, 
                       contract_abi=contract_abi_tbar)
                address = token_sdk.get_address()
                tbar_balance = token_sdk.get_ether_balance(address)
                if tbar_balance >= int(amount):
                    tx_id = token_sdk.send_tokens(to_address,int(amount))
                    users.update({"email":email},{'$set': {'tx_id': tx_id}})
                    return {"tx_id":tx_id}
        else:
            abort(400, message='Something went wrong')
    
  


class getBalance(Resource):
    #@login_required

    def post(self):
        address=request.json["address"]
        token_sdk = erc20token.SDK(provider_endpoint_uri=provider_endpoint_url, 
                       contract_address=contract_address, 
                       contract_abi=contract_abi_tbar)
        tbar_balance=token_sdk.get_address_token_balance(address) 
        eth_balance = token_sdk.get_address_ether_balance(address)
        total_tbar_supply = token_sdk.get_token_total_supply()

        return {"tbar_balance":str(tbar_balance),"eth_balance":str(eth_balance),"total_tbar_supply":str(total_tbar_supply)}




api.add_resource(Register, '/v1/register')
api.add_resource(Activate, '/v1/activate')
api.add_resource(Login, '/v1/login')
api.add_resource(userWallet, '/v1/userwallet')
api.add_resource(transactEth,'/v1/transactEth')
api.add_resource(transactTbar,'/v1/transacTbar')
api.add_resource(getBalance,'/v1/getbalances')



if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
