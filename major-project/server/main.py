from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

# from flask import Flask, render_template, request
import sys
sys.path.append('D:/Blockchain/ETHIndia-2.0-Hackathon/flaskUmbral/pyUmbral/umbral')
# sys.path.append('/home/dhrumil/secret-sharing/secretsharing')
# from umbral import config
from umbral.curve import SECP256K1
from umbral import keys, signing, params
from umbral import pre
import json
import base64
#import ipfshttpclient
import random
#from secretsharing import PlaintextToHexSecretSharer

#client = ipfshttpclient.connect('/ip4/127.0.0.1/tcp/5001/http')

# config.set_default_curve(SECP256K1)

from umbral import SecretKey,Signer,PublicKey,Capsule

from utils import create_authentication_challenge, verify_authentication, save_user, get_user

app = FastAPI()

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)                

@app.get("/")
def root():
    return { "message": "Server application is running." }

@app.post("/register")
async def register(request: Request):
    commit = await request.json()
    commit['c'] = create_authentication_challenge(commit)
    save_user(commit)
    return commit

@app.get("/auth/{username}")
def authenticate(username: str, s: int):
    user = get_user(username)
    if not user:
        return False
    return verify_authentication(user, s)



# app = Flask(__name__)
# app.secret_key = "Poojan Patel"


class SetEncoder(json.JSONEncoder):
    def default(self, obj):
       if isinstance(obj, set):
          return list(obj)
       return json.JSONEncoder.default(self, obj)

def bytes_to_string(b):
    encoded = base64.b64encode(b)
    return encoded.decode('utf-8')

def string_to_bytes(s):
    sd = s.encode('utf-8')
    return base64.b64decode(sd)

kfrags = list()

@app.route('/alice')
def alice():
    return render_template('alice.html')

@app.route('/gen_keys')
def gen_keys():
    #generate the private and public keys required for encryption of data
    person_privKey =  SecretKey.random()
    person_pubKey = person_privKey.public_key()
    #Make a JSON object 
    person_keys = {
        "person_privKey": bytes_to_string(person_privKey.to_secret_bytes()),
        "person_pubKey": bytes_to_string(person_pubKey.__bytes__())
    }
    return render_template('generate.html', person_keys=person_keys)

@app.route('/encrypt',methods=["GET","POST"])
def encrypt():
    if request.method == 'POST':
        # Get the data from the request payload
        print(request.data)
        plaintext = request.form["plaintext"].encode("utf-8")
        pubKey = string_to_bytes(request.form["person_pubKey"])
        pubKey = PublicKey._from_exact_bytes(pubKey)
    
        #Encrypt the data
        capsule, ciphertext = pre.encrypt(pubKey, plaintext)

        # response Text
        dataToBeStored = {
            "ciphertext": bytes_to_string(ciphertext),
            "capsule": bytes_to_string(capsule.__bytes__())
        }
        with open('data.json', 'w') as outfile:
            json.dump(dataToBeStored, outfile, cls=SetEncoder)
    
    return render_template('encrypt.html')

@app.route('/grant_access',methods=["GET","POST"])
def grant_access():
    if request.method == 'POST':
        # Get the data from the request payload and convert them to bytes
        bobPubKey = string_to_bytes(request.form["bobPubKey"])
        bobPubKey = PublicKey._from_exact_bytes(bobPubKey)
        alicePrivKey = string_to_bytes(request.form["alicePrivKey"])
        alicePrivKey =SecretKey._from_exact_bytes(alicePrivKey)
        alicePubKey = alicePrivKey.public_key()

        #generate the signing key
        alices_signing_key = SecretKey.random()
        alices_verifying_key = alices_signing_key.public_key()
        alices_signer = signing.Signer(alices_signing_key)

        # Generating kfrags
        global kfrags
        kfrags = pre.generate_kfrags(delegating_sk=alicePrivKey,receiving_pk=bobPubKey,signer=alices_signer,threshold=10,shares=20)
        
        # Storing the kfrags on the bob's side
        dataToBeStoredBob = {
            # "fragments": bytes_to_string(kfrags.__bytes__()),
            "alice_signing_key": bytes_to_string(alices_signing_key.to_secret_bytes()),
            "alicePrivKey": bytes_to_string(alicePrivKey.to_secret_bytes()),

        }

        dataToBeChecked= {
            "bobsPubKey": bytes_to_string(bobPubKey.__bytes__())
        }

        with open('hospital.json', 'w') as outfile:
            json.dump(dataToBeStoredBob, outfile, cls=SetEncoder)

        with open('check.json','w') as outfile:
            json.dump(dataToBeChecked,outfile,cls=SetEncoder)
        
    return render_template('grant.html')


@app.route('/decrypt',methods=["GET","POST"])
def decrypt():
    if request.method == 'POST':
        # Get the private key
        bobPrivKey = string_to_bytes(request.form["bobPrivKey"])
        bobPrivKey = SecretKey._from_exact_bytes(bobPrivKey)
        bobPubKey = bobPrivKey.public_key()

        # read the capsule from the json dump
        with open('data.json') as json_file:
            data1 = json.load(json_file)
            ciphertext = string_to_bytes(data1['ciphertext'])
            capsule = string_to_bytes(data1['capsule'])
            # capsule = pre.Capsule.from_bytes(capsule, params.UmbralParameters(SECP256K1))
            capsule=Capsule._from_exact_bytes(capsule)
        
        # get the kfrags

        with open('hospital.json') as json_file:
            data2 = json.load(json_file)
            # kfrags = data2['kfrags']
            alicePrivKey = string_to_bytes(data2["alicePrivKey"])
            alicePrivKey = SecretKey._from_exact_bytes(alicePrivKey)
            alicePubKey=alicePrivKey.public_key()

            alice_signing_key = string_to_bytes(data2["alice_signing_key"])
            alice_signing_key = SecretKey._from_exact_bytes(alice_signing_key)
            alices_verifying_key = alice_signing_key.public_key()
            alices_signer = signing.Signer(alice_signing_key)

        with open('check.json') as json_file:
            data3=json.load(json_file)
            bobsPubKey=string_to_bytes(data3["bobsPubKey"])
            bobsPubKey=PublicKey._from_exact_bytes(bobsPubKey)

        if(bobPubKey!=bobsPubKey):
            raise ValueError("access not granted")

        # global kfrags
        # kfrags = random.choice((kfrags,10))
        global kfrags
        kfrags = pre.generate_kfrags(delegating_sk=alicePrivKey,receiving_pk=bobPubKey,signer=alices_signer,threshold=10,shares=20)
    
        # capsule.set_correctness_keys(delegating=alicePubKey,receiving=bobPubKey,verifying=alice_verifying_key)
        cfrags = list()
        for kfrag in kfrags[ :10]:
            cfrag = pre.reencrypt(capsule=capsule,kfrag=kfrag)
            cfrags.append(cfrag)

        # assert len(cfrags) == 0
    
        # capsule.set_correctness_keys(delegating=alicePubKey,receiving=bobPubKey,verifying=alice_verifying_key)

        # for cfrag in cfrags:
        #     capsule.attach_cfrag(cfrag)
        
        #decrypt the data
        plainBobtext = pre.decrypt_reencrypted(receiving_sk=bobPrivKey,
                                        delegating_pk=alicePubKey,
                                        capsule=capsule,
                                        verified_cfrags=cfrags,
                                        ciphertext=ciphertext)
        plainBobtext = plainBobtext.decode('utf-8')
        return render_template('decrypt.html', plainBobtext=plainBobtext, data=data1)
    
    with open('data.json') as json_file:
        data1 = json.load(json_file)
    
    return render_template('decrypt.html',data=data1)


@app.route('/split_keys',methods=["GET","POST"])
def split_keys():
    if request.method == 'POST':
        # Get the request data
        dataToSplit = request.form["dataToSplit"]
        howManyCanReContruct = request.form["howManyCanReContruct"]
        howManyPeople = request.form["howManyPeople"]
        shares = PlaintextToHexSecretSharer.split_secret(dataToSplit, howManyCanReContruct, howManyPeople)
        return render_template('split_keys.html', shares=shares)



# if __name__ == '__main__':
#     app.run(debug=True)