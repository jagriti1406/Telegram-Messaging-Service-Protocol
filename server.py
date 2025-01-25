from flask import Flask,request
from dh_config import get_fixed_dh_parameters
from flask_socketio import SocketIO, emit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(16)
socketio = SocketIO(app, async_mode='threading')
message_count = 0

parameters = get_fixed_dh_parameters()
client_data = {}

def generate_private_key():
    return parameters.generate_private_key()

def get_public_key(private_key):
    return private_key.public_key()

def serialize_public_key(public_key):
    pem = public_key.public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)
    return pem.decode('utf-8')

def deserialize_public_key(pem):
    try:
        return serialization.load_pem_public_key(pem.encode('utf-8'), backend=default_backend())
    except Exception as e:
        print(f"Failed to deserialize key: {e}")
        return None

def generate_shared_secret(private_key, peer_public_key):
    shared_key = private_key.exchange(peer_public_key)
    salt = os.urandom(8)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,  
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)
    return derived_key, salt

def regenerate_keys(session_id):
    if session_id in client_data:
        data = client_data[session_id]
        private_key = generate_private_key()
        peer_public_key = data['peer_public_key']
        if peer_public_key:
            shared_secret, salt = generate_shared_secret(private_key, peer_public_key)
            client_data[session_id].update({
                'private_key': private_key,
                'shared_secret': shared_secret,
                'salt': salt
            })
            socketio.emit('exchange_complete', {
                'key': shared_secret.hex(),
                'salt': salt.hex(),
                'session_id': session_id
            },broadcast=True)

@socketio.on('client_hello')
def handle_client_hello(data):
    client_id = data['client_id']
    private_key = generate_private_key()
    public_key = get_public_key(private_key)
    session_id = request.sid
    client_data[session_id] = {'private_key': private_key, 'client_id': client_id,'peer_public_key': None }
    emit('server_hello', {'public_key': serialize_public_key(public_key)})

@socketio.on('client_exchange')
def handle_client_exchange(data):
    session_id = request.sid
    private_key = client_data[session_id]['private_key']
    peer_public_key = deserialize_public_key(data['peer_public_key'])
    shared_secret,salt = generate_shared_secret(private_key, peer_public_key)
    client_data[session_id]['shared_secret'] = shared_secret
    client_data[session_id]['salt'] = salt 
    client_data[session_id]['peer_public_key'] = peer_public_key 
    emit('exchange_complete', {'key': shared_secret.hex(), 'salt': salt.hex(), 'session_id': session_id},broadcast=True)


@socketio.on('send_message')
def handle_send_message(data):
    global message_count
    session_id = request.sid
    recipient_id = data['client_id']
    print(recipient_id,"recipient_id")
    print(session_id,"session_id")
    if session_id in client_data:
        for client_id in client_data:
            if client_id != session_id:
                print("Sending message to:", client_id)
                message_count += 1
                emit('receive_message', {'message': data['message']}, room=client_id)
    else:
        print("Recipient not connected.")
    if message_count == 4:
        message_count = 0
        regenerate_keys(session_id)

@socketio.on('disconnect')
def handle_disconnect():
    session_id = request.sid
    if session_id in client_data:
        del client_data[session_id]
        print(f"Client {session_id} data removed.")

if __name__ == '__main__':
    socketio.run(app, debug=True, host='127.0.0.1', port=5001)
