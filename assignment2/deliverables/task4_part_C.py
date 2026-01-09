#!/usr/bin/env python3
import socket
import threading
import json
import os
import sys
import bcrypt
import hmac
import hashlib
import pyotp
import qrcode
from datetime import datetime

SHARED_KEY = b'my_shared_secret_key'
USERS_FILE = 'users.json'
ISSUER_NAME = 'SecureText'

class SecureTextServer:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.users = self._load_users()
        self._migrate_plaintext_passwords()
        self.active_connections = {}
        self.totp_failures = {}

    def _load_users(self):
        if os.path.exists(USERS_FILE):
            try:
                with open(USERS_FILE, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _save_users(self):
        with open(USERS_FILE, 'w') as f:
            json.dump(self.users, f, indent=2)
        try:
            os.chmod(USERS_FILE, 0o600)
        except Exception:
            pass

    def _migrate_plaintext_passwords(self):
        migrated = False
        for user, data in list(self.users.items()):
            pw = data.get('password', '')
            if not pw.startswith('$2'):
                data['password'] = bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
                data.pop('hash_alg', None)
                data.pop('totp_secret', None)
                migrated = True
        if migrated:
            self._save_users()

    def _hash_password(self, pw):
        return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

    def _verify_password(self, pw, hsh):
        return bcrypt.checkpw(pw.encode(), hsh.encode())

    def _compute_hmac(self, msg):
        return hmac.new(SHARED_KEY, msg, hashlib.sha256).hexdigest()

    def _verify_hmac(self, msg, mac):
        return hmac.compare_digest(self._compute_hmac(msg), mac)

    def create_account(self, username, password):
        if username in self.users:
            return False, "Username exists", None
        pw_hash = self._hash_password(password)
        totp_secret = pyotp.random_base32()
        self.users[username] = {
            'password': pw_hash,
            'created_at': datetime.now().isoformat(),
            'totp_secret': totp_secret
        }
        self._save_users()
        return True, "Account created", totp_secret

    def authenticate(self, username, password, totp_code):
        now = datetime.now().timestamp()
        attempts = self.totp_failures.get(username, [])
        window = 60
        attempts = [ts for ts in attempts if now - ts < window]
        if len(attempts) >= 5:
            self.totp_failures[username] = attempts
            return False, "Too many attempts. Try again later"
        user = self.users.get(username)
        if not user or not self._verify_password(password, user['password']):
            attempts.append(now)
            self.totp_failures[username] = attempts
            return False, "Invalid credentials"
        secret = user.get('totp_secret')
        totp = pyotp.TOTP(secret)
        if not totp.verify(totp_code, valid_window=1):
            attempts.append(now)
            self.totp_failures[username] = attempts
            return False, "Invalid credentials"
        self.totp_failures[username] = []
        return True, "Authentication successful"

    def handle_client(self, conn, addr):
        current_user = None
        try:
            while True:
                raw = conn.recv(4096)
                if not raw:
                    break
                msg = json.loads(raw.decode('utf-8'))
                cmd = msg.get('command')
                if cmd == 'CREATE_ACCOUNT':
                    ok, m, secret = self.create_account(msg['username'], msg['password'])
                    resp = {'status': 'success' if ok else 'error', 'message': m}
                    if ok:
                        resp['totp_secret'] = secret
                elif cmd == 'LOGIN':
                    ok, m = self.authenticate(msg.get('username',''), msg.get('password',''), msg.get('totp',''))
                    if ok:
                        current_user = msg['username']
                        self.active_connections[current_user] = conn
                    resp = {'status': 'success' if ok else 'error', 'message': m}
                elif cmd == 'SEND_MESSAGE':
                    if not current_user:
                        resp = {'status':'error','message':'Not logged in'}
                    else:
                        to = msg['recipient']
                        content = msg['content']
                        if to in self.active_connections:
                            payload = {'type':'MESSAGE','from':current_user,'content':content,'timestamp':datetime.now().isoformat()}
                            self.active_connections[to].send(json.dumps(payload).encode('utf-8'))
                            resp = {'status':'success','message':'Sent'}
                        else:
                            resp = {'status':'error','message':'Offline'}
                elif cmd == 'EXEC_COMMAND':
                    if not current_user:
                        resp = {'status':'error','message':'Not logged in'}
                    else:
                        payload = msg.get('payload','').encode('latin1')
                        mac     = msg.get('mac','')
                        if not self._verify_hmac(payload, mac):
                            resp = {'status':'error','message':'HMAC bad'}
                        else:
                            text = payload.decode('latin1')
                            parts = text.split('&')
                            kv = dict(p.split('=',1) for p in parts if '=' in p)
                            if kv.get('CMD')=='SET_QUOTA':
                                resp = {'status':'success','message':f"Quota={kv['LIMIT']} set for {kv['USER']}"}
                            elif kv.get('CMD')=='GRANT_ADMIN':
                                resp = {'status':'success','message':f"Admin granted to {kv['USER']}"}
                            else:
                                resp = {'status':'error','message':'Unknown CMD'}
                elif cmd == 'LIST_USERS':
                    if not current_user:
                        resp = {'status':'error','message':'Not logged in'}
                    else:
                        resp = {'status':'success','online_users': list(self.active_connections),'all_users': list(self.users)}
                else:
                    resp = {'status':'error','message':'Unknown command'}
                conn.send(json.dumps(resp).encode('utf-8'))
        except ConnectionResetError:
            pass
        finally:
            if current_user in self.active_connections:
                del self.active_connections[current_user]
            conn.close()

    def start_server(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen(5)
            while True:
                conn, addr = s.accept()
                threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()

class SecureTextClient:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.socket = None
        self.logged_in = False
        self.username = None
        self.running = False

    def connect(self):
        try:
            self.socket = socket.socket()
            self.socket.connect((self.host, self.port))
            return True
        except:
            print("Connection failed")
            return False

    def send_json(self, obj):
        self.socket.send(json.dumps(obj).encode('utf-8'))
        return json.loads(self.socket.recv(4096).decode('utf-8'))

    def create_account(self):
        u = input("Username: ").strip()
        p = input("Password: ").strip()
        resp = self.send_json({'command':'CREATE_ACCOUNT','username':u,'password':p})
        print(resp['message'])
        if resp['status']=='success':
            secret = resp.get('totp_secret')
            uri = pyotp.totp.TOTP(secret).provisioning_uri(name=u, issuer_name=ISSUER_NAME)
            qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L)
            qr.add_data(uri)
            qr.make(fit=True)
            qr.print_ascii(invert=True)
            print(f"Secret: {secret}")

    def login(self):
        u = input("Username: ").strip()
        p = input("Password: ").strip()
        code = input("TOTP Code: ").strip()
        resp = self.send_json({'command':'LOGIN','username':u,'password':p,'totp':code})
        print(resp['message'])
        if resp['status']=='success':
            self.logged_in = True
            self.username = u
            self.running = True
            threading.Thread(target=self.listen, daemon=True).start()

    def send_message(self):
        to = input("To: ").strip()
        msg = input("Message: ").strip()
        resp = self.send_json({'command':'SEND_MESSAGE','recipient':to,'content':msg})
        print(resp['message'])

    def execute_command(self):
        cmd_str = input("Enter CMD (e.g. CMD=SET_QUOTA&USER=bob&LIMIT=100): ").strip()
        payload = cmd_str.encode('latin1')
        mac = hmac.new(SHARED_KEY, payload, hashlib.sha256).hexdigest()
        resp = self.send_json({'command':'EXEC_COMMAND','payload':cmd_str,'mac':mac})
        print(resp['message'])

    def list_users(self):
        resp = self.send_json({'command':'LIST_USERS'})
        if resp['status']=='success':
            print("Online:", resp['online_users'])
            print("All   :", resp['all_users'])
        else:
            print(resp['message'])

    def listen(self):
        while self.running:
            try:
                data = self.socket.recv(4096).decode('utf-8')
                msg = json.loads(data)
                if msg.get('type')=='MESSAGE':
                    print(f"[{msg['timestamp']}] {msg['from']}: {msg['content']}")
            except:
                break

    def run(self):
        if not self.connect():
            return
        while True:
            if not self.logged_in:
                print("1) Create Account  2) Login  3) Exit")
                c = input("> ").strip()
                if c=='1': self.create_account()
                elif c=='2': self.login()
                elif c=='3': break
            else:
                print("1) Send Msg  2) Exec Cmd  3) List Users  4) Logout")
                c = input("> ").strip()
                if c=='1': self.send_message()
                elif c=='2': self.execute_command()
                elif c=='3': self.list_users()
                elif c=='4':
                    self.logged_in = False
                    self.running = False
                    print("Logged out")
                else:
                    print("Invalid")

        self.socket.close()

if __name__ == '__main__':
    if len(sys.argv)>1 and sys.argv[1]=='server':
        SecureTextServer().start_server()
    else:
        SecureTextClient().run()
