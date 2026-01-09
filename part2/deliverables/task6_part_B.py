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
import secrets
import urllib.parse
import urllib.request
import webbrowser
import base64
from datetime import datetime, timedelta

SHARED_KEY = b'my_shared_secret_key'
USERS_FILE = 'users.json'
ISSUER_NAME = 'SecureText'
GITHUB_CLIENT_ID = 'Ov23liheGmYhtFQmmAQw'
GITHUB_CLIENT_SECRET = '63aae758772469421597b2d5d04cb3680cdc6fa9'
REDIRECT_URI = 'http://localhost'
SCOPES = 'read:user user:email'
SESSION_TIMEOUT = timedelta(minutes=5)
SESSION_ACTION_LIMIT = 10

class SecureTextServer:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.users = self._load_users()
        self._migrate_plaintext_passwords()
        self._migrate_roles()
        self.active_connections = {}
        self.sessions = {}
        self.oauth_states = {}

    def _load_users(self):
        if os.path.exists(USERS_FILE):
            try:
                with open(USERS_FILE, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {}

    def _save_users(self):
        with open(USERS_FILE, 'w') as f:
            json.dump(self.users, f, indent=2)
        try:
            os.chmod(USERS_FILE, 0o600)
        except:
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

    def _migrate_roles(self):
        migrated = False
        for user, data in self.users.items():
            if 'role' not in data:
                data['role'] = 'user'
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
            return False, 'Username exists', None
        pw_hash = self._hash_password(password)
        totp_secret = pyotp.random_base32()
        self.users[username] = {
            'password': pw_hash,
            'totp_secret': totp_secret,
            'created_at': datetime.now().isoformat(),
            'role': 'user'
        }
        self._save_users()
        return True, 'Account created', totp_secret

    def reset_password(self, username, new_password):
        if username not in self.users:
            return False, 'User not found'
        self.users[username]['password'] = self._hash_password(new_password)
        self._save_users()
        return True, 'Password reset'

    def authenticate(self, username, password, totp_code):
        user = self.users.get(username)
        if not user or not self._verify_password(password, user['password']):
            return False, 'Invalid credentials'
        secret = user.get('totp_secret')
        if not secret:
            return False, 'Invalid credentials'
        totp = pyotp.TOTP(secret)
        if not totp.verify(totp_code, valid_window=1):
            return False, 'Invalid credentials'
        return True, 'Authentication successful'

    def get_oauth_url(self):
        state = secrets.token_urlsafe(16)
        verifier = secrets.token_urlsafe(64)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
        self.oauth_states[state] = verifier
        params = {
            'client_id': GITHUB_CLIENT_ID,
            'redirect_uri': REDIRECT_URI,
            'scope': SCOPES,
            'state': state,
            'code_challenge': challenge,
            'code_challenge_method': 'S256'
        }
        url = 'https://github.com/login/oauth/authorize?' + urllib.parse.urlencode(params)
        return url, state

    def oauth_login(self, code, state, conn):
        verifier = self.oauth_states.pop(state, None)
        if not verifier:
            return False, 'OAuth failed'
        data = urllib.parse.urlencode({
            'client_id': GITHUB_CLIENT_ID,
            'client_secret': GITHUB_CLIENT_SECRET,
            'code': code,
            'redirect_uri': REDIRECT_URI,
            'state': state,
            'code_verifier': verifier
        }).encode()
        req = urllib.request.Request('https://github.com/login/oauth/access_token', data=data, headers={'Accept': 'application/json'})
        with urllib.request.urlopen(req) as r:
            token_resp = json.load(r)
        token = token_resp.get('access_token')
        if not token:
            return False, 'OAuth failed'
        req2 = urllib.request.Request('https://api.github.com/user',
                                       headers={'Authorization': f'token {token}', 'Accept': 'application/json'})
        with urllib.request.urlopen(req2) as r2:
            user_info = json.load(r2)
        github_login = user_info.get('login')
        email = user_info.get('email')
        if not email:
            req3 = urllib.request.Request('https://api.github.com/user/emails',
                                           headers={'Authorization': f'token {token}', 'Accept': 'application/json'})
            with urllib.request.urlopen(req3) as r3:
                emails = json.load(r3)
            for e in emails:
                if e.get('primary') and e.get('verified'):
                    email = e.get('email')
                    break
        if not email:
            email = f'{github_login}@users.noreply.github.com'
        local_user = None
        for u, data in self.users.items():
            if data.get('email') == email or data.get('github_login') == github_login:
                local_user = u
                break
        if not local_user:
            local_user = github_login
            self.users[local_user] = {
                'github_login': github_login,
                'email': email,
                'created_at': datetime.now().isoformat(),
                'role': 'user'
            }
            self._save_users()
        self.active_connections[local_user] = conn
        self.sessions[local_user] = {'last_activity': datetime.now(), 'actions': 0}
        return True, local_user

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
                    ok, m = self.authenticate(msg.get('username', ''), msg.get('password', ''), msg.get('totp', ''))
                    if ok:
                        current_user = msg['username']
                        self.active_connections[current_user] = conn
                        self.sessions[current_user] = {'last_activity': datetime.now(), 'actions': 0}
                    resp = {'status': 'success' if ok else 'error', 'message': m}

                elif cmd == 'GET_OAUTH_URL':
                    url, state = self.get_oauth_url()
                    resp = {'status': 'success', 'auth_url': url, 'state': state}

                elif cmd == 'OAUTH_LOGIN':
                    ok, result = self.oauth_login(msg.get('code',''), msg.get('state',''), conn)
                    if ok:
                        current_user = result
                        resp = {'status': 'success', 'message': f'Logged in as {result}'}
                    else:
                        resp = {'status': 'error', 'message': result}

                elif cmd == 'LOGOUT':
                    if current_user:
                        del self.active_connections[current_user]
                        del self.sessions[current_user]
                        current_user = None
                    resp = {'status': 'success', 'message': 'Logged out'}

                else:
                    # session timeout / action limit check
                    if current_user:
                        sess = self.sessions.get(current_user)
                        now = datetime.now()
                        if not sess or now - sess['last_activity'] > SESSION_TIMEOUT or sess['actions'] >= SESSION_ACTION_LIMIT:
                            if current_user in self.active_connections:
                                del self.active_connections[current_user]
                            if current_user in self.sessions:
                                del self.sessions[current_user]
                            current_user = None
                            resp = {'status': 'error', 'message': 'Session expired'}
                            conn.send(json.dumps(resp).encode('utf-8'))
                            continue
                        sess['last_activity'] = now
                        sess['actions'] += 1

                    if cmd == 'RESET_PASSWORD':
                        if not current_user:
                            resp = {'status': 'error', 'message': 'Not logged in'}
                        elif self.users[current_user]['role'] != 'admin':
                            resp = {'status': 'error', 'message': 'Permission denied'}
                        else:
                            pw = msg.get('password','')
                            totp = msg.get('totp','')
                            ok2, m2 = self.authenticate(current_user, pw, totp)
                            if not ok2:
                                resp = {'status': 'error', 'message': 'Re-authentication failed'}
                            else:
                                ok3, m3 = self.reset_password(msg.get('username',''), msg.get('new_password',''))
                                resp = {'status': 'success' if ok3 else 'error', 'message': m3}

                    elif cmd == 'LIST_USERS':
                        if not current_user:
                            resp = {'status': 'error', 'message': 'Not logged in'}
                        elif self.users[current_user]['role'] != 'admin':
                            resp = {'status': 'error', 'message': 'Permission denied'}
                        else:
                            pw = msg.get('password','')
                            totp = msg.get('totp','')
                            ok2, m2 = self.authenticate(current_user, pw, totp)
                            if not ok2:
                                resp = {'status': 'error', 'message': 'Re-authentication failed'}
                            else:
                                resp = {
                                    'status': 'success',
                                    'online_users': list(self.active_connections),
                                    'all_users': list(self.users)
                                }

                    elif cmd == 'SEND_MESSAGE' or cmd == 'EXEC_COMMAND':
                        # existing handlers...
                        if cmd == 'SEND_MESSAGE':
                            to = msg['recipient']
                            content = msg['content']
                            if to in self.active_connections:
                                payload = {'type': 'MESSAGE','from': current_user,'content': content,'timestamp': datetime.now().isoformat()}
                                self.active_connections[to].send(json.dumps(payload).encode('utf-8'))
                                resp = {'status': 'success','message': 'Sent'}
                            else:
                                resp = {'status': 'error','message': 'Offline'}
                        else:
                            payload = msg.get('payload','').encode('latin1')
                            mac = msg.get('mac','')
                            if not self._verify_hmac(payload, mac):
                                resp = {'status': 'error','message': 'HMAC bad'}
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
                    else:
                        resp = {'status': 'error', 'message': 'Unknown command'}

                conn.send(json.dumps(resp).encode('utf-8'))
        except:
            pass
        finally:
            if current_user in self.active_connections:
                del self.active_connections[current_user]
            if current_user in self.sessions:
                del self.sessions[current_user]
            conn.close()

    def start_server(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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

    def connect(self):
        try:
            self.socket = socket.socket()
            self.socket.connect((self.host, self.port))
            return True
        except:
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
            uri = pyotp.TOTP(secret).provisioning_uri(name=u, issuer_name=ISSUER_NAME)
            qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L)
            qr.add_data(uri)
            qr.make(fit=True)
            qr.print_ascii(invert=True)
            print(secret)

    def login(self):
        u = input("Username: ").strip()
        p = input("Password: ").strip()
        code = input("TOTP Code: ").strip()
        resp = self.send_json({'command':'LOGIN','username':u,'password':p,'totp':code})
        print(resp['message'])
        if resp['status']=='success':
            self.username = u

    def reset_password(self):
        target = input("Target Username: ").strip()
        new_pw = input("New Password: ").strip()
        pw = input("Your Password: ").strip()
        code = input("Your TOTP Code: ").strip()
        resp = self.send_json({
            'command':'RESET_PASSWORD',
            'username':target,
            'new_password':new_pw,
            'password':pw,
            'totp':code
        })
        print(resp['message'])

    def list_users(self):
        pw = input("Your Password: ").strip()
        code = input("Your TOTP Code: ").strip()
        resp = self.send_json({'command':'LIST_USERS','password':pw,'totp':code})
        if resp['status']=='success':
            print("Online:", resp['online_users'])
            print("All   :", resp['all_users'])
        else:
            print(resp['message'])

    def run(self):
        if not self.connect(): return
        while True:
            print("1) Create Account  2) Login  3) OAuth Login  4) Exit")
            c = input("> ").strip()
            if c=='1':
                self.create_account()
            elif c=='2':
                self.login()
            elif c=='3':
                pass
            elif c=='4':
                break
            else:
                print("Invalid choice")
            if hasattr(self, 'username'):
                while True:
                    print("1) List Users  2) Reset Password  3) Logout")
                    c2 = input("> ").strip()
                    if c2=='1':
                        self.list_users()
                    elif c2=='2':
                        self.reset_password()
                    elif c2=='3':
                        self.send_json({'command':'LOGOUT'})
                        print("Logged out")
                        del self.username
                        break
                    else:
                        print("Invalid")
        self.socket.close()

if __name__ == '__main__':
    if len(sys.argv)>1 and sys.argv[1]=='server':
        SecureTextServer().start_server()
    else:
        SecureTextClient().run()
