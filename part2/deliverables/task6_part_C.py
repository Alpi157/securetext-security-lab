#!/usr/bin/env python3
import socket
import threading
import json
import os
import sys
import time
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
import logging
from datetime import datetime, timedelta

SHARED_KEY = b'my_shared_secret_key'
USERS_FILE = 'users.json'
ISSUER_NAME = 'SecureText'
GITHUB_CLIENT_ID = 'Ov23liheGmYhtFQmmAQw'
GITHUB_CLIENT_SECRET = '63aae758772469421597b2d5d04cb3680cdc6fa9'
REDIRECT_URI = 'http://localhost'
SCOPES = 'read:user user:email'
SESSION_TIMEOUT = timedelta(minutes=5)
MAX_ACTIONS = 10

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[
        logging.FileHandler('securetext.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

class SecureTextServer:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.users = self._load_users()
        self._migrate_plaintext_passwords()
        self.active_connections = {}
        self.oauth_states = {}
        self.challenges = {}
        self.totp_challenges = {}
        self.login_failures = {}
        self.sessions = {}

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
        for u, d in list(self.users.items()):
            pw = d.get('password','')
            if not pw.startswith('$2'):
                d['password'] = bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
                d.pop('hash_alg', None)
                d.pop('totp_secret', None)
                d.setdefault('role','user')
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
            'totp_secret': totp_secret,
            'role': 'user'
        }
        self._save_users()
        logging.info("Created account %s role=user", username)
        return True, "Account created", totp_secret

    def authenticate(self, username, password, totp_code):
        now = time.time()
        fails = self.login_failures.get(username,0)
        user = self.users.get(username)
        if not user or not self._verify_password(password, user['password']):
            fails += 1
            self.login_failures[username] = fails
            logging.warning("Invalid credentials for %s (%d failures)", username, fails)
            if fails>=3:
                logging.warning("User %s reached %d failed logins", username, fails)
            return False, "Invalid credentials"
        secret = user.get('totp_secret')
        totp = pyotp.TOTP(secret) if secret else None
        if not totp or not totp.verify(totp_code, valid_window=1):
            fails += 1
            self.login_failures[username] = fails
            logging.warning("Invalid TOTP for %s (%d failures)", username, fails)
            if fails>=3:
                logging.warning("User %s reached %d failed logins", username, fails)
            return False, "Invalid credentials"
        self.login_failures[username] = 0
        logging.info("Successful login for %s", username)
        return True, "Authentication successful"

    def get_oauth_url(self):
        state = secrets.token_urlsafe(16)
        verifier = secrets.token_urlsafe(64)
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()
        ).decode().rstrip('=')
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
            return False, "OAuth failed"
        data = urllib.parse.urlencode({
            'client_id': GITHUB_CLIENT_ID,
            'client_secret': GITHUB_CLIENT_SECRET,
            'code': code,
            'redirect_uri': REDIRECT_URI,
            'state': state,
            'code_verifier': verifier
        }).encode()
        req = urllib.request.Request(
            'https://github.com/login/oauth/access_token',
            data=data,
            headers={'Accept':'application/json'}
        )
        with urllib.request.urlopen(req) as r:
            token = json.load(r).get('access_token')
        if not token:
            return False, "OAuth failed"
        req2 = urllib.request.Request(
            'https://api.github.com/user',
            headers={'Authorization':f'token {token}','Accept':'application/json'}
        )
        with urllib.request.urlopen(req2) as r2:
            info = json.load(r2)
        login = info.get('login')
        email = info.get('email')
        if not email:
            req3 = urllib.request.Request(
                'https://api.github.com/user/emails',
                headers={'Authorization':f'token {token}','Accept':'application/json'}
            )
            with urllib.request.urlopen(req3) as r3:
                for e in json.load(r3):
                    if e.get('primary') and e.get('verified'):
                        email = e.get('email')
                        break
        if not email:
            email = f"{login}@users.noreply.github.com"
        local = None
        for u,d in self.users.items():
            if d.get('email')==email or d.get('github_login')==login:
                local = u; break
        if not local:
            local = login
            self.users[local] = {
                'github_login':login,
                'email':email,
                'created_at':datetime.now().isoformat(),
                'role':'user'
            }
            self._save_users()
            logging.info("Linked new OAuth user %s", local)
        logging.info("OAuth login for %s", local)
        return True, local

    def handle_client(self, conn, addr):
        uid = None
        while True:
            try:
                raw = conn.recv(4096)
                if not raw: break
                msg = json.loads(raw.decode())
                cmd = msg.get('command')
                now = datetime.now()
                if uid:
                    sess = self.sessions.get(uid)
                    if sess:
                        if now - sess['last_active']>SESSION_TIMEOUT:
                            conn.send(json.dumps({'status':'error','message':'Session expired'}).encode())
                            logging.info("Session expired %s", uid)
                            del self.active_connections[uid]
                            del self.sessions[uid]
                            break
                        if sess['actions']>=MAX_ACTIONS:
                            conn.send(json.dumps({'status':'error','message':'Action limit reached'}).encode())
                            logging.info("Action limit %s", uid)
                            del self.active_connections[uid]
                            del self.sessions[uid]
                            break

                resp = {'status':'error','message':'Unknown command'}
                if cmd=='CREATE_ACCOUNT':
                    ok,m,secret = self.create_account(msg['username'],msg['password'])
                    resp={'status':'success' if ok else 'error','message':m}
                    if ok: resp['totp_secret']=secret

                elif cmd=='GET_CHALLENGE':
                    ch=secrets.token_urlsafe(32)
                    self.challenges[id(conn)] = ch
                    resp={'status':'success','challenge':ch}

                elif cmd=='CHALLENGE_RESPONSE':
                    mac=msg.get('mac','')
                    ch=self.challenges.pop(id(conn),None)
                    if ch and self._verify_hmac(ch.encode(),mac):
                        resp={'status':'success','message':'Challenge passed'}
                    else:
                        resp={'status':'error','message':'Challenge failed'}

                elif cmd=='GET_TOTP_CHALLENGE':
                    c=int(time.time()//30)
                    self.totp_challenges[id(conn)] = c
                    resp={'status':'success','challenge':c}

                elif cmd=='TOTP_CHALLENGE_RESPONSE':
                    user=msg.get('username'); code=msg.get('code')
                    c=self.totp_challenges.pop(id(conn),None)
                    urec=self.users.get(user)
                    if c and urec:
                        totp=pyotp.TOTP(urec['totp_secret'])
                        if totp.verify(code,for_time=c*30):
                            resp={'status':'success','message':'TOTP passed'}
                        else:
                            resp={'status':'error','message':'TOTP failed'}

                elif cmd=='LOGIN':
                    ok,m = self.authenticate(
                        msg.get('username',''),
                        msg.get('password',''),
                        msg.get('totp','')
                    )
                    resp={'status':'success' if ok else 'error','message':m}
                    if ok:
                        uid=msg['username']
                        self.active_connections[uid]=conn
                        self.sessions[uid]={'last_active':now,'actions':0}

                elif cmd=='GET_OAUTH_URL':
                    url,state=self.get_oauth_url()
                    resp={'status':'success','auth_url':url,'state':state}

                elif cmd=='OAUTH_LOGIN':
                    ok,result=self.oauth_login(msg.get('code',''),msg.get('state',''),conn)
                    if ok:
                        uid=result
                        self.active_connections[uid]=conn
                        self.sessions[uid]={'last_active':now,'actions':0}
                        resp={'status':'success','message':f"Logged in as {uid}"}
                    else:
                        resp={'status':'error','message':result}

                elif cmd=='LOGOUT':
                    if uid:
                        del self.active_connections[uid]
                        del self.sessions[uid]
                        logging.info("Logout %s", uid)
                        uid=None
                    resp={'status':'success','message':'Logged out'}

                elif cmd=='RESET_PASSWORD':
                    tgt=msg.get('target')
                    if not uid or self.users[uid]['role']!='admin':
                        resp={'status':'error','message':'Denied'}
                        logging.warning("Denied reset %s by %s",tgt,uid)
                    else:
                        ok,_=self.authenticate(uid,msg.get('password',''),msg.get('totp',''))
                        if ok:
                            self.users[tgt]['password']=self._hash_password(msg.get('new_password',''))
                            self._save_users()
                            resp={'status':'success','message':'Password reset'}
                            logging.info("Admin %s reset %s",uid,tgt)
                        else:
                            resp={'status':'error','message':'Re-auth failed'}

                elif cmd=='LIST_USERS':
                    if not uid or self.users[uid]['role']!='admin':
                        resp={'status':'error','message':'Denied'}
                        logging.warning("Denied list by %s",uid)
                    else:
                        ok,_=self.authenticate(uid,msg.get('password',''),msg.get('totp',''))
                        if ok:
                            resp={'status':'success',
                                  'online_users':list(self.active_connections),
                                  'all_users':list(self.users)}
                            logging.info("Admin %s listed users",uid)
                        else:
                            resp={'status':'error','message':'Re-auth failed'}

                elif cmd=='SEND_MESSAGE':
                    if not uid:
                        resp={'status':'error','message':'Not logged in'}
                    else:
                        tgt=msg['recipient']; cmsg=msg['content']
                        if tgt in self.active_connections:
                            pl={'type':'MESSAGE','from':uid,
                                'content':cmsg,'timestamp':now.isoformat()}
                            self.active_connections[tgt].send(json.dumps(pl).encode())
                            resp={'status':'success','message':'Sent'}
                        else:
                            resp={'status':'error','message':'Offline'}

                elif cmd=='EXEC_COMMAND':
                    if not uid:
                        resp={'status':'error','message':'Not logged in'}
                    else:
                        p=msg.get('payload','').encode('latin1')
                        mac=msg.get('mac','')
                        if not self._verify_hmac(p,mac):
                            resp={'status':'error','message':'HMAC bad'}
                        else:
                            txt=p.decode('latin1')
                            kv=dict(x.split('=',1) for x in txt.split('&') if '=' in x)
                            if kv.get('CMD')=='SET_QUOTA':
                                resp={'status':'success','message':f"Quota={kv['LIMIT']} set for {kv['USER']}"}
                            elif kv.get('CMD')=='GRANT_ADMIN':
                                resp={'status':'success','message':f"Admin granted to {kv['USER']}"}
                            else:
                                resp={'status':'error','message':'Unknown'}

                conn.send(json.dumps(resp).encode())
                if uid:
                    self.sessions[uid]['last_active']=now
                    self.sessions[uid]['actions']+=1
                logging.info("User %s cmd=%s res=%s", uid or addr, cmd, resp['status'])
            except:
                break
        if uid in self.active_connections:
            del self.active_connections[uid]
        conn.close()

    def start_server(self):
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        s.bind((self.host,self.port))
        s.listen(5)
        logging.info("Listening %s:%d",self.host,self.port)
        while True:
            conn, addr = s.accept()
            logging.info("Conn %s",addr)
            threading.Thread(target=self.handle_client,args=(conn,addr),daemon=True).start()

class SecureTextClient:
    def __init__(self,host='localhost',port=12345):
        self.host=host; self.port=port
        self.socket=None; self.logged_in=False
        self.username=None; self.running=False

    def connect(self):
        try:
            self.socket=socket.socket(); self.socket.connect((self.host,self.port))
            return True
        except:
            return False

    def send_json(self,obj):
        self.socket.send(json.dumps(obj).encode())
        return json.loads(self.socket.recv(4096).decode())

    def create_account(self):
        u=input("Username: ").strip(); p=input("Password: ").strip()
        r=self.send_json({'command':'CREATE_ACCOUNT','username':u,'password':p})
        print(r['message'])
        if r['status']=='success':
            s=r.get('totp_secret')
            uri=pyotp.TOTP(s).provisioning_uri(name=u,issuer_name=ISSUER_NAME)
            qr=qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L)
            qr.add_data(uri); qr.make(fit=True); qr.print_ascii(invert=True)
            print("Save TOTP secret:",s)

    def get_challenge(self):
        r=self.send_json({'command':'GET_CHALLENGE'})
        return r.get('challenge') if r.get('status')=='success' else None

    def respond_challenge(self,ch):
        mac=hmac.new(SHARED_KEY,ch.encode(),hashlib.sha256).hexdigest()
        r=self.send_json({'command':'CHALLENGE_RESPONSE','mac':mac})
        print(r.get('message'))
        return r.get('status')=='success'

    def get_totp_challenge(self):
        r=self.send_json({'command':'GET_TOTP_CHALLENGE'})
        return r.get('challenge') if r.get('status')=='success' else None

    def respond_totp_challenge(self,u,c):
        r=self.send_json({'command':'TOTP_CHALLENGE_RESPONSE','username':u,'code':c})
        print(r.get('message'))
        return r.get('status')=='success'

    def login(self):
        print("1) HMAC CR  2) TOTP CR")
        m=input("> ").strip()
        if m=='1':
            ch=self.get_challenge()
            if not ch or not self.respond_challenge(ch): return
        elif m=='2':
            u=input("Username: ").strip()
            ch=self.get_totp_challenge()
            if not ch: return
            c=input(f"Enter TOTP for window {ch}: ").strip()
            if not self.respond_totp_challenge(u,c): return
        else:
            print("Invalid"); return
        u=input("Username: ").strip(); p=input("Password: ").strip(); t=input("TOTP Code: ").strip()
        r=self.send_json({'command':'LOGIN','username':u,'password':p,'totp':t})
        print(r['message'])
        if r['status']=='success':
            self.logged_in=True; self.username=u; self.running=True
            threading.Thread(target=self.listen,daemon=True).start()

    def oauth_login(self):
        r=self.send_json({'command':'GET_OAUTH_URL'})
        if r['status']=='success':
            url=r['auth_url']; st=r['state']
            webbrowser.open(url,new=2); print(url)
            red=input("Paste redirect URL: ").strip()
            ps=urllib.parse.parse_qs(urllib.parse.urlparse(red).query)
            c=ps.get('code',[None])[0]; rs=ps.get('state',[None])[0]
            if rs!=st or not c: print("Fail"); return
            r2=self.send_json({'command':'OAUTH_LOGIN','code':c,'state':st})
            print(r2['message'])
            if r2['status']=='success':
                self.logged_in=True
                self.username=r2['message'].split()[-1]
                self.running=True
                threading.Thread(target=self.listen,daemon=True).start()
        else:
            print("Error")

    def logout(self):
        if self.logged_in:
            self.send_json({'command':'LOGOUT'})
            self.logged_in=False; self.running=False
            print("Logged out")

    def reset_password(self):
        tgt=input("Target: ").strip()
        pw=input("Your pw: ").strip(); t=input("Your TOTP: ").strip()
        npw=input("New pw: ").strip()
        r=self.send_json({'command':'RESET_PASSWORD','target':tgt,'password':pw,'totp':t,'new_password':npw})
        print(r['message'])

    def list_users(self):
        pw=input("Your pw: ").strip(); t=input("Your TOTP: ").strip()
        r=self.send_json({'command':'LIST_USERS','password':pw,'totp':t})
        if r['status']=='success':
            print("Online:",r['online_users'])
            print("All   :",r['all_users'])
        else:
            print(r['message'])

    def send_message(self):
        t=input("To: ").strip(); m=input("Msg: ").strip()
        r=self.send_json({'command':'SEND_MESSAGE','recipient':t,'content':m})
        print(r['message'])

    def execute_command(self):
        c=input("CMD: ").strip()
        mac=hmac.new(SHARED_KEY,c.encode('latin1'),hashlib.sha256).hexdigest()
        r=self.send_json({'command':'EXEC_COMMAND','payload':c,'mac':mac})
        print(r['message'])

    def listen(self):
        while self.running:
            try:
                d=self.socket.recv(4096).decode()
                m=json.loads(d)
                if m.get('type')=='MESSAGE':
                    print(f"[{m['timestamp']}] {m['from']}: {m['content']}")
            except:
                break

    def run(self):
        if not self.connect(): return
        while True:
            if not self.logged_in:
                print("1) Create 2) Login 3) OAuth 4) Exit")
                c=input("> ").strip()
                if c=='1': self.create_account()
                elif c=='2': self.login()
                elif c=='3': self.oauth_login()
                elif c=='4': break
            else:
                print("1) Send 2) Cmd 3) List 4) ResetPw 5) Logout")
                c=input("> ").strip()
                if c=='1': self.send_message()
                elif c=='2': self.execute_command()
                elif c=='3': self.list_users()
                elif c=='4': self.reset_password()
                elif c=='5': self.logout()
                else: print("Invalid")
        self.socket.close()

    def connect(self):
        try:
            self.socket=socket.socket(); self.socket.connect((self.host,self.port))
            return True
        except:
            return False

if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='server':
        SecureTextServer().start_server()
    else:
        SecureTextClient().run()
