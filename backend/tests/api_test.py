import http.client, json, subprocess, time, os, sys, signal, re
PORT=8099; BIN='./build/scamshield-server'; DB='/tmp/it_accounts.db'
for f in (DB, DB+'-wal', DB+'-shm', DB+'.key'):
    if os.path.exists(f): os.remove(f)
ok=fail=0
def check(name, cond, extra=''):
    global ok, fail
    if cond: ok+=1
    else: fail+=1; print('FAIL:', name, extra)
def start():
    env=dict(os.environ, SCAMSHIELD_PORT=str(PORT), SCAMSHIELD_DB=DB, ANTHROPIC_API_KEY='')
    p=subprocess.Popen([BIN], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); time.sleep(1.0); return p
class C:
    def __init__(s, origin='http://localhost:5173'): s.cookie=None; s.origin=origin; s.last_headers=None
    def req(s, method, path, body=None, ctype='application/json', origin='default'):
        h={}
        if s.cookie: h['Cookie']='ss_session='+s.cookie
        o = s.origin if origin=='default' else origin
        if o: h['Origin']=o
        data=None
        if body is not None:
            data=json.dumps(body) if not isinstance(body,str) else body
            if ctype: h['Content-Type']=ctype
        c=http.client.HTTPConnection('127.0.0.1',PORT,timeout=20); c.request(method,path,data,h); r=c.getresponse()
        raw=r.read().decode(); s.last_headers=dict(r.getheaders())
        sc=r.getheader('Set-Cookie')
        if sc:
            m=re.match(r'ss_session=([^;]*)',sc); s.cookie=m.group(1) or None
        try: j=json.loads(raw)
        except Exception: j=None
        return r.status,j
srv=start()
try:
    mom,kid,other=C(),C(),C()
    st,j=mom.req('POST','/api/auth/signup',{'email':'Mom@Example.com','password':'a long password 1','displayName':'Mom','role':'protected'}); check('signup mom',st==201 and j['user']['email']=='mom@example.com',(st,j))
    sc=mom.last_headers.get('Set-Cookie','')
    check('cookie HttpOnly',('HttpOnly' in sc)); check('cookie SameSite=Strict','SameSite=Strict' in sc); check('no password hash in response','pw_hash' not in json.dumps(j))
    st,j=kid.req('POST','/api/auth/signup',{'email':'kid@example.com','password':'another long password','displayName':'Jehu','role':'helper'}); check('signup kid',st==201)
    st,j=other.req('POST','/api/auth/signup',{'email':'other@example.com','password':'yet another password','displayName':'Stranger','role':'helper'}); check('signup other',st==201)
    st,_=C().req('POST','/api/auth/signup',{'email':'mom@example.com','password':'a long password 1','displayName':'Dup','role':'helper'}); check('duplicate email rejected',st==400,st)
    st,_=C().req('POST','/api/auth/signup',{'email':'x@example.com','password':'short','displayName':'X','role':'helper'}); check('short password rejected',st==400)
    st,_=C().req('POST','/api/auth/signup',{'email':'x@example.com','password':'a long password 1','displayName':'X','role':'admin'}); check('bad role rejected',st==400)
    st,_=C().req('POST','/api/auth/signup',{'email':'not-an-email','password':'a long password 1','displayName':'X','role':'helper'}); check('bad email rejected',st==400)
    # CSRF-type checks
    st,_=C().req('POST','/api/auth/login',{'email':'mom@example.com','password':'a long password 1'},origin='http://evil.example'); check('foreign Origin refused',st==403,st)
    st,_=C().req('POST','/api/auth/login','{"email":"a"}',ctype='text/plain'); check('non-JSON content type refused',st==415,st)
    # me
    st,j=mom.req('GET','/api/auth/me'); check('me works',st==200 and j['user']['role']=='protected')
    st,_=C().req('GET','/api/auth/me'); check('me without session 401',st==401)
    # roles
    st,_=kid.req('POST','/api/links/invite',{}); check('helper cannot create invite',st==403,st)
    st,_=mom.req('POST','/api/links/accept',{'code':'AAAA-AAAA'}); check('protected cannot accept',st==403,st)
    st,_=mom.req('GET','/api/inbox'); check('protected cannot read inbox',st==403,st)
    st,_=C().req('POST','/api/share',{'text':'x'}); check('share needs login',st==401)
    # share before link
    st,j=mom.req('POST','/api/share',{'text':'hello'}); check('share before link refused',st==400,(st,j))
    # link
    st,j=mom.req('POST','/api/links/invite',{}); code=j['code']; check('invite code format',re.fullmatch(r'[A-Z0-9]{4}-[A-Z0-9]{4}',code) is not None,code)
    st,j=kid.req('POST','/api/links/accept',{'code':'ZZZZ-ZZZZ'}); check('wrong code rejected',st==400)
    st,j=kid.req('POST','/api/links/accept',{'code':code.lower()}); check('right code accepted',st==200 and j['linked']['displayName']=='Mom',(st,j))
    st,j=other.req('POST','/api/links/accept',{'code':code}); check('code is single use',st==400)
    st,j=mom.req('GET','/api/links'); check('mom sees helper',st==200 and len(j['links'])==1 and j['links'][0]['displayName']=='Jehu',j)
    st,j=kid.req('GET','/api/links'); check('helper sees mom',len(j['links'])==1)
    # share
    msg='IRS: you owe back taxes. Pay now with gift cards or you will be arrested. Call 561-555-0142 SECRETMARKER'
    st,j=mom.req('POST','/api/share',{'text':msg}); check('share ok',st==201,(st,j))
    st,j=kid.req('GET','/api/inbox'); check('helper inbox has item',st==200 and len(j['items'])==1 and j['unread']==1,j)
    item=j['items'][0]; check('inbox shows sender + text + level',item['from']['displayName']=='Mom' and 'SECRETMARKER' in item['message']['text'] and item['level']=='high',item)
    st,j=other.req('GET','/api/inbox'); check('other helper sees nothing',st==200 and j['items']==[])
    st,_=other.req('POST',f"/api/inbox/{item['id']}/read",{}); check('other helper cannot mark read',st==404)
    st,_=other.req('DELETE',f"/api/inbox/{item['id']}"); check('other helper cannot delete',st==404)
    st,_=kid.req('POST',f"/api/inbox/{item['id']}/read",{}); check('mark read',st==200)
    st,j=kid.req('GET','/api/auth/me'); check('unread count drops',j.get('unread')==0,j)
    st,_=mom.req('POST','/api/share',{'text':'x'*6000}); check('too long refused',st==413)
    st,_=mom.req('POST','/api/share',{'text':'hello','helperId':99999}); check('cannot share to unlinked id',st==400)
    # encryption at rest
    blob=b''.join(open(f,'rb').read() for f in (DB,DB+'-wal') if os.path.exists(f))
    check('message not stored in plaintext',b'SECRETMARKER' not in blob and b'gift cards or you' not in blob)
    check('password not stored in plaintext',b'a long password 1' not in blob)
    check('db file owner-only',oct(os.stat(DB).st_mode & 0o777)=='0o600',oct(os.stat(DB).st_mode & 0o777))
    check('key file owner-only',oct(os.stat(DB+'.key').st_mode & 0o777)=='0o600')
    # unlink
    st,_=mom.req('DELETE',f"/api/links/{kid_id}") if (kid_id:=kid.req('GET','/api/auth/me')[1]['user']['id']) else (0,0); check('unlink ok',st==200,st)
    st,j=kid.req('GET','/api/inbox'); check('helper loses access after unlink',j['items']==[])
    # logout
    st,_=kid.req('POST','/api/auth/logout',{}); check('logout',st==200)
    st,_=kid.req('GET','/api/auth/me'); check('session dead after logout',st==401)
    st,j=kid.req('POST','/api/auth/login',{'email':'kid@example.com','password':'another long password'}); check('login works',st==200)
    # delete account (restart first so the sign-in rate limit window is fresh; sessions live in the database)
    srv.terminate(); srv.wait(); srv=start()
    st,_=other.req('POST','/api/account/delete',{'password':'wrong'}); check('delete needs right password',st==401)
    st,_=other.req('POST','/api/account/delete',{'password':'yet another password'}); check('delete account',st==200)
    st,_=C().req('POST','/api/auth/login',{'email':'other@example.com','password':'yet another password'}); check('deleted account cannot log in',st==401)
    # existing anonymous features still work
    st,j=C().req('POST','/api/analyze',{'text':'Pay with gift cards now or be arrested'},origin=None); check('analyze still anonymous',st==200 and j['level'] in ('medium','high'),(st,j))
    st,j=C(origin=None).req('POST','/api/explain',{'text':'hi','consent':True,'language':'en'},origin=None); check('explain still works',st==200 and j['source']=='builtin',(st,j))
finally:
    srv.terminate(); srv.wait()

# Phase B: lockout after repeated bad passwords (fresh rate-limit window, same database)
srv=start()
try:
    c=C(); codes=[]
    for i in range(6):
        st,_=c.req('POST','/api/auth/login',{'email':'mom@example.com','password':'wrong password %d'%i}); codes.append(st)
    check('5 failures then lockout',codes[:5]==[401]*5 and codes[5]==429,codes)
    st,_=c.req('POST','/api/auth/login',{'email':'mom@example.com','password':'a long password 1'}); check('locked even with right password',st==429,st)
    st,_=C().req('POST','/api/auth/login',{'email':'kid@example.com','password':'another long password'}); check('other accounts unaffected',st==200,st)
finally:
    srv.terminate(); srv.wait()

# Phase C: AI cost controls, using a fake Claude endpoint (no real API calls)
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
calls=[]
class Fake(BaseHTTPRequestHandler):
    def do_POST(self):
        n=int(self.headers.get('content-length',0)); calls.append(json.loads(self.rfile.read(n)))
        out=json.dumps({'content':[{'type':'text','text':'Fake Claude explanation.'}]}).encode()
        self.send_response(200); self.send_header('content-type','application/json'); self.end_headers(); self.wfile.write(out)
    def log_message(self,*a): pass
fake=HTTPServer(('127.0.0.1',9998),Fake); threading.Thread(target=fake.serve_forever,daemon=True).start()
env=dict(os.environ, SCAMSHIELD_PORT=str(PORT), SCAMSHIELD_DB=DB, ANTHROPIC_API_KEY='sk-test', ANTHROPIC_BASE_URL='http://127.0.0.1:9998',
         SCAMSHIELD_AI_USER_CAP='2', SCAMSHIELD_AI_DAILY_CAP='3')
srv=subprocess.Popen([BIN],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); time.sleep(1.0)
try:
    def ex(c,text,lang='en'): return c.req('POST','/api/explain',{'text':text,'language':lang,'consent':True})
    anon,ua,ub=C(),C(),C()
    st,j=ex(anon,'Pay with gift cards now or be arrested. Call 561-555-0142'); check('anonymous gets built-in',st==200 and j['source']=='builtin' and 'Sign in' in j['note'],j); check('anonymous makes no API call',len(calls)==0)
    ua.req('POST','/api/auth/signup',{'email':'a@example.com','password':'a long password 1','displayName':'A','role':'helper'})
    ub.req('POST','/api/auth/signup',{'email':'b@example.com','password':'a long password 2','displayName':'B','role':'helper'})
    st,j=ex(ua,'Pay with gift cards now or be arrested. Call 561-555-0142'); check('signed-in gets Claude',st==200 and j['source']=='claude' and j['remainingToday']==1,j); check('one API call made',len(calls)==1)
    sent=json.dumps(calls[0]); check('phone number redacted before sending',('561-555-0142' not in sent) and '[PHONE]' in sent)
    st,j=ex(ua,'Pay with gift cards now or be arrested. Call 555-555-0199'); check('same message (different number) served from cache',j['source']=='claude' and len(calls)==1 and j['remainingToday']==1,(j,len(calls)))
    st,j=ex(ua,'Your account is locked. Verify at http://bit.ly/abc'); check('second distinct message uses quota',j['source']=='claude' and j['remainingToday']==0 and len(calls)==2,j)
    st,j=ex(ua,'You won a free iPhone, claim your prize'); check('per-account limit stops AI',j['source']=='builtin' and "used today's 2" in j['note'] and len(calls)==2,j)
    st,j=ex(ub,'Hi mom this is my new number, I need bail money'); check('other account still allowed',j['source']=='claude' and len(calls)==3,j)
    st,j=ex(ub,'Your package could not be delivered, update your address'); check('overall daily cap stops AI',j['source']=='builtin' and 'paused for today' in j['note'] and len(calls)==3,j)
    st,j=ex(ub,'Pay with gift cards now or be arrested. Call 561-555-0142'); check('cache still works after cap is reached',j['source']=='claude' and len(calls)==3,j)
finally:
    srv.terminate(); srv.wait(); fake.shutdown()

# Phase D: password reset, using a fake mail provider (no real email is sent)
mails=[]
class FakeMail(BaseHTTPRequestHandler):
    def do_POST(self):
        n=int(self.headers.get('content-length',0)); body=json.loads(self.rfile.read(n))
        mails.append({'path':self.path,'auth':self.headers.get('Authorization'),'body':body})
        self.send_response(200); self.send_header('content-type','application/json'); self.end_headers(); self.wfile.write(b'{"id":"fake"}')
    def log_message(self,*a): pass
fakemail=HTTPServer(('127.0.0.1',9997),FakeMail); threading.Thread(target=fakemail.serve_forever,daemon=True).start()
def wait_mails(n,secs=4):
    end=time.time()+secs
    while len(mails)<n and time.time()<end: time.sleep(0.05)
    time.sleep(0.2)
def token_of(m):
    r=re.search(r'http://localhost:5173/#reset=([0-9a-f]{64})',m['body']['text']); return r.group(1) if r else None
mailenv=dict(os.environ, SCAMSHIELD_PORT=str(PORT), SCAMSHIELD_DB=DB, ANTHROPIC_API_KEY='', SCAMSHIELD_MAIL_API_KEY='mail-test-key',
             SCAMSHIELD_MAIL_FROM='Scam Shield <no-reply@example.com>', SCAMSHIELD_MAIL_BASE_URL='http://127.0.0.1:9997',
             SCAMSHIELD_APP_URL='http://localhost:5173/')
srv=subprocess.Popen([BIN],env=mailenv,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); time.sleep(1.0)
try:
    c=C()
    st,j1=c.req('POST','/api/auth/forgot',{'email':'A@Example.com'}); wait_mails(1)
    check('forgot known email: ok',st==200 and j1.get('ok') is True,(st,j1)); check('one email sent',len(mails)==1,len(mails))
    m=mails[0]
    check('email goes to the right address via provider API',m['path']=='/emails' and m['body']['to']==['a@example.com'] and m['auth']=='Bearer mail-test-key',m)
    check('email has from + subject',m['body']['from'].startswith('Scam Shield') and 'password' in m['body']['subject'].lower())
    tok1=token_of(m); check('email has reset link with 64-hex token (fragment, trailing slash handled)',tok1 is not None,m['body']['text'])
    check('email tells the person to ignore if not them','did not ask' in m['body']['text'])
    st,j2=c.req('POST','/api/auth/forgot',{'email':'a@example.com'}); wait_mails(2)
    st,j3=c.req('POST','/api/auth/forgot',{'email':'a@example.com'}); wait_mails(3)
    st,j4=c.req('POST','/api/auth/forgot',{'email':'a@example.com'}); time.sleep(0.5)
    check('fourth request in an hour sends no more mail',len(mails)==3 and st==200,len(mails))
    check('same answer every time',j2==j1==j4)
    tok3=token_of(mails[2])
    st,ju=c.req('POST','/api/auth/forgot',{'email':'nobody@example.com'}); time.sleep(0.5)
    check('unknown email: same answer, no mail',st==200 and ju==j1 and len(mails)==3,(st,ju,len(mails)))
    blob=b''.join(open(f,'rb').read() for f in (DB,DB+'-wal') if os.path.exists(f))
    check('reset token not stored in plaintext',tok1.encode() not in blob and tok3.encode() not in blob)
finally:
    srv.terminate(); srv.wait()

srv=subprocess.Popen([BIN],env=mailenv,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); time.sleep(1.0)
try:
    st,_=C().req('POST','/api/auth/forgot',{'email':'not-an-email'}); check('forgot with bad email format 400',st==400,st)
    st,_=C().req('POST','/api/auth/forgot',{'email':'a@example.com'},origin='http://evil.example'); check('forgot with foreign Origin refused',st==403,st)
    ua=C(); st,_=ua.req('POST','/api/auth/login',{'email':'a@example.com','password':'a long password 1'}); check('login before reset',st==200)
    st,_=ua.req('GET','/api/auth/me'); check('session works before reset',st==200)
    st,_=C().req('POST','/api/auth/reset',{'token':tok1,'password':'my brand new password'}); check('older link was replaced by newer one',st==400,st)
    st,_=C().req('POST','/api/auth/reset',{'token':'nonsense','password':'my brand new password'}); check('garbage token refused',st==400)
    st,j=C().req('POST','/api/auth/reset',{'token':tok3,'password':'short'}); check('weak password refused',st==400,(st,j))
    st,_=C().req('POST','/api/auth/reset',{'token':tok3,'password':'my brand new password'},origin=None); check('reset works after a failed attempt (token not burned)',st==200,st)
    st,_=C().req('POST','/api/auth/reset',{'token':tok3,'password':'yet another new password'}); check('link cannot be used twice',st==400,st)
    st,_=ua.req('GET','/api/auth/me'); check('old sessions are signed out by a reset',st==401,st)
    st,_=C().req('POST','/api/auth/login',{'email':'a@example.com','password':'a long password 1'}); check('old password no longer works',st==401,st)
    st,j=C().req('POST','/api/auth/login',{'email':'a@example.com','password':'my brand new password'}); check('new password works',st==200 and j['user']['email']=='a@example.com',(st,j))
finally:
    srv.terminate(); srv.wait()

# Dev mode: no mail provider configured, so the link is printed in the server console
devlog='/tmp/it_devmode.log'
devenv=dict(os.environ, SCAMSHIELD_PORT=str(PORT), SCAMSHIELD_DB=DB, ANTHROPIC_API_KEY='')
for k in ('SCAMSHIELD_MAIL_API_KEY','SCAMSHIELD_MAIL_FROM','SCAMSHIELD_MAIL_BASE_URL','SCAMSHIELD_APP_URL'): devenv.pop(k,None)
with open(devlog,'w') as lf:
    srv=subprocess.Popen([BIN],env=devenv,stdout=lf,stderr=subprocess.STDOUT); time.sleep(1.0)
    try:
        st,_=C().req('POST','/api/auth/forgot',{'email':'b@example.com'}); time.sleep(0.5)
        out=open(devlog).read(); mm=re.search(r'http://localhost:5173/#reset=([0-9a-f]{64})',out)
        check('dev mode prints the link in the console',st==200 and mm is not None,out[-300:])
        check('console says it is dev mode','dev mode' in out.lower())
        if mm:
            st,_=C().req('POST','/api/auth/reset',{'token':mm.group(1),'password':'dev mode new password'}); check('dev-mode link works',st==200,st)
            st,_=C().req('POST','/api/auth/login',{'email':'b@example.com','password':'dev mode new password'}); check('login after dev-mode reset',st==200,st)
    finally:
        srv.terminate(); srv.wait()
fakemail.shutdown()
print('API checks passed: %d/%d'%(ok,ok+fail)); sys.exit(1 if fail else 0)
