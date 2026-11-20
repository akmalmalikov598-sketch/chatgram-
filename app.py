
import os
import secrets
import hashlib
from datetime import datetime, timezone

from fastapi import FastAPI, Request, Response, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from sqlalchemy import create_engine, Column, Integer, String, Text, ForeignKey, DateTime, UniqueConstraint
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from itsdangerous import URLSafeTimedSerializer, BadSignature

# =====================================================
# CHATGRAM - NEXT GENERATION MESSENGER
# =====================================================

app = FastAPI(title="CHATGRAM", version="1.0.0")

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///chatgram.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
)

DB = sessionmaker(bind=engine, expire_on_commit=False)
Base = declarative_base()

SECRET = os.getenv("SESSION_SECRET")
if not SECRET:
    raise RuntimeError("SESSION_SECRET kerak")

serializer = URLSafeTimedSerializer(SECRET)

# =====================================================
# DATABASE MODELS
# =====================================================

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(32), unique=True, index=True, nullable=False)
    password = Column(String(256), nullable=False)
    name = Column(String(80), default="")
    bio = Column(String(250), default="")
    avatar = Column(String(500), default="")
    created = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class Chat(Base):
    __tablename__ = "chats"

    id = Column(Integer, primary_key=True)
    title = Column(String(100), default="")
    kind = Column(String(20), default="private")
    created = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    members = relationship("Member", back_populates="chat", cascade="all, delete-orphan")


class Member(Base):
    __tablename__ = "members"

    id = Column(Integer, primary_key=True)
    chat_id = Column(Integer, ForeignKey("chats.id"))
    user_id = Column(Integer, ForeignKey("users.id"))

    chat = relationship("Chat", back_populates="members")
    __table_args__ = (UniqueConstraint("chat_id", "user_id"),)


class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True)
    chat_id = Column(Integer, ForeignKey("chats.id"), index=True)
    sender_id = Column(Integer, ForeignKey("users.id"))
    content = Column(Text)
    created = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class Story(Base):
    __tablename__ = "stories"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    media_url = Column(String(1000))
    caption = Column(String(500), default="")
    created = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class Channel(Base):
    __tablename__ = "channels"

    id = Column(Integer, primary_key=True)
    owner_id = Column(Integer, ForeignKey("users.id"))
    title = Column(String(100))
    description = Column(Text, default="")
    created = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class Bot(Base):
    __tablename__ = "bots"

    id = Column(Integer, primary_key=True)
    owner_id = Column(Integer, ForeignKey("users.id"))
    name = Column(String(100))
    username = Column(String(100), unique=True)
    token = Column(String(256), unique=True)
    welcome_text = Column(Text, default="Salom!")
    active = Column(Integer, default=1)


Base.metadata.create_all(engine)

# =====================================================
# SECURITY
# =====================================================

def password_hash(password):
    salt = secrets.token_hex(16)
    value = hashlib.scrypt(
        password.encode(),
        salt=salt.encode(),
        n=2**14,
        r=8,
        p=1
    ).hex()
    return salt + "$" + value


def password_check(password, stored):
    try:
        salt, old = stored.split("$", 1)
        value = hashlib.scrypt(
            password.encode(),
            salt=salt.encode(),
            n=2**14,
            r=8,
            p=1
        ).hex()
        return secrets.compare_digest(value, old)
    except Exception:
        return False


def token_create(user_id):
    return serializer.dumps({"uid": user_id})


def authenticated(request, db):
    token = request.cookies.get("chatgram_session")
    if not token:
        raise HTTPException(401, "Avval tizimga kiring")

    try:
        data = serializer.loads(token, max_age=2592000)
        user = db.get(User, int(data["uid"]))
        if not user:
            raise HTTPException(401, "Akkaunt topilmadi")
        return user
    except BadSignature:
        raise HTTPException(401, "Sessiya yaroqsiz")


def user_json(user):
    return {
        "id": user.id,
        "username": user.username,
        "name": user.name,
        "bio": user.bio,
        "avatar": user.avatar
    }


def is_member(db, chat_id, user_id):
    return db.query(Member).filter_by(
        chat_id=chat_id,
        user_id=user_id
    ).first() is not None


# =====================================================
# AUTHENTICATION
# =====================================================

@app.post("/api/register")
def register(data: dict, response: Response):
    username = str(data.get("username", "")).strip().lower()
    password = str(data.get("password", ""))
    name = str(data.get("name", "")).strip()

    if not 3 <= len(username) <= 32:
        raise HTTPException(400, "Username 3-32 belgi bo'lishi kerak")

    if not username.replace("_", "").isalnum():
        raise HTTPException(400, "Username noto'g'ri")

    if not 8 <= len(password) <= 128:
        raise HTTPException(400, "Parol kamida 8 belgi bo'lsin")

    with DB() as db:
        if db.query(User).filter_by(username=username).first():
            raise HTTPException(409, "Username band")

        user = User(
            username=username,
            password=password_hash(password),
            name=name[:80] or username
        )

        db.add(user)
        db.commit()
        db.refresh(user)

        response.set_cookie(
            "chatgram_session",
            token_create(user.id),
            httponly=True,
            secure=True,
            samesite="lax",
            max_age=2592000
        )

        return user_json(user)


@app.post("/api/login")
def login(data: dict, response: Response):
    username = str(data.get("username", "")).strip().lower()
    password = str(data.get("password", ""))

    with DB() as db:
        user = db.query(User).filter_by(username=username).first()

        if not user or not password_check(password, user.password):
            raise HTTPException(401, "Login yoki parol xato")

        response.set_cookie(
            "chatgram_session",
            token_create(user.id),
            httponly=True,
            secure=True,
            samesite="lax",
            max_age=2592000
        )

        return user_json(user)


@app.post("/api/logout")
def logout(response: Response):
    response.delete_cookie("chatgram_session")
    return {"ok": True}


@app.get("/api/me")
def me(request: Request):
    with DB() as db:
        return user_json(authenticated(request, db))


# =====================================================
# USERS
# =====================================================

@app.get("/api/users/search")
def search_users(request: Request, q: str = ""):
    with DB() as db:
        me = authenticated(request, db)
        q = q.strip().lower()[:32]

        if not q:
            return []

        users = db.query(User).filter(
            User.username.contains(q),
            User.id != me.id
        ).limit(30).all()

        return [user_json(u) for u in users]


@app.patch("/api/profile")
def update_profile(request: Request, data: dict):
    with DB() as db:
        user = authenticated(request, db)

        if "name" in data:
            user.name = str(data["name"])[:80]

        if "bio" in data:
            user.bio = str(data["bio"])[:250]

        if "avatar" in data:
            user.avatar = str(data["avatar"])[:500]

        db.commit()
        return user_json(user)


# =====================================================
# CHATS
# =====================================================

@app.post("/api/chats")
def create_chat(request: Request, data: dict):
    username = str(data.get("username", "")).strip().lower()

    with DB() as db:
        me = authenticated(request, db)
        other = db.query(User).filter_by(username=username).first()

        if not other or other.id == me.id:
            raise HTTPException(404, "Foydalanuvchi topilmadi")

        if db.query(Member).filter(
            Member.user_id == me.id,
            Member.chat_id.in_(
                db.query(Member.chat_id).filter_by(user_id=other.id)
            )
        ).first():
            for m in db.query(Member).filter_by(user_id=me.id).all():
                chat = db.get(Chat, m.chat_id)
                ids = {x.user_id for x in chat.members}
                if ids == {me.id, other.id} and chat.kind == "private":
                    return {"id": chat.id}

        chat = Chat(kind="private")
        db.add(chat)
        db.flush()

        db.add_all([
            Member(chat_id=chat.id, user_id=me.id),
            Member(chat_id=chat.id, user_id=other.id)
        ])

        db.commit()
        return {"id": chat.id}


@app.post("/api/groups")
def create_group(request: Request, data: dict):
    title = str(data.get("title", "")).strip()
    usernames = data.get("members", [])

    if not title or len(title) > 100:
        raise HTTPException(400, "Guruh nomi noto'g'ri")

    if not isinstance(usernames, list) or len(usernames) > 100:
        raise HTTPException(400, "A'zolar ro'yxati noto'g'ri")

    with DB() as db:
        me = authenticated(request, db)
        chat = Chat(title=title, kind="group")
        db.add(chat)
        db.flush()

        ids = {me.id}

        for username in usernames:
            user = db.query(User).filter_by(
                username=str(username).lower()
            ).first()
            if user:
                ids.add(user.id)

        for uid in ids:
            db.add(Member(chat_id=chat.id, user_id=uid))

        db.commit()
        return {"id": chat.id, "title": title}


@app.get("/api/chats")
def list_chats(request: Request):
    with DB() as db:
        me = authenticated(request, db)
        members = db.query(Member).filter_by(user_id=me.id).all()

        result = []

        for member in members:
            chat = db.get(Chat, member.chat_id)
            last = db.query(Message).filter_by(
                chat_id=chat.id
            ).order_by(Message.id.desc()).first()

            users = []
            for m in chat.members:
                u = db.get(User, m.user_id)
                users.append(user_json(u))

            result.append({
                "id": chat.id,
                "title": chat.title,
                "kind": chat.kind,
                "users": users,
                "last_message": last.content[:100] if last else ""
            })

        return result


# =====================================================
# MESSAGES
# =====================================================

@app.get("/api/chats/{chat_id}/messages")
def get_messages(chat_id: int, request: Request, before: int = 0):
    with DB() as db:
        me = authenticated(request, db)

        if not is_member(db, chat_id, me.id):
            raise HTTPException(403, "Ruxsat yo'q")

        query = db.query(Message).filter_by(chat_id=chat_id)

        if before:
            query = query.filter(Message.id < before)

        messages = query.order_by(Message.id.desc()).limit(50).all()
        messages.reverse()

        return [{
            "id": m.id,
            "sender_id": m.sender_id,
            "content": m.content,
            "created": m.created.isoformat()
        } for m in messages]


# =====================================================
# REALTIME WEBSOCKET
# =====================================================

connections = {}


@app.websocket("/ws/{chat_id}")
async def websocket_chat(ws: WebSocket, chat_id: int):
    token = ws.cookies.get("chatgram_session")

    with DB() as db:
        try:
            info = serializer.loads(token, max_age=2592000)
            user = db.get(User, int(info["uid"]))
        except Exception:
            user = None

        if not user or not is_member(db, chat_id, user.id):
            await ws.close(code=1008)
            return

        user_id = user.id

    await ws.accept()
    connections.setdefault(chat_id, set()).add(ws)

    try:
        while True:
            data = await ws.receive_json()
            content = str(data.get("content", "")).strip()

            if not content or len(content) > 4000:
                continue

            with DB() as db:
                if not is_member(db, chat_id, user_id):
                    await ws.close(code=1008)
                    return

                msg = Message(
                    chat_id=chat_id,
                    sender_id=user_id,
                    content=content
                )

                db.add(msg)
                db.commit()
                db.refresh(msg)

                payload = {
                    "id": msg.id,
                    "sender_id": user_id,
                    "content": content,
                    "created": msg.created.isoformat()
                }

            for client in list(connections.get(chat_id, set())):
                try:
                    await client.send_json(payload)
                except Exception:
                    connections[chat_id].discard(client)

    except WebSocketDisconnect:
        pass
    finally:
        connections.get(chat_id, set()).discard(ws)


# =====================================================
# STORIES
# =====================================================

@app.post("/api/stories")
def create_story(request: Request, data: dict):
    media = str(data.get("media_url", "")).strip()
    caption = str(data.get("caption", ""))[:500]

    if not media.startswith("https://"):
        raise HTTPException(400, "HTTPS media manzili kerak")

    with DB() as db:
        me = authenticated(request, db)
        story = Story(
            user_id=me.id,
            media_url=media,
            caption=caption
        )
        db.add(story)
        db.commit()
        return {"ok": True, "id": story.id}


@app.get("/api/stories")
def get_stories(request: Request):
    with DB() as db:
        me = authenticated(request, db)
        stories = db.query(Story).order_by(
            Story.created.desc()
        ).limit(100).all()

        return [{
            "id": s.id,
            "user": user_json(db.get(User, s.user_id)),
            "media_url": s.media_url,
            "caption": s.caption,
            "created": s.created.isoformat()
        } for s in stories]


# =====================================================
# CHANNELS
# =====================================================

@app.post("/api/channels")
def create_channel(request: Request, data: dict):
    title = str(data.get("title", "")).strip()
    description = str(data.get("description", ""))[:2000]

    if not title or len(title) > 100:
        raise HTTPException(400, "Kanal nomi noto'g'ri")

    with DB() as db:
        me = authenticated(request, db)
        channel = Channel(
            owner_id=me.id,
            title=title,
            description=description
        )
        db.add(channel)
        db.commit()
        return {"id": channel.id, "title": title}


@app.get("/api/channels")
def channels():
    with DB() as db:
        items = db.query(Channel).order_by(
            Channel.id.desc()
        ).limit(100).all()

        return [{
            "id": c.id,
            "title": c.title,
            "description": c.description
        } for c in items]


# =====================================================
# BOT STUDIO
# =====================================================

@app.post("/api/bots")
def create_bot(request: Request, data: dict):
    name = str(data.get("name", "")).strip()
    username = str(data.get("username", "")).strip().lower()
    welcome = str(data.get("welcome_text", "Salom!"))[:2000]

    if not name or len(name) > 100:
        raise HTTPException(400, "Bot nomi noto'g'ri")

    if not 3 <= len(username) <= 32 or not username.replace("_", "").isalnum():
        raise HTTPException(400, "Bot username noto'g'ri")

    with DB() as db:
        me = authenticated(request, db)

        if db.query(Bot).filter_by(username=username).first():
            raise HTTPException(409, "Bot username band")

        token = secrets.token_urlsafe(32)

        bot = Bot(
            owner_id=me.id,
            name=name,
            username=username,
            token=token,
            welcome_text=welcome
        )

        db.add(bot)
        db.commit()

        return {
            "id": bot.id,
            "name": bot.name,
            "username": bot.username,
            "token": token
        }


@app.get("/api/bots")
def my_bots(request: Request):
    with DB() as db:
        me = authenticated(request, db)
        bots = db.query(Bot).filter_by(owner_id=me.id).all()

        return [{
            "id": b.id,
            "name": b.name,
            "username": b.username,
            "active": bool(b.active)
        } for b in bots]


# =====================================================
# HEALTH
# =====================================================

@app.get("/health")
def health():
    return {
        "status": "online",
        "platform": "CHATGRAM",
        "version": "1.0.0"
    }


# =====================================================
# ORIGINAL CHATGRAM FRONTEND
# =====================================================

HTML = r"""
<!DOCTYPE html>
<html lang="uz">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CHATGRAM</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#080c18;color:#fff;font-family:Inter,Arial,sans-serif}
button,input{font:inherit}
button{cursor:pointer}
.app{height:100vh;display:flex;align-items:center;justify-content:center;padding:16px}
.shell{width:100%;height:100%;max-width:1600px;max-height:950px;display:grid;grid-template-columns:75px 330px minmax(250px,1fr);background:#10182a;border:1px solid #273653;border-radius:22px;overflow:hidden;box-shadow:0 25px 100px #0008}
.rail{background:#0c1425;border-right:1px solid #25334e;display:flex;align-items:center;flex-direction:column;padding:20px 8px;gap:20px}
.brand{font-size:22px;color:#a98bff;font-weight:1000}
.nav{width:48px;height:48px;border-radius:15px;background:transparent;color:#91a2c3;font-size:21px}
.nav.active,.nav:hover{background:#30235a;color:#c3a7ff}
.side{border-right:1px solid #293752;padding:20px;display:flex;flex-direction:column;min-width:0}
.logo{font-size:25px;font-weight:900;letter-spacing:2px;color:#b49aff}
.logo span{color:#48dcd4}
.tag{font-size:11px;color:#8495b5;margin-top:5px;letter-spacing:2px}
.search{margin:25px 0 15px;width:100%;padding:14px;background:#0a1222;border:1px solid #293752;border-radius:13px;color:white;outline:none}
.tabs{display:flex;gap:5px;flex-wrap:wrap}
.tab{background:transparent;color:#8999b7;padding:9px 10px;border-radius:10px;font-size:12px}
.tab.active{background:#30235a;color:#c6adff}
.chatlist{overflow:auto;margin-top:12px}
.chat{display:flex;align-items:center;gap:12px;padding:13px 9px;border-radius:13px;cursor:pointer;margin:3px 0}
.chat:hover,.chat.active{background:#1e2a44}
.avatar{width:43px;height:43px;border-radius:50%;background:linear-gradient(135deg,#a16bff,#36d6d0);display:grid;place-items:center;font-weight:bold;flex-shrink:0}
.chat b{font-size:14px}
.chat small{display:block;color:#8293b1;margin-top:5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:200px}
.main{display:flex;flex-direction:column;min-width:0;background:radial-gradient(ellipse at 55% 90%,#44216d55,transparent 45%),#111a2c}
.top{height:76px;border-bottom:1px solid #293752;display:flex;align-items:center;justify-content:space-between;padding:0 24px}
.top small{display:block;color:#8393af;margin-top:5px}
.actions{display:flex;gap:8px}
.action{border:1px solid #354263;background:#18243b;color:#b89bff;border-radius:11px;padding:10px}
.messages{flex:1;overflow:auto;padding:25px;display:flex;flex-direction:column;gap:15px}
.bubble{max-width:70%;padding:13px 16px;background:#202d48;border:1px solid #344362;border-radius:16px 16px 16px 4px;overflow-wrap:anywhere;line-height:1.5}
.bubble.mine{align-self:flex-end;background:linear-gradient(120deg,#633cbd,#774bd5);border:0;border-radius:16px 16px 4px 16px}
.composer{padding:16px 22px;display:flex;align-items:center;gap:10px;border-top:1px solid #293752}
.composer input{flex:1;min-width:0;padding:15px;border:1px solid #354363;border-radius:15px;background:#0c1425;color:white;outline:none}
.send{background:linear-gradient(120deg,#8c61ef,#37bfc9);color:white;padding:14px 20px;border-radius:13px;border:0;font-weight:bold}
.empty{margin:auto;text-align:center;color:#8999b7;line-height:2}
.auth{max-width:400px;width:100%;margin:auto;padding:30px;background:#111b30;border:1px solid #30405e;border-radius:24px}
.auth input{width:100%;margin:8px 0;padding:14px;border-radius:12px;border:1px solid #354363;background:#0b1426;color:white}
.primary{width:100%;padding:14px;background:linear-gradient(110deg,#8c61ef,#37bfc9);border:0;border-radius:12px;color:white;font-weight:bold;margin-top:8px}
#status{font-size:12px;color:#42d8c7}
.hidden{display:none!important}
@media(max-width:800px){.shell{grid-template-columns:55px 1fr}.main{display:none}.rail{padding:10px 3px}.side{padding:12px}}
@media(min-width:801px) and (max-width:1100px){.shell{grid-template-columns:60px 270px 1fr}}
</style>
</head>
<body>
<div id="auth" class="app">
<div class="auth">
<h1 class="logo">CHAT<span>GRAM</span></h1>
<p style="color:#91a1bd">Your world. Your connection.</p>
<input id="username" placeholder="Username">
<input id="name" placeholder="Ismingiz (ro'yxatdan o'tish)">
<input id="password" type="password" placeholder="Parol">
<button class="primary" onclick="login()">Kirish</button>
<button class="primary" onclick="register()">Akkaunt yaratish</button>
<p id="error" style="color:#ff7777"></p>
</div>
</div>
<div id="messenger" class="app hidden">
<div class="shell">
<aside class="rail">
<div class="brand">C.</div>
<button class="nav active" title="Chat">▣</button>
<button class="nav" title="Stories" onclick="showStories()">◉</button>
<button class="nav" title="Guruh" onclick="makeGroup()">♧</button>
<button class="nav" title="Kanallar" onclick="showChannels()">▤</button>
<button class="nav" title="Botlar" onclick="showBots()">✧</button>
<button class="nav" title="Profil" onclick="profile()">◉</button>
<button class="nav" title="Chiqish" onclick="logout()">↪</button>
</aside>
<aside class="side">
<div class="logo">CHAT<span>GRAM</span></div>
<div class="tag">NEXT GENERATION MESSENGER</div>
<input class="search" id="search" placeholder="Odam qidirish..." oninput="searchUsers()">
<div class="tabs">
<button class="tab active" onclick="filterChats('all',this)">Hammasi</button>
<button class="tab" onclick="filterChats('private',this)">Shaxsiy</button>
<button class="tab" onclick="filterChats('group',this)">Guruhlar</button>
</div>
<div id="results"></div>
<div id="chatlist" class="chatlist"></div>
</aside>
<main class="main">
<header class="top">
<div><b id="title">CHATGRAM</b><small id="status">Yangi avlod muloqot platformasi</small></div>
<div class="actions">
<button class="action" onclick="alert('Audio qo‘ng‘iroq keyingi modulda ulanadi')">☎</button>
<button class="action" onclick="alert('Video qo‘ng‘iroq keyingi modulda ulanadi')">▣</button>
<button class="action" onclick="alert('Qo‘shimcha sozlamalar')">⋮</button>
</div>
</header>
<div id="messages" class="messages"><div class="empty">CHATGRAM<br>Yangi suhbat boshlang</div></div>
<div class="composer">
<input id="message" placeholder="Xabaringizni yozing..." onkeydown="if(event.key==='Enter')send()">
<button class="send" onclick="send()">➤</button>
</div>
</main>
</div>
</div>
<script>
let me=null,active=null,socket=null,chats=[],kind='all';
const $=id=>document.getElementById(id);

async function api(url,method='GET',data=null){
 const r=await fetch(url,{
  method,
  headers:{'Content-Type':'application/json'},
  body:data?JSON.stringify(data):null
 });
 const d=await r.json().catch(()=>({}));
 if(!r.ok)throw Error(d.detail||'Xatolik');
 return d;
}
function error(e){$('error').textContent=e.message}

async function register(){
 try{
 await api('/api/register','POST',{
 username:$('username').value,
 password:$('password').value,
 name:$('name').value
 });
 await start();
 }catch(e){error(e)}
}
async function login(){
 try{
 await api('/api/login','POST',{
 username:$('username').value,
 password:$('password').value
 });
 await start();
 }catch(e){error(e)}
}
async function start(){
 me=await api('/api/me');
 $('auth').classList.add('hidden');
 $('messenger').classList.remove('hidden');
 await loadChats();
}
async function logout(){
 if(socket)socket.close();
 await api('/api/logout','POST');
 location.reload();
}
async function loadChats(){
 chats=await api('/api/chats');
 renderChats();
}
function renderChats(){
 $('chatlist').innerHTML='';
 chats.filter(c=>kind==='all'||c.kind===kind).forEach(c=>{
 let other=c.users.find(u=>u.id!==me.id);
 let name=c.title||other?.name||other?.username||'Chat';
 let el=document.createElement('div');
 el.className='chat'+(active===c.id?' active':'');
 let avatar=document.createElement('div');
 avatar.className='avatar';
 avatar.textContent=name.charAt(0).toUpperCase();
 let info=document.createElement('div');
 let b=document.createElement('b');b.textContent=name;
 let small=document.createElement('small');small.textContent=c.last_message||'Suhbatni boshlang';
 info.append(b,small);el.append(avatar,info);
 el.onclick=()=>openChat(c.id,name);
 $('chatlist').append(el);
 });
}
function filterChats(value,button){
 kind=value;
 document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));
 button.classList.add('active');
 renderChats();
}
let searchTimer;
async function searchUsers(){
 clearTimeout(searchTimer);
 searchTimer=setTimeout(async()=>{
 try{
 let users=await api('/api/users/search?q='+encodeURIComponent($('search').value));
 $('results').innerHTML='';
 users.forEach(u=>{
 let b=document.createElement('button');
 b.className='primary';b.textContent=u.name+' @'+u.username;
 b.onclick=async()=>{
 try{
 let c=await api('/api/chats','POST',{username:u.username});
 await loadChats();
 openChat(c.id,u.name);
 }catch(e){alert(e.message)}
 };
 $('results').append(b);
 });
 }catch(e){}
 },300);
}
async function openChat(id,name){
 active=id;
 if(socket)socket.close();
 $('title').textContent=name;
 $('messages').innerHTML='';
 let history=await api('/api/chats/'+id+'/messages');
 history.forEach(draw);
 let protocol=location.protocol==='https:'?'wss://':'ws://';
 socket=new WebSocket(protocol+location.host+'/ws/'+id);
 socket.onopen=()=>$('status').textContent='Online';
 socket.onclose=()=>$('status').textContent='Ulanish uzildi';
 socket.onmessage=e=>draw(JSON.parse(e.data));
 renderChats();
}
function draw(m){
 let el=document.createElement('div');
 el.className='bubble'+(m.sender_id===me.id?' mine':'');
 el.textContent=m.content;
 $('messages').append(el);
 $('messages').scrollTop=$('messages').scrollHeight;
}
function send(){
 let input=$('message');
 let text=input.value.trim();
 if(!text||!socket||socket.readyState!==WebSocket.OPEN)return;
 socket.send(JSON.stringify({content:text}));
 input.value='';
}
async function makeGroup(){
 let title=prompt('Guruh nomi:');
 if(!title)return;
 let members=prompt('A’zolar username-lari (vergul bilan):')||'';
 try{
 let c=await api('/api/groups','POST',{
 title,
 members:members.split(',').map(x=>x.trim()).filter(Boolean)
 });
 await loadChats();
 openChat(c.id,title);
 }catch(e){alert(e.message)}
}
async function showStories(){
 try{
 let stories=await api('/api/stories');
 alert(stories.length?stories.map(s=>s.user.name+': '+s.caption).join('\n'):'Hozircha stories yo‘q');
 }catch(e){alert(e.message)}
}
async function showChannels(){
 try{
 let items=await api('/api/channels');
 alert(items.length?items.map(c=>c.title).join('\n'):'Hozircha kanallar yo‘q');
 }catch(e){alert(e.message)}
}
async function showBots(){
 try{
 let bots=await api('/api/bots');
 alert(bots.length?bots.map(b=>b.name+' @'+b.username).join('\n'):'Hozircha botlar yo‘q');
 }catch(e){alert(e.message)}
}
async function profile(){
 let name=prompt('Yangi ismingiz:',me.name);
 if(name===null)return;
 let bio=prompt('Bio:',me.bio||'')||'';
 try{
 me=await api('/api/profile','PATCH',{name,bio});
 alert('Profil yangilandi');
 }catch(e){alert(e.message)}
}
(async()=>{try{await start()}catch(e){}})();
</script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def home():
    return HTML


@app.get("/health")
def health():
    return {"status": "online", "platform": "CHATGRAM"}
