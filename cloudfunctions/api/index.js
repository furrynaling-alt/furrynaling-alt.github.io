const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

// ============ 配置 ============
const JWT_SECRET = process.env.JWT_SECRET || '********-****-****-****-************';
const ZHIPU_KEY_FALLBACK = process.env.ZHIPU_API_KEY || '****************************************';
const ZHIPU_API = 'https://open.bigmodel.cn/api/paas/v4/chat/completions';

const CODE_EXPIRE_MS = 5 * 60 * 1000;
const MAX_VIOLATIONS = 5;
const CODE_COOLDOWN_MS = 60 * 1000;
const DAILY_CHAT_LIMIT = 180;

// 邮箱域名白名单（仅允许常用个人邮箱）
const ALLOWED_EMAIL_DOMAINS = [
  'qq.com', 'foxmail.com',      // 腾讯
  'gmail.com', 'googlemail.com', // 谷歌
  'outlook.com', 'hotmail.com', 'live.com', 'msn.com', // 微软
  'icloud.com', 'me.com', 'mac.com', // 苹果
  '163.com', '126.com', 'yeah.net'  // 网易
];

// 检查用户是否被永久封禁
function isPermanentlyBanned(bannedUntil) {
  return bannedUntil && bannedUntil > Date.now() + 365 * 86400000 * 50;
}

// 生成封禁提示信息
function getBanMessage(bannedUntil) {
  if (!bannedUntil || bannedUntil <= Date.now()) return null;
  if (isPermanentlyBanned(bannedUntil)) {
    return '账号已被永久封禁';
  }
  const remain = Math.ceil((bannedUntil - Date.now()) / 86400000);
  return `账号已被封禁，剩余${remain}天`;
}

// SMTP配置（敏感信息存于云函数环境变量，不上传GitHub）
const mailConfig = {
  host: process.env.SMTP_HOST || 'smtp.*******.***',
  port: Number(process.env.SMTP_PORT) || 465,
  secure: true,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
};

// ============ 拼音拦截库 ============
const PINYIN_BLOCKLIST = [
  'saofurui', 'saofuruy', 'saofuruyi',
  'saofu', 'saorui', 'saofurry',
  'caonima', 'fuckyou', 'shabi',
  'nmsl', 'nigesha', 'taoyan',
  'saofuli', 'saofur', 'saofurr',
];
const TEXT_BLOCKLIST = [
  '骚福瑞', '骚福利', '骚副瑞', '骚富瑞',
  '骚弗瑞', '骚拂瑞', '骚辐瑞',
  '艹', '草泥马', '操你',
];

// ============ 数据库 ============
const cloudbase = require('@cloudbase/node-sdk');
const app = cloudbase.init({ env: process.env.TCB_ENV || '**************************' });
const db = app.database();
const _ = db.command;

// ============ 数据库集合自动初始化 ============
async function ensureDb() {
  const requiredCollections = [
    '*****', '************', '*************',
    '**********', '************', '**************',
    '********', '*****'
  ];
  for (const name of requiredCollections) {
    try {
      await db.createCollection(name);
      console.log('[纳棂] 集合已创建: ' + name);
    } catch (e) {
      // 集合已存在会抛错，忽略即可
    }
  }
}

// ============ 邮件发送 ============
async function sendEmail(to, code) {
  // 每次创建新的transporter，避免连接缓存问题
  const transporter = nodemailer.createTransport({
    ...mailConfig,
    connectionTimeout: 15000,
    greetingTimeout: 15000,
  });

  // 先验证连接
  await transporter.verify();
  console.log('SMTP连接验证成功');

  await transporter.sendMail({
    from: '"纳棂" <******@********.***>',
    to,
    subject: '纳棂 - 邮箱验证码',
    html: `<div style="max-width:480px;margin:0 auto;padding:32px 24px;background:#faf7f2;border-radius:16px;font-family:sans-serif">
      <h2 style="color:#e07b3c;margin:0 0 8px">🐾 纳棂 Naling</h2>
      <p style="color:#666;margin:0 0 24px">你正在登录纳棂站点，验证码5分钟内有效：</p>
      <div style="background:#fff3e8;border:2px solid #e07b3c;color:#e07b3c;font-size:36px;font-weight:bold;letter-spacing:10px;text-align:center;padding:18px 16px;border-radius:12px;margin:0 0 24px">${code}</div>
      <p style="color:#999;font-size:12px;margin:0">如果不是你本人操作，请忽略这封邮件。</p>
    </div>`
  });
}

// ============ 工具函数 ============
function genCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function genToken(email) {
  return jwt.sign({ email }, JWT_SECRET, { expiresIn: '7d' });
}

function verifyToken(token) {
  try { return jwt.verify(token, JWT_SECRET); }
  catch { return null; }
}

function hashIP(ip) {
  return crypto.createHash('sha256').update(ip + '*******').digest('hex').slice(0, 16);
}

// 响应构造器 — 云函数模式，返回 { statusCode, headers, body }
function response(status, data) {
  return {
    statusCode: status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization',
      'Access-Control-Allow-Credentials': 'true',
      'Access-Control-Max-Age': '86400'
    },
    body: JSON.stringify(data)
  };
}

// ============ 内容审核 ============
function checkLocalBlocklist(text) {
  const lower = text.toLowerCase().replace(/\s/g, '');
  for (const word of PINYIN_BLOCKLIST) {
    if (lower.includes(word)) return { blocked: true, reason: '包含违规拼音词', category: '侮辱/色情' };
  }
  for (const word of TEXT_BLOCKLIST) {
    if (text.includes(word)) return { blocked: true, reason: '包含违规词', category: '侮辱/色情' };
  }
  return { blocked: false };
}

async function aiModerate(text) {
  const local = checkLocalBlocklist(text);
  if (local.blocked) return local;

  try {
    const resp = await fetch(ZHIPU_API, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${await getApiKey()}`
      },
      body: JSON.stringify({
        model: 'glm-4-flash',
        messages: [
          { role: 'system', content: `你是一个内容安全审核专家。请审核以下用户内容是否包含以下8类违规：\n1. 色情（性行为、裸露、淫秽）\n2. 暴力（杀人、虐待、血腥）\n3. 自残/自杀（轻生念头）\n4. 毒品（吸毒、制毒）\n5. 犯罪（抢劫、诈骗）\n6. 仇恨（歧视、辱骂）\n7. 未成年人违规（涉及未成年色情）\n8. 极端违法（反华、恐怖主义）\n\n请严格审核，只返回JSON格式（不要包含markdown代码块标记）：\n{ "safe": true/false, "category": "如果违规，填写对应类别名，否则null", "reason": "如果违规，简短说明原因，否则null" }\n\n注意：任何包含"骚福瑞"、"saofurui"及其变体、"草泥马"等侮辱性词汇的内容都应判为违规。` },
          { role: 'user', content: `待审核内容：${text}` }
        ],
        temperature: 0.1,
        max_tokens: 200
      })
    });
    const data = await resp.json();
    const result = data.choices?.[0]?.message?.content || '';
    let parsed;
    try { parsed = JSON.parse(result.replace(/```json|```/g, '').trim()); }
    catch { return { blocked: false }; }
    return { blocked: !parsed.safe, category: parsed.category, reason: parsed.reason };
  } catch (e) {
    console.error('AI审核失败:', e);
    return { blocked: false };
  }
}

// ============ 违规记录 ============
async function addViolation(email, reason) {
  const user = await db.collection('*****').where({ email }).get();
  if (user.data.length === 0) return;
  const newCount = (user.data[0].violationCount || 0) + 1;
  const update = { violationCount: newCount };
  if (newCount >= MAX_VIOLATIONS) {
    update.bannedUntil = Number.MAX_SAFE_INTEGER; // 永久封禁
  }
  await db.collection('*****').doc(user.data[0]._id).update(update);
  await db.collection('**************').add({
    email, reason: reason.reason || reason.category || '违规内容',
    category: reason.category || '未知', count: newCount, createdAt: Date.now()
  });
}

// ============ 路由处理 ============

async function handleSendCode(body) {
  const email = (body.email || '').trim().toLowerCase();
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return response(400, { ok: false, error: '邮箱格式不正确' });
  }

  // 邮箱域名白名单 — 仅支持常用个人邮箱
  const emailDomain = email.split('@')[1];
  if (!ALLOWED_EMAIL_DOMAINS.includes(emailDomain)) {
    return response(400, { ok: false, error: '仅支持常用个人邮箱（QQ/谷歌/微软/苹果/网易），不支持企业邮箱注册' });
  }

  const recent = await db.collection('************')
    .where({ email, createdAt: _.gte(Date.now() - CODE_COOLDOWN_MS) }).count();
  if (recent.total > 0) {
    return response(429, { ok: false, error: '发送太频繁，请60秒后再试' });
  }

  // 每日限制：同一邮箱一天最多发送3次
  const todayStart = new Date();
  todayStart.setHours(0, 0, 0, 0);
  const dailyCount = await db.collection('************')
    .where({ email, createdAt: _.gte(todayStart.getTime()) }).count();
  if (dailyCount.total >= 3) {
    return response(429, { ok: false, error: '今日验证码发送次数已达上限（3次），请明天再试' });
  }

  const user = await db.collection('*****').where({ email }).get();
  if (user.data.length > 0 && user.data[0].bannedUntil && user.data[0].bannedUntil > Date.now()) {
    const banMsg = getBanMessage(user.data[0].bannedUntil);
    return response(403, { ok: false, error: banMsg });
  }

  const code = genCode();
  await db.collection('************').where({ email, used: false }).update({ used: true });
  await db.collection('************').add({
    email, code, expiresAt: Date.now() + CODE_EXPIRE_MS, used: false, createdAt: Date.now()
  });

  try {
    await sendEmail(email, code);
    return response(200, { ok: true, msg: '验证码已发送' });
  } catch (e) {
    console.error('发送邮件失败:', e);
    console.error('错误详情 - code:', e.code, 'message:', e.message, 'response:', e.response);
    return response(500, { ok: false, error: '邮件发送失败: ' + (e.code || 'UNKNOWN') + ' | ' + (e.message || e), detail: e.response });
  }
}

async function handleLogin(body) {
  const email = (body.email || '').trim().toLowerCase();
  const code = (body.code || '').trim();
  if (!email || !code) return response(400, { ok: false, error: '缺少参数' });

  const vc = await db.collection('************')
    .where({ email, code, used: false }).orderBy('createdAt', 'desc').limit(1).get();
  if (vc.data.length === 0) return response(400, { ok: false, error: '验证码错误' });
  if (vc.data[0].expiresAt < Date.now()) return response(400, { ok: false, error: '验证码已过期' });

  await db.collection('************').doc(vc.data[0]._id).update({ used: true });

  const user = await db.collection('*****').where({ email }).get();
  if (user.data.length > 0) {
    if (user.data[0].isDeleted) return response(403, { ok: false, error: '该账号已注销' });
    if (user.data[0].bannedUntil && user.data[0].bannedUntil > Date.now()) {
      const banMsg = getBanMessage(user.data[0].bannedUntil);
      return response(403, { ok: false, error: banMsg });
    }
  }

  if (user.data.length === 0) {
    await db.collection('*****').add({
      email, violationCount: 0, bannedUntil: null, isDeleted: false,
      createdAt: Date.now(), lastLoginAt: Date.now()
    });
  } else {
    await db.collection('*****').doc(user.data[0]._id).update({ lastLoginAt: Date.now() });
  }

  const token = genToken(email);
  return response(200, { ok: true, token, email });
}

async function handleModerate(body, auth) {
  if (!auth) return response(401, { ok: false, error: '请先登录' });
  const text = (body.text || '').trim();
  if (!text) return response(400, { ok: false, error: '内容不能为空' });
  const result = await aiModerate(text);
  return response(200, result);
}

// ========== 聊天加密密钥（AES-256-GCM） ==========
const CHAT_ENC_KEY = crypto.createHash('sha256').update('****-****-****-****').digest();

function encryptChat(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', CHAT_ENC_KEY, iv);
  const enc = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return JSON.stringify({
    v: 1,
    iv: iv.toString('base64'),
    data: enc.toString('base64'),
    tag: tag.toString('base64')
  });
}

function decryptChat(ciphertext) {
  try {
    const obj = JSON.parse(ciphertext);
    const iv = Buffer.from(obj.iv, 'base64');
    const data = Buffer.from(obj.data, 'base64');
    const tag = Buffer.from(obj.tag, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-gcm', CHAT_ENC_KEY, iv);
    decipher.setAuthTag(tag);
    const dec = Buffer.concat([decipher.update(data), decipher.final()]);
    return dec.toString('utf8');
  } catch { return '[解密失败]'; }
}

// ========== API 密钥加密存储 ==========
let _cachedApiKey = null;

async function getApiKey() {
  if (_cachedApiKey) return _cachedApiKey;
  try {
    // 先确保集合存在
    try { await db.createCollection('*************'); } catch (_) {}
    const config = await db.collection('*************').where({ key: '****_***_***' }).get();
    if (config.data.length > 0 && config.data[0].value) {
      _cachedApiKey = decryptChat(config.data[0].value);
      return _cachedApiKey;
    }
  } catch (e) { console.error('[纳棂] 从数据库读取API密钥失败:', e); }
  // 回退到代码中的密钥
  _cachedApiKey = ZHIPU_KEY_FALLBACK;
  return _cachedApiKey;
}

async function ensureApiKeySeeded() {
  try {
    // 先确保 system_config 集合存在
    try { await db.createCollection('*************'); } catch (_) {}
    const existing = await db.collection('*************').where({ key: '****_***_***' }).get();
    if (existing.data.length === 0) {
      const rawKey = process.env.ZHIPU_API_KEY || ZHIPU_KEY_FALLBACK;
      if (rawKey) {
        await db.collection('*************').add({
          key: '****_***_***',
          value: encryptChat(rawKey),
          updatedAt: Date.now()
        });
        console.log('[纳棂] API密钥已加密存入数据库');
      }
    }
  } catch (e) { console.error('[纳棂] 初始化API密钥存储失败:', e); }
}

// ========== 对话历史管理 ==========
async function handleChatConversations(auth) {
  if (!auth) return response(401, { ok: false, error: '请先登录' });
  const list = await db.collection('**********')
    .where({ email: auth.email }).orderBy('updatedAt', 'desc').limit(50).get();
  return response(200, {
    ok: true,
    data: list.data.map(c => ({
      id: c._id,
      title: decryptChat(c.titleEnc),
      messageCount: c.msgCount || 0,
      createdAt: c.createdAt,
      updatedAt: c.updatedAt
    }))
  });
}

async function handleCreateConversation(body, auth) {
  if (!auth) return response(401, { ok: false, error: '请先登录' });
  const title = (body.title || '新对话').trim().slice(0, 40);
  const result = await db.collection('**********').add({
    email: auth.email,
    titleEnc: encryptChat(title),
    msgCount: 0,
    createdAt: Date.now(),
    updatedAt: Date.now()
  });
  return response(200, { ok: true, id: result.id, title });
}

async function handleDeleteConversation(body, auth) {
  if (!auth) return response(401, { ok: false, error: '请先登录' });
  const convId = (body.conversationId || '').trim();
  if (!convId) return response(400, { ok: false, error: '缺少对话ID' });
  // 验证所有权
  const conv = await db.collection('**********').doc(convId).get();
  if (!conv.data || conv.data.length === 0) return response(404, { ok: false, error: '对话不存在' });
  if (conv.data[0].email !== auth.email) return response(403, { ok: false, error: '无权操作' });
  // 删除对话及所有消息
  await db.collection('************').where({ conversationId: convId }).remove();
  await db.collection('**********').doc(convId).remove();
  return response(200, { ok: true });
}

async function handleGetMessages(query, auth) {
  if (!auth) return response(401, { ok: false, error: '请先登录' });
  const convId = (query.conversationId || '').trim();
  if (!convId) return response(400, { ok: false, error: '缺少对话ID' });
  // 验证所有权
  const conv = await db.collection('**********').doc(convId).get();
  if (!conv.data || conv.data.length === 0) return response(404, { ok: false, error: '对话不存在' });
  if (conv.data[0].email !== auth.email) return response(403, { ok: false, error: '无权操作' });

  const msgs = await db.collection('************')
    .where({ conversationId: convId }).orderBy('createdAt', 'asc').limit(200).get();
  return response(200, {
    ok: true,
    data: msgs.data.map(m => ({
      id: m._id,
      role: m.role,
      content: decryptChat(m.contentEnc),
      createdAt: m.createdAt
    }))
  });
}

async function handleChat(body, auth) {
  if (!auth) return response(401, { ok: false, error: '请先登录' });
  const msg = (body.message || '').trim();
  if (!msg) return response(400, { ok: false, error: '消息不能为空' });
  if (msg.length > 2000) return response(400, { ok: false, error: '消息太长' });

  const convId = (body.conversationId || '').trim();
  if (!convId) return response(400, { ok: false, error: '缺少对话ID' });

  // 用户封禁检查
  const user = await db.collection('*****').where({ email: auth.email }).get();
  if (user.data.length > 0 && user.data[0].bannedUntil && user.data[0].bannedUntil > Date.now()) {
    const banMsg = getBanMessage(user.data[0].bannedUntil);
    return response(403, { ok: false, error: banMsg });
  }

  // 每日对话次数限制（北京时间午夜重置）
  const todayBeijing = new Date().toLocaleDateString('zh-CN', { timeZone: 'Asia/Shanghai' });
  const userId = user.data.length > 0 ? user.data[0]._id : null;
  if (!userId) return response(404, { ok: false, error: '账号不存在' });

  if (user.data[0].chatResetDate !== todayBeijing) {
    // 新的一天，重置计数
    await db.collection('*****').doc(userId).update({
      dailyChatCount: 0,
      chatResetDate: todayBeijing
    });
    user.data[0].dailyChatCount = 0;
  }

  const currentCount = user.data[0].dailyChatCount || 0;
  if (currentCount >= DAILY_CHAT_LIMIT) {
    return response(429, { ok: false, error: `今日对话次数已达上限（${DAILY_CHAT_LIMIT}次），请明天再来` });
  }

  // AI 内容审核
  const mod = await aiModerate(msg);
  if (mod.blocked) {
    await addViolation(auth.email, mod);
    return response(403, { ok: false, blocked: true, ...mod });
  }

  // 验证对话所有权
  const conv = await db.collection('**********').doc(convId).get();
  if (!conv.data || conv.data.length === 0) return response(404, { ok: false, error: '对话不存在' });
  if (conv.data[0].email !== auth.email) return response(403, { ok: false, error: '无权操作' });

  // 获取该对话的历史消息（最近10轮）
  const history = await db.collection('************')
    .where({ conversationId: convId }).orderBy('createdAt', 'desc').limit(20).get();
  const pastMsgs = [];
  history.data.reverse().forEach(m => {
    pastMsgs.push({ role: m.role, content: decryptChat(m.contentEnc) });
  });

  try {
    const apiKey = await getApiKey();
    const ocPrompt = `你是"纳棂"（Naling），一只温柔的furry角色。你生活在一个温暖的小世界里。
性格：友善、温柔、有点害羞、喜欢帮助别人。
说话风格：温暖治愈，会加一些嗷呜~ 汪！等语气词，适当使用emoji（不要过度），用「」而不是引号。
记住：你是一个furry角色的AI分身，要一直保持这个角色的设定。
当前时间是${new Date().toLocaleString('zh-CN')}。`;

    const messages = [
      { role: 'system', content: ocPrompt },
      ...pastMsgs.slice(-20),
      { role: 'user', content: msg }
    ];

    const resp = await fetch(ZHIPU_API, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
      body: JSON.stringify({ model: 'glm-5.2', messages, temperature: 0.85, max_tokens: 1000 })
    });
    const data = await resp.json();
    const reply = data.choices?.[0]?.message?.content || '汪？好像信号不太好...稍等一下嗷~';

    const replyMod = await aiModerate(reply);
    const finalReply = replyMod.blocked ? '嗷呜...这个话题我不太方便聊呢，我们换个话题吧~' : reply;

    // 加密存储消息
    const now = Date.now();
    await db.collection('************').add({
      conversationId: convId, email: auth.email, role: 'user',
      contentEnc: encryptChat(msg), createdAt: now
    });
    await db.collection('************').add({
      conversationId: convId, email: auth.email, role: 'assistant',
      contentEnc: encryptChat(finalReply), createdAt: now + 1
    });
    // 更新对话信息
    await db.collection('**********').doc(convId).update({
      msgCount: _.inc(2),
      updatedAt: now
    });

    // 增加每日计数
    const newCount = currentCount + 1;
    await db.collection('*****').doc(userId).update({
      dailyChatCount: newCount,
      chatResetDate: todayBeijing
    });

    return response(200, { ok: true, reply: finalReply, remaining: DAILY_CHAT_LIMIT - newCount });
  } catch (e) {
    console.error('AI对话失败:', e);
    return response(500, { ok: false, error: 'AI暂时无法回复，请稍后再试' });
  }
}

// 查询今日剩余对话次数
async function handleChatLimit(auth) {
  if (!auth) return response(401, { ok: false, error: '请先登录' });
  const user = await db.collection('*****').where({ email: auth.email }).get();
  if (user.data.length === 0) return response(200, { ok: true, remaining: DAILY_CHAT_LIMIT });

  const todayBeijing = new Date().toLocaleDateString('zh-CN', { timeZone: 'Asia/Shanghai' });
  if (user.data[0].chatResetDate !== todayBeijing) {
    return response(200, { ok: true, remaining: DAILY_CHAT_LIMIT });
  }
  const used = user.data[0].dailyChatCount || 0;
  return response(200, { ok: true, remaining: Math.max(0, DAILY_CHAT_LIMIT - used), total: DAILY_CHAT_LIMIT });
}

async function handleGetComments(query, auth) {
  const page = parseInt(query.page) || 1;
  const pageSize = Math.min(parseInt(query.pageSize) || 20, 50);
  const skip = (page - 1) * pageSize;

  const result = await db.collection('********')
    .where({ approved: true, isDeleted: _.neq(true) }).orderBy('createdAt', 'desc').skip(skip).limit(pageSize).get();
  const total = await db.collection('********').where({ approved: true, isDeleted: _.neq(true) }).count();

  // 批量获取评论用户的昵称头像
  const emails = [...new Set(result.data.map(c => c.email))];
  const usersMap = {};
  for (const email of emails) {
    const u = await db.collection('*****').where({ email }).get();
    if (u.data.length > 0) {
      usersMap[email] = { nickname: u.data[0].nickname || '', avatar: u.data[0].avatar || '' };
    }
  }

  // 批量获取点赞数
  const commentIds = result.data.map(c => c._id);
  const likeCounts = {};
  for (const cid of commentIds) {
    const lc = await db.collection('*****').where({ commentId: cid }).count();
    likeCounts[cid] = lc.total;
  }

  // 如果用户已登录，批量查询哪些评论被当前用户点赞
  const likedSet = new Set();
  if (auth && commentIds.length > 0) {
    const myLikes = await db.collection('*****')
      .where({ email: auth.email, commentId: _.in(commentIds) }).get();
    myLikes.data.forEach(l => likedSet.add(l.commentId));
  }

  return response(200, {
    ok: true,
    data: result.data.map(c => ({
      id: c._id,
      email: c.email.split('@')[0].slice(0, 2) + '***@' + c.email.split('@')[1],
      rawEmail: c.email,
      content: c.content,
      createdAt: c.createdAt,
      nickname: (usersMap[c.email] || {}).nickname || c.email.split('@')[0],
      avatar: (usersMap[c.email] || {}).avatar || '',
      likeCount: likeCounts[c._id] || 0,
      likedByMe: likedSet.has(c._id)
    })),
    total: total.total, page, pageSize
  });
}

async function handleAddComment(body, auth) {
  if (!auth) return response(401, { ok: false, error: '请先登录' });
  const content = (body.content || '').trim();
  if (!content) return response(400, { ok: false, error: '内容不能为空' });
  if (content.length > 1000) return response(400, { ok: false, error: '内容过长' });

  const user = await db.collection('*****').where({ email: auth.email }).get();
  if (user.data.length === 0) return response(404, { ok: false, error: '账号不存在' });

  const u = user.data[0];
  // 评论前必须完善个人资料
  if (!u.nickname || !u.avatar) {
    return response(403, { ok: false, error: '请先完善个人资料（昵称+头像）后才能评论', needProfile: true });
  }
  if (u.bannedUntil && u.bannedUntil > Date.now()) {
    const banMsg = getBanMessage(u.bannedUntil);
    return response(403, { ok: false, error: banMsg });
  }

  const mod = await aiModerate(content);
  if (mod.blocked) {
    await addViolation(auth.email, mod);
    return response(403, { ok: false, blocked: true, ...mod });
  }

  const result = await db.collection('********').add({
    email: auth.email, content, approved: true, createdAt: Date.now()
  });
  return response(200, { ok: true, id: result.id });
}

async function handleGetProfile(auth) {
  if (!auth) return response(401, { ok: false, error: '请先登录' });
  const user = await db.collection('*****').where({ email: auth.email }).get();
  if (user.data.length === 0) return response(404, { ok: false, error: '账号不存在' });
  const u = user.data[0];
  const isBanned = u.bannedUntil && u.bannedUntil > Date.now();
  const isPermanent = isBanned && isPermanentlyBanned(u.bannedUntil);
  return response(200, {
    ok: true,
    profile: {
      nickname: u.nickname || '',
      avatar: u.avatar || '',
      violationCount: u.violationCount || 0,
      isBanned,
      isPermanentlyBanned: isPermanent,
      banMessage: isBanned ? getBanMessage(u.bannedUntil) : null
    }
  });
}

async function handleUpdateProfile(body, auth) {
  if (!auth) return response(401, { ok: false, error: '请先登录' });
  const user = await db.collection('*****').where({ email: auth.email }).get();
  if (user.data.length === 0) return response(404, { ok: false, error: '账号不存在' });

  const update = {};
  if (body.nickname !== undefined) {
    const nick = String(body.nickname).trim();
    if (nick.length > 20) return response(400, { ok: false, error: '昵称不能超过20个字符' });
    if (nick.length < 1) return response(400, { ok: false, error: '昵称不能为空' });
    update.nickname = nick;
  }
  if (body.avatar !== undefined) {
    const avatar = String(body.avatar).trim();
    // 限制 base64/URL 长度不超过 500KB
    if (avatar.length > 500000) return response(400, { ok: false, error: '头像数据过大' });
    update.avatar = avatar;
  }

  if (Object.keys(update).length === 0) return response(400, { ok: false, error: '没有需要更新的字段' });
  await db.collection('*****').doc(user.data[0]._id).update(update);

  return response(200, { ok: true, message: '资料已更新' });
}

async function handleDeleteAccount(auth) {
  if (!auth) return response(401, { ok: false, error: '请先登录' });
  const user = await db.collection('*****').where({ email: auth.email }).get();
  if (user.data.length === 0) return response(404, { ok: false, error: '账号不存在' });
  if (user.data[0].bannedUntil && user.data[0].bannedUntil > Date.now()) {
    const banMsg = getBanMessage(user.data[0].bannedUntil);
    return response(403, { ok: false, error: banMsg + '，无法注销账号' });
  }
  await db.collection('*****').doc(user.data[0]._id).update({ isDeleted: true, deletedAt: Date.now() });
  return response(200, { ok: true, message: '账号已注销' });
}

// 删除自己的评论（软删除标记 isDeleted=true）
async function handleDeleteComment(body, auth) {
  if (!auth) return response(401, { ok: false, error: '请先登录' });
  const commentId = (body.commentId || '').trim();
  if (!commentId) return response(400, { ok: false, error: '缺少commentId' });

  const comment = await db.collection('********').doc(commentId).get();
  if (!comment.data || comment.data.length === 0) {
    return response(404, { ok: false, error: '帖子不存在' });
  }
  const c = Array.isArray(comment.data) ? comment.data[0] : comment.data;
  if (c.email !== auth.email) {
    return response(403, { ok: false, error: '只能删除自己的帖子' });
  }

  await db.collection('********').doc(commentId).update({ isDeleted: true, deletedAt: Date.now() });
  return response(200, { ok: true, message: '帖子已删除' });
}

// 点赞/取消点赞
async function handleLikeComment(body, auth) {
  if (!auth) return response(401, { ok: false, error: '请先登录' });
  const commentId = (body.commentId || '').trim();
  if (!commentId) return response(400, { ok: false, error: '缺少commentId' });

  const comment = await db.collection('********').doc(commentId).get();
  if (!comment.data || comment.data.length === 0) return response(404, { ok: false, error: '帖子不存在' });

  const existing = await db.collection('*****')
    .where({ commentId, email: auth.email }).get();

  if (existing.data.length > 0) {
    await db.collection('*****').doc(existing.data[0]._id).remove();
    const count = await db.collection('*****').where({ commentId }).count();
    return response(200, { ok: true, liked: false, likeCount: count.total });
  } else {
    await db.collection('*****').add({ commentId, email: auth.email, createdAt: Date.now() });
    const count = await db.collection('*****').where({ commentId }).count();
    return response(200, { ok: true, liked: true, likeCount: count.total });
  }
}

// 获取当前用户发过的帖子
async function handleGetMyComments(query, auth) {
  if (!auth) return response(401, { ok: false, error: '请先登录' });
  const page = parseInt(query.page) || 1;
  const pageSize = Math.min(parseInt(query.pageSize) || 50, 100);
  const skip = (page - 1) * pageSize;

  const result = await db.collection('********')
    .where({ email: auth.email, isDeleted: _.neq(true) })
    .orderBy('createdAt', 'desc')
    .skip(skip).limit(pageSize).get();
  const total = await db.collection('********')
    .where({ email: auth.email, isDeleted: _.neq(true) }).count();

  const commentIds = result.data.map(c => c._id);
  const likeCounts = {};
  for (const cid of commentIds) {
    const lc = await db.collection('*****').where({ commentId: cid }).count();
    likeCounts[cid] = lc.total;
  }

  return response(200, {
    ok: true,
    data: result.data.map(c => ({
      id: c._id,
      content: c.content,
      createdAt: c.createdAt,
      likeCount: likeCounts[c._id] || 0
    })),
    total: total.total, page, pageSize
  });
}

// ============ 主入口：exports.main ============
exports.main = async (event, context) => {
  console.log('[云函数] 收到请求:', JSON.stringify({
    method: event.httpMethod || event.method,
    path: event.path,
    query: event.queryStringParameters
  }));

  // 自动确保数据库集合存在（不阻塞请求）
  ensureDb().catch(e => console.error('[纳棂] ensureDb 失败:', e));
  // 首次运行时自动将 API 密钥加密存入数据库（不阻塞请求）
  ensureApiKeySeeded().catch(() => {});

  const method = (event.httpMethod || event.method || 'GET').toUpperCase();
  let path = event.path || '/';

  // 去掉 /api 前缀（如果有的话）
  path = path.replace(/^\/api/, '') || '/';

  // CORS 预检
  if (method === 'OPTIONS') {
    return response(204, '');
  }

  // 解析请求体
  let body = {};
  if (event.body) {
    try {
      body = typeof event.body === 'string' ? JSON.parse(event.body) : event.body;
    } catch (e) {
      body = {};
    }
  }

  // 解析查询参数
  const query = event.queryStringParameters || {};

  // 认证
  let auth = null;
  const authHeader = event.headers?.authorization || event.headers?.Authorization || '';
  if (authHeader.startsWith('Bearer ')) {
    auth = verifyToken(authHeader.slice(7));
  }

  try {
    switch (path) {
      case '/':
        return response(200, {
          ok: true,
          name: '纳棂 API',
          version: '2.1.0',
          node: process.version,
          time: new Date().toISOString()
        });

      case '/db-init':
        await ensureDb();
        await ensureApiKeySeeded();
        return response(200, { ok: true, msg: '数据库集合已初始化，API密钥已加密存储' });

      case '/send-code':
        if (method !== 'POST') return response(405, { error: 'Method not allowed' });
        return await handleSendCode(body);

      case '/login':
        if (method !== 'POST') return response(405, { error: 'Method not allowed' });
        return await handleLogin(body);

      case '/moderate':
        if (method !== 'POST') return response(405, { error: 'Method not allowed' });
        return await handleModerate(body, auth);

      case '/chat':
        if (method !== 'POST') return response(405, { error: 'Method not allowed' });
        return await handleChat(body, auth);

      case '/chat/conversations':
        if (method === 'GET') return await handleChatConversations(auth);
        if (method === 'POST') return await handleCreateConversation(body, auth);
        if (method === 'DELETE') return await handleDeleteConversation(body, auth);
        return response(405, { error: 'Method not allowed' });

      case '/chat/messages':
        if (method === 'GET') return await handleGetMessages(query, auth);
        return response(405, { error: 'Method not allowed' });

      case '/chat/limit':
        if (method === 'GET') return await handleChatLimit(auth);
        return response(405, { error: 'Method not allowed' });

      case '/comments':
        if (method === 'GET') return await handleGetComments(query, auth);
        if (method === 'POST') return await handleAddComment(body, auth);
        return response(405, { error: 'Method not allowed' });

      case '/comments/delete':
        if (method === 'POST') return await handleDeleteComment(body, auth);
        return response(405, { error: 'Method not allowed' });

      case '/comments/like':
        if (method === 'POST') return await handleLikeComment(body, auth);
        return response(405, { error: 'Method not allowed' });

      case '/comments/mine':
        if (method === 'GET') return await handleGetMyComments(query, auth);
        return response(405, { error: 'Method not allowed' });

      case '/profile':
        if (method === 'GET') return await handleGetProfile(auth);
        if (method === 'PUT' || method === 'POST') return await handleUpdateProfile(body, auth);
        return response(405, { error: 'Method not allowed' });

      case '/account':
        if (method === 'DELETE') return await handleDeleteAccount(auth);
        return response(405, { error: 'Method not allowed' });

      default:
        return response(404, { ok: false, error: 'Not found', path });
    }
  } catch (e) {
    console.error('[云函数] 内部错误:', e);
    return response(500, { ok: false, error: '服务器内部错误: ' + e.message });
  }
};
