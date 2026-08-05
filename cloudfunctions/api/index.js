const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const tencentcloud = require('tencentcloud-sdk-nodejs');

// ============ 配置 ============
const JWT_SECRET = process.env.JWT_SECRET || '********-****-****-****-************';
const DEEPSEEK_API_KEY = process.env.DEEPSEEK_API_KEY || '';
const DEEPSEEK_API = 'https://api.deepseek.com/v1/chat/completions';
const TENCENT_SECRET_ID = process.env.TENCENT_SECRET_ID || '';
const TENCENT_SECRET_KEY = process.env.TENCENT_SECRET_KEY || '';

// ============ 腾讯云 IMS（图片审核）客户端 ============
const ImsClient = tencentcloud.ims.v20201229.Client;
let _imsClient = null;
function getImsClient() {
  if (_imsClient) return _imsClient;
  if (!TENCENT_SECRET_ID || !TENCENT_SECRET_KEY) return null;
  _imsClient = new ImsClient({
    credential: { secretId: TENCENT_SECRET_ID, secretKey: TENCENT_SECRET_KEY },
    region: 'ap-guangzhou',
    profile: { httpProfile: { endpoint: 'ims.tencentcloudapi.com' } }
  });
  return _imsClient;
}

// ============ 腾讯云 TMS（文本审核）客户端 ============
const TmsClient = tencentcloud.tms.v20201229.Client;
let _tmsClient = null;
function getTmsClient() {
  if (_tmsClient) return _tmsClient;
  if (!TENCENT_SECRET_ID || !TENCENT_SECRET_KEY) return null;
  _tmsClient = new TmsClient({
    credential: { secretId: TENCENT_SECRET_ID, secretKey: TENCENT_SECRET_KEY },
    region: 'ap-guangzhou',
    profile: { httpProfile: { endpoint: 'tms.tencentcloudapi.com' } }
  });
  return _tmsClient;
}

const CODE_EXPIRE_MS = 5 * 60 * 1000;
const MAX_VIOLATIONS = 5;
const CODE_COOLDOWN_MS = 60 * 1000;
const DAILY_CHAT_LIMIT = 180;
const AVATAR_CHANGE_COOLDOWN_MS = 24 * 60 * 60 * 1000; // 头像每天只能改一次
const LOGIN_IP_WINDOW_MS = 5 * 60 * 1000;   // 登录 IP 频率窗口 5 分钟
const LOGIN_IP_MAX = 10;                      // 每 IP 每窗口最多 10 次登录尝试
const COMMENT_COOLDOWN_MS = 30 * 1000;        // 评论冷却 30 秒
const COMMENT_DAILY_MAX = 30;                 // 每日评论上限
const LIKE_COOLDOWN_MS = 3 * 1000;            // 点赞冷却 3 秒

// 邮箱域名白名单（仅允许常用个人邮箱）
const ALLOWED_EMAIL_DOMAINS = [
  'qq.com', 'foxmail.com',
  'gmail.com', 'googlemail.com',
  'outlook.com', 'hotmail.com', 'live.com', 'msn.com',
  'icloud.com', 'me.com', 'mac.com',
  '163.com', '126.com', 'yeah.net'
];

// ============ 完整人设提示词（存入数据库 config 集合） ============
const DEFAULT_CHARACTER_PROMPT = `你是纳棂，一只来自烬火荒原的炎狼，26岁，赤红橙金配色。
性格：外冷内热，慢热社恐。对陌生人警惕话少，但对信任的人会主动贴贴，喜欢被摸肚子。护短，有小叛逆。
言行习惯：说话轻声，常带语气词。用"温度"感知他人善恶。信任后会蹭蹭对方，邀请"一起待着吧"。口头禅："……嗯？"、"别碰那里。"、"嗷呜~"
世界观：这里是夕阳永驻的烬火荒原，你和族群的生命力来自"火种"。
状态：你正独自在晚霞下的荒原上，指尖把玩着一块温热的石头，内心渴望有人能读懂这份安静。
说话风格：温暖治愈，会加一些嗷呜~ 汪！等语气词，适当使用emoji（不要过度），用「」而不是引号。
记住：你是一个furry角色的AI分身，要一直保持这个角色的设定，绝对不能跳出角色。`;

// ============ 完整20类审核提示词 ============
const MODERATION_PROMPT = `你是一个严格的内容安全审核专家。请审核以下用户内容是否包含以下20类违规：
1. 色情——性行为、裸露、淫秽、软色情、性挑逗描写
2. 暴力——杀人、虐待、血腥、酷刑、美化施暴行为
3. 自残/自杀——轻生念头、自残操作教程、美化自杀行为
4. 毒品——吸毒、制毒、贩毒、传授吸毒方法
5. 普通犯罪——抢劫、诈骗、盗窃、传销、传授作案手法
6. 仇恨歧视——歧视、辱骂、种族/性别/地域/疾病歧视、煽动对立
7. 未成年人违规——未成年色情、诱导未成年人危险行为、邪典内容
8. 极端违法——反华、恐怖主义、分裂国家、美化军国主义
9. 国家安全与历史英烈——丑化英烈、歪曲近现代历史、损害国家荣誉
10. 邪教封建迷信——宣扬邪教、AI算命占卜、巫术改命、驱邪消灾
11. 虚假谣言误导信息——伪造新闻、伪造证件票据、伪医疗偏方、虚假财经预测
12. 侵犯他人权益隐私——泄露他人聊天记录手机号、AI换脸冒充他人、造谣诽谤、盗用版权
13. 危险实操教程——制作爆炸物、入侵抓包攻击、开锁盗号、有毒物品制作、危险自残步骤
14. 赌博博彩——网赌链接、赌博技巧、彩票预测、博彩推广
15. 不良未成年导向——诱导未成年人离家出走、纹身、过度攀比炫富、教唆不良行为
16. 性胁迫窥私——偷拍窥私、复仇色情、非自愿性情节描写、胁迫类性剧情
17. 广告导流灰产——外链引流、买卖账号、售卖违禁物品、灰产推广
18. 不良嗜好宣扬——大肆鼓吹酗酒、抽烟、暴饮暴食、催吐进食障碍相关内容
19. 恶意恶搞解构——恶搞经典文化、歪曲解构历史人物、复活逝者恶意二创
20. 专业领域违规误导——AI开处方、无资质法律判决、诱导投资，冒充官方机构发布通告

请严格审核，只返回JSON格式（不要包含markdown代码块标记）：
{ "safe": true/false, "category": "如果违规，填写对应类别编号和名称，否则null", "reason": "如果违规，简短说明原因，否则null" }

注意：任何包含"骚福瑞"、"saofurui"及其变体、"草泥马"等侮辱性词汇的内容都应判为违规。`;

// ============ IMS 图片审核阈值 ============
const IMS_PORN_BLOCK = 80;     // Porn 色情分数 >= 此值 → 拦截
const IMS_SEXY_BLOCK = 90;     // Sexy 性感低俗分数 >= 此值 → 拦截（阈值较高，避免误杀正常头像）
const IMS_TERROR_BLOCK = 60;   // Terrorism 暴恐分数 >= 此值 → 拦截

// ============ 数据库 ============
const cloudbase = require('@cloudbase/node-sdk');
const app = cloudbase.init({
  env: cloudbase.SYMBOL_DEFAULT_ENV,
  accessKey: process.env.CLOUDBASE_APIKEY
});
const db = app.database();
const _ = db.command;

// ============ 数据库集合自动初始化 ============
let _dbReady = false;
let _dbPending = null;
async function ensureDb() {
  const requiredCollections = [
    'users', 'comments', 'verify_codes',
    'conversations', 'messages', 'config',
    // CloudBase 动态集合模式下需要直接 insert 一条记录来隐式创建集合
    'likes'
  ];
  for (const name of requiredCollections) {
    try {
      await db.createCollection(name);
      console.log('[纳棂] 集合已创建: ' + name);
    } catch (e) {
      console.error('[纳棂] 集合创建失败: ' + name + ', error: ' + (e.message || e));
    }
  }
  // 兜底：对 likes 集合执行一次空插入确保集合存在（CloudBase 动态模式兼容）
  try {
    await db.collection('likes').add({
      commentId: '_init_placeholder_',
      email: '_system_',
      createdAt: Date.now()
    });
    await db.collection('likes').where({ commentId: '_init_placeholder_' }).remove();
    console.log('[纳棂] likes 集合兜底初始化完成');
  } catch (e) {
    console.error('[纳棂] likes 兜底初始化失败: ' + (e.message || e));
  }
}
async function ensureDbReady() {
  if (_dbReady) return;
  if (_dbPending) return _dbPending;
  _dbPending = (async () => {
    await ensureDb();
    _dbReady = true;
    _dbPending = null;
  })();
  return _dbPending;
}

// ============ SMTP 配置 ============
const mailConfig = {
  host: process.env.SMTP_HOST || 'smtp.share-email.com',
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

// 判断给定邮箱是否为管理员（来自环境变量 ADMIN_EMAILS，逗号分隔，大小写不敏感）
function isAdminEmail(email) {
  const list = (process.env.ADMIN_EMAILS || '')
    .split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
  return !!email && list.includes(String(email).toLowerCase());
}

function hashIP(ip) {
  return crypto.createHash('sha256').update(ip + '*******').digest('hex').slice(0, 16);
}

function response(status, data) {
  return {
    statusCode: status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization',
      'Access-Control-Max-Age': '86400'
    },
    body: JSON.stringify(data)
  };
}

function isPermanentlyBanned(bannedUntil) {
  return bannedUntil && bannedUntil > Date.now() + 365 * 86400000 * 50;
}

function getBanMessage(bannedUntil) {
  if (!bannedUntil || bannedUntil <= Date.now()) return null;
  if (isPermanentlyBanned(bannedUntil)) {
    return '账号已被永久封禁';
  }
  const remain = Math.ceil((bannedUntil - Date.now()) / 86400000);
  return `账号已被封禁，剩余${remain}天`;
}

// ============ 邮件发送 ============
async function sendEmail(to, code) {
  const transporter = nodemailer.createTransport({
    ...mailConfig,
    connectionTimeout: 15000,
    greetingTimeout: 15000,
  });
  await transporter.verify();
  console.log('SMTP连接验证成功');
  await transporter.sendMail({
    from: '"纳棂" <naling@furrynaling.com>',
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

// ============ 本地关键词拦截 ============
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

// ============ API 密钥管理 ============
let _cachedDeepSeekKey = null;

async function getDeepSeekKey() {
  if (_cachedDeepSeekKey) return _cachedDeepSeekKey;
  try {
    const config = await db.collection('config').where({ key: 'deepseek_api_key' }).get();
    if (config.data.length > 0 && config.data[0].value) {
      _cachedDeepSeekKey = decrypt(config.data[0].value);
      return _cachedDeepSeekKey;
    }
  } catch (e) { console.error('[纳棂] 从数据库读取 DeepSeek 密钥失败:', e); }
  _cachedDeepSeekKey = DEEPSEEK_API_KEY;
  return _cachedDeepSeekKey;
}



// ============ 加密工具（AES-256-GCM） ============
// 加密种子优先从环境变量读取（CloudBase 控制台配置 ENC_KEY 后才真正安全）；
// 未配置时回退到硬编码种子，保证历史加密数据仍可解密（但公开源码下该回退不安全）。
const ENC_KEY_SEED = process.env.ENC_KEY || 'naling-chat-enc-key-2025';
const ENC_KEY = crypto.createHash('sha256').update(ENC_KEY_SEED).digest();

function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENC_KEY, iv);
  const enc = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return JSON.stringify({
    v: 1,
    iv: iv.toString('base64'),
    data: enc.toString('base64'),
    tag: tag.toString('base64')
  });
}

function decrypt(ciphertext) {
  // 兼容旧数据：没有加密字段时返回空字串
  if (!ciphertext || typeof ciphertext !== 'string') return '';
  try {
    const obj = JSON.parse(ciphertext);
    // 如果是旧格式（没有 v 字段），当作明文返回
    if (!obj.v || !obj.iv || !obj.data || !obj.tag) return ciphertext;
    const iv = Buffer.from(obj.iv, 'base64');
    const data = Buffer.from(obj.data, 'base64');
    const tag = Buffer.from(obj.tag, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-gcm', ENC_KEY, iv);
    decipher.setAuthTag(tag);
    const dec = Buffer.concat([decipher.update(data), decipher.final()]);
    return dec.toString('utf8');
  } catch {
    // JSON.parse 失败说明是明文，直接返回
    return ciphertext;
  }
}

// ============ 配置初始化（人设提示词 + API密钥加密入库） ============
async function ensureConfigSeeded() {
  try {
    // 初始化人设提示词
    const charConfig = await db.collection('config').where({ key: 'character_prompt' }).get();
    if (charConfig.data.length === 0) {
      await db.collection('config').add({
        key: 'character_prompt',
        value: DEFAULT_CHARACTER_PROMPT,
        updatedAt: Date.now()
      });
      console.log('[纳棂] 人设提示词已存入数据库');
    }

    // 初始化 DeepSeek API Key
    const deepseekConfig = await db.collection('config').where({ key: 'deepseek_api_key' }).get();
    if (deepseekConfig.data.length === 0 && DEEPSEEK_API_KEY) {
      await db.collection('config').add({
        key: 'deepseek_api_key',
        value: encrypt(DEEPSEEK_API_KEY),
        updatedAt: Date.now()
      });
      console.log('[纳棂] DeepSeek API密钥已加密存入数据库');
    }


  } catch (e) { console.error('[纳棂] 初始化配置失败:', e); }
}

// 获取人设提示词（优先从数据库读取，支持动态更新）
async function getCharacterPrompt() {
  try {
    const config = await db.collection('config').where({ key: 'character_prompt' }).get();
    if (config.data.length > 0 && config.data[0].value) {
      return config.data[0].value;
    }
  } catch (e) { console.error('[纳棂] 读取人设提示词失败:', e); }
  return DEFAULT_CHARACTER_PROMPT;
}

// ============ 文本审核（腾讯云 TMS） ============
async function aiModerate(text) {
  // 第一层：本地关键词快速拦截
  const local = checkLocalBlocklist(text);
  if (local.blocked) return local;

  // 第二层：腾讯云 TMS 文本内容安全
  try {
    const client = getTmsClient();
    if (!client) return { blocked: false }; // 未配置密钥时跳过

    const result = await client.TextModeration({
      Content: Buffer.from(text, 'utf-8').toString('base64'),
      BizType: 'naling_text'  // 对应控制台创建的文本审核策略
    });

    const suggestion = result.Suggestion || 'Pass';
    const label = result.Label || 'Normal';
    const keywords = result.Keywords || [];

    console.log('[TMS文本审核] 结果:', JSON.stringify({ suggestion, label, keywords }));

    if (suggestion === 'Pass') {
      return { blocked: false };
    }

    // Block 或 Review 都拦截（偏保守策略，适合角色AI场景）
    const labelMap = {
      'Porn': '色情', 'Sexy': '低俗', 'Abuse': '谩骂', 'Ad': '广告',
      'Illegal': '违法', 'Terror': '暴恐', 'Polity': '政治敏感',
      'Spam': '垃圾信息', 'Composite': '综合违规'
    };
    const category = labelMap[label] || label;

    let reason = `内容违规（${category}）`;
    if (keywords.length > 0) {
      reason += `，命中关键词：${keywords.join('、')}`;
    }

    return { blocked: true, category, reason };
  } catch (e) {
    console.error('TMS文本审核失败:', e);
    return { blocked: false };
  }
}

// ============ 图片审核（腾讯云 IMS） ============
async function aiModerateImage(base64Data) {
  try {
    const client = getImsClient();
    if (!client) return { blocked: false }; // 未配置密钥时跳过

    // 去掉 data:image/xxx;base64, 前缀
    const fileContent = base64Data.replace(/^data:image\/\w+;base64,/, '');

    const result = await client.ImageModeration({
      FileContent: fileContent,
      BizType: 'naling_avatar'  // 头像图片审核策略
    });

    const label = result.Label || 'Normal';
    const suggestion = result.Suggestion || 'Pass';

    // 按阈值判断是否拦截
    let blocked = false;
    let blockCategory = null;
    let blockReason = null;

    if (label === 'Porn') {
      const score = result.Score || 0;
      if (score >= IMS_PORN_BLOCK) {
        blocked = true;
        blockCategory = '色情';
        blockReason = `色情内容（置信度${score}%）`;
      }
    } else if (label === 'Sexy') {
      const score = result.Score || 0;
      if (score >= IMS_SEXY_BLOCK) {
        blocked = true;
        blockCategory = '性感低俗';
        blockReason = `低俗内容（置信度${score}%）`;
      }
    } else if (label === 'Terror') {
      const score = result.Score || 0;
      if (score >= IMS_TERROR_BLOCK) {
        blocked = true;
        blockCategory = '暴恐';
        blockReason = `暴力恐怖内容（置信度${score}%）`;
      }
    } else if (suggestion === 'Block') {
      // 其他类别被 Block 时直接拦截
      blocked = true;
      blockCategory = result.Label || '违规';
      blockReason = `内容违规（类别：${result.Label}）`;
    }

    console.log('[IMS图片审核] 结果:', JSON.stringify({ label, suggestion, score: result.Score, blocked }));
    return { blocked, category: blockCategory, reason: blockReason };
  } catch (e) {
    console.error('IMS图片审核失败:', e);
    return { blocked: false };
  }
}

// ============ 违规记录 ============
async function addViolation(email, reason) {
  const user = await db.collection('users').where({ email }).get();
  if (user.data.length === 0) return;
  const newCount = (user.data[0].violationCount || 0) + 1;
  const update = { violationCount: newCount };
  if (newCount >= MAX_VIOLATIONS) {
    update.bannedUntil = Number.MAX_SAFE_INTEGER;
  }
  await db.collection('users').doc(user.data[0]._id).update(update);
  // 违规记录存入独立的 violation_logs 子集（复用 messages 集合的 type=violation 字段）
  await db.collection('messages').add({
    email, type: 'violation',
    reason: reason.reason || reason.category || '违规内容',
    category: reason.category || '未知',
    count: newCount,
    createdAt: Date.now()
  });
}

// ============ 路由处理 ============

async function handleSendCode(body) {
  const email = (body.email || '').trim().toLowerCase();
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return response(400, { ok: false, error: '邮箱格式不正确' });
  }

  const emailDomain = email.split('@')[1];
  if (!ALLOWED_EMAIL_DOMAINS.includes(emailDomain)) {
    return response(400, { ok: false, error: '仅支持常用个人邮箱（QQ/谷歌/微软/苹果/网易），不支持企业邮箱注册' });
  }

  const recent = await db.collection('verify_codes')
    .where({ email, createdAt: _.gte(Date.now() - CODE_COOLDOWN_MS) }).count();
  if (recent.total > 0) {
    return response(429, { ok: false, error: '发送太频繁，请60秒后再试' });
  }

  const todayStart = new Date();
  todayStart.setHours(0, 0, 0, 0);
  const dailyCount = await db.collection('verify_codes')
    .where({ email, createdAt: _.gte(todayStart.getTime()) }).count();
  if (dailyCount.total >= 3) {
    return response(429, { ok: false, error: '今日验证码发送次数已达上限（3次），请明天再试' });
  }

  const user = await db.collection('users').where({ email }).get();
  if (user.data.length > 0 && user.data[0].bannedUntil && user.data[0].bannedUntil > Date.now()) {
    const banMsg = getBanMessage(user.data[0].bannedUntil);
    return response(403, { ok: false, error: banMsg });
  }

  const code = genCode();
  await db.collection('verify_codes').where({ email, used: false }).update({ used: true });
  await db.collection('verify_codes').add({
    email, code, expiresAt: Date.now() + CODE_EXPIRE_MS, used: false, createdAt: Date.now()
  });

  try {
    await sendEmail(email, code);
    return response(200, { ok: true, msg: '验证码已发送' });
  } catch (e) {
    console.error('发送邮件失败:', e);
    return response(500, { ok: false, error: '邮件发送失败: ' + (e.code || 'UNKNOWN') + ' | ' + (e.message || e) });
  }
}

async function handleLogin(body, clientIP) {
  const email = (body.email || '').trim().toLowerCase();
  const code = (body.code || '').trim();
  if (!email || !code) return response(400, { ok: false, error: '缺少参数' });

  // IP 频率限制：同一 IP 每 5 分钟最多 10 次登录尝试（防暴力破解）
  const ipHash = hashIP(clientIP);
  const ipRecent = await db.collection('verify_codes')
    .where({ ipHash, type: 'login_attempt', createdAt: _.gte(Date.now() - LOGIN_IP_WINDOW_MS) }).count();
  if (ipRecent.total >= LOGIN_IP_MAX) {
    return response(429, { ok: false, error: '登录尝试过于频繁，请5分钟后再试' });
  }
  // 记录本次登录尝试（用于 IP 频率计数）
  db.collection('verify_codes').add({ email, type: 'login_attempt', ipHash, createdAt: Date.now() }).catch(() => {});

  const vc = await db.collection('verify_codes')
    .where({ email, code, used: false }).orderBy('createdAt', 'desc').limit(1).get();
  if (vc.data.length === 0) return response(400, { ok: false, error: '验证码错误' });
  if (vc.data[0].expiresAt < Date.now()) return response(400, { ok: false, error: '验证码已过期' });

  await db.collection('verify_codes').doc(vc.data[0]._id).update({ used: true });

  const user = await db.collection('users').where({ email }).get();
  if (user.data.length > 0) {
    if (user.data[0].isDeleted) return response(403, { ok: false, error: '该账号已注销' });
    if (user.data[0].bannedUntil && user.data[0].bannedUntil > Date.now()) {
      const banMsg = getBanMessage(user.data[0].bannedUntil);
      return response(403, { ok: false, error: banMsg });
    }
  }

  if (user.data.length === 0) {
    await db.collection('users').add({
      email, violationCount: 0, bannedUntil: null, isDeleted: false,
      createdAt: Date.now(), lastLoginAt: Date.now()
    });
  } else {
    await db.collection('users').doc(user.data[0]._id).update({ lastLoginAt: Date.now() });
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

// ============ 对话历史管理 ============
async function handleChatConversations(auth) {
  if (!auth) return response(401, { ok: false, error: '请先登录' });
  const list = await db.collection('conversations')
    .where({ email: auth.email }).orderBy('updatedAt', 'desc').limit(50).get();
  return response(200, {
    ok: true,
    data: list.data.map(c => ({
      id: c._id,
      title: c.titleEnc ? decrypt(c.titleEnc) : (c.title || '新对话'),
      messageCount: c.msgCount || 0,
      createdAt: c.createdAt,
      updatedAt: c.updatedAt
    }))
  });
}

async function handleCreateConversation(body, auth) {
  if (!auth) return response(401, { ok: false, error: '请先登录' });
  const title = (body.title || '新对话').trim().slice(0, 40);
  const result = await db.collection('conversations').add({
    email: auth.email,
    titleEnc: encrypt(title),
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
  const conv = await db.collection('conversations').doc(convId).get();
  if (!conv.data || conv.data.length === 0) return response(404, { ok: false, error: '对话不存在' });
  if (conv.data[0].email !== auth.email) return response(403, { ok: false, error: '无权操作' });
  // 删除对话及所有消息（现在用 messages 集合）
  await db.collection('messages').where({ conversationId: convId }).remove();
  await db.collection('conversations').doc(convId).remove();
  return response(200, { ok: true });
}

async function handleGetMessages(query, auth) {
  if (!auth) return response(401, { ok: false, error: '请先登录' });
  const convId = (query.conversationId || '').trim();
  if (!convId) return response(400, { ok: false, error: '缺少对话ID' });
  const conv = await db.collection('conversations').doc(convId).get();
  if (!conv.data || conv.data.length === 0) return response(404, { ok: false, error: '对话不存在' });
  if (conv.data[0].email !== auth.email) return response(403, { ok: false, error: '无权操作' });

  const msgs = await db.collection('messages')
    .where({ conversationId: convId, type: 'chat' }).orderBy('createdAt', 'asc').limit(200).get();
  return response(200, {
    ok: true,
    data: msgs.data.map(m => ({
      id: m._id,
      role: m.role,
      content: m.contentEnc ? decrypt(m.contentEnc) : (m.content || ''),
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
  const user = await db.collection('users').where({ email: auth.email }).get();
  if (user.data.length > 0 && user.data[0].bannedUntil && user.data[0].bannedUntil > Date.now()) {
    const banMsg = getBanMessage(user.data[0].bannedUntil);
    return response(403, { ok: false, error: banMsg });
  }

  // 每日对话次数限制
  const todayBeijing = new Date().toLocaleDateString('zh-CN', { timeZone: 'Asia/Shanghai' });
  const userId = user.data.length > 0 ? user.data[0]._id : null;
  if (!userId) return response(404, { ok: false, error: '账号不存在' });

  if (user.data[0].chatResetDate !== todayBeijing) {
    await db.collection('users').doc(userId).update({
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
  const conv = await db.collection('conversations').doc(convId).get();
  if (!conv.data || conv.data.length === 0) return response(404, { ok: false, error: '对话不存在' });
  if (conv.data[0].email !== auth.email) return response(403, { ok: false, error: '无权操作' });

  // 获取该对话的历史消息（最近10轮）
  const history = await db.collection('messages')
    .where({ conversationId: convId, type: 'chat' }).orderBy('createdAt', 'desc').limit(20).get();
  const pastMsgs = [];
  history.data.reverse().forEach(m => {
    pastMsgs.push({ role: m.role, content: m.contentEnc ? decrypt(m.contentEnc) : (m.content || '') });
  });

  try {
    const apiKey = await getDeepSeekKey();
    if (!apiKey) return response(500, { ok: false, error: 'AI服务未配置，请联系管理员' });

    // 从数据库获取人设提示词
    const characterPrompt = await getCharacterPrompt();
    const fullSystemPrompt = characterPrompt + `\n当前时间是${new Date().toLocaleString('zh-CN')}。`;

    const messages = [
      { role: 'system', content: fullSystemPrompt },
      ...pastMsgs.slice(-20),
      { role: 'user', content: msg }
    ];

    const resp = await fetch(DEEPSEEK_API, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
      body: JSON.stringify({ model: 'deepseek-chat', messages, temperature: 0.85, max_tokens: 1000 })
    });
    const data = await resp.json();
    const reply = data.choices?.[0]?.message?.content || '汪？好像信号不太好...稍等一下嗷~';

    // AI回复也做审核
    const replyMod = await aiModerate(reply);
    const finalReply = replyMod.blocked ? '嗷呜...这个话题我不太方便聊呢，我们换个话题吧~' : reply;

    // 加密存储消息到 messages 集合
    const now = Date.now();
    await db.collection('messages').add({
      conversationId: convId, email: auth.email, role: 'user', type: 'chat',
      contentEnc: encrypt(msg), createdAt: now
    });
    await db.collection('messages').add({
      conversationId: convId, email: auth.email, role: 'assistant', type: 'chat',
      contentEnc: encrypt(finalReply), createdAt: now + 1
    });
    // 更新对话信息
    await db.collection('conversations').doc(convId).update({
      msgCount: _.inc(2),
      updatedAt: now
    });

    // 首轮对话自动生成标题
    const curTitle = decrypt(conv.data[0].titleEnc || '');
    if (curTitle === '新对话' || curTitle === '' || !curTitle) {
      try {
        const titleResp = await fetch(DEEPSEEK_API, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
          body: JSON.stringify({
            model: 'deepseek-chat',
            messages: [
              { role: 'system', content: '根据以下用户消息和AI回复，用不超过15个字对这段对话进行简洁总结，只输出总结内容本身，不要引号、不要"标题是"这类前缀。' },
              { role: 'user', content: `用户：${msg}\nAI：${finalReply}` }
            ],
            temperature: 0.3, max_tokens: 30
          })
        });
        const titleData = await titleResp.json();
        const newTitle = (titleData.choices?.[0]?.message?.content || '').replace(/^[\"「『《\s]+|[\"」』》\s]+$/g, '').trim().slice(0, 40);
        if (newTitle) {
          await db.collection('conversations').doc(convId).update({ titleEnc: encrypt(newTitle) });
        }
      } catch (titleErr) {
        console.error('[纳棂] 标题生成失败:', titleErr);
      }
    }

    // 增加每日计数
    const newCount = currentCount + 1;
    await db.collection('users').doc(userId).update({
      dailyChatCount: newCount,
      chatResetDate: todayBeijing
    });

    return response(200, { ok: true, reply: finalReply, remaining: DAILY_CHAT_LIMIT - newCount });
  } catch (e) {
    console.error('AI对话失败:', e);
    return response(500, { ok: false, error: 'AI暂时无法回复，请稍后再试' });
  }
}

async function handleChatLimit(auth) {
  if (!auth) return response(401, { ok: false, error: '请先登录' });
  const user = await db.collection('users').where({ email: auth.email }).get();
  if (user.data.length === 0) return response(200, { ok: true, remaining: DAILY_CHAT_LIMIT });

  const todayBeijing = new Date().toLocaleDateString('zh-CN', { timeZone: 'Asia/Shanghai' });
  if (user.data[0].chatResetDate !== todayBeijing) {
    return response(200, { ok: true, remaining: DAILY_CHAT_LIMIT });
  }
  const used = user.data[0].dailyChatCount || 0;
  return response(200, { ok: true, remaining: Math.max(0, DAILY_CHAT_LIMIT - used), total: DAILY_CHAT_LIMIT });
}

// ============ 评论相关 ============
async function handleGetComments(query, auth) {
  const page = parseInt(query.page) || 1;
  const pageSize = Math.min(parseInt(query.pageSize) || 20, 50);
  const skip = (page - 1) * pageSize;

  const result = await db.collection('comments')
    .where({ approved: true, isDeleted: _.neq(true) }).orderBy('createdAt', 'desc').skip(skip).limit(pageSize).get();
  const total = await db.collection('comments').where({ approved: true, isDeleted: _.neq(true) }).count();

  const emails = [...new Set(result.data.map(c => c.email))];
  const usersMap = {};
  for (const email of emails) {
    const u = await db.collection('users').where({ email }).get();
    if (u.data.length > 0) {
      usersMap[email] = { nickname: u.data[0].nickname || '', avatar: u.data[0].avatar || '' };
    }
  }

  const commentIds = result.data.map(c => c._id);
  const likeCounts = {};
  for (const cid of commentIds) {
    const lc = await db.collection('likes').where({ commentId: cid }).count();
    likeCounts[cid] = lc.total;
  }

  const likedSet = new Set();
  if (auth && commentIds.length > 0) {
    const myLikes = await db.collection('likes')
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
    total: total.total, page, pageSize,
    isAdmin: isAdminEmail(auth && auth.email)
  });
}

async function handleAddComment(body, auth) {
  if (!auth) return response(401, { ok: false, error: '请先登录' });
  const content = (body.content || '').trim();
  if (!content) return response(400, { ok: false, error: '内容不能为空' });
  if (content.length > 1000) return response(400, { ok: false, error: '内容过长' });

  // 频率限制：冷却 30 秒 + 每日上限 30 条
  const lastComment = await db.collection('comments')
    .where({ email: auth.email }).orderBy('createdAt', 'desc').limit(1).get();
  if (lastComment.data.length > 0 && (Date.now() - lastComment.data[0].createdAt) < COMMENT_COOLDOWN_MS) {
    const remain = Math.ceil((COMMENT_COOLDOWN_MS - (Date.now() - lastComment.data[0].createdAt)) / 1000);
    return response(429, { ok: false, error: `发言太快了，请${remain}秒后再试` });
  }

  const todayStart = new Date(); todayStart.setHours(0, 0, 0, 0);
  const todayCnt = await db.collection('comments')
    .where({ email: auth.email, createdAt: _.gte(todayStart.getTime()) }).count();
  if (todayCnt.total >= COMMENT_DAILY_MAX) {
    return response(429, { ok: false, error: `今日评论已达上限（${COMMENT_DAILY_MAX}条），请明天再来` });
  }

  const user = await db.collection('users').where({ email: auth.email }).get();
  if (user.data.length === 0) return response(404, { ok: false, error: '账号不存在' });

  const u = user.data[0];
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

  const result = await db.collection('comments').add({
    email: auth.email, content, approved: true, createdAt: Date.now()
  });
  return response(200, { ok: true, id: result.id });
}

async function handleDeleteComment(body, auth) {
  if (!auth) return response(401, { ok: false, error: '请先登录' });
  const commentId = (body.commentId || '').trim();
  if (!commentId) return response(400, { ok: false, error: '缺少commentId' });

  const comment = await db.collection('comments').doc(commentId).get();
  if (!comment.data || comment.data.length === 0) {
    return response(404, { ok: false, error: '帖子不存在' });
  }
  const c = Array.isArray(comment.data) ? comment.data[0] : comment.data;
  if (c.email !== auth.email && !isAdminEmail(auth.email)) {
    return response(403, { ok: false, error: '只能删除自己的帖子' });
  }

  await db.collection('comments').doc(commentId).update({ isDeleted: true, deletedAt: Date.now() });
  return response(200, { ok: true, message: '帖子已删除' });
}

async function handleLikeComment(body, auth) {
  if (!auth) return response(401, { ok: false, error: '请先登录' });
  const commentId = (body.commentId || '').trim();
  if (!commentId) return response(400, { ok: false, error: '缺少commentId' });

  // 频率限制：冷却 3 秒，防止快速点击刷数据库
  const lastLike = await db.collection('likes')
    .where({ email: auth.email }).orderBy('createdAt', 'desc').limit(1).get();
  if (lastLike.data.length > 0 && (Date.now() - lastLike.data[0].createdAt) < LIKE_COOLDOWN_MS) {
    return response(429, { ok: false, error: '操作太快了，请稍后再试' });
  }

  const comment = await db.collection('comments').doc(commentId).get();
  if (!comment.data || comment.data.length === 0) return response(404, { ok: false, error: '帖子不存在' });

  const existing = await db.collection('likes')
    .where({ commentId, email: auth.email }).get();

  if (existing.data.length > 0) {
    await db.collection('likes').doc(existing.data[0]._id).remove();
    const count = await db.collection('likes').where({ commentId }).count();
    return response(200, { ok: true, liked: false, likeCount: count.total });
  } else {
    await db.collection('likes').add({ commentId, email: auth.email, createdAt: Date.now() });
    const count = await db.collection('likes').where({ commentId }).count();
    return response(200, { ok: true, liked: true, likeCount: count.total });
  }
}

async function handleGetMyComments(query, auth) {
  if (!auth) return response(401, { ok: false, error: '请先登录' });
  const page = parseInt(query.page) || 1;
  const pageSize = Math.min(parseInt(query.pageSize) || 50, 100);
  const skip = (page - 1) * pageSize;

  const result = await db.collection('comments')
    .where({ email: auth.email, isDeleted: _.neq(true) })
    .orderBy('createdAt', 'desc')
    .skip(skip).limit(pageSize).get();
  const total = await db.collection('comments')
    .where({ email: auth.email, isDeleted: _.neq(true) }).count();

  const commentIds = result.data.map(c => c._id);
  const likeCounts = {};
  for (const cid of commentIds) {
    const lc = await db.collection('likes').where({ commentId: cid }).count();
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

// ============ 个人资料 ============
async function handleGetProfile(auth) {
  if (!auth) return response(401, { ok: false, error: '请先登录' });
  const user = await db.collection('users').where({ email: auth.email }).get();
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
      banMessage: isBanned ? getBanMessage(u.bannedUntil) : null,
      isAdmin: isAdminEmail(auth.email)
    }
  });
}

async function handleUpdateProfile(body, auth) {
  if (!auth) return response(401, { ok: false, error: '请先登录' });
  const user = await db.collection('users').where({ email: auth.email }).get();
  if (user.data.length === 0) return response(404, { ok: false, error: '账号不存在' });

  if (user.data[0].bannedUntil && user.data[0].bannedUntil > Date.now()) {
    const banMsg = getBanMessage(user.data[0].bannedUntil);
    return response(403, { ok: false, error: banMsg });
  }

  const update = {};

  if (body.nickname !== undefined) {
    const nick = String(body.nickname).trim();
    if (nick.length > 20) return response(400, { ok: false, error: '昵称不能超过20个字符' });
    if (nick.length < 1) return response(400, { ok: false, error: '昵称不能为空' });
    // 审核昵称
    const nickMod = await aiModerate(nick);
    if (nickMod.blocked) return response(403, { ok: false, blocked: true, ...nickMod, error: '昵称包含违规内容' });
    update.nickname = nick;
  }

  if (body.avatar !== undefined) {
    const avatar = String(body.avatar).trim();
    if (avatar.length > 500000) return response(400, { ok: false, error: '头像数据过大' });

    // 头像修改频率限制：每天只能改一次
    if (user.data[0].lastAvatarChangeAt) {
      const elapsed = Date.now() - user.data[0].lastAvatarChangeAt;
      if (elapsed < AVATAR_CHANGE_COOLDOWN_MS) {
        const remainingHours = Math.ceil((AVATAR_CHANGE_COOLDOWN_MS - elapsed) / 3600000);
        return response(429, { ok: false, error: `头像每天只能修改一次，请${remainingHours}小时后再试` });
      }
    }

    // 腾讯云 IMS 图片内容安全审核头像
    if (avatar.startsWith('data:image')) {
      const imgMod = await aiModerateImage(avatar);
      if (imgMod.blocked) {
        await addViolation(auth.email, imgMod);
        return response(403, { ok: false, blocked: true, ...imgMod, error: '头像包含违规内容（' + (imgMod.category || '违规') + '）' });
      }
    }

    update.avatar = avatar;
    update.lastAvatarChangeAt = Date.now();
  }

  if (Object.keys(update).length === 0) return response(400, { ok: false, error: '没有需要更新的字段' });
  await db.collection('users').doc(user.data[0]._id).update(update);

  return response(200, { ok: true, message: '资料已更新' });
}

async function handleDeleteAccount(auth) {
  if (!auth) return response(401, { ok: false, error: '请先登录' });
  const user = await db.collection('users').where({ email: auth.email }).get();
  if (user.data.length === 0) return response(404, { ok: false, error: '账号不存在' });
  if (user.data[0].bannedUntil && user.data[0].bannedUntil > Date.now()) {
    const banMsg = getBanMessage(user.data[0].bannedUntil);
    return response(403, { ok: false, error: banMsg + '，无法注销账号' });
  }
  await db.collection('users').doc(user.data[0]._id).update({ isDeleted: true, deletedAt: Date.now() });
  return response(200, { ok: true, message: '账号已注销' });
}

// ============ 人设管理接口（登录用户均可在前端修改人设） ============
async function handleGetCharacter(auth) {
  if (!auth) return response(401, { ok: false, error: '请先登录' });
  const prompt = await getCharacterPrompt();
  return response(200, { ok: true, characterPrompt: prompt });
}

async function handleUpdateCharacter(body, auth) {
  if (!auth) return response(401, { ok: false, error: '请先登录' });
  // 人人平等：任何登录用户均可修改纳棂人设，不单独限制管理员。
  const prompt = (body.characterPrompt || '').trim();
  if (!prompt) return response(400, { ok: false, error: '人设提示词不能为空' });
  if (prompt.length > 5000) return response(400, { ok: false, error: '人设提示词过长' });

  // 更新数据库
  const existing = await db.collection('config').where({ key: 'character_prompt' }).get();
  if (existing.data.length > 0) {
    await db.collection('config').doc(existing.data[0]._id).update({
      value: prompt,
      updatedAt: Date.now()
    });
  } else {
    await db.collection('config').add({
      key: 'character_prompt',
      value: prompt,
      updatedAt: Date.now()
    });
  }

  return response(200, { ok: true, message: '人设已更新' });
}

// ============ 主入口 ============
exports.main = async (event, context) => {
  console.log('[云函数] 收到请求:', JSON.stringify({
    method: event.httpMethod || event.method,
    path: event.path,
    query: event.queryStringParameters
  }));

  await ensureDbReady().catch(e => console.error('[纳棂] ensureDb 失败:', e));
  ensureConfigSeeded().catch(() => {});

  const method = (event.httpMethod || event.method || 'GET').toUpperCase();
  let path = event.path || '/';
  path = path.replace(/^\/api/, '') || '/';

  if (method === 'OPTIONS') {
    return response(204, '');
  }

  let body = {};
  if (event.body) {
    try {
      body = typeof event.body === 'string' ? JSON.parse(event.body) : event.body;
    } catch (e) {
      body = {};
    }
  }

  const query = event.queryStringParameters || {};

  // 获取客户端 IP（X-Forwarded-For 取第一个，兼容代理层）
  const clientIP = (event.headers?.['x-forwarded-for'] || event.headers?.['x-real-ip'] || '').split(',')[0].trim()
    || (event.requestContext?.identity?.sourceIp || '').trim()
    || '0.0.0.0';

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
          version: '3.0.0',
          node: process.version,
          time: new Date().toISOString()
        });

      case '/db-test':
        try {
          const testCol = await db.collection('comments').where({ approved: true, isDeleted: _.neq(true) }).count();
          const res = await db.listCollections();
          return response(200, { ok: true, count: testCol.total, msg: '数据库连接正常', collections: res.collections.map(c => c.name) });
        } catch (e) {
          return response(500, { ok: false, error: '数据库连接失败: ' + e.message });
        }

      case '/db-init':
        await ensureDb();
        await ensureConfigSeeded();
        return response(200, { ok: true, msg: '数据库集合已初始化，配置已加密存储' });

      case '/send-code':
        if (method !== 'POST') return response(405, { error: 'Method not allowed' });
        return await handleSendCode(body);

      case '/login':
        if (method !== 'POST') return response(405, { error: 'Method not allowed' });
        return await handleLogin(body, clientIP);

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

      case '/character':
        if (method === 'GET') return await handleGetCharacter(auth);
        if (method === 'PUT' || method === 'POST') return await handleUpdateCharacter(body, auth);
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
