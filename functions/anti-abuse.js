/**
 * 防恶意爬虫/API滥用保护模块
 * 适用于 Cloudflare Workers / Pages Functions
 * 
 * 保护策略：
 *   1. Origin/Referer 白名单校验 — 拒绝跨站调用
 *   2. 请求体大小限制    — 防止恶意超大请求消耗token
 *   3. IP速率限制        — 同实例内60秒窗口限流
 *   4. User-Agent基础检查 — 拒绝空UA和已知爬虫
 */

// ===================== 配置 =====================
const CONFIG = {
  // 请求体最大字节数 (默认5KB，简历润色场景最高15KB)
  MAX_BODY_SIZE: 15000,
  // 速率限制：60秒窗口内最大请求数
  RATE_WINDOW_SEC: 60,
  RATE_MAX_REQUESTS: 15,
  // 清理过期IP记录的间隔(秒)
  CLEANUP_INTERVAL: 300,
};

// IP速率计数器（同Worker实例内共享）
const ipCounters = new Map();
let lastCleanup = Date.now();

// ===================== Origin 白名单 =====================
// 安全接受以下来源的请求
const ORIGIN_WHITELIST = [
  // 本地开发
  'http://localhost:8501',
  'http://localhost:8787',
  'http://localhost:8788',
  'http://127.0.0.1:8501',
  'http://127.0.0.1:8787',
  'http://127.0.0.1:8788',
  // Cloudflare Pages 默认域名（部署后自动匹配）
  // 格式: https://*.pages.dev
  // 具体域名在 checkOrigin 中动态匹配
];

// 已知爬虫/恶意 UA 特征（锚定开头避免误杀）
const BOT_UA_PATTERNS = [
  /^$/,
  /^curl\//i,
  /^Wget\//i,
  /^python-requests\//i,
  /^python-urllib\//i,
  /^Go-http-client\//i,
  /^libwww-perl\//i,
  /^scrapy/i,
  /^okhttp\//i,
  /^aiohttp\//i,
  /^axios\//i,
  /^node-fetch/i,
];

// ===================== 辅助函数 =====================

/** 检查 Origin/Referer */
function checkOrigin(request, customWhitelist = []) {
  const origin = request.headers.get('Origin');
  const referer = request.headers.get('Referer');
  const allAllowed = [...ORIGIN_WHITELIST, ...customWhitelist];

  // 如果没有 Origin 和 Referer：大概率是同源请求或嵌入式浏览器
  // 不做拦截，让UA检查兜底
  if (!origin && !referer) {
    return { ok: true };
  }

  const sourceUrl = origin || referer || '';

  for (const allowed of allAllowed) {
    if (allowed.includes('*')) {
      // 通配符匹配
      const regex = new RegExp('^' + allowed.replace(/\*/g, '.*') + '$');
      if (regex.test(sourceUrl)) {
        return { ok: true };
      }
    } else if (sourceUrl.startsWith(allowed)) {
      return { ok: true };
    }
  }

  // 特殊处理: Cloudflare Pages 默认域名 *.pages.dev
  if (/^https?:\/\/[a-zA-Z0-9-]+\.pages\.dev/.test(sourceUrl)) {
    return { ok: true };
  }

  // 特殊处理: 允许无Origin的same-site请求
  const fetchSite = request.headers.get('Sec-Fetch-Site');
  if (!origin && !referer && (fetchSite === 'same-origin')) {
    return { ok: true };
  }

  return { ok: false, reason: 'origin_blocked', code: 403, source: sourceUrl };
}

/** 检查 User-Agent */
function checkUserAgent(request) {
  const ua = request.headers.get('User-Agent') || '';

  for (const pattern of BOT_UA_PATTERNS) {
    if (pattern.test(ua)) {
      return { ok: false, reason: 'bot_ua', code: 403, ua };
    }
  }

  return { ok: true };
}

/** 检查请求体大小 */
async function checkBodySize(request, maxSize = CONFIG.MAX_BODY_SIZE) {
  const contentLength = parseInt(request.headers.get('Content-Length') || '0', 10);
  if (contentLength > maxSize) {
    return { ok: false, reason: 'body_too_large', code: 413, maxSize, actualSize: contentLength };
  }
  return { ok: true };
}

/** IP速率限制（基于CF-Connecting-IP） */
function checkRateLimit(request) {
  const ip = request.headers.get('CF-Connecting-IP') || 
             request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() || 
             request.headers.get('X-Real-IP') || 
             'unknown';

  const now = Date.now();
  const windowMs = CONFIG.RATE_WINDOW_SEC * 1000;

  // 定期清理过期记录
  if (now - lastCleanup > CONFIG.CLEANUP_INTERVAL * 1000) {
    for (const [key, entry] of ipCounters) {
      if (now - entry.resetTime > windowMs * 2) {
        ipCounters.delete(key);
      }
    }
    lastCleanup = now;
  }

  let entry = ipCounters.get(ip);

  if (!entry || now - entry.resetTime > windowMs) {
    // 新窗口
    entry = { count: 1, resetTime: now + windowMs };
    ipCounters.set(ip, entry);
    return { 
      ok: true, 
      remaining: CONFIG.RATE_MAX_REQUESTS - 1,
      limit: CONFIG.RATE_MAX_REQUESTS,
      reset: Math.ceil(entry.resetTime / 1000)
    };
  }

  entry.count++;

  if (entry.count > CONFIG.RATE_MAX_REQUESTS) {
    return {
      ok: false,
      reason: 'rate_limited',
      code: 429,
      retryAfter: Math.ceil((entry.resetTime - now) / 1000),
      limit: CONFIG.RATE_MAX_REQUESTS
    };
  }

  return {
    ok: true,
    remaining: CONFIG.RATE_MAX_REQUESTS - entry.count,
    limit: CONFIG.RATE_MAX_REQUESTS,
    reset: Math.ceil(entry.resetTime / 1000)
  };
}

// ===================== 主入口 =====================

/**
 * 防爬保护主检查函数
 * @param {Request} request - 请求对象
 * @param {object} options - 可选配置
 * @param {string[]} options.allowedOrigins - 额外允许的 Origin
 * @param {number} options.maxBodySize - 请求体最大字节
 * @param {boolean} options.skipOriginCheck - 跳过Origin检查（用于公开API）
 * @returns {Promise<{blocked: boolean, response?: Response, headers?: object}>}
 */
export async function checkAbuse(request, options = {}) {
  const {
    allowedOrigins = [],
    maxBodySize = CONFIG.MAX_BODY_SIZE,
    skipOriginCheck = false,
  } = options;

  // 1. User-Agent 检查
  const uaCheck = checkUserAgent(request);
  if (!uaCheck.ok) {
    return {
      blocked: true,
      response: new Response(JSON.stringify({
        error: 'Access denied',
        reason: uaCheck.reason,
        message: '检测到可疑请求，如误判请联系站长'
      }), {
        status: uaCheck.code,
        headers: { 'Content-Type': 'application/json' }
      })
    };
  }

  // 2. Origin 检查（除非显式跳过）
  if (!skipOriginCheck) {
    const originCheck = checkOrigin(request, allowedOrigins);
    if (!originCheck.ok) {
      return {
        blocked: true,
        response: new Response(JSON.stringify({
          error: 'Access denied',
          reason: originCheck.reason,
          message: '不允许跨站调用本API，请从官方页面使用'
        }), {
          status: originCheck.code,
          headers: { 'Content-Type': 'application/json' }
        })
      };
    }
  }

  // 3. 请求体大小检查
  const bodyCheck = await checkBodySize(request, maxBodySize);
  if (!bodyCheck.ok) {
    return {
      blocked: true,
      response: new Response(JSON.stringify({
        error: 'Payload too large',
        maxSize: bodyCheck.maxSize,
        actualSize: bodyCheck.actualSize
      }), {
        status: bodyCheck.code,
        headers: { 'Content-Type': 'application/json' }
      })
    };
  }

  // 4. IP速率限制
  const rateCheck = checkRateLimit(request);
  if (!rateCheck.ok) {
    return {
      blocked: true,
      response: new Response(JSON.stringify({
        error: 'Too many requests',
        message: `请求太频繁，请${rateCheck.retryAfter}秒后重试`,
        retryAfter: rateCheck.retryAfter
      }), {
        status: rateCheck.code,
        headers: {
          'Content-Type': 'application/json',
          'Retry-After': String(rateCheck.retryAfter),
        }
      })
    };
  }

  // 通过所有检查，返回速率限制头
  return {
    blocked: false,
    headers: {
      'X-RateLimit-Limit': String(rateCheck.limit),
      'X-RateLimit-Remaining': String(rateCheck.remaining),
      'X-RateLimit-Reset': String(rateCheck.reset),
    }
  };
}

/**
 * 获取标准 CORS 响应头
 * @param {string[]} allowedOrigins - 允许的来源
 */
export function corsHeaders(allowedOrigins = ['*']) {
  return {
    'Access-Control-Allow-Origin': allowedOrigins.join(', ') || '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
}

/**
 * 处理 OPTIONS 预检请求
 */
export function handleOptions(allowedOrigins = ['*']) {
  return new Response(null, {
    status: 204,
    headers: corsHeaders(allowedOrigins),
  });
}

/**
 * 创建错误响应
 */
export function errorResponse(message, status = 400, extraHeaders = {}) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      ...extraHeaders,
    }
  });
}
