const config = {
  WebToken: 'sub', // 此处修改登录密码token
  FileName: 'Colab',
  MainData: '',
  urls: [],
  subconverter: "SUBAPI.fxxk.dedyn.io",
  subconfig: "https://raw.githubusercontent.com/cmliu/ACL4SSR/main/Clash/config/ACL4SSR_Online_MultiCountry.ini",
  subProtocol: 'https',
};

export default {
  async fetch(request, env) {
    // 获取用户代理信息并转换为小写
    const userAgent = request.headers.get('User-Agent')?.toLowerCase() || "null";
    const url = new URL(request.url);
    const token = url.searchParams.get('token');

    // 使用环境变量覆盖默认配置
    config.WebToken = env.TOKEN || config.WebToken;
    config.subconverter = env.SUBAPI || config.subconverter;
    config.subconfig = env.SUBCONFIG || config.subconfig;
    config.FileName = env.SUBNAME || config.FileName;
    config.MainData = env.LINK || config.MainData;
    
    // 如果存在LINKSUB环境变量，添加链接到urls数组
    if (env.LINKSUB) config.urls = await addLinks(env.LINKSUB);

    // 获取并解密数据
    await fetchAndDecryptData();

    // 计算当天日期的零点时间戳
    const currentDate = new Date();
    currentDate.setHours(0, 0, 0, 0);
    const fakeToken = await MD5MD5(`${config.WebToken}${Math.ceil(currentDate.getTime() / 1000)}`);

    // 合并所有链接
    let allLinks = await addLinks(config.MainData + '\n' + config.urls.join('\n'));
    let selfHostedNodes = "", subscriptionLinks = "";
    allLinks.forEach(x => x.toLowerCase().startsWith('http') ? subscriptionLinks += x + '\n' : selfHostedNodes += x + '\n');
    config.MainData = selfHostedNodes;
    config.urls = await addLinks(subscriptionLinks);

    // 验证token
    if (![config.WebToken, fakeToken].includes(token) && !url.pathname.includes("/" + config.WebToken)) {
      return new Response(await forbiddenPage(), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
    }

    // 确定订阅格式
    const subscriptionFormat = determineSubscriptionFormat(userAgent, url);
    let subscriptionConversionUrl = `${url.origin}/${await MD5MD5(fakeToken)}?token=${fakeToken}`;
    
    // 性能优化：将getSubscription的调用移到这里，避免重复调用
    const [subscriptionContent, unconvertedLinks] = await getSubscription(config.urls, "v2rayn", request.headers.get('User-Agent'));
    let req_data = config.MainData + subscriptionContent.join('\n');
    subscriptionConversionUrl += `|${unconvertedLinks.join("|")}`;

    // 如果存在WARP环境变量，添加WARP链接
    if (env.WARP) subscriptionConversionUrl += `|${(await addLinks(env.WARP)).join("|")}`;

    // 将数据转换为base64编码
    const base64Data = btoa(unescape(encodeURIComponent(req_data)));

    // 根据订阅格式返回相应的内容
    if (subscriptionFormat === 'base64' || token === fakeToken) {
      return new Response(base64Data, { headers: { "content-type": "text/plain; charset=utf-8" } });
    }

    try {
      // 使用subconverter进行订阅格式转换
      const subconverterResponse = await fetch(buildSubconverterUrl(subscriptionFormat, subscriptionConversionUrl));
      if (!subconverterResponse.ok) throw new Error();
      let subconverterContent = await subconverterResponse.text();
      if (subscriptionFormat === 'clash') subconverterContent = await clashFix(subconverterContent);
      return new Response(subconverterContent, {
        headers: {
          "Content-Disposition": `attachment; filename*=utf-8''${encodeURIComponent(config.FileName)}; filename=${config.FileName}`,
          "content-type": "text/plain; charset=utf-8",
        },
      });
    } catch {
      // 如果转换失败，返回base64编码数据
      return new Response(base64Data, { headers: { "content-type": "text/plain; charset=utf-8" } });
    }
  }
};

/**
 * 从API获取加密数据并解密
 * @returns {Promise<void>}
 */
async function fetchAndDecryptData() {
  const apiUrl = 'http://api.skrapp.net/api/serverlist';
  const headers = { 
    'accept': '/', 
    'appversion': '1.3.1', 
    'user-agent': 'SkrKK/1.3.1', 
    'content-type': 'application/x-www-form-urlencoded' 
  };
  const key = new TextEncoder().encode('65151f8d966bf596');
  const iv = new TextEncoder().encode('88ca0f0ea1ecf975');

  try {
    const encryptedData = await (await fetch(apiUrl, { headers })).text();
    const decryptedData = await aes128cbcDecrypt(encryptedData, key, iv);
    const data = JSON.parse(decryptedData.match(/({.*})/)[0]).data;
    config.MainData = data.map(o => `ss://${btoa(`aes-256-cfb:${o.password}`)}@${o.ip}:${o.port}#${encodeURIComponent(o.title || '未命名')}`).join('\n');
  } catch (error) {
    throw new Error('Error fetching or decrypting data: ' + error.message);
  }
}

/**
 * 确定订阅格式
 * @param {string} userAgent - 用户代理字符串
 * @param {URL} url - URL对象
 * @returns {string} - 订阅格式
 */
function determineSubscriptionFormat(userAgent, url) {
  if (userAgent.includes('null') || userAgent.includes('subconverter')) return 'base64';
  if (userAgent.includes('clash') || url.searchParams.has('clash')) return 'clash';
  if (userAgent.includes('sing-box') || url.searchParams.has('sb') || url.searchParams.has('singbox')) return 'singbox';
  if (userAgent.includes('surge') || url.searchParams.has('surge')) return 'surge';
  return 'base64';
}

/**
 * 构建subconverter的URL
 * @param {string} subscriptionFormat - 订阅格式
 * @param {string} subscriptionConversionUrl - 订阅转换URL
 * @returns {string} - 构建后的URL
 */
function buildSubconverterUrl(subscriptionFormat, subscriptionConversionUrl) {
  return `${config.subProtocol}://${config.subconverter}/sub?target=${subscriptionFormat}&url=${encodeURIComponent(subscriptionConversionUrl)}&config=${encodeURIComponent(config.subconfig)}`;
}

/**
 * 添加链接到数组中，过滤空行
 * @param {string} data - 包含链接的字符串
 * @returns {Promise<Array>} - 过滤后的链接数组
 */
async function addLinks(data) {
  return data.split("\n").map(line => line.trim()).filter(e => e !== "");
}

/**
 * 获取订阅内容
 * @param {Array} urls - 订阅链接数组
 * @param {string} UA - 用户代理字符串
 * @param {string} userAgentHeader - 请求头中的用户代理
 * @returns {Promise<Array>} - 包含订阅内容和未转换链接的数组
 */
async function getSubscription(urls, UA, userAgentHeader) {
  const headers = { "User-Agent": userAgentHeader || UA };
  let subscriptionContent = [], unconvertedLinks = [];
  for (const url of urls) {
    try {
      const response = await fetch(url, { headers });
      if (response.status === 200) {
        subscriptionContent.push((await response.text()).split("\n").map(line => line.trim()).filter(line => line));
      } else {
        unconvertedLinks.push(url);
      }
    } catch {
      unconvertedLinks.push(url);
    }
  }
  return [subscriptionContent.flat(), unconvertedLinks];
}

/**
 * 修复Clash配置文件中的格式问题
 * @param {string} content - 原始Clash配置内容
 * @returns {Promise<string>} - 修复后的Clash配置内容
 */
async function clashFix(content) {
  return content.split("\n").reduce((acc, line) => {
    if (line.startsWith("  - name: ")) acc += `  - name: ${line.split("name: ")[1]}\n`;
    else acc += line + "\n";
    return acc;
  }, '');
}

/**
 * 返回403 Forbidden页面
 * @returns {Promise<string>} - HTML内容
 */
async function forbiddenPage() {
  return `<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1><p>Access Denied</p></body></html>`;
}

/**
 * 计算字符串的MD5哈希值
 * @param {string} value - 需要计算哈希的字符串
 * @returns {Promise<string>} - MD5哈希值
 */
async function MD5MD5(value) {
  const encoded = new TextEncoder().encode(value);
  const buffer = await crypto.subtle.digest("MD5", await crypto.subtle.digest("MD5", encoded));
  return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, "0")).join("");
}

/**
 * 使用AES-128-CBC解密数据
 * @param {string} encryptedText - 加密后的文本
 * @param {Uint8Array} key - 解密密钥
 * @param {Uint8Array} iv - 初始化向量
 * @returns {Promise<string>} - 解密后的文本
 */
async function aes128cbcDecrypt(encryptedText, key, iv) {
  const encryptedBuffer = hexStringToUint8Array(encryptedText);
  const algorithm = { name: 'AES-CBC', iv };
  const keyObj = await crypto.subtle.importKey('raw', key, algorithm, false, ['decrypt']);
  try {
    const decryptedBuffer = await crypto.subtle.decrypt(algorithm, keyObj, encryptedBuffer);
    return new TextDecoder().decode(decryptedBuffer).replace(/\0+$/, '');
  } catch {
    throw new Error('Decryption failed');
  }
}

/**
 * 将十六进制字符串转换为Uint8Array
 * @param {string} hexString - 十六进制字符串
 * @returns {Uint8Array} - 转换后的Uint8Array
 */
function hexStringToUint8Array(hexString) {
  return new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}
