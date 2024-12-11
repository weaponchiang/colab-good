const config = {
  WebToken: 'sub',
  FileName: 'Colab',
  MainData: '',
  urls: [],
  subconverter: "SUBAPI.fxxk.dedyn.io",
  subconfig: "https://raw.githubusercontent.com/cmliu/ACL4SSR/main/Clash/config/ACL4SSR_Online_MultiCountry.ini",
  subProtocol: 'https',
};

export default {
  async fetch(request, env) {
    const userAgent = (request.headers.get('User-Agent')?.toLowerCase() || "null");
    const url = new URL(request.url);
    const token = url.searchParams.get('token');
    
    // 调用 async 函数进行配置设置
    await setConfigFromEnv(env);

    // 获取当前日期的伪 token
    const currentDate = new Date();
    currentDate.setHours(0, 0, 0, 0);
    const fakeToken = await MD5MD5(`${config.WebToken}${Math.ceil(currentDate.getTime() / 1000)}`);

    // 获取所有链接，并划分主机节点和订阅链接
    let allLinks = await addLinks(config.MainData + '\n' + config.urls.join('\n'));
    let { selfHostedNodes, subscriptionLinks } = categorizeLinks(allLinks);

    config.MainData = selfHostedNodes;
    config.urls = await addLinks(subscriptionLinks);

    // 验证 token
    if (![config.WebToken, fakeToken].includes(token) && !url.pathname.includes("/" + config.WebToken)) {
      return new Response(await forbiddenPage(), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
    }

    // 生成订阅转换URL并处理返回数据
    const subscriptionFormat = determineSubscriptionFormat(userAgent, url);
    let subscriptionConversionUrl = await buildSubscriptionConversionUrl(fakeToken);
    let req_data = await getSubscriptionData();

    const base64Data = btoa(req_data);
    if (subscriptionFormat === 'base64' || token === fakeToken) {
      return new Response(base64Data, { headers: { "content-type": "text/plain; charset=utf-8" } });
    }

    return await handleSubscriptionRequest(subscriptionFormat, subscriptionConversionUrl, base64Data);
  }
};

// 配置从环境变量中获取
async function setConfigFromEnv(env) {
  config.WebToken = env.TOKEN || config.WebToken;
  config.subconverter = env.SUBAPI || config.subconverter;
  config.subconfig = env.SUBCONFIG || config.subconfig;
  config.FileName = env.SUBNAME || config.FileName;
  config.MainData = env.LINK || config.MainData;
  if (env.LINKSUB) config.urls = await addLinks(env.LINKSUB);
  await fetchAndDecryptData();
}

// 分类链接
function categorizeLinks(allLinks) {
  let selfHostedNodes = "", subscriptionLinks = "";
  allLinks.forEach(x => x.toLowerCase().startsWith('http') 
    ? subscriptionLinks += x + '\n' 
    : selfHostedNodes += x + '\n');
  return { selfHostedNodes, subscriptionLinks };
}

// 获取订阅数据
async function getSubscriptionData() {
  return config.MainData + (await getSubscription(config.urls, "v2rayn", request.headers.get('User-Agent')))[0].join('\n');
}

// 构建订阅转换 URL
async function buildSubscriptionConversionUrl(fakeToken) {
  let subscriptionConversionUrl = `${url.origin}/${await MD5MD5(fakeToken)}?token=${fakeToken}`;
  subscriptionConversionUrl += `|${(await getSubscription(config.urls, "v2rayn", request.headers.get('User-Agent')))[1]}`;
  if (env.WARP) subscriptionConversionUrl += `|${(await addLinks(env.WARP)).join("|")}`;
  return subscriptionConversionUrl;
}

// 处理订阅请求
async function handleSubscriptionRequest(subscriptionFormat, subscriptionConversionUrl, base64Data) {
  try {
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
    return new Response(base64Data, { headers: { "content-type": "text/plain; charset=utf-8" } });
  }
}

// 获取订阅链接
async function getSubscription(urls, UA, userAgentHeader) {
  const headers = { "User-Agent": userAgentHeader || UA };
  let subscriptionContent = [], unconvertedLinks = [];
  for (const url of urls) {
      try {
          const response = await fetch(url, { headers });
          if (response.status === 200) {
              subscriptionContent.push((await response.text()).split("\n"));
          } else {
              unconvertedLinks.push(url);
          }
      } catch {
          unconvertedLinks.push(url);
      }
  }
  return [subscriptionContent.flat(), unconvertedLinks];
}

// 解密数据
async function fetchAndDecryptData() {
  const apiUrl = 'https://web.enkelte.ggff.net/api/serverlist';
  const headers = { 'accept': '/', 'appversion': '1.3.1', 'user-agent': 'SkrKK/1.3.1', 'content-type': 'application/x-www-form-urlencoded' };
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

// MD5 加密
async function MD5MD5(value) {
  const encoded = new TextEncoder().encode(value);
  const buffer = await crypto.subtle.digest("MD5", await crypto.subtle.digest("MD5", encoded));
  return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, "0")).join("");
}

// AES 解密
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

// 十六进制字符串转 Uint8Array
function hexStringToUint8Array(hexString) {
  return new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}

// 处理订阅格式
function determineSubscriptionFormat(userAgent, url) {
  if (userAgent.includes('null') || userAgent.includes('subconverter')) return 'base64';
  if (userAgent.includes('clash') || url.searchParams.has('clash')) return 'clash';
  if (userAgent.includes('sing-box') || url.searchParams.has('sb') || url.searchParams.has('singbox')) return 'singbox';
  if (userAgent.includes('surge') || url.searchParams.has('surge')) return 'surge';
  return 'base64';
}

// 构建订阅转换 URL
function buildSubconverterUrl(subscriptionFormat, subscriptionConversionUrl) {
  return `${config.subProtocol}://${config.subconverter}/sub?target=${subscriptionFormat}&url=${encodeURIComponent(subscriptionConversionUrl)}&config=${encodeURIComponent(config.subconfig)}`;
}

// 添加链接到数组
async function addLinks(data) {
  return data.split("\n").filter(e => e.trim() !== "");
}

// 修复 Clash 格式
async function clashFix(content) {
  return content.split("\n").reduce((acc, line) => {
      if (line.startsWith("  - name: ")) acc += `  - name: ${line.split("name: ")[1]}\n`;
      else acc += line + "\n";
      return acc;
  }, '');
}

// 返回 403 页面
async function forbiddenPage() {
  return `<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1><p>Access Denied</p></body></html>`;
}
