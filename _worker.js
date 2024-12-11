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
    setConfigFromEnv(env);

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
function setConfigFromEnv(env) {
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

// 其他函数（如 fetchAndDecryptData, MD5MD5, aes128cbcDecrypt 等）保持不变
