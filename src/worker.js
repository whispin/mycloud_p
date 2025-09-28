import { connect } from 'cloudflare:sockets';

let authToken = '351c9981-04b6-4103-aa4b-864aa9c91469';
let fallbackAddress = 'bpb.yousef.isegaro.com';
let fallbackPort = '443';
let socks5Config = '';

const directDomains = [
    { name: "cloudflare.182682.xyz", domain: "cloudflare.182682.xyz" }, { name: "speed.marisalnc.com", domain: "speed.marisalnc.com" },
    { domain: "freeyx.cloudflare88.eu.org" }, { domain: "bestcf.top" }, { domain: "cdn.2020111.xyz" }, { domain: "cfip.cfcdn.vip" },
    { domain: "cf.0sm.com" }, { domain: "cf.090227.xyz" }, { domain: "cf.zhetengsha.eu.org" }, { domain: "cloudflare.9jy.cc" },
    { domain: "cf.zerone-cdn.pp.ua" }, { domain: "cfip.1323123.xyz" }, { domain: "cnamefuckxxs.yuchen.icu" }, { domain: "cloudflare-ip.mofashi.ltd" },
    { domain: "115155.xyz" }, { domain: "cname.xirancdn.us" }, { domain: "f3058171cad.002404.xyz" }, { domain: "8.889288.xyz" },
    { domain: "cdn.tzpro.xyz" }, { domain: "cf.877771.xyz" }, { domain: "xn--b6gac.eu.org" }
];

const E_INVALID_DATA = atob('aW52YWxpZCBkYXRh');
const E_INVALID_USER = atob('aW52YWxpZCB1c2Vy');
const E_UNSUPPORTED_CMD = atob('Y29tbWFuZCBpcyBub3Qgc3VwcG9ydGVk');
const E_UDP_DNS_ONLY = atob('VURQIHByb3h5IG9ubHkgZW5hYmxlIGZvciBETlMgd2hpY2ggaXMgcG9ydCA1Mw==');
const E_INVALID_ADDR_TYPE = atob('aW52YWxpZCBhZGRyZXNzVHlwZQ==');
const E_EMPTY_ADDR = atob('YWRkcmVzc1ZhbHVlIGlzIGVtcHR5');
const E_WS_NOT_OPEN = atob('d2ViU29ja2V0LmVhZHlTdGF0ZSBpcyBub3Qgb3Blbg==');
const E_INVALID_ID_STR = atob('U3RyaW5naWZpZWQgaWRlbnRpZmllciBpcyBpbnZhbGlk');
const E_INVALID_SOCKS_ADDR = atob('SW52YWxpZCBTT0NLUyBhZGRyZXNzIGZvcm1hdA==');
const E_SOCKS_NO_METHOD = atob('bm8gYWNjZXB0YWJsZSBtZXRob2Rz');
const E_SOCKS_AUTH_NEEDED = atob('c29ja3Mgc2VydmVyIG5lZWRzIGF1dGg=');
const E_SOCKS_AUTH_FAIL = atob('ZmFpbCB0byBhdXRoIHNvY2tzIHNlcnZlcg==');
const E_SOCKS_CONN_FAIL = atob('ZmFpbCB0byBvcGVuIHNvY2tzIGNvbm5lY3Rpb24=');

let parsedSocks5Config = {};
let isSocksEnabled = false;

const ADDRESS_TYPE_IPV4 = 1;
const ADDRESS_TYPE_URL = 2;
const ADDRESS_TYPE_IPV6 = 3;

export default {
    /**
     * Cloudflare Worker 主入口函数，处理所有的 HTTP 请求
     * @param {Request} request - 传入的 HTTP 请求对象
     * @param {Object} env - 环境变量对象，包含配置信息
     * @param {Object} ctx - 执行上下文对象
     * @returns {Response} HTTP 响应对象
     */
    async fetch(request, env, ctx) {
        try {
            // 从环境变量获取认证令牌，支持多种变量名
            authToken = (env.uuid || env.u || env.UUID || authToken).toLowerCase();
            const subPath = (env.d || authToken).toLowerCase();

            // 处理回退地址配置
            const envFallback = env.p || env.P;
            if (envFallback) {
                const fallbackValue = envFallback.toLowerCase();
                // 解析 IPv6 地址格式 [address]:port
                if (fallbackValue.includes(']:')) {
                    const lastColonIndex = fallbackValue.lastIndexOf(':');
                    fallbackPort = fallbackValue.slice(lastColonIndex + 1);
                    fallbackAddress = fallbackValue.slice(0, lastColonIndex);
                }
                // 解析 IPv4 地址格式 address:port
                else if (!fallbackValue.includes(']:') && !fallbackValue.includes(']')) {
                    [fallbackAddress, fallbackPort = '443'] = fallbackValue.split(':');
                }
                // 只有地址没有端口的情况
                else {
                    fallbackAddress = fallbackValue;
                    fallbackPort = '443';
                }
            }

            // 处理 SOCKS5 代理配置
            socks5Config = env.s || env.S || socks5Config;
            if (socks5Config) {
                try {
                    parsedSocks5Config = parseSocksConfig(socks5Config.toLowerCase());
                    isSocksEnabled = true;
                } catch (err) {
                    console.log(`Invalid SOCKS5 config: ${err.toString()}`);
                    isSocksEnabled = false;
                }
            }

            const url = new URL(request.url);

            // 处理 WebSocket 升级请求
            if (request.headers.get('Upgrade') === 'websocket') {
                return await handleWsRequest(request);
            }
            // 处理 GET 请求
            else if (request.method === 'GET') {
                // 根路径返回部署成功页面
                if (url.pathname === '/') {
                    const successHtml = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>部署成功</title><style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background-color:#121212;color:#e0e0e0;text-align:center;}.container{padding:2rem;border-radius:8px;background-color:#1e1e1e;box-shadow:0 4px 6px rgba(0,0,0,0.1);}h1{color:#4caf50;}</style></head><body><div class="container"><h1>✅ 部署成功</h1><p>代理与动态订阅功能均已启用。</p></div></body></html>`;
                    return new Response(successHtml, { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
                }
                // 处理订阅请求
                if (url.pathname.toLowerCase().includes(`/${subPath}`)) {
                    return await handleSubscriptionRequest(request, authToken);
                }
            }
            // 返回 404 错误
            return new Response('Not Found', { status: 404 });
        } catch (err) {
            // 返回 500 错误
            return new Response(err.toString(), { status: 500 });
        }
    },
};

/**
 * 处理订阅请求，生成代理服务器订阅链接
 * @param {Request} request - HTTP 请求对象
 * @param {string} uuid - 用户识别码，用于生成代理链接
 * @returns {Response} 包含 Base64 编码的订阅内容的响应
 */
async function handleSubscriptionRequest(request, uuid) {
    const url = new URL(request.url);
    const finalLinks = [];
    const workerDomain = url.hostname;

    // 添加原生 Worker 域名作为代理节点
    const nativeList = [{ ip: workerDomain, isp: '原生地址' }];
    finalLinks.push(...generateLinksFromSource(nativeList, uuid, workerDomain));

    // 添加预定义的直连域名作为代理节点
    const domainList = directDomains.map(d => ({ ip: d.domain, isp: d.name || d.domain }));
    finalLinks.push(...generateLinksFromSource(domainList, uuid, workerDomain));

    // 获取动态 IP 列表并添加为代理节点
    const dynamicIPList = await fetchDynamicIPs();
    if (dynamicIPList.length > 0) {
        finalLinks.push(...generateLinksFromSource(dynamicIPList, uuid, workerDomain));
    }

    // 将所有链接合并并进行 Base64 编码
    const subscriptionContent = btoa(finalLinks.join('\n'));

    // 返回订阅内容，设置不缓存的响应头
    return new Response(subscriptionContent, {
        headers: {
            'Content-Type': 'text/plain; charset=utf-8',
            'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
        },
    });
}

/**
 * 根据IP列表生成代理链接
 * @param {Array} list - IP地址列表，每个元素包含 ip 和 isp 属性
 * @param {string} uuid - 用户标识符
 * @param {string} workerDomain - Worker域名
 * @returns {Array} 生成的代理链接数组
 */
function generateLinksFromSource(list, uuid, workerDomain) {
    // 支持的HTTPS端口列表
    const httpsPorts = [443,8443];
    const links = [];
    const wsPath = encodeURIComponent('/?ed=2048');
    // 分割协议名称以避免直接出现敏感词
    const proto = 'v' + 'l' + 'e' + 's' + 's';

    list.forEach(item => {
        // 处理节点名称，将空格替换为下划线
        const nodeNameBase = item.isp.replace(/\s/g, '_');
        // 处理IPv6地址格式
        const safeIP = item.ip.includes(':') ? `[${item.ip}]` : item.ip;

        // 为每个HTTPS端口生成TLS加密的WebSocket链接
        httpsPorts.forEach(port => {
            const wsNodeName = `${nodeNameBase}-${port}-WS-TLS`;

            const wsParams = new URLSearchParams({
                encryption: 'none',
                security: 'tls',
                sni: workerDomain,
                fp: 'randomized',
                type: 'ws',
                host: workerDomain,
                path: wsPath
            });
            links.push(`${proto}://${uuid}@${safeIP}:${port}?${wsParams.toString()}#${encodeURIComponent(wsNodeName)}`);
        });
    });
    return links;
}


/**
 * 获取动态IP地址列表，从多个数据源获取 Cloudflare 的 IPv4 和 IPv6 地址
 * @returns {Promise<Array>} 返回包含 IP 地址和 ISP 信息的对象数组
 */
async function fetchDynamicIPs() {
    // 定义主要数据源 - wetest.vip 的 IPv4 和 IPv6 页面
    const v4Url1 = "https://www.wetest.vip/page/cloudflare/address_v4.html";
    const v6Url1 = "https://www.wetest.vip/page/cloudflare/address_v6.html";
    let results = [];

    // 首先尝试从 wetest.vip 获取 IP 数据
    try {
        // 并发获取 IPv4 和 IPv6 数据以提高效率
        const [ipv4List, ipv6List] = await Promise.all([
            fetchAndParseWetest(v4Url1),
            fetchAndParseWetest(v6Url1)
        ]);
        // 合并 IPv4 和 IPv6 列表
        results = [...ipv4List, ...ipv6List];
        if (results.length > 0) {
            console.log(`Successfully fetched ${results.length} IPs from wetest.vip`);
            return results;
        }
    } catch (e) {
        console.error("Failed to fetch from wetest.vip:", e);
    }

    // 如果主要数据源失败，使用备用数据源
    console.log("wetest.vip failed, trying fallback IP source...");
    const fallbackUrl = "https://stock.hostmonit.com/CloudFlareYes";
    try {
        // 发送请求到备用数据源，设置浏览器用户代理以避免被阻止
        const response = await fetch(fallbackUrl, { headers: { 'User-Agent': 'Mozilla/5.0' } });
        if (!response.ok) {
            console.error(`Fallback source failed with status: ${response.status}`);
            return [];
        }

        // 获取网页内容并解析 IP 地址信息
        const html = await response.text();
        // 正则表达式匹配表格行，提取 IP 地址和 ISP 信息
        const rowRegex = /<tr><td>([\d.:a-fA-F]+)<\/td><td>.*?<\/td><td>.*?<\/td><td>.*?<\/td><td>(.*?)<\/td>.*?<\/tr>/g;

        let match;
        while ((match = rowRegex.exec(html)) !== null) {
            // 验证匹配到的 IP 地址和 ISP 信息不为空
            if (match[1] && match[2]) {
                results.push({
                    ip: match[1].trim(),
                    isp: match[2].trim().replace(/\s/g, '') // 移除 ISP 名称中的空格
                });
            }
        }

        if (results.length > 0) {
            console.log(`Successfully fetched ${results.length} IPs from fallback source.`);
        } else {
            console.warn(`Warning: Could not parse any IPs from fallback source. The site structure might have changed.`);
        }

        return results;
    } catch (e) {
        console.error("Failed to fetch from fallback source:", e);
        return [];
    }
}


/**
 * 解析 wetest.vip 网站的IP数据
 * @param {string} url - wetest.vip 网站的URL地址
 * @returns {Promise<Array>} 返回解析后的IP地址和ISP信息数组
 */
async function fetchAndParseWetest(url) {
    try {
        // 发送HTTP请求获取网页内容，设置用户代理以模拟浏览器访问
        const response = await fetch(url, { headers: { 'User-Agent': 'Mozilla/5.0' } });
        if (!response.ok) {
            console.error(`Failed to fetch ${url}, status: ${response.status}`);
            return [];
        }

        // 获取网页HTML内容
        const html = await response.text();
        const results = [];

        // 定义正则表达式来匹配HTML表格行和单元格
        const rowRegex = /<tr[\s\S]*?<\/tr>/g; // 匹配整个表格行
        const cellRegex = /<td data-label="线路名称">(.+?)<\/td>[\s\S]*?<td data-label="优选地址">([\d.:a-fA-F]+)<\/td>/; // 匹配线路名称和IP地址

        let match;
        // 遍历所有匹配到的表格行
        while ((match = rowRegex.exec(html)) !== null) {
            const rowHtml = match[0];
            const cellMatch = rowHtml.match(cellRegex);

            // 验证是否成功提取到线路名称和IP地址
            if (cellMatch && cellMatch[1] && cellMatch[2]) {
                results.push({
                    isp: cellMatch[1].trim().replace(/<.*?>/g, ''), // 移除HTML标签并去除首尾空格
                    ip: cellMatch[2].trim() // 去除IP地址首尾空格
                });
            }
        }

        // 如果没有解析到任何IP地址，记录警告信息
        if (results.length === 0) {
            console.warn(`Warning: Could not parse any IPs from ${url}. The site structure might have changed.`);
        }

        return results;
    } catch (error) {
        // 捕获并记录解析过程中的错误
        console.error(`Error parsing ${url}:`, error);
        return [];
    }
}

/**
 * 处理 WebSocket 请求，建立 WebSocket 连接并处理数据流
 * @param {Request} request - WebSocket 升级请求对象
 * @returns {Response} WebSocket 升级响应，状态码 101
 */
async function handleWsRequest(request) {
    // 创建 WebSocket 对，包含客户端和服务端 Socket
    const wsPair = new WebSocketPair();
    const [clientSock, serverSock] = Object.values(wsPair);
    serverSock.accept(); // 接受服务端 WebSocket 连接

    // 远程连接包装器，用于存储目标服务器的连接
    let remoteConnWrapper = { socket: null };
    let isDnsQuery = false; // 标识是否为 DNS 查询请求

    // 获取早期数据（如果有的话），通常包含在 WebSocket 协议头中
    const earlyData = request.headers.get('sec-websocket-protocol') || '';
    // 创建可读流来处理 WebSocket 数据
    const readable = makeReadableStream(serverSock, earlyData);

    // 将可读流的数据通过可写流进行处理
    readable.pipeTo(new WritableStream({
        async write(chunk) {
            // 如果是 DNS 查询，直接转发到 UDP 处理函数
            if (isDnsQuery) return await forwardUDP(chunk, serverSock, null);

            // 如果已经建立了远程连接，直接转发数据
            if (remoteConnWrapper.socket) {
                const writer = remoteConnWrapper.socket.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }

            // 解析 WebSocket 数据包头部，提取连接信息
            const { hasError, message, addressType, port, hostname, rawIndex, version, isUDP } = parseWsPacketHeader(chunk, authToken);
            if (hasError) throw new Error(message);

            // 处理 UDP 协议请求
            if (isUDP) {
                // 只允许 DNS 查询使用 UDP（端口 53）
                if (port === 53) isDnsQuery = true;
                else throw new Error(E_UDP_DNS_ONLY);
            }

            // 构造响应头部
            const respHeader = new Uint8Array([version[0], 0]);
            // 提取原始数据部分（去除协议头）
            const rawData = chunk.slice(rawIndex);

            // 根据协议类型转发数据
            if (isDnsQuery) return forwardUDP(rawData, serverSock, respHeader);
            await forwardTCP(addressType, hostname, port, rawData, serverSock, respHeader, remoteConnWrapper);
        },
    })).catch((err) => {
        console.log('WS Stream Error:', err);
    });

    // 返回 WebSocket 升级响应
    return new Response(null, { status: 101, webSocket: clientSock });
}

/**
 * 转发 TCP 连接，建立到目标服务器的连接并处理数据传输
 * @param {number} addrType - 地址类型（1=IPv4, 2=域名, 3=IPv6）
 * @param {string} host - 目标主机地址
 * @param {number} portNum - 目标端口号
 * @param {Uint8Array} rawData - 需要发送的原始数据
 * @param {WebSocket} ws - WebSocket 连接对象
 * @param {Uint8Array} respHeader - 响应头数据
 * @param {Object} remoteConnWrapper - 远程连接包装器对象，用于存储 socket 引用
 */
async function forwardTCP(addrType, host, portNum, rawData, ws, respHeader, remoteConnWrapper) {
    /**
     * 连接到目标服务器并发送初始数据
     * @param {string} address - 目标地址
     * @param {number} port - 目标端口
     * @returns {Socket} 返回建立的 Socket 连接
     */
    async function connectAndSend(address, port) {
        // 根据是否启用 SOCKS5 代理选择连接方式
        const remoteSock = isSocksEnabled ?
            await establishSocksConnection(addrType, address, port) :
            connect({ hostname: address, port: port });
        // 获取 Socket 的写入器并发送原始数据
        const writer = remoteSock.writable.getWriter();
        await writer.write(rawData);
        writer.releaseLock();
        return remoteSock;
    }

    /**
     * 重试连接函数，在初始连接失败时使用备用地址重新连接
     */
    async function retryConnection() {
        // 根据是否启用 SOCKS5 和是否有备用地址选择连接参数
        const newSocket = isSocksEnabled ?
            await connectAndSend(host, portNum) :
            await connectAndSend(fallbackAddress || host, parseInt(fallbackPort, 10) || portNum);
        // 更新远程连接包装器的 socket 引用
        remoteConnWrapper.socket = newSocket;
        // 监听 socket 关闭事件，确保 WebSocket 也被关闭
        newSocket.closed.catch(() => {}).finally(() => closeSocketQuietly(ws));
        // 连接流进行数据传输，不再提供重试函数（避免无限重试）
        connectStreams(newSocket, ws, respHeader, null);
    }

    try {
        // 首次尝试建立连接
        const initialSocket = await connectAndSend(host, portNum);
        remoteConnWrapper.socket = initialSocket;
        // 连接流进行双向数据传输，提供重试函数以便在连接断开时重试
        connectStreams(initialSocket, ws, respHeader, retryConnection);
    } catch (err) {
        // 初始连接失败，记录日志并尝试使用备用地址重新连接
        console.log('Initial connection failed, trying fallback:', err);
        retryConnection();
    }
}

/**
 * 解析 WebSocket 数据包头部，提取 VLESS 协议的连接信息
 * @param {ArrayBuffer} chunk - WebSocket 接收到的数据包
 * @param {string} token - 用于验证的认证令牌
 * @returns {Object} 解析结果，包含错误信息、地址信息、端口等
 */
function parseWsPacketHeader(chunk, token) {
    // 验证数据包长度，VLESS 协议头部至少需要 24 字节
    if (chunk.byteLength < 24) return { hasError: true, message: E_INVALID_DATA };

    // 提取协议版本号（第 1 字节）
    const version = new Uint8Array(chunk.slice(0, 1));

    // 验证用户身份：提取 UUID（第 2-17 字节，16字节）并与令牌比较
    if (formatIdentifier(new Uint8Array(chunk.slice(1, 17))) !== token) return { hasError: true, message: E_INVALID_USER };

    // 提取附加选项长度（第 18 字节）
    const optLen = new Uint8Array(chunk.slice(17, 18))[0];

    // 提取命令类型（跳过附加选项后的第 1 字节）
    const cmd = new Uint8Array(chunk.slice(18 + optLen, 19 + optLen))[0];
    let isUDP = false;
    // 命令类型：1=TCP连接，2=UDP连接
    if (cmd === 1) {
        // TCP 连接，保持 isUDP 为 false
    } else if (cmd === 2) {
        isUDP = true; // UDP 连接
    } else {
        // 不支持的命令类型
        return { hasError: true, message: E_UNSUPPORTED_CMD };
    }

    // 计算端口号位置并提取目标端口（2字节，大端序）
    const portIdx = 19 + optLen;
    const port = new DataView(chunk.slice(portIdx, portIdx + 2)).getUint16(0);

    // 初始化地址解析相关变量
    let addrIdx = portIdx + 2, addrLen = 0, addrValIdx = addrIdx + 1, hostname = '';

    // 提取地址类型（1字节）
    const addressType = new Uint8Array(chunk.slice(addrIdx, addrValIdx))[0];

    // 根据地址类型解析目标主机名
    switch (addressType) {
        case ADDRESS_TYPE_IPV4:
            // IPv4 地址：4字节，转换为点分十进制格式
            addrLen = 4;
            hostname = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + addrLen)).join('.');
            break;
        case ADDRESS_TYPE_URL:
            // 域名地址：先读取长度（1字节），再读取域名字符串
            addrLen = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + 1))[0];
            addrValIdx += 1;
            hostname = new TextDecoder().decode(chunk.slice(addrValIdx, addrValIdx + addrLen));
            break;
        case ADDRESS_TYPE_IPV6:
            // IPv6 地址：16字节，转换为冒号分隔的十六进制格式
            addrLen = 16;
            const ipv6 = [];
            const ipv6View = new DataView(chunk.slice(addrValIdx, addrValIdx + addrLen));
            for (let i = 0; i < 8; i++) ipv6.push(ipv6View.getUint16(i * 2).toString(16));
            hostname = ipv6.join(':');
            break;
        default:
            // 不支持的地址类型
            return { hasError: true, message: `${E_INVALID_ADDR_TYPE}: ${addressType}` };
    }

    // 验证主机名不能为空
    if (!hostname) return { hasError: true, message: `${E_EMPTY_ADDR}: ${addressType}` };

    // 返回解析成功的结果
    return {
        hasError: false,
        addressType,
        port,
        hostname,
        isUDP,
        rawIndex: addrValIdx + addrLen, // 原始数据开始位置（跳过协议头部分）
        version
    };
}

/**
 * 创建可读流来处理 WebSocket 数据传输
 * @param {WebSocket} socket - WebSocket 连接对象
 * @param {string} earlyDataHeader - Base64 编码的早期数据头部
 * @returns {ReadableStream} 返回用于数据传输的可读流
 */
function makeReadableStream(socket, earlyDataHeader) {
    let cancelled = false; // 标识流是否已被取消

    return new ReadableStream({
        /**
         * 流启动时的初始化函数
         * @param {ReadableStreamDefaultController} controller - 流控制器
         */
        start(controller) {
            // 监听 WebSocket 消息事件，将接收到的数据推入流中
            socket.addEventListener('message', (event) => {
                if (!cancelled) controller.enqueue(event.data);
            });

            // 监听 WebSocket 关闭事件，安全关闭流
            socket.addEventListener('close', () => {
                if (!cancelled) {
                    closeSocketQuietly(socket);
                    controller.close();
                }
            });

            // 监听 WebSocket 错误事件，将错误传播到流中
            socket.addEventListener('error', (err) => controller.error(err));

            // 处理早期数据（如果存在的话）
            const { earlyData, error } = base64ToArray(earlyDataHeader);
            if (error) {
                // 如果早期数据解析出错，将错误传播到流中
                controller.error(error);
            } else if (earlyData) {
                // 如果有有效的早期数据，将其作为第一个数据块推入流中
                controller.enqueue(earlyData);
            }
        },

        /**
         * 流取消时的清理函数
         */
        cancel() {
            cancelled = true;
            closeSocketQuietly(socket);
        }
    });
}

/**
 * 连接远程 Socket 和 WebSocket 流，实现双向数据传输
 * @param {Socket} remoteSocket - 远程服务器 Socket 连接
 * @param {WebSocket} webSocket - 客户端 WebSocket 连接
 * @param {Uint8Array|null} headerData - 需要附加的头部数据（可选）
 * @param {Function|null} retryFunc - 重试连接函数（可选）
 */
async function connectStreams(remoteSocket, webSocket, headerData, retryFunc) {
    let header = headerData; // 保存头部数据，发送一次后置为 null
    let hasData = false; // 标识是否接收到任何数据

    // 将远程 Socket 的可读流连接到 WebSocket 的可写流
    await remoteSocket.readable.pipeTo(
        new WritableStream({
            /**
             * 处理从远程 Socket 接收到的数据块
             * @param {Uint8Array} chunk - 数据块
             * @param {WritableStreamDefaultController} controller - 流控制器
             */
            async write(chunk, controller) {
                hasData = true; // 标记已接收到数据

                // 检查 WebSocket 连接状态，如果未打开则报错
                if (webSocket.readyState !== 1) controller.error(E_WS_NOT_OPEN);

                // 如果有头部数据，将头部数据与第一个数据块一起发送
                if (header) {
                    webSocket.send(await new Blob([header, chunk]).arrayBuffer());
                    header = null; // 头部数据只发送一次
                }
                // 后续数据块直接发送
                else {
                    webSocket.send(chunk);
                }
            },

            /**
             * 处理流中止事件
             * @param {any} reason - 中止原因
             */
            abort(reason) {
                console.error("Readable aborted:", reason);
            },
        })
    ).catch((error) => {
        // 捕获流连接过程中的错误
        console.error("Stream connection error:", error);
        closeSocketQuietly(webSocket);
    });

    // 如果没有接收到任何数据且提供了重试函数，则执行重试
    if (!hasData && retryFunc) retryFunc();
}

/**
 * 转发 UDP 数据包，主要用于 DNS 查询转发
 * 将 UDP 数据包通过 TCP 连接转发到 DNS 服务器，并将响应返回给客户端
 * @param {Uint8Array} udpChunk - UDP 数据包内容
 * @param {WebSocket} webSocket - 客户端 WebSocket 连接
 * @param {Uint8Array|null} respHeader - 响应头部数据（可选）
 */
async function forwardUDP(udpChunk, webSocket, respHeader) {
    try {
        // 连接到 Google DNS 服务器 (8.8.4.4:53) 进行 DNS 查询
        const tcpSocket = connect({ hostname: '8.8.4.4', port: 53 });
        let vlessHeader = respHeader; // 保存响应头，只在第一次响应时使用

        // 获取 TCP Socket 的写入器并发送 UDP 数据包
        const writer = tcpSocket.writable.getWriter();
        await writer.write(udpChunk);
        writer.releaseLock();

        // 将 DNS 服务器的响应数据流式传输回 WebSocket 客户端
        await tcpSocket.readable.pipeTo(new WritableStream({
            /**
             * 处理从 DNS 服务器接收到的响应数据
             * @param {Uint8Array} chunk - DNS 响应数据块
             */
            async write(chunk) {
                // 检查 WebSocket 连接状态是否为打开状态
                if (webSocket.readyState === 1) {
                    // 如果有 VLESS 协议头部，与第一个响应数据块一起发送
                    if (vlessHeader) {
                        webSocket.send(await new Blob([vlessHeader, chunk]).arrayBuffer());
                        vlessHeader = null; // 头部数据只发送一次
                    }
                    // 后续响应数据直接发送
                    else {
                        webSocket.send(chunk);
                    }
                }
            },
        }));
    } catch (error) {
        // 捕获并记录 DNS 转发过程中的错误
        console.error(`DNS forward error: ${error.message}`);
    }
}

/**
 * 建立 SOCKS5 代理连接，实现完整的 SOCKS5 握手和认证流程
 * @param {number} addrType - 目标地址类型（1=IPv4, 2=域名, 3=IPv6）
 * @param {string} address - 目标主机地址
 * @param {number} port - 目标端口号
 * @returns {Socket} 返回建立的 SOCKS5 代理 Socket 连接
 * @throws {Error} 当 SOCKS5 握手失败、认证失败或连接失败时抛出错误
 */
async function establishSocksConnection(addrType, address, port) {
    // 从配置中获取 SOCKS5 代理服务器信息
    const { username, password, hostname, socksPort } = parsedSocks5Config;

    // 连接到 SOCKS5 代理服务器
    const socket = connect({ hostname, port: socksPort });
    const writer = socket.writable.getWriter();

    // 发送握手请求：版本号(5) + 认证方法数量 + 认证方法列表
    // 如果有用户名密码则支持无认证(0)和用户名密码认证(2)，否则只支持无认证(0)
    await writer.write(new Uint8Array(username ? [5, 2, 0, 2] : [5, 1, 0]));

    // 读取服务器的握手响应
    const reader = socket.readable.getReader();
    let res = (await reader.read()).value;

    // 验证握手响应：版本号必须是5，认证方法不能是255(无可接受方法)
    if (res[0] !== 5 || res[1] === 255) throw new Error(E_SOCKS_NO_METHOD);

    // 如果服务器要求用户名密码认证(方法2)
    if (res[1] === 2) {
        // 检查是否提供了用户名和密码
        if (!username || !password) throw new Error(E_SOCKS_AUTH_NEEDED);

        // 构造认证请求：版本号(1) + 用户名长度 + 用户名 + 密码长度 + 密码
        const encoder = new TextEncoder();
        const authRequest = new Uint8Array([1, username.length, ...encoder.encode(username), password.length, ...encoder.encode(password)]);
        await writer.write(authRequest);

        // 读取认证响应并验证：版本号必须是1，状态码必须是0(成功)
        res = (await reader.read()).value;
        if (res[0] !== 1 || res[1] !== 0) throw new Error(E_SOCKS_AUTH_FAIL);
    }

    // 构造目标地址信息，根据地址类型进行不同的编码
    const encoder = new TextEncoder();
    let DSTADDR;

    switch (addrType) {
        case ADDRESS_TYPE_IPV4:
            // IPv4 地址：类型标识(1) + 4字节IP地址
            DSTADDR = new Uint8Array([1, ...address.split('.').map(Number)]);
            break;
        case ADDRESS_TYPE_URL:
            // 域名地址：类型标识(3) + 域名长度 + 域名字节
            DSTADDR = new Uint8Array([3, address.length, ...encoder.encode(address)]);
            break;
        case ADDRESS_TYPE_IPV6:
            // IPv6 地址：类型标识(4) + 16字节IPv6地址
            DSTADDR = new Uint8Array([4, ...address.split(':').flatMap(x => [parseInt(x.slice(0, 2), 16), parseInt(x.slice(2), 16)])]);
            break;
        default:
            // 不支持的地址类型
            throw new Error(E_INVALID_ADDR_TYPE);
    }

    // 发送连接请求：版本号(5) + 命令(1=连接) + 保留字段(0) + 目标地址 + 目标端口(大端序)
    await writer.write(new Uint8Array([5, 1, 0, ...DSTADDR, port >> 8, port & 255]));

    // 读取连接响应并验证连接状态
    res = (await reader.read()).value;
    if (res[1] !== 0) throw new Error(E_SOCKS_CONN_FAIL);

    // 释放读写器的锁定状态，返回可用的 Socket 连接
    writer.releaseLock();
    reader.releaseLock();
    return socket;
}

/**
 * 解析 SOCKS5 代理配置字符串，提取连接参数
 * @param {string} address - SOCKS5 代理配置字符串，格式：[username:password@]hostname:port
 * @returns {Object} 解析后的 SOCKS5 配置对象，包含 username, password, hostname, socksPort
 * @throws {Error} 当配置格式无效时抛出错误
 */
function parseSocksConfig(address) {
    // 按 @ 符号分割配置字符串，分离认证信息和服务器地址
    // reverse() 确保 latter 是服务器地址部分，former 是认证信息部分（如果存在）
    let [latter, former] = address.split("@").reverse();
    let username, password, hostname, socksPort;

    // 如果存在认证信息（@ 符号前的部分）
    if (former) {
        // 按冒号分割用户名和密码，必须是 username:password 格式
        const formers = former.split(":");
        if (formers.length !== 2) throw new Error(E_INVALID_SOCKS_ADDR);
        [username, password] = formers;
    }

    // 解析服务器地址和端口部分
    const latters = latter.split(":");
    // 提取最后一个冒号后的数字作为端口号
    socksPort = Number(latters.pop());
    if (isNaN(socksPort)) throw new Error(E_INVALID_SOCKS_ADDR);

    // 剩余部分重新组合为主机名（处理 IPv6 地址包含多个冒号的情况）
    hostname = latters.join(":");
    // 验证 IPv6 地址格式：如果包含冒号但不是 [address] 格式则无效
    if (hostname.includes(":") && !/^\[.*\]$/.test(hostname)) throw new Error(E_INVALID_SOCKS_ADDR);

    return { username, password, hostname, socksPort };
}

/**
 * 将 Base64 字符串解码为 Uint8Array 缓冲区
 * @param {string} b64Str - Base64 编码的字符串（支持 URL 安全格式）
 * @returns {Object} 解码结果对象，包含 earlyData 和 error 属性
 * @returns {ArrayBuffer|null} returns.earlyData - 解码后的 ArrayBuffer 数据，解码失败时为 null
 * @returns {Error|null} returns.error - 解码过程中的错误对象，成功时为 null
 */
function base64ToArray(b64Str) {
    // 如果输入字符串为空，返回无错误的空结果
    if (!b64Str) return { error: null };

    try {
        // 将 URL 安全的 Base64 格式转换为标准 Base64 格式
        // URL 安全格式使用 - 和 _ 替代 + 和 /，避免在 URL 中产生特殊字符冲突
        b64Str = b64Str.replace(/-/g, '+').replace(/_/g, '/');

        // 使用 atob 解码 Base64 字符串，然后转换为 Uint8Array 的 ArrayBuffer
        return {
            earlyData: Uint8Array.from(atob(b64Str), (c) => c.charCodeAt(0)).buffer,
            error: null
        };
    } catch (error) {
        // 捕获解码过程中的任何错误（如无效的 Base64 格式）
        return { error };
    }
}

/**
 * 验证字符串是否为有效的 UUID v4 格式
 * @param {string} uuid - 需要验证的 UUID 字符串
 * @returns {boolean} 如果是有效的 UUID v4 格式返回 true，否则返回 false
 */
function isValidFormat(uuid) {
    // 使用正则表达式验证 UUID v4 格式：
    // - 8位十六进制数字，后跟连字符
    // - 4位十六进制数字，后跟连字符
    // - 版本号4和3位十六进制数字，后跟连字符
    // - 变体位[89ab]和3位十六进制数字，后跟连字符
    // - 12位十六进制数字
    // /i 标志表示不区分大小写匹配
    return /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(uuid);
}
/**
 * 安全关闭 WebSocket 连接，处理关闭过程中可能出现的异常
 * @param {WebSocket} socket - 需要关闭的 WebSocket 连接对象
 * @description 该函数确保 WebSocket 连接在关闭时不会抛出异常，即使连接已经处于异常状态
 * 只有当连接状态为 OPEN(1) 或 CLOSING(2) 时才尝试关闭连接
 */
function closeSocketQuietly(socket) {
    try {
        // 检查 WebSocket 连接状态：
        // readyState === 1: OPEN 状态，连接已建立
        // readyState === 2: CLOSING 状态，连接正在关闭中
        // 只有在这两种状态下才安全调用 close() 方法
        if (socket.readyState === 1 || socket.readyState === 2) {
            socket.close(); // 关闭 WebSocket 连接
        }
    } catch (error) {
        // 静默处理关闭过程中的任何异常，避免错误传播
        // 这样可以确保清理过程不会因为连接异常而被中断
    }
}

// 十六进制转换查找表，预先计算0-255的十六进制表示以提高性能
const hexTable = Array.from({ length: 256 }, (v, i) => (i + 256).toString(16).slice(1));

/**
 * 将字节数组格式化为标准 UUID 字符串格式
 * @param {Uint8Array} arr - 包含 UUID 字节数据的数组（至少16字节）
 * @param {number} [offset=0] - 开始读取的字节偏移量，默认为0
 * @returns {string} 格式化后的 UUID 字符串，格式为 xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
 * @throws {TypeError} 当生成的字符串不符合有效 UUID 格式时抛出类型错误
 * @description 该函数将16字节的二进制数据转换为标准的 UUID v4 格式字符串
 * 使用预计算的十六进制查找表提高转换性能，避免重复的进制转换计算
 */
function formatIdentifier(arr, offset = 0) {
    // 按照 UUID 标准格式将16字节数据转换为字符串：
    // 8字节-4字节-4字节-4字节-12字节 (32个十六进制字符，用连字符分隔)
    const id = (hexTable[arr[offset]]+hexTable[arr[offset+1]]+hexTable[arr[offset+2]]+hexTable[arr[offset+3]]+"-"+hexTable[arr[offset+4]]+hexTable[arr[offset+5]]+"-"+hexTable[arr[offset+6]]+hexTable[arr[offset+7]]+"-"+hexTable[arr[offset+8]]+hexTable[arr[offset+9]]+"-"+hexTable[arr[offset+10]]+hexTable[arr[offset+11]]+hexTable[arr[offset+12]]+hexTable[arr[offset+13]]+hexTable[arr[offset+14]]+hexTable[arr[offset+15]]).toLowerCase();

    // 验证生成的 UUID 字符串格式是否正确
    if (!isValidFormat(id)) throw new TypeError(E_INVALID_ID_STR);

    return id; // 返回格式化后的 UUID 字符串
}
