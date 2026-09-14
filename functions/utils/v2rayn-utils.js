/**
 * v2rayN 客户端专有节点格式转换工具
 *
 * 处理形如: v2rayn://<protocol>/<base64-json> 的专有链接
 * 例如: v2rayn://anytls/eyJDb25maWdUeXBlIjoxMS...
 */

function normalizeBase64(input) {
    let s = String(input || '')
        .trim()
        .replace(/\s+/g, '');
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    return s;
}

function safeBase64Decode(str) {
    try {
        const normalized = normalizeBase64(str);
        const binary = atob(normalized);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return new TextDecoder('utf-8').decode(bytes);
    } catch {
        return null;
    }
}

/**
 * 判断是否为 v2rayn:// 协议链接
 * @param {string} url
 * @returns {boolean}
 */
export function isV2raynUrl(url) {
    return typeof url === 'string' && url.trim().toLowerCase().startsWith('v2rayn://');
}

/**
 * 将 v2rayn:// 协议链接转换为标准节点 URL (例如 anytls://)
 * 如果不是 v2rayn:// 或转换失败则返回原始 url
 * @param {string} url
 * @returns {string}
 */
export function convertV2raynUrlToStandard(url) {
    if (!isV2raynUrl(url)) return url;

    try {
        const match = url.trim().match(/^v2rayn:\/\/([^\/]+)\/([A-Za-z0-9+/=_-]+)/i);
        if (!match) return url;

        const subType = match[1].toLowerCase();
        const payloadBase64 = match[2];
        const jsonStr = safeBase64Decode(payloadBase64);
        if (!jsonStr) return url;

        const config = JSON.parse(jsonStr);
        if (!config || typeof config !== 'object') return url;

        if (subType === 'anytls') {
            const password = config.Password || '';
            const address = config.Address || '';
            const port = config.Port || 443;
            const remarks = config.Remarks || '';

            const params = [];
            if (config.Sni) params.push(`sni=${encodeURIComponent(config.Sni)}`);
            if (config.AllowInsecure === 'true' || config.AllowInsecure === true) {
                params.push('insecure=1');
            }
            // v2rayN anytls 的 CertSha 对应 Clash/MiSub 的 certSha / pcs
            if (config.CertSha) {
                params.push(`certSha=${encodeURIComponent(config.CertSha)}`);
                params.push(`pcs=${encodeURIComponent(config.CertSha)}`);
            }
            if (config.Fingerprint) {
                params.push(`fp=${encodeURIComponent(config.Fingerprint)}`);
            }
            if (config.Alpn) {
                params.push(`alpn=${encodeURIComponent(config.Alpn)}`);
            }

            const query = params.length > 0 ? `?${params.join('&')}` : '';
            const hash = remarks ? `#${encodeURIComponent(remarks)}` : '';
            return `anytls://${encodeURIComponent(password)}@${address}:${port}${query}${hash}`;
        }

        return url;
    } catch (e) {
        console.debug('[V2raynUtils] Convert v2rayn url failed:', e);
        return url;
    }
}
