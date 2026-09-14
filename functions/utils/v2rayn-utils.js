/**
 * v2rayN 客户端专有节点格式工具
 *
 * 处理形如: v2rayn://<protocol>/<base64-json> 的专有链接
 * 支持保留自签名证书 (Cert) 并支持修改节点名称 (Remarks)
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

function safeBase64Encode(str) {
    return btoa(unescape(encodeURIComponent(str)));
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
 * 更新 v2rayn:// 专有链接内部的 Remarks (节点名称)
 * 保留原有的全部参数 (包括自签名证书 Cert 等)
 * @param {string} url
 * @param {Function|string} updater - 更新函数 (oldRemarks => newRemarks) 或直接传入新名称
 * @returns {string}
 */
export function updateV2raynRemarks(url, updater) {
    if (!isV2raynUrl(url)) return url;

    try {
        const match = url.trim().match(/^v2rayn:\/\/([^\/]+)\/([A-Za-z0-9+/=_-]+)/i);
        if (!match) return url;

        const subType = match[1];
        const payloadBase64 = match[2];
        const jsonStr = safeBase64Decode(payloadBase64);
        if (!jsonStr) return url;

        const config = JSON.parse(jsonStr);
        if (!config || typeof config !== 'object') return url;

        const oldRemarks = config.Remarks || '';
        const newRemarks = typeof updater === 'function' ? updater(oldRemarks) : String(updater);

        if (newRemarks === oldRemarks) return url;

        config.Remarks = newRemarks;
        const newBase64 = safeBase64Encode(JSON.stringify(config));
        return `v2rayn://${subType}/${newBase64}`;
    } catch (e) {
        console.debug('[V2raynUtils] updateV2raynRemarks failed:', e);
        return url;
    }
}

/**
 * 将 v2rayn:// 专有链接转换为标准节点 URL (例如 anytls://)
 * 供 Clash / Singbox 生成器或其它非 v2rayN 客户端使用
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
            params.push(`security=${encodeURIComponent(config.StreamSecurity || 'tls')}`);

            if (config.Sni) {
                params.push(`sni=${encodeURIComponent(config.Sni)}`);
            }

            if (config.Fingerprint) {
                params.push(`fp=${encodeURIComponent(config.Fingerprint)}`);
            }

            if (config.CertSha) {
                params.push(`pcs=${encodeURIComponent(config.CertSha)}`);
            }

            params.push('type=tcp');
            params.push('headerType=none');

            if (config.AllowInsecure === 'true' || config.AllowInsecure === true) {
                params.push('insecure=1');
            }

            if (config.Alpn) {
                params.push(`alpn=${encodeURIComponent(config.Alpn)}`);
            }

            const query = `?${params.join('&')}`;
            const hash = remarks ? `#${encodeURIComponent(remarks)}` : '';
            return `anytls://${encodeURIComponent(password)}@${address}:${port}${query}${hash}`;
        }

        return url;
    } catch (e) {
        console.debug('[V2raynUtils] Convert v2rayn url failed:', e);
        return url;
    }
}
