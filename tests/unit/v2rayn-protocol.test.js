import { describe, it, expect } from 'vitest';
import { parseNodeList, extractValidNodes } from '../../functions/modules/utils/node-parser.js';
import { urlToClashProxy, urlsToClashProxies } from '../../functions/utils/url-to-clash.js';
import { convertV2raynUrlToStandard, isV2raynUrl } from '../../functions/utils/v2rayn-utils.js';
import { parseNodeInfo } from '../../functions/modules/utils/geo-utils.js';
import { prependNodeName } from '../../functions/utils/node-utils.js';

describe('v2rayn:// format support', () => {
    const sampleV2raynPayload = {
        ConfigType: 11,
        ConfigVersion: 4,
        Remarks: 'JP-01-0.9X-SoftBank',
        Address: 'jp01.pandanetwork.dpdns.org',
        Port: 34354,
        Password: 'b672f7f9-7f72-48a4-a8fb-fe1ae565856e',
        StreamSecurity: 'tls',
        AllowInsecure: 'false',
        Sni: 'update.nintendo.net',
        Fingerprint: 'qq',
        CertSha: '2602F93C72D01197860B5EE757728831E2F8F4ACE3DECF7DED0B15759E1F59C8',
        Cert: '-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----',
    };

    const b64Json = Buffer.from(JSON.stringify(sampleV2raynPayload)).toString('base64');
    const v2raynUrl = `v2rayn://anytls/${b64Json}`;

    it('identifies v2rayn url correctly', () => {
        expect(isV2raynUrl(v2raynUrl)).toBe(true);
        expect(isV2raynUrl('vless://uuid@host:443')).toBe(false);
    });

    it('converts v2rayn://anytls to standard anytls url', () => {
        const standard = convertV2raynUrlToStandard(v2raynUrl);
        expect(standard.startsWith('anytls://')).toBe(true);
        expect(standard).toContain('jp01.pandanetwork.dpdns.org:34354');
        expect(standard).toContain('sni=update.nintendo.net');
        expect(standard).toContain(
            'pcs=2602F93C72D01197860B5EE757728831E2F8F4ACE3DECF7DED0B15759E1F59C8'
        );
        expect(standard).toContain('fp=qq');
        expect(standard).toContain('#JP-01-0.9X-SoftBank');
    });

    it('extractValidNodes extracts v2rayn url lines', () => {
        const content = `vless://uuid@host:443#Node1\n${v2raynUrl}`;
        const nodes = extractValidNodes(content);
        expect(nodes).toHaveLength(2);
        expect(nodes[1]).toBe(v2raynUrl);
    });

    it('parseNodeList correctly parses v2rayn nodes and extracts info', () => {
        const content = `vless://b672f7f9-7f72-48a4-a8fb-fe1ae565856e@singgcdn.singgnetworkcdn.com:443?mode=multi&security=tls#Node1\n${v2raynUrl}`;
        const nodes = parseNodeList(content);
        expect(nodes).toHaveLength(2);
        expect(nodes[1].protocol).toBe('anytls');
        expect(nodes[1].name).toBe('JP-01-0.9X-SoftBank');
        expect(nodes[1].server).toBe('jp01.pandanetwork.dpdns.org');
        expect(nodes[1].port).toBe('34354');
        expect(nodes[1].region).toBe('日本');
    });

    it('urlToClashProxy directly converts v2rayn url to Clash proxy', () => {
        const proxy = urlToClashProxy(v2raynUrl);
        expect(proxy).not.toBeNull();
        expect(proxy.type).toBe('anytls');
        expect(proxy.name).toBe('JP-01-0.9X-SoftBank');
        expect(proxy.server).toBe('jp01.pandanetwork.dpdns.org');
        expect(proxy.port).toBe(34354);
        expect(proxy.password).toBe('b672f7f9-7f72-48a4-a8fb-fe1ae565856e');
        expect(proxy.sni).toBe('update.nintendo.net');
        expect(proxy.pinnedPeerCertSha256).toBe(sampleV2raynPayload.CertSha);
        expect(proxy['client-fingerprint']).toBe('qq');
    });

    it('urlsToClashProxies batch converts with v2rayn url', () => {
        const urls = [
            'vless://b672f7f9-7f72-48a4-a8fb-fe1ae565856e@singgcdn.singgnetworkcdn.com:443?mode=multi&security=tls#HK',
            v2raynUrl,
        ];
        const proxies = urlsToClashProxies(urls);
        expect(proxies).toHaveLength(2);
        expect(proxies[0].type).toBe('vless');
        expect(proxies[1].type).toBe('anytls');
    });

    it('parseNodeInfo extracts server, port, and region from v2rayn url', () => {
        const info = parseNodeInfo(v2raynUrl);
        expect(info.protocol).toBe('anytls');
        expect(info.name).toBe('JP-01-0.9X-SoftBank');
        expect(info.server).toBe('jp01.pandanetwork.dpdns.org');
        expect(info.port).toBe('34354');
        expect(info.region).toBe('日本');
    });

    it('prependNodeName handles v2rayn url by converting to standard with prefix', () => {
        const prepended = prependNodeName(v2raynUrl, 'MyPrefix');
        expect(prepended.startsWith('anytls://')).toBe(true);
        expect(prepended).toContain('#MyPrefix%20-%20JP-01-0.9X-SoftBank');
    });
});
