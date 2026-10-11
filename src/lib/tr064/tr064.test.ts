/// <reference types="mocha" />
import { strict as assert } from 'node:assert';
import { buildDigestHeader, parseDigestChallenge } from './digest';
import { Tr064Fault, buildEnvelope, escapeXml, parseDeviceDescription, parseResponse } from './soap';

describe('digest', () => {
    it('parses a challenge', () => {
        const c = parseDigestChallenge('Digest realm="F!Box SOAP-Auth", nonce="ABC123", algorithm=MD5, qop="auth"');
        assert.equal(c?.realm, 'F!Box SOAP-Auth');
        assert.equal(c?.nonce, 'ABC123');
        assert.equal(c?.qop, 'auth');
    });

    it('ignores other schemes', () => {
        assert.equal(parseDigestChallenge('Basic realm="x"'), undefined);
        assert.equal(parseDigestChallenge(undefined), undefined);
    });

    it('matches the RFC 2617 example', () => {
        const h = buildDigestHeader({
            challenge: { realm: 'testrealm@host.com', nonce: 'dcd98b7102dd2f0e8b11d0f600bfb0c093', qop: 'auth' },
            method: 'GET',
            uri: '/dir/index.html',
            username: 'Mufasa',
            password: 'Circle Of Life',
            nc: 1,
            cnonce: '0a4f113b',
        });
        assert.match(h, /response="6629fae49393a05397450978507c4ef1"/);
        assert.match(h, /nc=00000001/);
        assert.doesNotMatch(h, /Circle Of Life/);
    });
});

describe('soap', () => {
    it('escapes arguments', () => {
        assert.equal(escapeXml(`<a href="x">'&`), '&lt;a href=&quot;x&quot;&gt;&apos;&amp;');
        const env = buildEnvelope('urn:dslforum-org:service:Hosts:1', 'GetGenericHostEntry', { NewIndex: '<0>' });
        assert.match(env, /<NewIndex>&lt;0&gt;<\/NewIndex>/);
        assert.match(env, /<u:GetGenericHostEntry xmlns:u="urn:dslforum-org:service:Hosts:1">/);
    });

    it('reads response values', () => {
        const xml = `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>
            <u:GetInfoResponse xmlns:u="urn:dslforum-org:service:UserInterface:1">
            <NewUpgradeAvailable>1</NewUpgradeAvailable><NewX_AVM-DE_Version>8.30</NewX_AVM-DE_Version><NewEmpty></NewEmpty>
            </u:GetInfoResponse></s:Body></s:Envelope>`;
        const r = parseResponse(xml, 'GetInfo');
        assert.equal(r.NewUpgradeAvailable, '1');
        assert.equal(r['NewX_AVM-DE_Version'], '8.30');
        assert.equal(r.NewEmpty, '');
    });

    it('turns faults into errors', () => {
        const xml = `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault>
            <faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail><UPnPError xmlns="urn:dslforum-org:control-1-0">
            <errorCode>606</errorCode><errorDescription>Action Not Authorized</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`;
        assert.throws(
            () => parseResponse(xml, 'GetInfo'),
            (e: unknown) => e instanceof Tr064Fault && e.code === 606,
        );
    });

    it('reads the device description', () => {
        const xml = `<root xmlns="urn:dslforum-org:device-1-0"><systemVersion><Display>154.08.25</Display></systemVersion><device>
            <deviceType>urn:dslforum-org:device:InternetGatewayDevice:1</deviceType><friendlyName>FRITZ!Box 7590</friendlyName><modelName>FRITZ!Box 7590</modelName>
            <serviceList><service><serviceType>urn:dslforum-org:service:DeviceInfo:1</serviceType><controlURL>/upnp/control/deviceinfo</controlURL><SCPDURL>/deviceinfoSCPD.xml</SCPDURL></service></serviceList>
            <deviceList><device><deviceType>urn:dslforum-org:device:LANDevice:1</deviceType><serviceList><service>
            <serviceType>urn:dslforum-org:service:WLANConfiguration:1</serviceType><controlURL>/upnp/control/wlanconfig1</controlURL><SCPDURL>/wlanconfigSCPD.xml</SCPDURL>
            </service></serviceList></device></deviceList></device></root>`;
        const d = parseDeviceDescription(xml);
        assert.equal(d.modelName, 'FRITZ!Box 7590');
        assert.equal(d.firmware, '154.08.25');
        assert.ok(d.services.has('urn:dslforum-org:service:DeviceInfo:1'));
        assert.ok(d.services.has('urn:dslforum-org:service:WLANConfiguration:1'));
    });
});
