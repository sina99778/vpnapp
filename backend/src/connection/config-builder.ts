/**
 * Build the sing-box outbound config JSON the native core consumes. This is the
 * ONLY place the real node address/port/Reality keys appear in cleartext, and it
 * is immediately encrypted by the PayloadCipher before leaving the server.
 *
 * `security` mirrors node_endpoints.security: { sni, fp, pbk, sid, alpn, path }.
 */
export interface ConfigParams {
  protocol: string; // vless | vmess | trojan | shadowsocks
  address: string;
  port: number;
  uuid: string; // credential_ref
  flow?: string;
  security: Record<string, unknown>;
}

export function buildSingboxConfig(p: ConfigParams): string {
  const s = p.security ?? {};
  const sni = (s.sni as string) ?? p.address;
  const fp = (s.fp as string) ?? 'chrome';
  const pbk = s.pbk as string | undefined;
  const sid = s.sid as string | undefined;
  const alpn = s.alpn as string[] | undefined;

  const tls: Record<string, unknown> = {
    enabled: true,
    server_name: sni,
    utls: { enabled: true, fingerprint: fp },
  };
  if (alpn) tls.alpn = alpn;
  // Reality params present → enable reality; otherwise plain TLS.
  if (pbk) {
    tls.reality = { enabled: true, public_key: pbk, short_id: sid ?? '' };
  }

  const outbound: Record<string, unknown> = {
    type: p.protocol,
    tag: 'proxy',
    server: p.address,
    server_port: p.port,
  };
  if (p.protocol === 'vless' || p.protocol === 'vmess') {
    outbound.uuid = p.uuid;
    if (p.flow) outbound.flow = p.flow;
  } else {
    // trojan / shadowsocks use a password credential.
    outbound.password = p.uuid;
  }
  outbound.tls = tls;

  const config = {
    log: { level: 'warn' },
    outbounds: [
      outbound,
      { type: 'direct', tag: 'direct' },
    ],
  };
  return JSON.stringify(config);
}
