import { Injectable, Logger } from '@nestjs/common';
import { pool } from '../db/pool';

export interface PanelConfig {
  provider: 'rebecca' | 'remnawave';
  rebecca?: {
    baseUrl: string;
    username?: string;
    password?: string;
  };
  remnawave?: {
    baseUrl: string;
    token: string;
    caddyToken?: string;
    squadUuids: string[];
  };
}

@Injectable()
export class SettingsService {
  private readonly log = new Logger(SettingsService.name);

  async getSetting<T>(key: string): Promise<T | null> {
    const res = await pool.query('SELECT value FROM system_settings WHERE key = $1', [key]);
    if (res.rows.length === 0) return null;
    return res.rows[0].value as T;
  }

  async setSetting(key: string, value: any): Promise<void> {
    await pool.query(
      `INSERT INTO system_settings (key, value, updated_at)
       VALUES ($1, $2::jsonb, now())
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
      [key, JSON.stringify(value)]
    );
  }

  async getPanelConfig(): Promise<PanelConfig> {
    const config = await this.getSetting<PanelConfig>('panel_config');
    if (config) return config;

    // Fallback to env vars for initial boot
    return {
      provider: (process.env.PANEL_PROVIDER as any) ?? 'rebecca',
      rebecca: {
        baseUrl: process.env.PANEL_BASE_URL ?? '',
        username: process.env.PANEL_ADMIN_USER ?? '',
        password: process.env.PANEL_ADMIN_PASS ?? ''
      },
      remnawave: {
        baseUrl: process.env.REMNAWAVE_BASE_URL ?? '',
        token: process.env.REMNAWAVE_TOKEN ?? '',
        caddyToken: process.env.REMNAWAVE_CADDY_TOKEN ?? '',
        squadUuids: process.env.REMNAWAVE_SQUAD_UUIDS ? process.env.REMNAWAVE_SQUAD_UUIDS.split(',') : []
      }
    };
  }

  async setPanelConfig(config: PanelConfig) {
    await this.setSetting('panel_config', config);
  }
}
