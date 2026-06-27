import { Injectable, Logger } from '@nestjs/common';
import { IPanelClient, PanelUserParams, PanelUserResult } from './IPanelClient';
import { RebeccaPanelClient } from './RebeccaPanelClient';
import { RemnawavePanelClient } from './RemnawavePanelClient';
import { SettingsService } from '../core/settings.service';

@Injectable()
export class DynamicPanelClient implements IPanelClient {
  private readonly log = new Logger(DynamicPanelClient.name);
  private cachedClient: IPanelClient | null = null;
  private lastConfigJson: string = '';

  constructor(private readonly settings: SettingsService) {}

  private async getClient(): Promise<IPanelClient> {
    const config = await this.settings.getPanelConfig();
    const configStr = JSON.stringify(config);
    if (this.cachedClient && this.lastConfigJson === configStr) {
      return this.cachedClient;
    }
    
    this.log.log(`Panel config changed or initializing. Switching to provider: ${config.provider}`);
    if (config.provider === 'remnawave') {
      this.cachedClient = new RemnawavePanelClient(config.remnawave);
    } else {
      this.cachedClient = new RebeccaPanelClient(config.rebecca);
    }
    this.lastConfigJson = configStr;
    return this.cachedClient;
  }

  async createUser(params: PanelUserParams): Promise<PanelUserResult> {
    return (await this.getClient()).createUser(params);
  }

  async extendUser(username: string, params: PanelUserParams): Promise<void> {
    return (await this.getClient()).extendUser(username, params);
  }

  async revokeUser(username: string): Promise<void> {
    return (await this.getClient()).revokeUser(username);
  }

  async deleteUser(username: string): Promise<void> {
    return (await this.getClient()).deleteUser(username);
  }

  async getUserDataUsage(username: string): Promise<number | null> {
    return (await this.getClient()).getUserDataUsage(username);
  }
}
