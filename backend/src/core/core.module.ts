import { Global, Module } from '@nestjs/common';
import { PANEL_CLIENT } from '../panel/IPanelClient';
import { DynamicPanelClient } from '../panel/DynamicPanelClient';
import { SettingsService } from './settings.service';

/**
 * Global singletons shared across every feature module. 
 * SettingsService provides dynamic configuration from the database.
 * DynamicPanelClient uses SettingsService to instantiate the correct panel client
 * on-the-fly and automatically adapts to changes made via the admin dashboard.
 */
@Global()
@Module({
  providers: [
    SettingsService,
    { provide: PANEL_CLIENT, useClass: DynamicPanelClient }
  ],
  exports: [SettingsService, PANEL_CLIENT],
})
export class CoreModule {}
