import { Global, Module } from '@nestjs/common';
import { PANEL_CLIENT } from '../panel/IPanelClient';
import { RebeccaPanelClient } from '../panel/RebeccaPanelClient';

/**
 * Global singletons shared across every feature module. PANEL_CLIENT lives here
 * (not in each feature module) so there is ONE Rebecca client — one cached admin
 * JWT, one connection — rather than a separate login per module. Swapping panels
 * is still a one-line change (useClass).
 */
@Global()
@Module({
  providers: [{ provide: PANEL_CLIENT, useClass: RebeccaPanelClient }],
  exports: [PANEL_CLIENT],
})
export class CoreModule {}
