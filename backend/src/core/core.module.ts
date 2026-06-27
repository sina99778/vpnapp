import { Global, Module } from '@nestjs/common';
import { PANEL_CLIENT } from '../panel/IPanelClient';
import { RebeccaPanelClient } from '../panel/RebeccaPanelClient';
import { RemnawavePanelClient } from '../panel/RemnawavePanelClient';

/**
 * Global singletons shared across every feature module. PANEL_CLIENT lives here
 * (not in each feature module) so there is ONE panel client — one cached
 * connection / token — rather than a separate one per module.
 *
 * Which panel backs the service is chosen by PANEL_PROVIDER:
 *   • "rebecca"   (default) → RebeccaPanelClient   (Marzban-family, integer nodes)
 *   • "remnawave"           → RemnawavePanelClient (UUID nodes, squad scoping)
 * The ad/session logic depends only on IPanelClient, so this is the ONLY switch.
 */
const PANEL_PROVIDER = (process.env.PANEL_PROVIDER ?? 'rebecca').toLowerCase();
const PanelClient = PANEL_PROVIDER === 'remnawave' ? RemnawavePanelClient : RebeccaPanelClient;

@Global()
@Module({
  providers: [{ provide: PANEL_CLIENT, useClass: PanelClient }],
  exports: [PANEL_CLIENT],
})
export class CoreModule {}
