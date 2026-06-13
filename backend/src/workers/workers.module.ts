import { Module } from '@nestjs/common';
import { ReaperWorker } from './reaper.worker';
import { OutboxDrainerWorker } from './outbox-drainer.worker';
import { NodeSyncWorker } from './node-sync.worker';

/**
 * Background workers. PANEL_CLIENT is resolved from the global CoreModule.
 * Scheduling is driven by ScheduleModule.forRoot() (registered in AppModule).
 *   • ReaperWorker        — @Cron every minute, DB-only, queues panel cleanup.
 *   • OutboxDrainerWorker — @Interval, drains panel_operations to the panel.
 *   • NodeSyncWorker      — @Cron 5-min, reconciles node status (never is_active).
 */
@Module({
  providers: [ReaperWorker, OutboxDrainerWorker, NodeSyncWorker],
})
export class WorkersModule {}
