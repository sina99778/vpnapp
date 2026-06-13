import { Module } from '@nestjs/common';
import { AdminController } from './admin.controller';
import { AdminService } from './admin.service';
import { AdminGuard } from './admin.guard';
import { AuditService } from './audit.service';
import { AuditLogInterceptor } from './audit-log.interceptor';

/**
 * Admin management layer. PANEL_CLIENT resolves from the global CoreModule.
 * AdminService + AuditService are exported so the Telegram bot can reuse the
 * exact same logic and audit trail (behind its own env whitelist).
 */
@Module({
  controllers: [AdminController],
  providers: [AdminService, AdminGuard, AuditService, AuditLogInterceptor],
  exports: [AdminService, AuditService],
})
export class AdminModule {}
