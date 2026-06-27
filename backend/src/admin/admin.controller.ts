import {
  Body,
  Controller,
  Get,
  HttpCode,
  Param,
  ParseUUIDPipe,
  Patch,
  Post,
  Put,
  Query,
  Req,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { IsBoolean, IsIn, IsInt, IsOptional, IsString, IsUUID, Max, MaxLength, Min } from 'class-validator';
import { Type } from 'class-transformer';
import type { Request } from 'express';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { CurrentUser, AuthUser } from '../auth/current-user.decorator';
import { AdminGuard } from './admin.guard';
import { AdminService } from './admin.service';
import { AuditService, AdminActionType } from './audit.service';
import { AuditLogInterceptor } from './audit-log.interceptor';
import { SettingsService, PanelConfig } from '../core/settings.service';

class ListUsersQuery {
  @IsOptional() @IsString() @MaxLength(254)
  search?: string;

  @IsOptional() @Type(() => Number) @IsInt() @Min(1) @Max(100)
  limit?: number;

  @IsOptional() @Type(() => Number) @IsInt() @Min(0)
  offset?: number;
}

class MutateUserDto {
  @IsOptional() @IsIn(['free', 'premium'])
  tier?: 'free' | 'premium';

  @IsOptional() @IsBoolean()
  isBanned?: boolean;
}

class NodeStatusDto {
  @IsBoolean()
  isActive!: boolean;
}

class AuditQuery {
  @IsOptional()
  @IsIn([
    'KICK_SESSION',
    'BAN_USER',
    'UNBAN_USER',
    'CHANGE_TIER',
    'PANIC_FREE_SESSIONS',
    'SET_NODE_STATUS',
    'FORCE_MIGRATE_NODE',
  ])
  actionType?: AdminActionType;

  @IsOptional() @IsUUID()
  adminId?: string;

  @IsOptional() @Type(() => Number) @IsInt() @Min(1) @Max(200)
  limit?: number;

  @IsOptional() @Type(() => Number) @IsInt() @Min(0)
  offset?: number;
}

/**
 * All endpoints require a valid access token AND role='admin' (fresh-checked).
 * AuditLogInterceptor records every successful MUTATING action out-of-band.
 */
@UseGuards(JwtAuthGuard, AdminGuard)
@UseInterceptors(AuditLogInterceptor)
@Controller('admin')
export class AdminController {
  constructor(
    private readonly admin: AdminService,
    private readonly audit: AuditService,
    private readonly settings: SettingsService,
  ) {}

  @Get('stats')
  stats() {
    return this.admin.stats();
  }

  @Get('users')
  users(@Query() q: ListUsersQuery) {
    return this.admin.listUsers(q);
  }

  @HttpCode(200)
  @Post('users/:id/mutate')
  mutate(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: MutateUserDto,
    @CurrentUser() user: AuthUser,
    @Req() req: Request,
  ) {
    // Actor passed through for the durable in-tx BAN audit.
    return this.admin.mutateUser(id, dto, { adminId: user.userId, ip: req.ip ?? null });
  }

  @HttpCode(200)
  @Post('sessions/:id/kick')
  kick(@Param('id', ParseUUIDPipe) id: string) {
    return this.admin.kickSession(id);
  }

  @Get('nodes/health')
  nodesHealth() {
    return this.admin.nodesHealth();
  }

  /** Drain (isActive=false) or enable a node. Audited via the interceptor. */
  @HttpCode(200)
  @Patch('nodes/:id/status')
  setNodeStatus(@Param('id', ParseUUIDPipe) id: string, @Body() dto: NodeStatusDto) {
    return this.admin.setNodeActive(id, dto.isActive);
  }

  /**
   * Emergency evacuation: drain the node AND instantly revoke every live session
   * on it. Audited DURABLY in-tx (the interceptor skips this handler to avoid a
   * duplicate row).
   */
  @HttpCode(200)
  @Post('nodes/:id/migrate')
  forceMigrate(
    @Param('id', ParseUUIDPipe) id: string,
    @CurrentUser() user: AuthUser,
    @Req() req: Request,
  ) {
    return this.admin.forceMigrateNode(id, { adminId: user.userId, ip: req.ip ?? null });
  }

  /** Read the audit trail (paginated, filter by action/admin). GET → not audited. */
  @Get('audit')
  auditLogs(@Query() q: AuditQuery) {
    return this.audit.list(q);
  }

  /** Emergency: revoke every free-tier live session. */
  @HttpCode(200)
  @Post('panic/revoke-free-sessions')
  panic(@CurrentUser() user: AuthUser, @Req() req: Request) {
    return this.admin.panicRevokeFreeSessions({ adminId: user.userId, ip: req.ip ?? null });
  }

  // --- Settings API ---

  @Get('settings/panel')
  getPanelSettings() {
    return this.settings.getPanelConfig();
  }

  @HttpCode(200)
  @Put('settings/panel')
  async setPanelSettings(@Body() dto: PanelConfig) {
    await this.settings.setPanelConfig(dto);
    return { success: true };
  }
}
