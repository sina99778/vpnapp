import { Logger, UseGuards } from '@nestjs/common';
import { Command, Ctx, Hears, Start, Update } from 'nestjs-telegraf';
import type { Context } from 'telegraf';
import { AdminService } from '../admin/admin.service';
import { AuditService } from '../admin/audit.service';
import { TelegramAdminGuard } from './telegram-admin.guard';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Telegram Ops CLI. Reuses the SAME AdminService as the HTTP API, so a /kick
 * from Telegram goes through the identical transaction + outbox path as the
 * admin endpoint. Every handler is gated by the whitelist guard.
 *
 * ⚠️ SECURITY: ALL Telegram handlers MUST live in THIS @Update class so they
 * inherit @UseGuards(TelegramAdminGuard). Do NOT create a second @Update class
 * for new handlers — it would bypass the whitelist. Add methods here instead.
 */
@Update()
@UseGuards(TelegramAdminGuard)
export class TelegramUpdate {
  private readonly log = new Logger(TelegramUpdate.name);

  constructor(
    private readonly admin: AdminService,
    private readonly audit: AuditService,
  ) {}

  @Start()
  async start(@Ctx() ctx: Context): Promise<void> {
    await ctx.reply('Ops bot online.\nCommands:\n/stats\n/find <email>\n/kick_<session_id>');
  }

  @Command('stats')
  async stats(@Ctx() ctx: Context): Promise<void> {
    const s = await this.admin.stats();
    await ctx.reply(
      [
        '📊 System stats',
        `• Active sessions: ${s.activeSessions}`,
        `• Ads watched today: ${s.adsWatchedToday}`,
        `• Total users: ${s.totalUsers}`,
        `• Premium users: ${s.premiumUsers}`,
      ].join('\n'),
    );
  }

  @Hears(/^\/find\s+(.+)$/)
  async find(@Ctx() ctx: Context & { match: RegExpExecArray }): Promise<void> {
    const email = ctx.match[1].trim();
    const u = await this.admin.findUserByEmail(email);
    if (!u) {
      await ctx.reply(`No user found for "${email}".`);
      return;
    }
    const sessions = u.activeSessions.length
      ? u.activeSessions.map((s) => `  • ${s.id} (${s.tier}/${s.status})`).join('\n')
      : '  • none';
    await ctx.reply(
      [
        `👤 ${u.email ?? '(anonymous)'}`,
        `id: ${u.id}`,
        `role: ${u.role}   banned: ${u.isBanned ? 'YES ⛔' : 'no'}   status: ${u.status}`,
        `active sessions:`,
        sessions,
      ].join('\n'),
    );
  }

  @Hears(/^\/kick_(.+)$/)
  async kick(@Ctx() ctx: Context & { match: RegExpExecArray }): Promise<void> {
    const sessionId = ctx.match[1].trim();
    if (!UUID_RE.test(sessionId)) {
      await ctx.reply('Usage: /kick_<session_id> (a session UUID).');
      return;
    }
    try {
      await this.admin.kickSession(sessionId);
      // Audit with the Telegram operator recorded in details (no backend user id).
      void this.audit
        .record({
          adminId: null,
          actionType: 'KICK_SESSION',
          targetId: sessionId,
          details: {
            source: 'telegram',
            telegramId: ctx.from?.id ?? null,
            telegramUsername: ctx.from?.username ?? null,
          },
        })
        .catch(() => undefined);
      await ctx.reply(`✅ Kicked session ${sessionId} (revoke queued to the panel).`);
    } catch (e) {
      await ctx.reply(`⚠️ Could not kick ${sessionId}: ${(e as Error).message}`);
    }
  }
}
