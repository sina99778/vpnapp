import { CanActivate, ExecutionContext, Injectable, Logger } from '@nestjs/common';
import { TelegrafExecutionContext } from 'nestjs-telegraf';
import type { Context } from 'telegraf';

/**
 * ABSOLUTE whitelist. The bot ignores every update whose sender Telegram ID is
 * not explicitly listed in ADMIN_TELEGRAM_IDS. Returning false makes the handler
 * silently not run — no reply, no acknowledgement to a stranger. Only NUMERIC
 * ids are accepted (a malformed entry can never match a real Telegram id, but we
 * filter anyway), and an empty set means NOBODY — fail-closed by construction.
 */
const WHITELIST = new Set(
  (process.env.ADMIN_TELEGRAM_IDS ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter((s) => /^\d+$/.test(s)),
);
if (WHITELIST.size === 0) {
  new Logger('TelegramAdminGuard').warn(
    'ADMIN_TELEGRAM_IDS is empty/invalid — the Telegram bot will ignore everyone.',
  );
}

@Injectable()
export class TelegramAdminGuard implements CanActivate {
  canActivate(ctx: ExecutionContext): boolean {
    const tgCtx = TelegrafExecutionContext.create(ctx).getContext<Context>();
    const fromId = tgCtx.from?.id;
    return fromId != null && WHITELIST.has(String(fromId));
  }
}
