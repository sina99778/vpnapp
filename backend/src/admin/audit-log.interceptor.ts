import { CallHandler, ExecutionContext, Injectable, NestInterceptor } from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import type { Request } from 'express';
import { AuditService, AdminActionType } from './audit.service';

const MUTATING = new Set(['POST', 'PUT', 'DELETE', 'PATCH']);

interface Inferred {
  actionType: AdminActionType;
  targetId: string | null;
  details: Record<string, unknown>;
}

/**
 * Records an audit entry for each successful MUTATING AdminController action.
 *
 * Non-blocking: the entry is written AFTER the handler emits its result (so we
 * capture the outcome) but is fired-and-forgotten — the client's response is not
 * held for the audit write. AuditService.record never throws, and we attach a
 * defensive .catch, so a logging failure can never crash the request or the
 * process. Read (GET) endpoints are skipped.
 */
@Injectable()
export class AuditLogInterceptor implements NestInterceptor {
  constructor(private readonly audit: AuditService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const req = context.switchToHttp().getRequest<Request & { user?: { userId?: string } }>();
    if (!MUTATING.has(req.method)) return next.handle();

    const handlerName = context.getHandler().name;
    const adminId = req.user?.userId ?? null;
    const ip = req.ip ?? null;

    return next.handle().pipe(
      // tap's success path only fires when the handler RESOLVED — we never audit
      // a failed/rejected action.
      tap((result) => {
        const entries = infer(handlerName, req.params as Record<string, string>, req.body, result);
        for (const e of entries) {
          // Fire-and-forget. .catch is belt-and-suspenders (record() already
          // swallows) so there is never an unhandled rejection.
          void this.audit.record({ adminId, ip, ...e }).catch(() => undefined);
        }
      }),
    );
  }
}

/**
 * Map (handler, params, body, result) → 0..n audit entries for the ASYNC path.
 *
 * DEDUPE: BAN_USER, PANIC_FREE_SESSIONS and FORCE_MIGRATE_NODE are written
 * DURABLY in-transaction by AdminService, so we deliberately DO NOT emit them
 * here — otherwise a single action would produce two log rows. We still
 * async-log the non-destructive mutations (kick, unban, tier change).
 */
function infer(
  handlerName: string,
  params: Record<string, string>,
  body: unknown,
  result: unknown,
): Inferred[] {
  const b = (body ?? {}) as { isBanned?: boolean; tier?: string; isActive?: boolean };
  switch (handlerName) {
    case 'kick':
      return [{ actionType: 'KICK_SESSION', targetId: params.id ?? null, details: { result } }];

    case 'setNodeStatus':
      return [
        {
          actionType: 'SET_NODE_STATUS',
          targetId: params.id ?? null,
          details: { isActive: b.isActive, result },
        },
      ];

    case 'panic':
      return []; // logged in-tx by AdminService.panicRevokeFreeSessions

    case 'forceMigrate':
      return []; // logged in-tx by AdminService.forceMigrateNode

    case 'mutate': {
      const out: Inferred[] = [];
      const target = params.id ?? null;
      // BAN_USER is logged in-tx; only the UNBAN here.
      if (b.isBanned === false) {
        out.push({ actionType: 'UNBAN_USER', targetId: target, details: { result } });
      }
      if (b.tier) {
        out.push({ actionType: 'CHANGE_TIER', targetId: target, details: { tier: b.tier, result } });
      }
      return out;
    }

    default:
      // An unmapped mutating endpoint records nothing (add a case when you add
      // a new destructive action).
      return [];
  }
}
