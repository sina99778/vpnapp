import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { STATUS_CODES } from 'http';
import type { Request, Response } from 'express';

/**
 * Global exception filter. Guarantees the client NEVER sees a stack trace or an
 * internal error message — only a clean { statusCode, error, message }. The full
 * error (with stack) is logged server-side for diagnosis.
 *
 * - HttpException (incl. the controllers' Forbidden/ServiceUnavailable/Conflict)
 *   → passed through with its status + safe message.
 * - Anything else (a bug, a DB error) → 500 with a generic message; details stay
 *   in the server log only.
 */
@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly log = new Logger('Exception');

  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const res = ctx.getResponse<Response>();
    const req = ctx.getRequest<Request>();

    let status = HttpStatus.INTERNAL_SERVER_ERROR;
    let message: string | string[] = 'Internal server error';
    let error = 'Internal Server Error';

    if (exception instanceof HttpException) {
      status = exception.getStatus();
      // Default the label to the status' standard reason phrase (e.g. 503 →
      // "Service Unavailable"), overridable by the exception body.
      error = STATUS_CODES[status] ?? error;
      const body = exception.getResponse();
      if (typeof body === 'string') {
        message = body;
      } else if (body && typeof body === 'object') {
        const b = body as { message?: string | string[]; error?: string };
        message = b.message ?? exception.message;
        error = b.error ?? error;
      }
      // Class-validator errors (array of messages) are safe to return.
    } else {
      // Unknown/unexpected → log full detail, return generic to the client.
      const e = exception as Error;
      this.log.error(`Unhandled ${req.method} ${req.url}: ${e?.message}`, e?.stack);
    }

    res.status(status).json({
      statusCode: status,
      error,
      message,
      // No stack, no internal detail. timestamp aids client-side correlation.
      timestamp: new Date().toISOString(),
      path: req.url,
    });
  }
}
