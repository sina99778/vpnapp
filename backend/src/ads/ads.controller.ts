import {
  BadRequestException,
  Body,
  Controller,
  Get,
  HttpCode,
  InternalServerErrorException,
  Logger,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { IsIn, IsOptional, IsUUID } from 'class-validator';
import type { Request } from 'express';
import { AdsService } from './ads.service';
import { AdMobSsvVerifier, SsvVerificationError } from './admob-ssv.verifier';

// These come from the auth module (Phase 1 design): JwtAuthGuard validates the
// access-JWT SIGNATURE server-side (never trusting TLS/pinning alone), and
// @CurrentUser() exposes the verified principal.
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { CurrentUser, AuthUser } from '../auth/current-user.decorator';

class RequestAdTokenDto {
  @IsIn(['connect', 'extend', 'disconnect'])
  purpose!: 'connect' | 'extend' | 'disconnect';

  @IsOptional()
  @IsUUID()
  sessionId?: string;
}

class VerifyAdRewardDto {
  @IsUUID()
  grantId!: string;

  @IsUUID()
  sessionId!: string;
}

@Controller('ads')
export class AdsController {
  private readonly log = new Logger(AdsController.name);

  constructor(
    private readonly ads: AdsService,
    private readonly ssv: AdMobSsvVerifier,
  ) {}

  /**
   * POST /ads/request-ad-token
   * Issues a single-use grant + nonce. The client passes `nonce` as the AdMob
   * rewarded-ad `custom_data` so the SSV callback can be bound back to it.
   */
  @UseGuards(JwtAuthGuard)
  @Post('request-ad-token')
  async requestAdToken(@CurrentUser() user: AuthUser, @Body() dto: RequestAdTokenDto) {
    return this.ads.requestAdToken(user.userId, user.deviceId, dto.purpose, dto.sessionId ?? null);
  }

  /**
   * POST /ads/verify-ad-reward
   * Claims a fulfilled grant. Trust comes from the SSV callbacks that already
   * populated ad_rewards — this endpoint only reads our own verified state,
   * extends the session by exactly grant_minutes, and mirrors to the panel
   * AFTER the DB transaction commits (no locks held during the panel call).
   */
  @UseGuards(JwtAuthGuard)
  @HttpCode(200)
  @Post('verify-ad-reward')
  async verifyAdReward(@CurrentUser() user: AuthUser, @Body() dto: VerifyAdRewardDto) {
    return this.ads.verifyAdReward(user.userId, dto.grantId, dto.sessionId);
  }

  /**
   * GET /ads/admob/ssv  (PUBLIC — called server-to-server by Google AdMob)
   *
   * This is the trust anchor. We verify the AdMob signature over the RAW query
   * string (re-encoding would break the signature), then record the reward.
   * The client is never involved, so a patched client cannot fabricate it.
   *
   * Status semantics tuned for AdMob's retry behaviour:
   *   200 → accepted (also for idempotent duplicates)
   *   400 → bad/forged signature or unknown grant  (do not credit)
   *   500 → transient server error  (AdMob will retry)
   */
  @Get('admob/ssv')
  @HttpCode(200)
  async admobSsv(@Req() req: Request): Promise<string> {
    // Take EVERYTHING after the first '?' verbatim — the signature is computed
    // over these exact bytes, so we must not re-encode or truncate. (split('?')[1]
    // would drop content after a second literal '?'.)
    const qIdx = req.originalUrl.indexOf('?');
    const rawQuery = qIdx >= 0 ? req.originalUrl.slice(qIdx + 1) : '';
    if (!rawQuery) throw new BadRequestException('empty callback');

    let reward;
    try {
      // Signature verification (may fetch keys over the network) happens BEFORE
      // any DB transaction is opened — no row locks held during off-box I/O.
      reward = await this.ssv.verify(rawQuery);
    } catch (err) {
      if (err instanceof SsvVerificationError) {
        this.log.warn(`rejected SSV callback: ${err.message}`);
        throw new BadRequestException('invalid signature');
      }
      throw err;
    }

    try {
      await this.ads.recordVerifiedReward(reward);
      return 'ok';
    } catch (err) {
      // Unknown nonce / ownership problems are client-side faults → 400, so we
      // do not invite an AdMob retry storm for a grant that will never exist.
      if (err && (err as { status?: number }).status === 404) {
        throw new BadRequestException('unknown grant');
      }
      this.log.error(`SSV record failed (will be retried by AdMob): ${(err as Error).message}`);
      throw new InternalServerErrorException('record failed');
    }
  }
}
