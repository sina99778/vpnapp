import { Module } from '@nestjs/common';
import { TelegrafModule } from 'nestjs-telegraf';
import { AdminModule } from '../admin/admin.module';
import { TelegramUpdate } from './telegram.update';
import { TelegramAdminGuard } from './telegram-admin.guard';

/**
 * Telegram Ops bot. Imported by AppModule ONLY when TELEGRAM_BOT_TOKEN is set,
 * so the app boots fine without a bot configured. Reuses AdminService (from
 * AdminModule) for all logic.
 */
@Module({
  imports: [
    AdminModule,
    TelegrafModule.forRootAsync({
      useFactory: () => ({ token: process.env.TELEGRAM_BOT_TOKEN ?? '' }),
    }),
  ],
  providers: [TelegramUpdate, TelegramAdminGuard],
})
export class TelegramModule {}
