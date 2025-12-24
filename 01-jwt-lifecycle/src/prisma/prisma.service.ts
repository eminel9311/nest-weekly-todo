import { Injectable, LogLevel } from '@nestjs/common';
import { PrismaClient } from '../generated/prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import { ConfigService } from '@nestjs/config';
import { IConfig } from 'src/config/interfaces/config.interface';

@Injectable()
export class PrismaService extends PrismaClient {
  constructor(private readonly configService: ConfigService) {
    const dbConfig = configService.get<IConfig['db']>('db');
    const adapter = new PrismaPg({
      connectionString: dbConfig.connectionString,
    });

    super({
      adapter,
      errorFormat: dbConfig.errorFormat,
      transactionOptions: dbConfig.transactionOptions,
    });
  }

  async onModuleInit() {
    await this.$connect();
  }

  async onModuleDestroy() {
    await this.$disconnect();
  }
}