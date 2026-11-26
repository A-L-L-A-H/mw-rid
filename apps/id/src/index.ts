import { startRidServer } from './server.js';

async function main(): Promise<void> {
  const host = process.env.MW_RID_HOST ?? '0.0.0.0';
  const port = Number(process.env.MW_RID_PORT ?? 4480);

  const running = await startRidServer({ host, port });
  console.log(
    JSON.stringify({
      event: 'mw_rid_started',
      url: running.url,
      port: running.port,
    }),
  );

  const shutdown = async () => {
    await running.close();
    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
