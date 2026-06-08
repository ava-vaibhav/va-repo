import { durable } from '@versori/run';
import { listIssuersWebhook } from './workflows/list-issuers';

async function main(): Promise<void> {
  const mi = await durable.DurableInterpreter.newInstance();

  mi.register(listIssuersWebhook);

  await mi.start();
}

main().catch((err) => console.error('Failed to run main()', err));
