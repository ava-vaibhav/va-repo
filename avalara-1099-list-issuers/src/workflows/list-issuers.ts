import { webhook, fn, http } from '@versori/run';

/**
 * Webhook: list-issuers
 *
 * Accepts an incoming request whose Authorization header carries a Bearer token.
 * Extracts the token, forwards it (always prefixed with "Bearer ") to the
 * Avalara 1099 API's GET /1099/issuers endpoint with sensible default filters,
 * then returns the raw Avalara response body to the caller.
 *
 * Filters applied:
 *   $top=100       – return up to 100 issuers per page
 *   $count=true    – include @recordSetCount in the response
 *   $orderBy=name ASC – alphabetical by issuer name
 */
export const listIssuersWebhook = webhook('list-issuers', { response: { mode: 'sync' } })
  .then(
    fn('extract-bearer-token', ({ data, log }) => {
      // In versori-run, ctx.data for the first step in a webhook chain contains
      // the full incoming request context: { headers: {...}, body: {...} }
      const rawHeader: string =
        data?.headers?.['authorization'] ??
        data?.headers?.['Authorization'] ??
        '';

      if (!rawHeader) {
        throw new Error(
          'Missing Authorization header – supply a Bearer token in the Authorization header of this request.',
        );
      }
			// this is the code comment added.
			// new code changes to commit.
			// new changes to go
      // Normalise: strip any existing "Bearer " prefix then re-apply it so the
      // outbound value is always "Bearer <token>", regardless of what the caller sent.
      const rawToken = rawHeader.replace(/^Bearer\s+/i, '').trim();

      if (!rawToken) {
        throw new Error('Authorization header is present but contains no token value.');
      }

      const bearerToken = `Bearer ${rawToken}`;
      log.info('Bearer token extracted from incoming Authorization header');

      return { bearerToken };
    }),
  )
  .then(
    http('fetch-issuers', { connection: 'avalara_1099' }, async ({ fetch, data, log }) => {
      // Filters: top 100 results, include total count, sorted by name.
      // Avalara REST filtering docs: https://developer.avalara.com/avatax/filtering-in-rest/
      const params = new URLSearchParams({
        '$top': '100',
        '$count': 'true',
        '$orderBy': 'name ASC',
      });

      // X-Correlation-Id is required by Avalara's 1099 API (GUID format).
      const correlationId = crypto.randomUUID();

      log.info('Calling GET /1099/issuers', { correlationId });

      const response = await fetch(`/1099/issuers?${params.toString()}`, {
        method: 'GET',
        headers: {
          // Forward the caller's Bearer token — always in "Bearer <token>" form.
          'Authorization': data.bearerToken,
          // Avalara 1099 API version header (required).
          'avalara-version': '2.0',
          'X-Correlation-Id': correlationId,
          'Accept': 'application/json',
        },
      });

      const body = await response.json();

      if (!response.ok) {
        log.error('Avalara 1099 API returned a non-2xx status', {
          status: response.status,
          correlationId,
          body,
        });
        throw new Error(`Avalara API error ${response.status}: ${JSON.stringify(body)}`);
      }

      log.info('Successfully retrieved issuers', {
        status: response.status,
        correlationId,
      });

      // Return the raw Avalara response — versori-run sync webhook will send
      // this directly as the HTTP response body to the original caller.
      return body;
    }),
  )
  .catch((ctx) => {
    ctx.log.error('list-issuers workflow failed', { error: String(ctx.data) });
    // Returning an error envelope lets the sync webhook surface a meaningful
    // response to the caller instead of an empty 500.
    return { error: String(ctx.data) };
  });
