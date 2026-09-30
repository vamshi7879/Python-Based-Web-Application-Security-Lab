/**
 * Cloudflare Workers Handler
 * Routes requests to the built React application
 */

import { getAssetFromKV, NotFoundError, MethodNotAllowedError } from '@cloudflare/kv-asset-handler'

type Env = {
  __STATIC_CONTENT: KVNamespace
  ENVIRONMENT?: string
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      // Handle API routes if needed
      const url = new URL(request.url)

      // For API routes, add custom handlers here
      if (url.pathname.startsWith('/api/')) {
        return new Response(JSON.stringify({ error: 'API not configured' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' },
        })
      }

      // Serve static assets and SPA
      const asset = await getAssetFromKV({
        request,
        waitUntil: (promise: Promise<any>) => {
          // Handle the waitUntil promise if needed
        }
      } as any, {
        ASSET_NAMESPACE: env.__STATIC_CONTENT
      } as any)

      return asset
    } catch (error) {
      // Handle 404 and route to index.html for SPA
      if (error instanceof NotFoundError || error instanceof MethodNotAllowedError) {
        return new Response(null, { status: 404 })
      }

      return new Response('Internal Server Error', {
        status: 500,
        headers: { 'Content-Type': 'text/plain' },
      })
    }
  },
} satisfies ExportedHandler<Env>
