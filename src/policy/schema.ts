import { z } from 'zod';

/**
 * The Solana-specific capability manifest schema.
 *
 * This is intentionally narrow for the MVP: it describes the *ceiling* of
 * what a tool is allowed to do. The static scanner's findings are checked
 * against it in src/policy/enforcer.ts. Fields like max_sol and
 * max_transactions_per_hour are captured here and are enforced at *runtime*
 * by a wrapping guard (see README "Roadmap") — they cannot be verified by
 * static analysis alone.
 */
export const PolicySchema = z.object({
  name: z.string(),
  description: z.string().optional(),
  permissions: z.object({
    solana: z
      .object({
        programs: z.array(z.string()).default([]),
        max_sol: z.number().default(0),
        tokens: z.array(z.string()).default([]),
      })
      .default({ programs: [], max_sol: 0, tokens: [] }),
    network: z
      .object({
        domains: z.array(z.string()).default([]),
      })
      .default({ domains: [] }),
    wallet: z
      .object({
        signing: z.boolean().default(false),
        max_transactions_per_hour: z.number().default(0),
      })
      .default({ signing: false, max_transactions_per_hour: 0 }),
  }),
});

export type Policy = z.infer<typeof PolicySchema>;
