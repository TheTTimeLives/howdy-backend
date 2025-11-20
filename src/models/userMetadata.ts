import { z } from 'zod';

// Firestore user_metadata/{uid}
export const UserMetadataDocSchema = z.object({
  id: z.string().min(1),
  username: z.string().nullable().optional(),
  photoUrl: z.string().nullable().optional(),
  verificationStatus: z
    .enum(['awaiting', 'processing', 'approved', 'reverify', 'denied'])
    .nullable()
    .optional(),
  onboarded: z.boolean().nullable().optional(),
  connectionCount: z.number().nullable().optional(),
  connectOutsidePreferences: z.boolean().nullable().optional(),
  bioResponses: z.record(z.any()).nullable().optional(),
  onboardingStage: z
    .enum(['connections', 'bio', 'interests', 'profile', 'complete'])
    .nullable()
    .optional(),
  groupCodes: z.array(z.string()).nullable().optional(),
  accountType: z.enum(['individual', 'carer', 'organization']).nullable().optional(),
  primaryGroupId: z.string().nullable().optional(),
  themeMode: z.string().nullable().optional(),
  textScale: z.number().nullable().optional(),
  currentPrompt: z.string().nullable().optional(),
  joinedPools: z.array(z.string()).nullable().optional(),
  blockedCategories: z.array(z.string()).nullable().optional(),
  // Chi fields used by /users/chi routes
  chiTotal: z.number().nullable().optional(),
  chiLevel: z.number().nullable().optional(),
  chiDailyKey: z.string().nullable().optional(),
  chiDailyCount: z.number().nullable().optional(),
});

export type UserMetadataDoc = z.infer<typeof UserMetadataDocSchema>;


