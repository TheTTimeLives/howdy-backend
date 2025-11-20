import { z } from 'zod';

// Firestore users/{uid}
export const UserDocSchema = z.object({
  id: z.string().min(1),
  email: z.string().email().nullable().optional(),
  pii: z
    .object({
      firstNameEnc: z.string().optional(),
      lastNameEnc: z.string().optional(),
    })
    .optional(),
});

export type UserDoc = z.infer<typeof UserDocSchema>;


