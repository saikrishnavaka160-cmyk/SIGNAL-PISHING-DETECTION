import { db } from './index.ts';
import { users } from './schema.ts';

export async function getOrCreateUser(uid: string, email: string) {
  const result = await db
    .insert(users)
    .values({
      uid,
      email,
    })
    .onConflictDoUpdate({
      target: users.uid,
      set: {
        email,
      },
    })
    .returning();

  return result[0];
}
