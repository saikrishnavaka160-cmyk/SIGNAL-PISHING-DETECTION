import { db } from './index.ts';
import { maliciousDomains } from './schema.ts';
import { inArray } from 'drizzle-orm';

export async function checkDomainHashPrefixes(hashPrefixes: string[]) {
  try {
    if (!hashPrefixes || hashPrefixes.length === 0) return [];
    return await db
      .select()
      .from(maliciousDomains)
      .where(inArray(maliciousDomains.domainHashPrefix, hashPrefixes));
  } catch (error) {
    console.error('Database query failed:', error);
    throw new Error('Database query failed. Please try again later.', { cause: error });
  }
}

export async function addMaliciousDomain(domainHashPrefix: string, threatType: string = 'phishing') {
  try {
    const result = await db
      .insert(maliciousDomains)
      .values({
        domainHashPrefix: domainHashPrefix.toLowerCase().trim(),
        threatType,
      })
      .onConflictDoNothing()
      .returning();
    return result[0];
  } catch (error) {
    console.error('Failed to add malicious domain:', error);
    throw new Error('Failed to record malicious domain.', { cause: error });
  }
}

export async function getAllMaliciousDomains() {
  try {
    return await db.select().from(maliciousDomains).limit(100);
  } catch (error) {
    console.error('Failed to get malicious domains:', error);
    throw new Error('Failed to fetch malicious domains.', { cause: error });
  }
}
