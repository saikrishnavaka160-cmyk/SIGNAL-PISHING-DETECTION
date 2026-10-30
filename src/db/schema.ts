import { pgTable, serial, varchar, timestamp, text, index } from 'drizzle-orm/pg-core';

export const maliciousDomains = pgTable(
  'malicious_domains',
  {
    id: serial('id').primaryKey(),
    domainHashPrefix: varchar('domain_hash_prefix', { length: 16 }).notNull().unique(),
    threatType: varchar('threat_type', { length: 32 }).default('phishing'),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow(),
  },
  (table) => ({
    idxHashPrefix: index('idx_hash_prefix').on(table.domainHashPrefix),
  })
);

export const users = pgTable('users', {
  id: serial('id').primaryKey(),
  uid: text('uid').notNull().unique(),
  email: text('email').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow(),
});
