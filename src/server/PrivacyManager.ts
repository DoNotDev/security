// packages/security/src/server/PrivacyManager.ts

/**
 * @fileoverview PrivacyManager
 * @description Right-to-erasure workflows and data retention policies.
 * Covers SOC2 Privacy Principle (P1-P8) and GDPR Article 17.
 *
 * @version 0.1.0
 * @since 0.0.1
 * @author AMBROISE PARK Consulting
 */

export interface RetentionPolicy {
  /** Collection/table name */
  collection: string;
  /**
   * Days to retain data. 0 = no automatic purge.
   * After `days` days, `shouldPurge()` returns true.
   */
  days: number;
  /**
   * Field to read for the document's creation timestamp (ISO 8601 string).
   * @default 'createdAt'
   */
  dateField?: string;
}

export interface ErasureRequest {
  /** User whose data should be erased */
  userId: string;
  /** Collections to erase data from */
  collections: string[];
  /**
   * Callback that performs the actual deletion for one collection.
   * Called once per collection in `collections`.
   */
  deleteUserData: (collection: string, userId: string) => Promise<void>;
}

export interface ErasureResult {
  /** Collections successfully erased */
  erased: string[];
  /** Collections that failed with error messages */
  errors: Array<{ collection: string; message: string }>;
}

/**
 * Privacy Manager — right-to-erasure (GDPR Art. 17) and retention policies (SOC2 P6).
 *
 * @example
 * ```typescript
 * const privacy = new PrivacyManager([
 *   { collection: 'audit_logs', days: 365 },
 *   { collection: 'sessions', days: 90 },
 * ]);
 *
 * // Erase all user data across collections:
 * await privacy.eraseUser({
 *   userId: 'u123',
 *   collections: ['users', 'orders', 'sessions'],
 *   deleteUserData: async (col, uid) => db.from(col).delete().eq('user_id', uid),
 * });
 *
 * // Check if a document should be purged:
 * privacy.shouldPurge('audit_logs', doc.createdAt); // true if > 365 days old
 * ```
 *
 * @version 0.1.0
 * @since 0.0.1
 * @author AMBROISE PARK Consulting
 */
export class PrivacyManager {
  private readonly policies: RetentionPolicy[];

  constructor(policies: RetentionPolicy[] = []) {
    this.policies = policies;
  }

  /**
   * Execute right-to-erasure for a user across multiple collections.
   * Calls `deleteUserData` for each collection; collects partial errors without aborting.
   * @throws {Error} if `collections` is empty — a silent no-op would be a GDPR violation.
   */
  async eraseUser(request: ErasureRequest): Promise<ErasureResult> {
    if (request.collections.length === 0) {
      throw new Error(
        '[dndev/security] eraseUser: collections array is empty. ' +
          'Provide at least one collection to erase user data from. ' +
          'A no-op erasure silently violates GDPR Art. 17.'
      );
    }

    const erased: string[] = [];
    const errors: Array<{ collection: string; message: string }> = [];

    for (const collection of request.collections) {
      try {
        await request.deleteUserData(collection, request.userId);
        erased.push(collection);
      } catch (err) {
        errors.push({
          collection,
          message: err instanceof Error ? err.message : String(err),
        });
      }
    }

    return { erased, errors };
  }

  /**
   * Check if a document should be purged based on its age and the configured retention policy.
   * Returns `false` if no policy is configured for the collection.
   *
   * @param collection - Collection name
   * @param dateIso - ISO 8601 creation timestamp of the document
   */
  shouldPurge(collection: string, dateIso: string): boolean {
    const policy = this.policies.find((p) => p.collection === collection);
    if (!policy || policy.days === 0) return false;

    if (!dateIso) {
      throw new Error(
        `[dndev/security] shouldPurge: missing dateIso for collection "${collection}". ` +
          'Expected ISO 8601 string. Cannot determine if document should be purged.'
      );
    }

    const ts = new Date(dateIso).getTime();
    if (isNaN(ts)) {
      throw new Error(
        `[dndev/security] shouldPurge: invalid dateIso "${dateIso}" for collection "${collection}". ` +
          'Expected ISO 8601 string. Cannot determine if document should be purged.'
      );
    }

    // WARNING: Clock skew between servers can cause inconsistent purge decisions.
    // In distributed deployments, use a centralized time source (e.g. NTP-synced) or
    // add a grace period to the policy to avoid premature purging of edge-case documents.
    const ageMs = Date.now() - ts;
    const policyMs = policy.days * 24 * 60 * 60 * 1000;
    return ageMs > policyMs;
  }

  /** Return all configured retention policies (used by `dn soc2` checker). */
  getPolicies(): RetentionPolicy[] {
    return this.policies;
  }
}
