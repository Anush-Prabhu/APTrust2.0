import path from 'node:path';
import { describe, expect, it } from 'vitest';

process.env.APTRUST_DATA_DIR = path.resolve(__dirname, '..', '..', '..', 'data');

import { loadAll } from '../data';
import { type EngineContext, verifyUrl } from '../engine/engine';

const ctx: EngineContext = loadAll();

describe('rule engine: SRS T-RULE table', () => {
  it('T-RULE-001: jhu.edu \u2192 https://jhu.edu/  \u2192 OFFICIAL / SELF_VERIFIED', () => {
    const r = verifyUrl({ boundary: 'jhu.edu', url: 'https://jhu.edu/' }, ctx);
    expect(r.status).toBe('OFFICIAL');
    expect(r.relationship).toBe('SELF_VERIFIED');
    expect(r.statusCode).toBe(95);
  });

  it('T-RULE-002: jhu.edu \u2192 https://www.jhu.edu/ \u2192 OFFICIAL / OFFICIAL_DOMAIN_DECLARED', () => {
    const r = verifyUrl(
      { boundary: 'jhu.edu', url: 'https://www.jhu.edu/' },
      ctx,
    );
    expect(r.status).toBe('OFFICIAL');
    expect(r.relationship).toBe('OFFICIAL_DOMAIN_DECLARED');
    expect(r.statusCode).toBe(90);
  });

  it('T-RULE-003: jhu.edu \u2192 https://johnshopkins.edu/ \u2192 OFFICIAL / OFFICIAL_DOMAIN_DECLARED', () => {
    const r = verifyUrl(
      { boundary: 'jhu.edu', url: 'https://johnshopkins.edu/' },
      ctx,
    );
    expect(r.status).toBe('OFFICIAL');
    expect(r.relationship).toBe('OFFICIAL_DOMAIN_DECLARED');
  });

  it('T-RULE-004: jhu.edu \u2192 https://www.hopkinsmedicine.org/ \u2192 RELATED / BIDIRECTIONAL_VERIFIED', () => {
    const r = verifyUrl(
      { boundary: 'jhu.edu', url: 'https://www.hopkinsmedicine.org/' },
      ctx,
    );
    expect(r.status).toBe('RELATED');
    expect(r.relationship).toBe('BIDIRECTIONAL_VERIFIED');
    expect(r.statusCode).toBe(85);
  });

  it('T-RULE-005: hopkinsmedicine.org \u2192 https://www.jhmi.edu/ \u2192 OFFICIAL / OFFICIAL_DOMAIN_DECLARED', () => {
    const r = verifyUrl(
      { boundary: 'hopkinsmedicine.org', url: 'https://www.jhmi.edu/' },
      ctx,
    );
    expect(r.status).toBe('OFFICIAL');
    expect(r.relationship).toBe('OFFICIAL_DOMAIN_DECLARED');
  });

  it('T-RULE-006: jhu.edu \u2192 https://www.jhmi.edu/ \u2192 RELATED / BIDIRECTIONAL_VERIFIED', () => {
    const r = verifyUrl(
      { boundary: 'jhu.edu', url: 'https://www.jhmi.edu/' },
      ctx,
    );
    expect(r.status).toBe('RELATED');
    expect(r.relationship).toBe('BIDIRECTIONAL_VERIFIED');
  });

  it('T-RULE-007: hopkinsmedicine.org \u2192 instagram social profile \u2192 SOCIAL_VERIFIED', () => {
    const r = verifyUrl(
      {
        boundary: 'hopkinsmedicine.org',
        url: 'https://www.instagram.com/hopkinsmedicine/',
      },
      ctx,
    );
    expect(r.status).toBe('SOCIAL_VERIFIED');
    expect(r.relationship).toBe('SOCIAL_PROFILE_DECLARED');
    expect(r.statusCode).toBe(80);
  });

  it('T-RULE-008: hopkinsmedicine.org \u2192 x.com social profile \u2192 SOCIAL_VERIFIED', () => {
    const r = verifyUrl(
      { boundary: 'hopkinsmedicine.org', url: 'https://x.com/HopkinsMedicine' },
      ctx,
    );
    expect(r.status).toBe('SOCIAL_VERIFIED');
    expect(r.relationship).toBe('SOCIAL_PROFILE_DECLARED');
  });

  it('T-RULE-009: jhu.edu \u2192 https://jhuu.edu/ \u2192 SUSPICIOUS_LOOKALIKE', () => {
    const r = verifyUrl({ boundary: 'jhu.edu', url: 'https://jhuu.edu/' }, ctx);
    expect(r.status).toBe('SUSPICIOUS_LOOKALIKE');
    expect(r.relationship).toBe('LOOKALIKE_DETECTED');
    expect(r.statusCode).toBe(15);
  });

  it('T-RULE-010: jhuu.com \u2192 https://jhu.edu/ \u2192 SUSPICIOUS_UNIDIRECTIONAL_CLAIM', () => {
    const r = verifyUrl({ boundary: 'jhuu.com', url: 'https://jhu.edu/' }, ctx);
    expect(r.status).toBe('SUSPICIOUS_UNIDIRECTIONAL_CLAIM');
    expect(r.relationship).toBe('UNIDIRECTIONAL_CLAIM');
    expect(r.statusCode).toBe(10);
  });

  it('T-RULE-011: jhu.edu \u2192 random unrelated domain \u2192 OUT_OF_BOUNDARY', () => {
    const r = verifyUrl(
      { boundary: 'jhu.edu', url: 'https://random-example.com/' },
      ctx,
    );
    expect(r.status).toBe('OUT_OF_BOUNDARY');
    expect(r.relationship).toBe('NO_RELATIONSHIP_FOUND');
  });

  it('T-RULE-012: jhu.edu \u2192 punycode lookalike \u2192 SUSPICIOUS_LOOKALIKE', () => {
    const r = verifyUrl(
      { boundary: 'jhu.edu', url: 'https://xn--jhu-example.com/' },
      ctx,
    );
    expect(r.status).toBe('SUSPICIOUS_LOOKALIKE');
    expect(r.relationship).toBe('LOOKALIKE_DETECTED');
  });

  it('T-RULE-013: jhu.edu \u2192 brand+keyword squat \u2192 SUSPICIOUS_LOOKALIKE', () => {
    const r = verifyUrl(
      { boundary: 'jhu.edu', url: 'https://jhu-login-security.com/' },
      ctx,
    );
    expect(r.status).toBe('SUSPICIOUS_LOOKALIKE');
    expect(r.relationship).toBe('LOOKALIKE_DETECTED');
  });
});

describe('rule engine: edge cases', () => {
  it('returns UNKNOWN for an unknown boundary', () => {
    const r = verifyUrl(
      { boundary: 'nope.example', url: 'https://example.com/' },
      ctx,
    );
    expect(r.status).toBe('UNKNOWN');
  });

  it('returns UNKNOWN when the URL cannot be parsed', () => {
    const r = verifyUrl({ boundary: 'jhu.edu', url: '' }, ctx);
    expect(r.status).toBe('UNKNOWN');
  });

  it('SUSPICIOUS_UNIDIRECTIONAL_CLAIM fires before lookalike when applicable', () => {
    const r = verifyUrl({ boundary: 'jhuu.com', url: 'https://jhu.edu/' }, ctx);
    expect(r.status).toBe('SUSPICIOUS_UNIDIRECTIONAL_CLAIM');
    expect(r.reasons.join(' ')).toMatch(/reciprocally/i);
  });
});

describe('rule engine: subdomain awareness (regression)', () => {
  it('subdomain of canonical boundary \u2192 OFFICIAL via OFFICIAL_DOMAIN_DECLARED', () => {
    const r = verifyUrl(
      { boundary: 'jhu.edu', url: 'https://news.jhu.edu/' },
      ctx,
    );
    expect(r.status).toBe('OFFICIAL');
    expect(r.relationship).toBe('OFFICIAL_DOMAIN_DECLARED');
    expect(r.reasons.join(' ')).toMatch(/subdomain/i);
  });

  it('multi-label subdomain of canonical \u2192 OFFICIAL', () => {
    const r = verifyUrl(
      { boundary: 'jhu.edu', url: 'https://apply.it.jhu.edu/' },
      ctx,
    );
    expect(r.status).toBe('OFFICIAL');
    expect(r.relationship).toBe('OFFICIAL_DOMAIN_DECLARED');
  });

  it('subdomain of officialDomain host \u2192 OFFICIAL via OFFICIAL_DOMAIN_DECLARED', () => {
    const r = verifyUrl(
      { boundary: 'jhu.edu', url: 'https://it.johnshopkins.edu/' },
      ctx,
    );
    expect(r.status).toBe('OFFICIAL');
    expect(r.relationship).toBe('OFFICIAL_DOMAIN_DECLARED');
    expect(r.reasons.join(' ')).toMatch(/subdomain/i);
  });

  it('subdomain of relatedOrg host \u2192 RELATED / BIDIRECTIONAL_VERIFIED', () => {
    const r = verifyUrl(
      { boundary: 'jhu.edu', url: 'https://news.hopkinsmedicine.org/' },
      ctx,
    );
    expect(r.status).toBe('RELATED');
    expect(r.relationship).toBe('BIDIRECTIONAL_VERIFIED');
  });

  it('subdomain of suspicious unidirectional claim \u2192 still flagged', () => {
    const r = verifyUrl(
      { boundary: 'jhuu.com', url: 'https://news.jhu.edu/' },
      ctx,
    );
    expect(r.status).toBe('SUSPICIOUS_UNIDIRECTIONAL_CLAIM');
    expect(r.relationship).toBe('UNIDIRECTIONAL_CLAIM');
  });

  it('subdomain of a lookalike registered domain is still SUSPICIOUS_LOOKALIKE', () => {
    const r = verifyUrl(
      { boundary: 'jhu.edu', url: 'https://login.jhuu.edu/' },
      ctx,
    );
    expect(r.status).toBe('SUSPICIOUS_LOOKALIKE');
    expect(r.relationship).toBe('LOOKALIKE_DETECTED');
  });

  it('label-aware: evil-jhu.edu must NOT be treated as a subdomain of jhu.edu', () => {
    const r = verifyUrl(
      { boundary: 'jhu.edu', url: 'https://evil-jhu.edu/' },
      ctx,
    );
    expect(r.status).not.toBe('OFFICIAL');
    expect(r.status).not.toBe('RELATED');
  });

  it('subdomain of a parent organization \u2192 RELATED', () => {
    const r = verifyUrl(
      {
        boundary: 'hopkinsmedicine.org',
        url: 'https://about.jhu.edu/',
      },
      ctx,
    );
    expect(r.status).toBe('RELATED');
    expect(r.relationship).toBe('BIDIRECTIONAL_VERIFIED');
  });
});

describe('rule engine: APT 1.0 features (excludedDomains, EXCLUDED status)', () => {
  it('hosts on excludedDomains return EXCLUDED with the manifest reason', () => {
    const r = verifyUrl(
      { boundary: 'jhu.edu', url: 'https://jhu-promo-giveaway.example/' },
      ctx,
    );
    expect(r.status).toBe('EXCLUDED');
    expect(r.statusCode).toBe(5);
    expect(r.reasons.join(' ')).toMatch(/excludedDomains/);
    expect(r.reasons.join(' ')).toMatch(/Reason: Phishing/);
  });

  it('subdomains of excluded hosts also return EXCLUDED', () => {
    const r = verifyUrl(
      {
        boundary: 'jhu.edu',
        url: 'https://win.jhu-promo-giveaway.example/?prize=1',
      },
      ctx,
    );
    expect(r.status).toBe('EXCLUDED');
  });

  it('EXCLUDED overrides any other allow-list rule', () => {
    const local: EngineContext = {
      ...ctx,
      manifests: {
        ...ctx.manifests,
        'jhu.edu': {
          ...ctx.manifests['jhu.edu'],
          excludedDomains: [
            { domain: 'jhu.edu', reason: 'forced exclusion in test' },
          ],
        },
      },
    };
    const r = verifyUrl({ boundary: 'jhu.edu', url: 'https://jhu.edu/' }, local);
    expect(r.status).toBe('EXCLUDED');
    expect(r.reasons.join(' ')).toMatch(/forced exclusion in test/);
  });
});

describe('rule engine: APT 1.0 features (additionalProfiles)', () => {
  it('exact match on a third-party additionalProfile \u2192 OFFICIAL', () => {
    const r = verifyUrl(
      {
        boundary: 'jhu.edu',
        url: 'https://johnshopkins.employment.ngwebsolutions.com/',
      },
      ctx,
    );
    expect(r.status).toBe('OFFICIAL');
    expect(r.relationship).toBe('ADDITIONAL_PROFILE_DECLARED');
  });

  it('match ignores trailing slash and query string', () => {
    const r = verifyUrl(
      {
        boundary: 'jhu.edu',
        url: 'https://jhu.qualtrics.com?surveyId=abc',
      },
      ctx,
    );
    expect(r.status).toBe('OFFICIAL');
    expect(r.relationship).toBe('ADDITIONAL_PROFILE_DECLARED');
  });

  it('different host on the same vendor platform is NOT trusted', () => {
    const r = verifyUrl(
      {
        boundary: 'jhu.edu',
        url: 'https://otheruniversity.qualtrics.com/',
      },
      ctx,
    );
    expect(r.status).not.toBe('OFFICIAL');
  });

  it('hopkinsmedicine.org additionalProfile (MyChart) resolves OFFICIAL', () => {
    const r = verifyUrl(
      {
        boundary: 'hopkinsmedicine.org',
        url: 'https://mychart.hopkinsmedicine.org/',
      },
      ctx,
    );
    expect(r.status).toBe('OFFICIAL');
  });
});

describe('rule engine: APT 1.0 features (officialMail)', () => {
  it('official mail tenant + matching realm \u2192 OFFICIAL_MAIL_DECLARED', () => {
    const r = verifyUrl(
      {
        boundary: 'jhu.edu',
        url: 'https://outlook.cloud.microsoft/mail/?realm=jh.edu',
      },
      ctx,
    );
    expect(r.status).toBe('OFFICIAL');
    expect(r.relationship).toBe('OFFICIAL_MAIL_DECLARED');
  });

  it('official mail tenant with WRONG realm does NOT auto-trust', () => {
    const r = verifyUrl(
      {
        boundary: 'jhu.edu',
        url: 'https://outlook.cloud.microsoft/mail/?realm=other.edu',
      },
      ctx,
    );
    expect(r.status).not.toBe('OFFICIAL');
  });
});

describe('rule engine: APT 1.0 features (social sub-path matching)', () => {
  it('exact declared social profile \u2192 SOCIAL_VERIFIED', () => {
    const r = verifyUrl(
      {
        boundary: 'jhu.edu',
        url: 'https://www.instagram.com/johnshopkinsu',
      },
      ctx,
    );
    expect(r.status).toBe('SOCIAL_VERIFIED');
  });

  it('sub-path of declared social profile \u2192 SOCIAL_VERIFIED', () => {
    const r = verifyUrl(
      {
        boundary: 'jhu.edu',
        url: 'https://www.instagram.com/johnshopkinsu/tagged',
      },
      ctx,
    );
    expect(r.status).toBe('SOCIAL_VERIFIED');
    expect(r.reasons.join(' ')).toMatch(/sub-path/i);
  });

  it('prefix-but-not-segment match is NOT trusted', () => {
    const r = verifyUrl(
      {
        boundary: 'jhu.edu',
        url: 'https://www.instagram.com/johnshopkinsuhelp',
      },
      ctx,
    );
    expect(r.status).not.toBe('SOCIAL_VERIFIED');
  });
});

describe('rule engine: per-org boundaries (jhmi.edu and jhuu.com)', () => {
  it('jhmi.edu boundary recognises its own canonical domain', () => {
    const r = verifyUrl(
      { boundary: 'jhmi.edu', url: 'https://www.jhmi.edu/' },
      ctx,
    );
    expect(r.status).toBe('OFFICIAL');
  });

  it('jhmi.edu boundary recognises jhu.edu as RELATED via parent', () => {
    const r = verifyUrl(
      { boundary: 'jhmi.edu', url: 'https://www.jhu.edu/' },
      ctx,
    );
    expect(r.status).toBe('RELATED');
    expect(r.relationship).toBe('BIDIRECTIONAL_VERIFIED');
  });

  it('jhuu.com boundary verifies its own canonical', () => {
    const r = verifyUrl(
      { boundary: 'jhuu.com', url: 'https://jhuu.com/' },
      ctx,
    );
    expect(r.status).toBe('OFFICIAL');
  });

  it('jhuu.com boundary flags a subdomain of any claimed record', () => {
    const r = verifyUrl(
      { boundary: 'jhuu.com', url: 'https://news.hopkinsmedicine.org/' },
      ctx,
    );
    expect(r.status).toBe('SUSPICIOUS_UNIDIRECTIONAL_CLAIM');
  });
});
