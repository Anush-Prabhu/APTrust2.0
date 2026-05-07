import { describe, expect, it } from 'vitest';
import {
  findHostScopeMatch,
  hostMatches,
  isPunycode,
  isSocialHost,
  isSubdomainOf,
  normalizeUrl,
  registeredDomain,
  socialProfileEquals,
  stripWww,
} from '../normalize';

describe('normalizeUrl', () => {
  it('parses scheme-less hostnames', () => {
    const r = normalizeUrl('JHU.edu');
    expect(r.ok).toBe(true);
    expect(r.host).toBe('jhu.edu');
  });

  it('returns ok=false for malformed input', () => {
    expect(normalizeUrl('').ok).toBe(false);
    expect(normalizeUrl('http://').ok).toBe(false);
  });

  it('preserves the social path without trailing slash', () => {
    const r = normalizeUrl('https://www.instagram.com/hopkinsmedicine/');
    expect(r.host).toBe('www.instagram.com');
    expect(r.path).toBe('/hopkinsmedicine');
  });
});

describe('helpers', () => {
  it('stripWww removes leading www only', () => {
    expect(stripWww('www.jhu.edu')).toBe('jhu.edu');
    expect(stripWww('jhu.edu')).toBe('jhu.edu');
    expect(stripWww('www.www.example.com')).toBe('www.example.com');
  });

  it('detects punycode prefix', () => {
    expect(isPunycode('xn--example.com')).toBe(true);
    expect(isPunycode('example.com')).toBe(false);
  });

  it('hostMatches treats www-variant as the same boundary', () => {
    expect(hostMatches('www.jhu.edu', 'jhu.edu')).toBe(true);
    expect(hostMatches('jhu.edu', 'www.jhu.edu')).toBe(true);
    expect(hostMatches('jhu.edu', 'jhuu.edu')).toBe(false);
  });

  it('socialProfileEquals is case-insensitive on path', () => {
    expect(
      socialProfileEquals(
        'https://x.com/HopkinsMedicine',
        'https://x.com/hopkinsmedicine',
      ),
    ).toBe(true);
    expect(
      socialProfileEquals(
        'https://www.instagram.com/hopkinsmedicine/',
        'https://www.instagram.com/hopkinsmedicine',
      ),
    ).toBe(true);
    expect(
      socialProfileEquals(
        'https://x.com/HopkinsMedicine',
        'https://x.com/JohnsHopkins',
      ),
    ).toBe(false);
  });
});

describe('subdomain helpers', () => {
  it('isSubdomainOf is label-aware (true positives)', () => {
    expect(isSubdomainOf('news.jhu.edu', 'jhu.edu')).toBe(true);
    expect(isSubdomainOf('jhu.edu', 'jhu.edu')).toBe(true);
    expect(isSubdomainOf('apply.it.jhu.edu', 'jhu.edu')).toBe(true);
    expect(isSubdomainOf('www.jhu.edu', 'jhu.edu')).toBe(true);
  });

  it('isSubdomainOf is label-aware (true negatives)', () => {
    expect(isSubdomainOf('jhuu.edu', 'jhu.edu')).toBe(false);
    expect(isSubdomainOf('evil-jhu.edu', 'jhu.edu')).toBe(false);
    expect(isSubdomainOf('something.com', 'jhu.edu')).toBe(false);
  });

  it('findHostScopeMatch returns the longest matching parent', () => {
    const scope = ['jhu.edu', 'it.jhu.edu', 'johnshopkins.edu'];
    expect(findHostScopeMatch('apply.it.jhu.edu', scope)).toEqual({
      matched: 'it.jhu.edu',
      subdomain: true,
    });
    expect(findHostScopeMatch('jhu.edu', scope)).toEqual({
      matched: 'jhu.edu',
      subdomain: false,
    });
    expect(findHostScopeMatch('news.johnshopkins.edu', scope)).toEqual({
      matched: 'johnshopkins.edu',
      subdomain: true,
    });
    expect(findHostScopeMatch('random.com', scope)).toBeNull();
  });

  it('registeredDomain returns the last 2 labels', () => {
    expect(registeredDomain('news.jhuu.edu')).toBe('jhuu.edu');
    expect(registeredDomain('jhu.edu')).toBe('jhu.edu');
    expect(registeredDomain('a.b.c.example.com')).toBe('example.com');
  });

  it('isSocialHost recognises common multi-tenant social platforms', () => {
    expect(isSocialHost('x.com')).toBe(true);
    expect(isSocialHost('www.x.com')).toBe(true);
    expect(isSocialHost('m.facebook.com')).toBe(true);
    expect(isSocialHost('jhu.edu')).toBe(false);
  });
});
