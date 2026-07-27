export const DOMAIN_RULES = [
  // Cloud & CDNs
  { match: /s3.*?\.amazonaws\.com/i, name: 'Amazon S3 Storage', category: 'Cloud Infrastructure' },
  { match: /\.amazonaws\.com/i, name: 'Amazon Web Services', category: 'Cloud Infrastructure' },
  { match: /\.cloudfront\.net/i, name: 'CloudFront CDN', category: 'CDN' },
  { match: /\.akamai(hd)?\.net/i, name: 'Akamai CDN', category: 'CDN' },
  { match: /\.fastly\.net/i, name: 'Fastly CDN', category: 'CDN' },
  { match: /\.cloudflare\.com/i, name: 'Cloudflare', category: 'CDN' },

  // Tech Giants & Telemetry
  { match: /\.1e100\.net/i, name: 'Google Background Services', category: 'Google', isBackground: true },
  { match: /google(apis|usercontent|syndication)\.com/i, name: 'Google Services', category: 'Google', isBackground: true },
  { match: /gstatic\.com/i, name: 'Google Static Content', category: 'Google', isBackground: true },
  { match: /\.google\.com/i, name: 'Google', category: 'Google', isBackground: false },
  { match: /\.apple\.com/i, name: 'Apple Services', category: 'Apple', isBackground: true },
  { match: /icloud\.com/i, name: 'Apple iCloud', category: 'Apple', isBackground: false },
  { match: /mzstatic\.com/i, name: 'Apple App Store', category: 'Apple', isBackground: true },
  { match: /\.microsoft\.com|microsoft\.com/i, name: 'Microsoft Services', category: 'Microsoft', isBackground: true },
  { match: /windowsupdate\.com/i, name: 'Windows Update', category: 'Microsoft', isBackground: true },
  { match: /azure\.com|azureedge\.net/i, name: 'Microsoft Azure', category: 'Cloud Infrastructure', isBackground: true },
  { match: /data\.microsoft\.com|events\.data\.microsoft/i, name: 'Microsoft Telemetry', category: 'Microsoft', isBackground: true },

  // Local Network & Broadcasts (mDNS, ARP, PTR)
  { match: /\.local$/i, name: 'Local Network Device', category: 'Local', isBackground: true },
  { match: /\.arpa$/i, name: 'Reverse DNS Lookup', category: 'Local', isBackground: true },

  // Social Media
  { match: /fbcdn\.net/i, name: 'Facebook CDN', category: 'Social Media' },
  { match: /\.facebook\.com/i, name: 'Facebook', category: 'Social Media' },
  { match: /\.instagram\.com/i, name: 'Instagram', category: 'Social Media' },
  { match: /twimg\.com/i, name: 'Twitter Media', category: 'Social Media' },
  { match: /\.twitter\.com|\.x\.com/i, name: 'X / Twitter', category: 'Social Media' },
  { match: /\.linkedin\.com/i, name: 'LinkedIn', category: 'Social Media' },

  // Streaming & Media
  { match: /nflxvideo\.net|nflxext\.com|netflix\.com/i, name: 'Netflix', category: 'Streaming' },
  { match: /spotify\.com/i, name: 'Spotify', category: 'Streaming' },
  { match: /youtube\.com|ytimg\.com|googlevideo\.com/i, name: 'YouTube', category: 'Streaming' },
  { match: /twitch\.tv/i, name: 'Twitch', category: 'Streaming' },

  // Analytics & Tracking
  { match: /google-analytics\.com/i, name: 'Google Analytics', category: 'Tracking / Analytics' },
  { match: /doubleclick\.net/i, name: 'Google Ads', category: 'Tracking / Analytics' },
];

export function simplifyDomain(domain) {
  if (!domain) return { name: 'Unknown', category: 'Unknown', raw: domain, isSimplified: false };

  for (const rule of DOMAIN_RULES) {
    if (rule.match.test(domain)) {
      return {
        name: rule.name,
        category: rule.category,
        raw: domain,
        isSimplified: true,
        isBackground: rule.isBackground || false
      };
    }
  }

  // Fallback: Try to extract a meaningful root domain
  const parts = domain.split('.');

  if (parts.length > 2) {
    const tld = parts[parts.length - 1];
    const sld = parts[parts.length - 2];

    // Check if it's a known country-code second-level domain (like co.uk, com.au, co.in)
    const isCcSld = tld.length === 2 && ['co', 'com', 'org', 'net', 'edu', 'gov', 'ac'].includes(sld);

    const partsToKeep = isCcSld ? 3 : 2;

    if (parts.length > partsToKeep) {
      const root = parts.slice(-partsToKeep).join('.');

      // Capitalize the main brand name part for a slightly friendlier look
      const brandPart = parts[parts.length - partsToKeep];
      const friendlyName = brandPart.charAt(0).toUpperCase() + brandPart.slice(1);

      return {
        name: friendlyName + ' (' + root + ')',
        category: 'General Traffic',
        raw: domain,
        isSimplified: true,
        isBackground: false
      };
    }
  }

  return {
    name: domain,
    category: 'General Traffic',
    raw: domain,
    isSimplified: false,
    isBackground: false
  };
}
