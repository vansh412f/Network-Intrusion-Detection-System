const SKIP_GEO_PATTERNS = ['127.0.0.1', 'localhost', 'MANUAL', '192.168.', '10.']

function getFlagEmoji(countryCode) {
  if (!countryCode) return '🌐'
  return countryCode
    .toUpperCase()
    .split('')
    .map((char) => String.fromCodePoint(127397 + char.charCodeAt(0)))
    .join('')
}

function shouldSkipGeo(ip) {
  if (!ip) return true
  if (SKIP_GEO_PATTERNS.some(pattern => ip.includes(pattern))) return true
  // RFC 1918: 172.16.0.0 – 172.31.255.255
  const m = ip.match(/^172\.(\d+)\./)
  if (m && +m[1] >= 16 && +m[1] <= 31) return true
  return false
}

function getMockGeo(ip) {
  const hash = (ip || '').split('.').reduce((a, b) => a + (parseInt(b) || 0), 0)
  const locations = [
    { country: 'United States', countryCode: 'US', city: 'San Francisco', lat: 37.7749,  lng: -122.4194 },
    { country: 'United States', countryCode: 'US', city: 'New York',      lat: 40.7128,  lng: -74.0060  },
    { country: 'United Kingdom',countryCode: 'GB', city: 'London',        lat: 51.5074,  lng: -0.1278   },
    { country: 'Germany',       countryCode: 'DE', city: 'Frankfurt',     lat: 50.1109,  lng: 8.6821    },
    { country: 'Japan',         countryCode: 'JP', city: 'Tokyo',         lat: 35.6895,  lng: 139.6917  },
    { country: 'Australia',     countryCode: 'AU', city: 'Sydney',        lat: -33.8688, lng: 151.2093  },
    { country: 'Brazil',        countryCode: 'BR', city: 'Sao Paulo',     lat: -23.5505, lng: -46.6333  },
    { country: 'Russia',        countryCode: 'RU', city: 'Moscow',        lat: 55.7558,  lng: 37.6173   },
    { country: 'China',         countryCode: 'CN', city: 'Beijing',       lat: 39.9042,  lng: 116.4074  }
  ]
  const loc = locations[hash % locations.length]
  return {
    ...loc,
    isp:  'Simulated ISP',
    flag: getFlagEmoji(loc.countryCode)
  }
}

let rateLimitedUntil = 0
const geoCache = new Map()

export async function enrichWithGeo(ip) {
  if (shouldSkipGeo(ip)) {
    let countryStr = 'Local Network'
    let ispStr     = 'Private Network'
    
    if (ip && ip.startsWith('MANUAL:')) {
      countryStr = 'Manual Input'
      ispStr     = ip.replace('MANUAL:', '')
    }

    return {
      country:     countryStr,
      countryCode: 'US',
      city:        'Localhost',
      isp:         ispStr,
      flag:        getFlagEmoji('US'),
      lat:         38.0,
      lng:         -97.0
    }
  }

  if (geoCache.has(ip)) return geoCache.get(ip)

  if (Date.now() < rateLimitedUntil) {
    const mock = getMockGeo(ip)
    geoCache.set(ip, mock)
    return mock
  }

  try {
    const response = await fetch(
      `https://ip-api.com/json/${ip}?fields=status,country,countryCode,city,isp,lat,lon`
    )

    if (response.status === 403 || response.status === 429) {
      rateLimitedUntil = Date.now() + 60000
      const mock = getMockGeo(ip)
      geoCache.set(ip, mock)
      return mock
    }

    if (!response.ok) {
      const mock = getMockGeo(ip)
      geoCache.set(ip, mock)
      return mock
    }

    const data = await response.json()
    if (data.status === 'fail') {
      const mock = getMockGeo(ip)
      geoCache.set(ip, mock)
      return mock
    }

    const geo = {
      country:     data.country,
      countryCode: data.countryCode,
      city:        data.city,
      isp:         data.isp,
      flag:        getFlagEmoji(data.countryCode),
      lat:         data.lat,
      lng:         data.lon
    }

    geoCache.set(ip, geo)
    return geo
  } catch {
    const mock = getMockGeo(ip)
    geoCache.set(ip, mock)
    return mock
  }
}
