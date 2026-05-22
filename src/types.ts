export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'good';

export interface Summary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  good: number;
  totalFindings?: number;
}

export interface Finding {
  severity: Severity | string;
  category?: string;
  message: string;
}

export interface WordPressInfo {
  detected: boolean;
  signals: string[];
}

export interface RobotsDisallow {
  agent: string;
  path: string;
}

export interface RobotsReport {
  raw?: string;
  disallows: RobotsDisallow[];
  allows: RobotsDisallow[];
  findings: Finding[];
}

export interface BackdoorPatternHit {
  type: string;
  id: string;
  label: string;
  url: string;
}

export interface BackdoorPathHit {
  path: string;
  url: string;
  status: number;
  patterns?: BackdoorPatternHit[];
  note?: string;
}

export interface PathProbe {
  path: string;
  url: string;
  status: number;
  exists: boolean;
  accessible: boolean;
  suspicious: boolean;
  snippet: string;
  backdoorPatterns: BackdoorPatternHit[];
}

export interface CrawledPage {
  url: string;
  status?: number;
  depth?: number;
}

export interface ScanReport {
  target: string;
  startedAt: string;
  finishedAt?: string;
  wordPress: WordPressInfo;
  robots: RobotsReport | null;
  crawledPages: CrawledPage[];
  backdoorPaths: BackdoorPathHit[];
  backdoorPatterns: BackdoorPatternHit[];
  probes: PathProbe[];
  admin: Finding[];
  xss: Finding[];
  errors: string[];
  summary: Summary;
}

export interface ProgressEvent {
  message: string;
}

export interface ScanRequest {
  url: string;
}

export interface ScanResponse {
  report: ScanReport;
  progress: ProgressEvent[];
}

export type StreamLine =
  | { type: 'progress'; message: string }
  | { type: 'complete'; report: ScanReport }
  | { type: 'error'; message: string };

export interface FetchResult {
  ok: boolean;
  status: number;
  url: string;
  headers: Record<string, string>;
  body: string;
  error?: string;
}
