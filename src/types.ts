export interface SignalItem {
  code: string;
  points: number;
  description: string;
}

export interface AnalysisResult {
  risk: 'High' | 'Suspicious' | 'Low';
  score: number;
  sender: string;
  signals: SignalItem[];
  linkDomains: string[];
  attachments: string[];
}

export interface DatasetEvaluation {
  evaluated: number;
  tp: number;
  fp: number;
  fn: number;
  tn: number;
  accuracy: string;
  precision: string;
  recall: string;
  f1: string;
}

export interface IndicatorCount {
  code: string;
  count: number;
}

export interface DatasetReport {
  scanned: number;
  blank: number;
  skipped: number;
  risks: {
    High: number;
    Suspicious: number;
    Low: number;
  };
  average: number;
  indicators: IndicatorCount[];
  threshold: number;
  evaluation?: DatasetEvaluation;
}

export type ViewType =
  | 'email-view'
  | 'gmail-view'
  | 'cases-view'
  | 'dataset-view'
  | 'phishtrace-view'
  | 'mobile-view'
  | 'guide-view';
