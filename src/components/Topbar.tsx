import React from 'react';
import { ViewType } from '../types';

interface TopbarProps {
  currentView: ViewType;
}

const VIEW_TITLES: Record<ViewType, string> = {
  'email-view': 'Analyze email',
  'gmail-view': 'Gmail inbox screening',
  'cases-view': 'Investigation cases & evidence vault',
  'dataset-view': 'Dataset review',
  'phishtrace-view': 'PhishTrace URL forensics',
  'mobile-view': 'Mobile link interception',
  'guide-view': 'How it works',
};

export const Topbar: React.FC<TopbarProps> = ({ currentView }) => {
  return (
    <header className="topbar">
      <div className="breadcrumb">
        <span>Workspace</span>
        <span className="crumb-separator">/</span>
        <strong>{VIEW_TITLES[currentView]}</strong>
      </div>
      <div className="topbar-right">
        <span className="local-badge">
          <i></i> PRIVATE BY DESIGN
        </span>
        <span className="avatar">S</span>
      </div>
    </header>
  );
};
