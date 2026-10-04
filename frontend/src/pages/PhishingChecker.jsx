import React, { Component } from 'react';
import PhishingCheckerPanel from '../components/PhishingCheckerPanel';

class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }
  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }
  render() {
    if (this.state.hasError) {
      return (
        <div className="p-6">
          <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-6">
            <h2 className="text-red-400 font-bold text-lg mb-2">Detection Error</h2>
            <p className="text-gray-400 text-sm mb-4">
              Something went wrong during analysis. The page will not crash again.
            </p>
            <button
              onClick={() => this.setState({ hasError: false, error: null })}
              className="px-4 py-2 bg-red-600 text-white rounded text-sm hover:bg-red-500 transition-colors"
            >
              Try Again
            </button>
            <details className="mt-3">
              <summary className="text-gray-500 text-xs cursor-pointer">Error details</summary>
              <pre className="text-red-400 text-xs mt-2 overflow-auto">{this.state.error?.toString()}</pre>
            </details>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

export default function PhishingCheckerWithBoundary() {
  return (
    <ErrorBoundary>
      <PhishingCheckerPanel />
    </ErrorBoundary>
  );
}
