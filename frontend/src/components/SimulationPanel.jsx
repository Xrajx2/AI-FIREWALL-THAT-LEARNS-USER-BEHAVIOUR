import React, { useState } from 'react';
import { Play, ShieldAlert, Network, Activity, Info, Loader2 } from 'lucide-react';
import { formatRecommendedAction, getRiskTone, normalizeRiskLevel } from '../utils/risk';
import { buildApiUrl, getAuthHeaders } from '../utils/auth';

export default function SimulationPanel() {
  const [loadingAction, setLoadingAction] = useState(null);
  const [lastResult, setLastResult] = useState(null);
  const [errorMessage, setErrorMessage] = useState('');
  const [backendDown, setBackendDown] = useState(false);

  React.useEffect(() => {
    const checkBackend = async () => {
      try {
        const res = await fetch(buildApiUrl('/api/health'), { signal: AbortSignal.timeout(3000) });
        if (!res.ok) setBackendDown(true);
        else setBackendDown(false);
      } catch {
        setBackendDown(true);
      }
    };
    checkBackend();
  }, []);

  const simulateAction = async (scenario) => {
    setLoadingAction(scenario.id);
    setLastResult(null);
    setErrorMessage('');
    
    try {
      // Adding a slight delay to make it feel like "running a simulation" visually
      await new Promise(resolve => setTimeout(resolve, 800));

      const payload = {
        action_type: scenario.action_type,
        device: 'simulation-vm-01',
        network_activity: scenario.network_activity,
        details: scenario.details
      };

      const response = await fetch(buildApiUrl('/api/activity/log'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...getAuthHeaders(),
        },
        body: JSON.stringify(payload)
      });

      if (response.ok) {
        setBackendDown(false);
        const data = await response.json();
        setLastResult({
          scenario: scenario.name,
          score: data.assessment?.score,
          level: data.assessment?.level,
          recommendedAction: data.assessment?.recommended_action,
          reasons: data.assessment?.reasons || [],
          learningState: data.assessment?.learning_state || null,
        });
      } else if (response.status === 401) {
        setErrorMessage('Your session has expired, so this protected simulation request was blocked. Log out and sign in again, then try the test scenario once more.');
      } else {
        setErrorMessage('The simulation request did not complete. Please try again.');
      }
    } catch (error) {
      console.error("Simulation failed:", error);
      setBackendDown(true);
      setErrorMessage('The backend service is currently offline or unreachable. Please verify that the backend is running.');
    } finally {
      setLoadingAction(null);
    }
  };

  const scenarios = [
    {
      id: 'normal',
      name: 'Normal Employee Traffic',
      description: 'Generates standard web browsing and document access logs.',
      icon: <Activity className="text-primary" size={24} />,
      btnColor: 'bg-primary/20 hover:bg-primary/30 text-primary border border-primary/30',
      action_type: 'web_browsing',
      network_activity: Math.random() * 5,
      details: 'Routine productivity task'
    },
    {
      id: 'outbound',
      name: 'Suspicious Outbound Traffic',
      description: 'Simulates a process reaching an unusual public remote host.',
      icon: <Network className="text-warning" size={24} />,
      btnColor: 'bg-warning/20 hover:bg-warning/30 text-warning border border-warning/30',
      action_type: 'network_connection_suspicious',
      network_activity: 62.0,
      details: 'Unknown process reached a public remote IP over a non-standard outbound port'
    },
    {
      id: 'exfil',
      name: 'Data Exfiltration Attempt',
      description: 'Simulates a massive outward file transfer typical of a data breach.',
      icon: <ShieldAlert className="text-danger" size={24} />,
      btnColor: 'bg-danger/20 hover:bg-danger/30 text-danger border border-danger/30',
      action_type: 'file_transfer',
      network_activity: 6500.0,
      details: 'Massive data exfiltration attempt'
    }
  ];

  const resultTone = getRiskTone(lastResult?.level, lastResult?.score);

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <header className="mb-8">
        <h2 className="text-3xl font-bold text-white mb-2">Threat Simulator</h2>
        <p className="text-gray-400">Trigger safe test scenarios to verify the AI Firewall\'s response capabilities.</p>
      </header>

      {backendDown && (
        <div className="rounded-2xl border border-rose-500/30 bg-rose-500/10 p-5 text-sm text-rose-300 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <ShieldAlert className="text-rose-500 shrink-0" size={24} />
            <div>
              <div className="font-semibold text-white">Backend Offline</div>
              <p>The backend service is unreachable. Simulation scenarios and AI threat scoring cannot run until the server is running.</p>
            </div>
          </div>
          <button
            onClick={async () => {
              try {
                const res = await fetch(buildApiUrl('/api/health'), { signal: AbortSignal.timeout(3000) });
                setBackendDown(!res.ok);
              } catch {
                setBackendDown(true);
              }
            }}
            className="px-3 py-1.5 bg-rose-500/20 hover:bg-rose-500/30 text-rose-200 rounded-lg text-xs font-semibold"
          >
            Retry Connection
          </button>
        </div>
      )}

      <div className="rounded-2xl border border-primary/20 bg-primary/10 p-5 text-sm text-gray-300">
        <div className="text-white font-semibold mb-2">What this page does</div>
        <p>
          This screen does not attack your computer and it does not run real malware. Each button simply sends a sample event into the scoring engine so you can verify how the dashboard, alerts, and anomaly scoring react.
        </p>
      </div>

      {errorMessage && (
        <div className="rounded-2xl border border-warning/20 bg-warning/10 p-4 text-sm text-warning">
          {errorMessage}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
       {scenarios.map((scenario) => (
         <div key={scenario.id} className="glass-panel p-6 rounded-2xl flex flex-col h-full">
           <div className="flex items-center space-x-4 mb-4">
             <div className="p-3 bg-white/5 rounded-xl">
               {scenario.icon}
             </div>
             <h3 className="text-lg font-semibold text-white">{scenario.name}</h3>
           </div>
           
           <p className="text-gray-400 text-sm mb-8 flex-1">
             {scenario.description}
           </p>

           <div className="text-xs text-gray-500 mb-4">
             Expected use: generate a sample detection path for testing and demos.
           </div>
           
           <button
             onClick={() => simulateAction(scenario)}
             disabled={loadingAction !== null || backendDown}
             className={`w-full py-3 rounded-xl font-medium transition-all flex items-center justify-center space-x-2 ${scenario.btnColor} ${loadingAction || backendDown ? 'opacity-50 cursor-not-allowed' : ''}`}
           >
             {loadingAction === scenario.id ? (
               <Loader2 size={18} className="animate-spin" />
             ) : (
               <Play size={18} />
             )}
             <span>{loadingAction === scenario.id ? 'Simulating...' : 'Launch Simulation'}</span>
           </button>
         </div>
       ))}
      </div>

      {lastResult && (
        <div className={`mt-8 p-6 rounded-2xl border flex items-start space-x-4 animate-in fade-in zoom-in-95 ${
          resultTone.soft
        }`}>
          <Info className={resultTone.text} />
          <div>
            <h4 className="text-white font-medium mb-1">Simulation Complete: {lastResult.scenario}</h4>
            <p className="text-gray-300 text-sm">
              The AI evaluated this action and assigned an anomaly score of <strong className="text-white">{lastResult.score}</strong> (Level: {normalizeRiskLevel(lastResult.level, lastResult.score)}).
              Check the Live Activity stream to see it propagate.
            </p>
            <div className="mt-3 flex items-center gap-2">
              <span className={`px-2 py-1 rounded-full border text-xs font-medium ${resultTone.badge}`}>
                {normalizeRiskLevel(lastResult.level, lastResult.score)}
              </span>
              <span className="text-xs text-gray-400">
                Recommended action: {formatRecommendedAction(lastResult.recommendedAction)}
              </span>
            </div>
            {lastResult.reasons?.length > 0 && (
              <div className="mt-3 space-y-1 text-sm text-gray-300">
                {lastResult.reasons.slice(0, 3).map((reason) => (
                  <div key={reason}>- {reason}</div>
                ))}
              </div>
            )}
            {lastResult.learningState && (
              <div className="mt-3 text-xs text-gray-400">
                Training samples: {lastResult.learningState.training_samples} | Isolation Forest: {lastResult.learningState.isolation_forest_ready ? 'ready' : 'learning'} | Clustering: {lastResult.learningState.cluster_model_ready ? 'ready' : 'learning'} | Markov sequence model: ready
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
