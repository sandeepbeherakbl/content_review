import React from 'react';
import { Check, Clock, X } from 'lucide-react';
import './WorkflowStepper.css';

const WorkflowStepper = ({ currentStage, status }) => {
  const stages = [
    { id: 1, label: 'Editorial Review' },
    { id: 2, label: 'Final Approval' },
    { id: 3, label: 'Approved' }
  ];

  const getStageStatus = (stageId) => {
    if (status === 'rejected' && stageId === currentStage) return 'rejected';
    if (stageId < currentStage) return 'completed';
    if (stageId === currentStage) return 'active';
    return 'upcoming';
  };

  return (
    <div className="stepper-container">
      {stages.map((stage, index) => (
        <React.Fragment key={stage.id}>
          <div className={`step ${getStageStatus(stage.id)}`}>
            <div className="step-icon">
              {getStageStatus(stage.id) === 'completed' ? <Check size={16} /> : 
               getStageStatus(stage.id) === 'rejected' ? <X size={16} /> : 
               stage.id}
            </div>
            <div className="step-label">{stage.label}</div>
          </div>
          {index < stages.length - 1 && (
            <div className={`step-line ${getStageStatus(stage.id + 1) === 'completed' || getStageStatus(stage.id) === 'completed' ? 'filled' : ''}`}></div>
          )}
        </React.Fragment>
      ))}
    </div>
  );
};

export default WorkflowStepper;
